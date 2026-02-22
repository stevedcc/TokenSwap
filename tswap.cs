#!/usr/bin/env -S dotnet-script
/*
 * tswap - YubiKey Secret Manager (dotnet-script version)
 *
 * This is the script version for development. For the compiled binary,
 * see Program.cs and build with: dotnet publish -c Release
 *
 * Usage:
 *   chmod +x tswap.cs
 *   ./tswap.cs <command>
 *
 * Prerequisites:
 *   - ykman CLI (YubiKey Manager)
 *   - dotnet-script: dotnet tool install -g dotnet-script
 *   - 2 YubiKeys with slot 2 configured: ykman otp chalresp --generate 2
 */

#nullable enable

#r "TswapCore/bin/Debug/net10.0/TswapCore.dll"

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TswapCore;

// ============================================================================
// CONFIGURATION
// ============================================================================

var Verbose = Args.Any(a => a == "-v" || a == "--verbose");

// Detect how tswap was invoked to show correct usage examples
string DetectInvocationPrefix()
{
    var processPath = Environment.ProcessPath;
    if (processPath == null) return "tswap";
    var processName = Path.GetFileName(processPath);
    // Compiled binary: process name is tswap (or whatever it was renamed to)
    if (!processName.Contains("dotnet"))
        return Path.GetFileNameWithoutExtension(processPath);
    // Script mode: check if invoked via 'dotnet script' or shebang
    if (Regex.IsMatch(Environment.CommandLine, @"dotnet\s+script\s+"))
        return "dotnet script tswap.cs --";
    // Shebang (#!/usr/bin/env -S dotnet-script) or direct dotnet-script invocation
    return "./tswap.cs";
}
var Prefix = DetectInvocationPrefix();

// When running under sudo, resolve config relative to the invoking user's home
// so that "sudo tswap get" finds the same database as "tswap create"
var sudoUser = Environment.GetEnvironmentVariable("SUDO_USER");
var appDataDir = sudoUser != null
    ? Path.Combine("/home", sudoUser, ".config")
    : Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
var ConfigDir = Path.Combine(appDataDir, "tswap-poc");
var ConfigFile = Path.Combine(ConfigDir, "config.json");
var SecretsFile = Path.Combine(ConfigDir, "secrets.json.enc");

const string PromptTemplate = @"# tswap - AI Agent Secret Management Instructions

You are working with tswap, a hardware-backed secret manager. Your role is to
manage secrets WITHOUT ever seeing their plaintext values.

## Commands you SHOULD use (no sudo required):
- `%CMD% create <name> [length]` — Generate a new random secret (value is never displayed)
- `%CMD% ingest <name>` — Pipe a secret from an external source: `<source> | %CMD% ingest <name>`
- `%CMD% names` — List all secret names (no values shown)
- `%CMD% run <command>` — Execute a command with {{secret-name}} token substitution
- `%CMD% burn <name> [reason]` — Mark a secret as burned if you accidentally see its value
- `%CMD% burned` — List all burned secrets that need rotation
- `%CMD% check <path>` — Scan a file or directory for `# tswap:` markers; exits non-zero if any referenced secret is missing
- `%CMD% redact <file>` — Print file to stdout with all known secret values replaced by [REDACTED] labels
- `%CMD% tocomment <file> [--dry-run]` — Replace inline secret values with empty values plus `# tswap: <name>` markers
- `%CMD% prompt` — Display these instructions
- `%CMD% prompt-hash` — Get hash of current instructions (to check if your cached copy is current)

## Commands you must NEVER use (require sudo, expose values):
- `sudo %CMD% add <name>` — Only for human interactive use
- `sudo %CMD% get <name>` — Exposes plaintext value
- `sudo %CMD% list` — Lists secrets with metadata
- `sudo %CMD% delete <name>` — Removes a secret

## Key rules:
1. NEVER use sudo commands — they expose secret values
2. NEVER generate, invent, or hardcode secret values yourself — always use `%CMD% create <name>` to
   generate secrets, then tell the user the name you chose so they can find it
3. Use {{secret-name}} tokens in `run` commands to use secrets without seeing them
4. If you see a plaintext secret value in ANY context (file contents, command output,
   log messages, error messages), you MUST IMMEDIATELY run `%CMD% burn <name> <reason>`
   BEFORE continuing any other work. Do not finish your current task first.
   Check `%CMD% names` to find the matching secret name if needed.
5. To import secrets from external systems, pipe them directly — NEVER use intermediate variables or
   echo. For Kubernetes, use jq (not jsonpath, which has shell quoting issues with dots/underscores):
   `kubectl get secret <secret> -n <ns> -o json | jq -r '.data[""<key>""] // empty' | base64 -d | %CMD% ingest <name>`
6. Check `%CMD% names` to see available secrets before constructing commands
7. Burned secrets should be rotated — check with `%CMD% burned`
8. When you create or ingest a secret, always inform the user of the secret name you used
9. Check `%CMD% burned` at the start of each session and inform the user of any pending rotations

## Keeping secrets out of config files:
- In Helm values.yaml and similar config files, replace plaintext secrets with empty
  values and a tswap comment: `password: """"  # tswap: k8s-namespace-secret-name`
- Use `%CMD% tocomment <file>` to automatically replace inline secret values with `# tswap:` markers
- Use `%CMD% check <path>` to verify that all `# tswap:` markers reference secrets that exist in the vault
- When deploying, scan for `# tswap:` comments and construct `%CMD% run` commands
  with `--set` flags using `{{token}}` substitution
- This allows agents to freely read config files without seeing secret values";
var PromptText = PromptTemplate.Replace("%CMD%", Prefix);

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// Config, Secret, SecretsDb are provided by TswapCore.dll

// ============================================================================
// YUBIKEY OPERATIONS
// ============================================================================

byte[] ChallengeYubiKey(int serial, string challenge)
{
    if (Verbose) Console.Write($"YubiKey (serial: {serial})... ");

    try
    {
        // Pad challenge to 64 bytes
        var challengeBytes = new byte[64];
        var inputBytes = Encoding.UTF8.GetBytes(challenge);
        Array.Copy(inputBytes, challengeBytes, Math.Min(inputBytes.Length, 64));

        // Convert to hex
        var hexChallenge = BitConverter.ToString(challengeBytes).Replace("-", "").ToLower();

        // Call ykman with --device to target the specific YubiKey
        var psi = new ProcessStartInfo
        {
            FileName = "ykman",
            Arguments = $"--device {serial} otp calculate 2 {hexChallenge}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (var process = Process.Start(psi)!)
        {
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
                throw new Exception($"ykman failed: {error}");

            // Parse hex response
            var hexResponse = output.Trim();
            var responseBytes = new byte[hexResponse.Length / 2];
            for (int i = 0; i < responseBytes.Length; i++)
                responseBytes[i] = Convert.ToByte(hexResponse.Substring(i * 2, 2), 16);

            if (Verbose) Console.WriteLine("✓");
            return responseBytes;
        }
    }
    catch (Exception ex)
    {
        if (Verbose) Console.WriteLine($"\nFailed: {ex.Message}");
        throw;
    }
}

int GetYubiKey(int? requiredSerial = null)
{
    // List connected YubiKeys via ykman
    var psi = new ProcessStartInfo
    {
        FileName = "ykman",
        Arguments = "list --serials",
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    using var process = Process.Start(psi)!;
    var output = process.StandardOutput.ReadToEnd();
    var error = process.StandardError.ReadToEnd();
    process.WaitForExit();

    if (process.ExitCode != 0)
        throw new Exception($"ykman failed: {error}");

    var serials = output.Trim()
        .Split('\n', StringSplitOptions.RemoveEmptyEntries)
        .Select(s => int.Parse(s.Trim()))
        .ToList();

    if (serials.Count == 0)
        throw new Exception("No YubiKey detected. Please insert YubiKey.");

    if (requiredSerial.HasValue)
    {
        if (!serials.Contains(requiredSerial.Value))
            throw new Exception($"YubiKey with serial {requiredSerial} not found.");
        return requiredSerial.Value;
    }

    if (serials.Count > 1)
    {
        Console.WriteLine("\nMultiple YubiKeys detected:");
        for (int i = 0; i < serials.Count; i++)
            Console.WriteLine($"  {i + 1}. Serial: {serials[i]}");
        Console.Write($"Select YubiKey (1-{serials.Count}): ");
        var choice = int.Parse(Console.ReadLine() ?? "1");
        return serials[choice - 1];
    }

    return serials[0];
}

bool? DetectTouchRequirement(int serial, int slot = 2)
{
    return YubiKey.DetectTouchRequirement(serial, slot);
}

// ============================================================================
// CRYPTO OPERATIONS
// ============================================================================

byte[] XorBytes(byte[] a, byte[] b)
{
    if (a.Length != b.Length)
        throw new ArgumentException("Byte arrays must be same length for XOR");
    
    return a.Zip(b, (x, y) => (byte)(x ^ y)).ToArray();
}

byte[] DeriveKey(byte[] k1, byte[] k2)
{
    var combined = k1.Concat(k2).ToArray();
    var salt = Encoding.UTF8.GetBytes("tswap-poc-v1");
    
    // Use new .NET 10 Pbkdf2 static method
    return Rfc2898DeriveBytes.Pbkdf2(
        combined,
        salt,
        100000,
        HashAlgorithmName.SHA256,
        32  // 256 bits
    );
}

byte[] Encrypt(byte[] plaintext, byte[] key)
{
    var tagSizeInBytes = AesGcm.TagByteSizes.MaxSize;
    using (var aes = new AesGcm(key, tagSizeInBytes))
    {
        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        var tag = new byte[tagSizeInBytes];
        var ciphertext = new byte[plaintext.Length];
        
        RandomNumberGenerator.Fill(nonce);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        
        return nonce.Concat(tag).Concat(ciphertext).ToArray();
    }
}

byte[] Decrypt(byte[] encrypted, byte[] key)
{
    var nonceSize = AesGcm.NonceByteSizes.MaxSize;
    var tagSize = AesGcm.TagByteSizes.MaxSize;
    
    var nonce = encrypted.Take(nonceSize).ToArray();
    var tag = encrypted.Skip(nonceSize).Take(tagSize).ToArray();
    var ciphertext = encrypted.Skip(nonceSize + tagSize).ToArray();
    
    using (var aes = new AesGcm(key, tagSize))
    {
        var plaintext = new byte[ciphertext.Length];
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}

// ============================================================================
// STORAGE OPERATIONS
// ============================================================================

Config LoadConfig()
{
    if (!File.Exists(ConfigFile))
        throw new Exception($"Not initialized. Run: {Prefix} init");
    
    var json = File.ReadAllText(ConfigFile);
    return JsonSerializer.Deserialize<Config>(json) 
        ?? throw new Exception("Invalid config");
}

void SaveConfig(Config config)
{
    Directory.CreateDirectory(ConfigDir);
    var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
    File.WriteAllText(ConfigFile, json);
}

SecretsDb LoadSecrets(byte[] key)
{
    if (!File.Exists(SecretsFile))
        return new SecretsDb(new Dictionary<string, Secret>());
    
    var encrypted = File.ReadAllBytes(SecretsFile);
    var decrypted = Decrypt(encrypted, key);
    var json = Encoding.UTF8.GetString(decrypted);
    return JsonSerializer.Deserialize<SecretsDb>(json) 
        ?? new SecretsDb(new Dictionary<string, Secret>());
}

void SaveSecrets(SecretsDb db, byte[] key)
{
    Directory.CreateDirectory(ConfigDir);
    var json = JsonSerializer.Serialize(db, new JsonSerializerOptions { WriteIndented = true });
    var plaintext = Encoding.UTF8.GetBytes(json);
    var encrypted = Encrypt(plaintext, key);
    File.WriteAllBytes(SecretsFile, encrypted);
}

byte[] UnlockWithYubiKey(Config config)
{
    // Warn about missing touch requirement
    YubiKey.WarnIfNoTouch(config);

    var serial = GetYubiKey();

    if (!config.YubiKeySerials.Contains(serial))
        throw new Exception($"YubiKey {serial} not authorized. Expected: {string.Join(", ", config.YubiKeySerials)}");

    // Challenge current YubiKey using the vault-unique challenge (falls back to the
    // legacy fixed challenge for configs created before this feature was added).
    var k_current = ChallengeYubiKey(serial, config.UnlockChallenge ?? "tswap-unlock");
    
    // Reconstruct other key via XOR
    var xorShare = Convert.FromHexString(config.RedundancyXor);
    var k_other = XorBytes(k_current, xorShare);
    
    // Determine order (use serials to ensure consistent ordering)
    byte[] k1, k2;
    if (serial == config.YubiKeySerials[0])
    {
        k1 = k_current;
        k2 = k_other;
    }
    else
    {
        k1 = k_other;
        k2 = k_current;
    }
    
    return DeriveKey(k1, k2);
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

string ReadPassword()
{
    var password = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(true);
        if (key.Key == ConsoleKey.Enter)
        {
            Console.WriteLine();
            break;
        }
        if (key.Key == ConsoleKey.Backspace && password.Length > 0)
        {
            password.Remove(password.Length - 1, 1);
            Console.Write("\b \b");
        }
        else if (!char.IsControl(key.KeyChar))
        {
            password.Append(key.KeyChar);
            Console.Write("*");
        }
    }
    return password.ToString();
}

void RequireSudo(string commandName)
{
    if (!Environment.IsPrivilegedProcess)
        throw new Exception(
            $"The '{commandName}' command requires sudo.\n" +
            $"Run: sudo {Prefix} {commandName} ...");
}

// ============================================================================
// COMMANDS
// ============================================================================

void CmdInit()
{
    if (File.Exists(ConfigFile))
    {
        Console.Write("Already initialized. Reinitialize? (yes/no): ");
        if (Console.ReadLine()?.ToLower() != "yes")
            return;
    }
    
    Console.WriteLine("\n╔════════════════════════════════════════╗");
    Console.WriteLine("║  tswap - YubiKey Initialization       ║");
    Console.WriteLine("╚════════════════════════════════════════╝\n");
    
    // Generate a vault-unique unlock challenge so the HMAC response cannot be
    // pre-computed by someone who briefly accesses a YubiKey without the config.
    var unlockChallenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    // Challenge first YubiKey
    Console.WriteLine("Insert YubiKey #1 and press Enter...");
    Console.ReadLine();
    var serial1 = GetYubiKey();
    var k1 = ChallengeYubiKey(serial1, unlockChallenge);

    // Challenge second YubiKey
    Console.WriteLine("\nRemove YubiKey #1, insert YubiKey #2, press Enter...");
    Console.ReadLine();
    var serial2 = GetYubiKey();

    if (serial1 == serial2)
        throw new Exception("Same YubiKey detected. Please use two different YubiKeys.");

    var k2 = ChallengeYubiKey(serial2, unlockChallenge);
    
    // Detect touch requirement for both keys
    Console.WriteLine("\nDetecting YubiKey slot configuration...");
    var touch1 = DetectTouchRequirement(serial1);
    var touch2 = DetectTouchRequirement(serial2);
    
    bool? requiresTouch = null;
    if (touch1.HasValue && touch2.HasValue)
    {
        requiresTouch = touch1.Value && touch2.Value;
    }
    
    // Compute XOR redundancy
    var xorShare = XorBytes(k1, k2);

    // Choose RNG mode for secret generation
    Console.WriteLine("\nPassword generation entropy source:");
    Console.WriteLine("  [1] System RNG  — one YubiKey touch per create (default)");
    Console.WriteLine("  [2] YubiKey     — two YubiKey touches per create; hardware-primary, immune to OS RNG compromise");
    Console.Write("Choose [1/2, default 1]: ");
    var rngChoice = Console.ReadLine()?.Trim();
    var rngMode = rngChoice == "2" ? "yubikey" : "system";

    // Save config
    var config = new Config(
        new List<int> { serial1, serial2 },
        Convert.ToHexString(xorShare),
        DateTime.UtcNow,
        requiresTouch,
        rngMode,
        unlockChallenge
    );
    
    SaveConfig(config);
    
    Console.WriteLine("\n╔════════════════════════════════════════╗");
    Console.WriteLine("║  ✓ INITIALIZATION COMPLETE            ║");
    Console.WriteLine("╚════════════════════════════════════════╝\n");
    Console.WriteLine($"YubiKey Serials: {serial1}, {serial2}");
    
    // Report touch requirement status
    if (requiresTouch == true)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("✓ Touch requirement: ENABLED (recommended)");
        Console.ResetColor();
    }
    else if (requiresTouch == false)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("⚠️  Touch requirement: DISABLED");
        Console.WriteLine("\nSECURITY NOTICE: Your YubiKeys are configured without button press");
        Console.WriteLine("requirement. Any process with access to inserted keys can unlock vault.");
        Console.WriteLine("\nTo enable touch requirement:");
        Console.WriteLine("  1. ykman otp delete 2      (for each key)");
        Console.WriteLine("  2. ykman otp chalresp --generate --touch 2");
        Console.WriteLine("  3. tswap init              (reinitialize)");
        Console.ResetColor();
    }
    
    Console.WriteLine($"Entropy mode:    {(rngMode == "yubikey" ? "YubiKey hardware (two touches per create)" : "System RNG (one touch per create)")}");

    Console.WriteLine("\n⚠️  CRITICAL: BACKUP XOR SHARE NOW\n");
    Console.WriteLine("XOR Share (hex):");
    Console.WriteLine(config.RedundancyXor);
    Console.WriteLine("\nBackup locations required:");
    Console.WriteLine("  [ ] Password manager (Bitwarden/1Password)");
    Console.WriteLine("  [ ] Printed copy (home safe)");
    Console.WriteLine("  [ ] Second printed copy (off-site)");
    Console.WriteLine("  [ ] Git repository");
    Console.WriteLine($"\nConfig saved to: {ConfigFile}");
}

void CmdAdd(string name)
{
    RequireSudo("add");
    var config = LoadConfig();
    
    Console.Write($"Secret value for '{name}': ");
    var value = ReadPassword();
    Console.Write("Confirm value: ");
    var confirm = ReadPassword();
    
    if (value != confirm)
        throw new Exception("Values don't match");
    
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);
    
    db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
    SaveSecrets(db, key);
    
    Console.WriteLine($"\n✓ Secret '{name}' added successfully");
}

void CmdCreate(string name, int length = 32)
{
    const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";

    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);

    if (db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{name}' already exists. Use 'delete' first to rotate.");

    byte[] entropy;
    if (config.RngMode == "yubikey" && TestKey == null)
    {
        Console.WriteLine("Touch YubiKey for entropy generation...");
        var entropySerial = GetYubiKey();
        var challenge = RandomNumberGenerator.GetBytes(20);
        var hmac = ChallengeYubiKey(entropySerial, Convert.ToHexString(challenge));
        entropy = SHA256.HashData(challenge.Concat(hmac).ToArray());
    }
    else
    {
        entropy = RandomNumberGenerator.GetBytes(length);
    }

    var password = new char[length];
    for (int i = 0; i < length; i++)
        password[i] = charset[entropy[i % entropy.Length] % charset.Length];

    var value = new string(password);
    db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
    SaveSecrets(db, key);

    Console.WriteLine($"\n✓ Secret '{name}' created ({length} chars)");
    Console.WriteLine("  Value was NOT displayed. Use 'run' to substitute it into commands.");
}

void CmdDelete(string name)
{
    RequireSudo("delete");

    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);

    if (!db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{name}' not found");

    db.Secrets.Remove(name);
    SaveSecrets(db, key);

    Console.WriteLine($"\n✓ Secret '{name}' deleted");
}

void CmdGet(string name)
{
    RequireSudo("get");
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);
    
    if (!db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{name}' not found");
    
    Console.WriteLine(db.Secrets[name].Value);
}

void CmdList()
{
    RequireSudo("list");
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);
    
    if (db.Secrets.Count == 0)
    {
        Console.WriteLine("No secrets stored.");
        return;
    }
    
    var nameWidth = Math.Max(20, db.Secrets.Keys.Max(n => n.Length));
    var lineWidth = nameWidth + 2 + 16 + 2 + 16; // name + gaps + two date columns

    Console.WriteLine($"\nSecrets ({db.Secrets.Count}):");
    Console.WriteLine($"{"NAME".PadRight(nameWidth)}  {"CREATED".PadRight(16)}  MODIFIED");
    Console.WriteLine("".PadRight(lineWidth, '-'));

    foreach (var (name, secret) in db.Secrets.OrderBy(s => s.Key))
    {
        Console.WriteLine($"{name.PadRight(nameWidth)}  {secret.Created:yyyy-MM-dd HH:mm}  {secret.Modified:yyyy-MM-dd HH:mm}");
    }
}

void CmdNames()
{
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);

    if (db.Secrets.Count == 0)
    {
        Console.WriteLine("No secrets stored.");
        return;
    }

    foreach (var name in db.Secrets.Keys.OrderBy(n => n))
    {
        var burned = db.Secrets[name].BurnedAt.HasValue ? " [BURNED]" : "";
        Console.WriteLine($"{name}{burned}");
    }
}

void CmdIngest(string name)
{
    if (Console.IsInputRedirected == false)
        throw new Exception($"No input piped. Use: <source> | {Prefix} ingest <name>\nFor interactive input, use: sudo {Prefix} add <name>");

    var value = Console.In.ReadToEnd().TrimEnd();
    if (string.IsNullOrEmpty(value))
        throw new Exception("Empty input received. Nothing to store.");

    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);

    if (db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{name}' already exists. Use 'delete' first to rotate.");

    db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
    SaveSecrets(db, key);

    Console.WriteLine($"\n✓ Secret '{name}' ingested from stdin");
    Console.WriteLine("  Value was NOT displayed. Use 'run' to substitute it into commands.");
}

void CmdBurn(string name, string? reason)
{
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);

    if (!db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{name}' not found");

    var existing = db.Secrets[name];
    db.Secrets[name] = existing with { BurnedAt = DateTime.UtcNow, BurnReason = reason };
    SaveSecrets(db, key);

    Console.WriteLine($"\n⚠ Secret '{name}' marked as BURNED");
    Console.WriteLine("  This secret should be rotated as soon as possible.");
}

void CmdBurned()
{
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);

    var burned = db.Secrets
        .Where(s => s.Value.BurnedAt.HasValue)
        .OrderBy(s => s.Value.BurnedAt)
        .ToList();

    if (burned.Count == 0)
    {
        Console.WriteLine("No burned secrets. All secrets are clean.");
        return;
    }

    var nameWidth = Math.Min(40, burned.Max(s => s.Key.Length));
    var dateWidth = 18; // "yyyy-MM-dd HH:mm" + 2 spaces
    var headerWidth = nameWidth + 2 + dateWidth + 2 + 6; // 6 = "REASON".Length

    Console.WriteLine($"\n⚠ Burned Secrets ({burned.Count}):");
    Console.WriteLine($"{"NAME".PadRight(nameWidth)}  {"BURNED AT".PadRight(dateWidth)}  REASON");
    Console.WriteLine("".PadRight(Math.Max(headerWidth, 60), '-'));

    foreach (var (name, secret) in burned)
    {
        var reason = secret.BurnReason ?? "(no reason given)";
        if (name.Length <= nameWidth)
        {
            Console.WriteLine($"{name.PadRight(nameWidth)}  {secret.BurnedAt:yyyy-MM-dd HH:mm}  {reason}");
        }
        else
        {
            Console.WriteLine(name);
            Console.WriteLine($"{"".PadRight(nameWidth)}  {secret.BurnedAt:yyyy-MM-dd HH:mm}  {reason}");
        }
    }

    Console.WriteLine($"\n→ Rotate these secrets, then 'delete' and re-create them.");
}

void CmdPrompt()
{
    Console.WriteLine(PromptText);
}

void CmdPromptHash()
{
    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(PromptText));
    Console.WriteLine(Convert.ToHexString(hash).ToLower());
}

void CmdRun(string[] args)
{
    // args[0] is "run", everything after is the command
    if (args.Length < 2)
        throw new Exception($"Usage: {Prefix} run <command> [args...]");
    
    var commandArgs = args.Skip(1).ToArray();
    var command = string.Join(" ", commandArgs);
    
    // Find {{tokens}}
    var tokenRegex = new Regex(@"\{\{([a-zA-Z0-9_-]+)\}\}");
    var matches = tokenRegex.Matches(command);
    var tokens = matches.Select(m => m.Groups[1].Value).Distinct().ToList();
    
    if (tokens.Count == 0)
        throw new Exception("No {{tokens}} found in command");

    // Block obvious attempts to exfiltrate secrets via run
    var baseCommand = commandArgs[0].ToLower();
    var blockedCommands = new HashSet<string>
        { "echo", "printf", "cat", "env", "printenv", "set", "tee" };
    if (blockedCommands.Contains(baseCommand))
        throw new Exception(
            $"The command '{baseCommand}' would expose secret values.\n" +
            "The 'run' command is for programs that *use* secrets, not display them.\n" +
            "Use 'sudo ... get <name>' to view a secret.");

    // Block shell output redirection (secrets could be written to readable files)
    if (Regex.IsMatch(command, @"[|>]"))
        throw new Exception(
            "Pipes and output redirection are not allowed in 'run' commands.\n" +
            "Secrets could be captured to files or piped to other programs.\n" +
            "Use 'sudo ... get <name>' to retrieve a secret value.");

    if (Verbose) Console.WriteLine($"Found tokens: {string.Join(", ", tokens)}");

    // Unlock and get secrets
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);
    
    // Verify all tokens exist
    foreach (var token in tokens)
    {
        if (!db.Secrets.ContainsKey(token))
            throw new Exception($"Secret '{{{{{token}}}}}' not found");
    }
    
    // Substitute tokens
    var substitutedCommand = command;
    foreach (var token in tokens)
    {
        var escapedValue = "'" + db.Secrets[token].Value.Replace("'", "'\\''") + "'";
        substitutedCommand = substitutedCommand.Replace($"{{{{{token}}}}}", escapedValue);
    }

    // Show sanitized version
    if (Verbose)
    {
        var sanitized = tokenRegex.Replace(command, "********");
        Console.WriteLine($"\nExecuting: {sanitized}");
        Console.WriteLine();
    }
    
    // Execute command
    var shell = OperatingSystem.IsWindows() ? "cmd" : "/bin/bash";
    var shellArg = OperatingSystem.IsWindows() ? "/c" : "-c";
    
    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = shell,
            Arguments = $"{shellArg} \"{substitutedCommand.Replace("\"", "\\\"")}\"",
            UseShellExecute = false
        }
    };
    
    process.Start();
    process.WaitForExit();
    
    Environment.Exit(process.ExitCode);
}


List<(string FilePath, int LineNumber, string SecretName)> ScanFileForMarkers(string filePath)
{
    var results = new List<(string, int, string)>();
    var markerRegex = new Regex(@"#\s*tswap\s*:\s*([a-zA-Z0-9_-]+)");
    string[] lines;
    try
    {
        lines = File.ReadAllLines(filePath);
    }
    catch
    {
        return results;
    }
    for (int i = 0; i < lines.Length; i++)
    {
        var matches = markerRegex.Matches(lines[i]);
        foreach (Match match in matches)
            results.Add((filePath, i + 1, match.Groups[1].Value));
    }
    return results;
}

List<(string FilePath, int LineNumber, string SecretName)> ScanPathForMarkers(string path)
{
    if (File.Exists(path))
        return ScanFileForMarkers(path);
    if (Directory.Exists(path))
    {
        var results = new List<(string, int, string)>();
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            results.AddRange(ScanFileForMarkers(file));
        return results;
    }
    throw new Exception($"Path not found: {path}");
}

void CmdCheck(string path)
{
    var markers = ScanPathForMarkers(path);

    if (markers.Count == 0)
    {
        Console.WriteLine("No # tswap: markers found.");
        return;
    }

    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);

    var byFile = markers.GroupBy(m => m.FilePath).OrderBy(g => g.Key);

    int okCount = 0, warnCount = 0, missingCount = 0;

    foreach (var fileGroup in byFile)
    {
        Console.WriteLine($"\n{fileGroup.Key}:");
        foreach (var (filePath, lineNumber, secretName) in fileGroup.OrderBy(m => m.LineNumber))
        {
            if (!db.Secrets.ContainsKey(secretName))
            {
                Console.WriteLine($"  ✗ {secretName} (line {lineNumber}) — NOT FOUND");
                missingCount++;
            }
            else if (db.Secrets[secretName].BurnedAt.HasValue)
            {
                Console.WriteLine($"  ⚠ {secretName} (line {lineNumber}) — BURNED, needs rotation");
                warnCount++;
            }
            else
            {
                Console.WriteLine($"  ✓ {secretName} (line {lineNumber})");
                okCount++;
            }
        }
    }

    Console.WriteLine($"\nSummary: {okCount} ok, {warnCount} warning(s), {missingCount} missing");

    if (missingCount > 0)
        Environment.Exit(1);
}

void CmdRedact(string filePath)
{
    if (!File.Exists(filePath))
        throw new Exception($"File not found: {filePath}");

    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);

    var content = File.ReadAllText(filePath);
    var redacted = Redact.RedactContent(content, db);

    Console.Write(redacted);

    var unknowns = Redact.FindUnknownSecrets(redacted);
    foreach (var (line, snippet) in unknowns)
        Console.Error.WriteLine($"⚠ Line {line}: possible unrecognized secret: {snippet}");
}

void CmdToComment(string filePath, bool dryRun)
{
    if (!File.Exists(filePath))
        throw new Exception($"File not found: {filePath}");

    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);

    var content = File.ReadAllText(filePath);
    var (newContent, changes) = Redact.ToComment(content, db);

    if (changes.Count == 0)
    {
        Console.WriteLine("No secrets found. File unchanged.");
        return;
    }

    foreach (var diff in changes)
    {
        Console.WriteLine($"  line {diff.LineNumber}:");
        Console.WriteLine($"  - {diff.Before}");
        Console.WriteLine($"  + {diff.After}");
    }

    if (dryRun)
    {
        Console.WriteLine($"\n(dry run) {changes.Count} line(s) would be modified.");
        return;
    }

    File.WriteAllText(filePath, newContent);
    Console.WriteLine($"\n✓ {changes.Count} line(s) updated in {filePath}");
}

void CmdApply(string filePath)
{
    if (!File.Exists(filePath))
        throw new Exception($"File not found: {filePath}");

    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);

    var content = File.ReadAllText(filePath);
    var applied = Apply.ApplySecrets(content, db);

    Console.Write(applied);
}

void CmdMigrate()
{
    Console.WriteLine("\n╔════════════════════════════════════════════════════════════════╗");
    Console.WriteLine("║  tswap - Security Configuration Migration                    ║");
    Console.WriteLine("╚════════════════════════════════════════════════════════════════╝\n");

    var config = LoadConfig();

    // UnlockChallenge == null is a reliable indicator the config predates the
    // vault-unique challenge and RngMode features (both were added together).
    bool needsRngPrompt          = config.UnlockChallenge == null;
    bool needsChallengeMigration = config.UnlockChallenge == null;
    bool needsTouchMigration     = config.RequiresTouch != true;
    bool needsReInit             = needsChallengeMigration || needsTouchMigration;

    // ── Status ───────────────────────────────────────────────────────────────
    Console.WriteLine("Current configuration:");
    Console.WriteLine($"  YubiKey #1:       {config.YubiKeySerials[0]}");
    Console.WriteLine($"  YubiKey #2:       {config.YubiKeySerials[1]}");

    Console.ForegroundColor = config.RequiresTouch == true ? ConsoleColor.Green : ConsoleColor.Yellow;
    Console.WriteLine(config.RequiresTouch == true
        ? "  Touch:            ENABLED ✓"
        : "  Touch:            not enabled ⚠");
    Console.ResetColor();

    Console.ForegroundColor = needsRngPrompt ? ConsoleColor.Yellow : ConsoleColor.Green;
    Console.WriteLine(needsRngPrompt
        ? "  Entropy mode:     not configured (defaults to system RNG) ⚠"
        : $"  Entropy mode:     {config.RngMode} ✓");
    Console.ResetColor();

    Console.ForegroundColor = needsChallengeMigration ? ConsoleColor.Yellow : ConsoleColor.Green;
    Console.WriteLine(needsChallengeMigration
        ? "  Unlock challenge: not set (fixed predictable challenge) ⚠"
        : "  Unlock challenge: vault-unique ✓");
    Console.ResetColor();

    if (!needsRngPrompt && !needsReInit)
    {
        Console.WriteLine("\n✓ All security settings are up to date. No migration needed.");
        return;
    }

    // ── Entropy mode: update in place, no re-init required ───────────────────
    if (needsRngPrompt)
    {
        Console.WriteLine("\n── Entropy mode for 'create' (no re-init required) ─────────────");
        Console.WriteLine("Password generation entropy source:");
        Console.WriteLine("  [1] System RNG  — one YubiKey touch per create (default)");
        Console.WriteLine("  [2] YubiKey     — two YubiKey touches per create; hardware-primary");
        Console.Write("Choose [1/2, default 1]: ");
        var rngChoice = Console.ReadLine()?.Trim();
        var newRngMode = rngChoice == "2" ? "yubikey" : "system";
        config = config with { RngMode = newRngMode };
        SaveConfig(config);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"✓ Entropy mode set to: {(newRngMode == "yubikey" ? "YubiKey hardware" : "System RNG")}");
        Console.ResetColor();
    }

    // ── Items requiring re-init ───────────────────────────────────────────────
    if (needsReInit)
    {
        Console.WriteLine("\n── Settings requiring re-initialization ─────────────────────────");
        if (needsChallengeMigration)
        {
            Console.WriteLine("  • Unlock challenge: a vault-unique challenge requires re-challenging");
            Console.WriteLine("    both YubiKeys and re-encrypting the vault with a new master key.");
        }
        if (needsTouchMigration)
            Console.WriteLine("  • Touch requirement: YubiKey slots must be reconfigured.");

        Console.WriteLine("\n⚠️  IMPORTANT: Ensure your XOR share is backed up before proceeding.");

        Console.Write("\nShow detailed re-initialization instructions? (yes/no): ");
        if ((Console.ReadLine()?.ToLower() ?? "") is "yes" or "y")
        {
            int step = 1;
            Console.WriteLine("\n" + new string('═', 64));
            Console.WriteLine("RE-INITIALIZATION GUIDE");
            Console.WriteLine(new string('═', 64) + "\n");

            Console.WriteLine($"Step {step++}: Export secret names (requires sudo)");
            Console.WriteLine("  mkdir -p ~/tswap-backup");
            Console.WriteLine("  sudo tswap list > ~/tswap-backup/secret-names.txt\n");

            if (needsTouchMigration)
            {
                Console.WriteLine($"Step {step++}: Reconfigure YubiKey slots to require touch");
                Console.WriteLine("  Insert YubiKey #1");
                Console.WriteLine($"  ykman --device {config.YubiKeySerials[0]} otp delete 2");
                Console.WriteLine($"  ykman --device {config.YubiKeySerials[0]} otp chalresp --generate --touch 2");
                Console.WriteLine("  Remove YubiKey #1, insert YubiKey #2");
                Console.WriteLine($"  ykman --device {config.YubiKeySerials[1]} otp delete 2");
                Console.WriteLine($"  ykman --device {config.YubiKeySerials[1]} otp chalresp --generate --touch 2\n");
            }

            Console.WriteLine($"Step {step++}: Reinitialize tswap (generates a new vault-unique unlock challenge)");
            Console.WriteLine("  tswap init\n");

            Console.WriteLine($"Step {step}: Restore secrets");
            Console.WriteLine("  sudo tswap add <name>    # re-add existing secrets");
            Console.WriteLine("  tswap create <name>      # or generate new random values\n");

            Console.WriteLine(new string('═', 64));
        }
    }
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

try
{
    if (Args.Count == 0)
    {
        var p = Prefix;
        Console.WriteLine("tswap - YubiKey Secret Manager");
        Console.WriteLine("\nUsage:");
        Console.WriteLine($"  {p} init                    Initialize with 2 YubiKeys");
        Console.WriteLine($"  {p} migrate                 Guide to upgrade slots for touch requirement");
        Console.WriteLine($"  {p} create <name> [len]     Generate random secret (no display)");
        Console.WriteLine($"  {p} ingest <name>           Pipe secret from stdin (no display)");
        Console.WriteLine($"  {p} names                   List secret names (no values)");
        Console.WriteLine($"  {p} run <cmd> [args...]     Execute with {{{{token}}}} substitution");
        Console.WriteLine($"  {p} check <path>            Verify # tswap: markers in file/dir");
        Console.WriteLine($"  {p} redact <file>           Output file with secret values redacted");
        Console.WriteLine($"  {p} tocomment <file>        Replace inline secrets with # tswap: comments");
        Console.WriteLine($"  {p} apply <file>            Output file with # tswap: markers substituted");
        Console.WriteLine($"  {p} burn <name> [reason]    Mark a secret as burned");
        Console.WriteLine($"  {p} burned                  List all burned secrets");
        Console.WriteLine($"  {p} prompt                  Show AI agent instructions");
        Console.WriteLine($"  {p} prompt-hash             Hash of agent instructions");
        Console.WriteLine($"  [sudo] {p} add <name>       Add a secret (user-provided value)");
        Console.WriteLine($"  [sudo] {p} get <name>       Get a secret value");
        Console.WriteLine($"  [sudo] {p} list             List all secrets");
        Console.WriteLine($"  [sudo] {p} delete <name>    Delete a secret");
        Console.WriteLine("\nCommands marked [sudo] require elevated privileges.");
        Console.WriteLine("Add -v or --verbose for detailed YubiKey output.");
        Console.WriteLine("\nExamples:");
        Console.WriteLine($"  {p} create storj-pass");
        Console.WriteLine($"  kubectl get secret db-pass -o jsonpath='{{{{.data.password}}}}' | base64 -d | {p} ingest db-pass");
        Console.WriteLine($"  {p} run rclone sync --password {{{{storj-pass}}}} /data remote:backup");
        Console.WriteLine($"  {p} check values.yaml");
        Console.WriteLine($"  {p} check ./helm/");
        Console.WriteLine($"  {p} redact values.yaml");
        Console.WriteLine($"  {p} tocomment values.yaml --dry-run");
        Console.WriteLine($"  {p} tocomment values.yaml");
        Console.WriteLine($"  {p} apply values.yaml");
        Console.WriteLine($"  {p} apply values.yaml > deployed.yaml");
        Console.WriteLine($"  helm upgrade app ./chart -f <({p} apply secrets.yaml)");
        Console.WriteLine($"  {p} burn db-pass \"accidentally logged\"");
        Console.WriteLine($"  sudo {p} get storj-pass");
        Console.WriteLine($"  sudo {p} list");
        Console.WriteLine("\nPrerequisites:");
        Console.WriteLine("  - ykman CLI: pip install yubikey-manager");
        Console.WriteLine("  - Configure YubiKeys with touch requirement (recommended):");
        Console.WriteLine("    ykman otp chalresp --generate --touch 2");
        Console.WriteLine("  - Or without touch (less secure):");
        Console.WriteLine("    ykman otp chalresp --generate 2");
        Console.WriteLine("  - For [sudo] commands, tswap must also be available to root");
        Environment.Exit(1);
    }
    
    var filteredArgs = Args.Where(a => a != "-v" && a != "--verbose").ToList();
    var command = filteredArgs[0].ToLower();

    switch (command)
    {
        case "init":
            CmdInit();
            break;
        
        case "migrate":
            CmdMigrate();
            break;
        
        case "create":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: {Prefix} create <name> [length]");
            var createLength = filteredArgs.Count >= 3 ? int.Parse(filteredArgs[2]) : 32;
            CmdCreate(filteredArgs[1], createLength);
            break;

        case "add":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: {Prefix} add <name>");
            CmdAdd(filteredArgs[1]);
            break;

        case "get":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: {Prefix} get <name>");
            CmdGet(filteredArgs[1]);
            break;

        case "names":
            CmdNames();
            break;

        case "list":
            CmdList();
            break;

        case "delete":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: {Prefix} delete <name>");
            CmdDelete(filteredArgs[1]);
            break;

        case "ingest":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: <source> | {Prefix} ingest <name>");
            CmdIngest(filteredArgs[1]);
            break;

        case "burn":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: {Prefix} burn <name> [reason]");
            var burnReason = filteredArgs.Count >= 3 ? string.Join(" ", filteredArgs.Skip(2)) : null;
            CmdBurn(filteredArgs[1], burnReason);
            break;

        case "burned":
            CmdBurned();
            break;

        case "prompt":
            CmdPrompt();
            break;

        case "prompt-hash":
            CmdPromptHash();
            break;

        case "check":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: {Prefix} check <path>");
            CmdCheck(filteredArgs[1]);
            break;

        case "redact":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: {Prefix} redact <file>");
            CmdRedact(filteredArgs[1]);
            break;

        case "tocomment":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: {Prefix} tocomment <file> [--dry-run]");
            CmdToComment(filteredArgs[1], filteredArgs.Contains("--dry-run"));
            break;

        case "apply":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: {Prefix} apply <file>");
            CmdApply(filteredArgs[1]);
            break;

        case "run":
            CmdRun(filteredArgs.ToArray());
            break;

        default:
            throw new Exception($"Unknown command: {command}");
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"\n❌ Error: {ex.Message}");
    Environment.Exit(1);
}
