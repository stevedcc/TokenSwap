/*
 * tswap - YubiKey Secret Manager (Compiled Entry Point)
 *
 * This is the AOT-compiled version of tswap.cs.
 * For the interpreted dotnet-script version, see tswap.cs.
 *
 * Build:   dotnet publish -c Release
 * Install: cp bin/Release/net10.0/linux-x64/publish/tswap ~/.local/bin/
 */

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TswapCore;

// Bridge dotnet-script's Args to compiled args
var Args = args.ToList();

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

// Allow overriding config directory for testing
var configDirOverride = Environment.GetEnvironmentVariable("TSWAP_CONFIG_DIR");
string ConfigDir;
if (configDirOverride != null)
{
    ConfigDir = configDirOverride;
}
else
{
    // When running under sudo, resolve config relative to the invoking user's home
    // so that "sudo tswap get" finds the same database as "tswap create"
    var sudoUser = Environment.GetEnvironmentVariable("SUDO_USER");
    var appDataDir = sudoUser != null
        ? Path.Combine("/home", sudoUser, ".config")
        : Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    ConfigDir = Path.Combine(appDataDir, "tswap-poc");
}

var PromptText = Prompt.GetText(Prefix);

// Storage instance using shared library
var storage = new Storage(ConfigDir);

// ============================================================================
// TEST KEY BYPASS
// ============================================================================

// When TSWAP_TEST_KEY is set (hex-encoded 32-byte key), all YubiKey operations
// are bypassed. This allows integration testing without hardware YubiKeys.
//
// Security note: TestKey also bypasses RequireSudo. The risk is bounded:
// an attacker who sets TSWAP_TEST_KEY still needs the correct 32-byte master
// key to decrypt vault data — an arbitrary TestKey value will cause AES-GCM
// authentication to fail on any secrets.json.enc encrypted with the real key.
// The sudo boundary protects AI agents from reading secrets via the tswap CLI,
// not from OS-level file access (which is out of scope regardless).
var testKeyHex = Environment.GetEnvironmentVariable("TSWAP_TEST_KEY");
byte[]? TestKey = null;
if (testKeyHex != null)
{
    TestKey = Convert.FromHexString(testKeyHex);
    if (TestKey.Length != 32)
        throw new Exception("TSWAP_TEST_KEY must be exactly 32 bytes (64 hex chars)");
    if (Verbose) Console.WriteLine("[TEST MODE] Using TSWAP_TEST_KEY — YubiKey operations bypassed");
}

// ============================================================================
// YUBIKEY OPERATIONS
// ============================================================================

byte[] ChallengeYubiKey(int serial, string challenge)
{
    if (TestKey != null)
        return TestKey[..20]; // Return first 20 bytes as simulated HMAC-SHA1 response

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
    if (TestKey != null)
        return requiredSerial ?? 99999999; // Return synthetic serial

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

byte[] UnlockWithYubiKey(Config config)
{
    if (TestKey != null)
        return TestKey; // Bypass YubiKey entirely — use test key as master key

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
    var k_other = Crypto.XorBytes(k_current, xorShare);

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

    return Crypto.DeriveKey(k1, k2);
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

string ReadPassword()
{
    // When stdin is redirected (e.g. in tests or piped input) skip interactive masking
    if (Console.IsInputRedirected)
        return Console.ReadLine() ?? "";

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
    if (TestKey != null) return; // test mode bypasses privilege check
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
    if (File.Exists(storage.ConfigFile))
    {
        Console.Write("Already initialized. Reinitialize? (yes/no): ");
        if (Console.ReadLine()?.ToLower() != "yes")
            return;
    }

    if (TestKey != null)
    {
        // Test mode: create synthetic config without YubiKey interaction
        var testConfig = new Config(
            new List<int> { 99999999, 99999998 },
            new string('0', 40), // 20-byte zero XOR share (hex)
            DateTime.UtcNow,
            null,
            "system",
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32))
        );
        storage.SaveConfig(testConfig);
        Console.WriteLine("Initialized (test mode)");
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
    var touch1 = YubiKey.DetectTouchRequirement(serial1);
    var touch2 = YubiKey.DetectTouchRequirement(serial2);
    
    bool? requiresTouch = null;
    if (touch1.HasValue && touch2.HasValue)
    {
        requiresTouch = touch1.Value && touch2.Value;
    }

    // Compute XOR redundancy
    var xorShare = Crypto.XorBytes(k1, k2);

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

    storage.SaveConfig(config);

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
    Console.WriteLine($"\nConfig saved to: {storage.ConfigFile}");
}

void CmdAdd(string name)
{
    RequireSudo("add");
    var config = storage.LoadConfig();

    Console.Write($"Secret value for '{name}': ");
    var value = ReadPassword();
    Console.Write("Confirm value: ");
    var confirm = ReadPassword();

    if (value != confirm)
        throw new Exception("Values don't match");

    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
    storage.SaveSecrets(db, key);

    Console.WriteLine($"\n✓ Secret '{name}' added successfully");
}

void CmdCreate(string name, int length = 32)
{
    const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";

    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    if (db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{name}' already exists. Use 'delete' first to rotate.");

    byte[] entropy;
    if (config.RngMode == "yubikey" && TestKey == null)
    {
        Console.WriteLine("Touch YubiKey for entropy generation...");
        var entropySerial = GetYubiKey();
        var challenge = RandomNumberGenerator.GetBytes(20);
        var hmac = ChallengeYubiKey(entropySerial, Convert.ToHexString(challenge));
        // Mix challenge + HMAC, then use HKDF to expand to exactly `length` bytes.
        // This avoids the period-32 bias that SHA256 truncation would cause for
        // passwords longer than 32 characters.
        var ikm = SHA256.HashData([..challenge, ..hmac]);
        entropy = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt: null, info: Encoding.UTF8.GetBytes("tswap-create"));
    }
    else
    {
        entropy = RandomNumberGenerator.GetBytes(length);
    }

    var password = new char[length];
    for (int i = 0; i < length; i++)
        password[i] = charset[entropy[i] % charset.Length];

    var value = new string(password);
    db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
    storage.SaveSecrets(db, key);

    Console.WriteLine($"\n✓ Secret '{name}' created ({length} chars)");
    Console.WriteLine("  Value was NOT displayed. Use 'run' to substitute it into commands.");
}

void CmdDelete(string name)
{
    RequireSudo("delete");

    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    if (!db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{name}' not found");

    db.Secrets.Remove(name);
    storage.SaveSecrets(db, key);

    Console.WriteLine($"\n✓ Secret '{name}' deleted");
}

void CmdGet(string name)
{
    RequireSudo("get");
    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    if (!db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{name}' not found");

    Console.WriteLine(db.Secrets[name].Value);
}

void CmdList()
{
    RequireSudo("list");
    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

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

void CmdExport(string path)
{
    RequireSudo("export");

    if (File.Exists(path))
    {
        Console.Write($"File '{path}' already exists. Overwrite? (yes/no): ");
        if (Console.ReadLine()?.ToLower() != "yes") return;
    }

    Console.Write("Export passphrase: ");
    var passphrase = ReadPassword();
    Console.Write("Confirm passphrase: ");
    var confirm = ReadPassword();
    if (passphrase != confirm)
        throw new Exception("Passphrases don't match");

    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    var salt = RandomNumberGenerator.GetBytes(32);
    var exportKey = Crypto.DeriveKeyFromPassphrase(passphrase, salt);
    var plaintext = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(db, TswapJsonContext.Default.SecretsDb));
    var ciphertext = Crypto.Encrypt(plaintext, exportKey);

    var exportFile = new ExportFile(
        "tswap-export-v1",
        DateTime.UtcNow,
        Convert.ToBase64String(salt),
        Convert.ToBase64String(ciphertext)
    );
    File.WriteAllText(path, JsonSerializer.Serialize(exportFile, TswapJsonContext.Default.ExportFile));

    var nonBurned = db.Secrets.Count(kv => kv.Value.BurnedAt == null);
    var burned = db.Secrets.Count(kv => kv.Value.BurnedAt != null);
    Console.WriteLine($"\n✓ Exported {nonBurned} secret(s) to: {path}");
    if (burned > 0)
        Console.WriteLine($"  ({burned} burned secret(s) included — will be skipped on import)");
    Console.WriteLine("  Keep this file and its passphrase secure.");
}

void CmdImport(string path)
{
    RequireSudo("import");

    if (!File.Exists(path))
        throw new Exception($"Export file not found: {path}");

    Console.Write("Export passphrase: ");
    var passphrase = ReadPassword();

    var exportFile = JsonSerializer.Deserialize(File.ReadAllText(path), TswapJsonContext.Default.ExportFile)
        ?? throw new Exception("Invalid export file");

    if (exportFile.Version != "tswap-export-v1")
        throw new Exception($"Unsupported export version: {exportFile.Version}");

    var salt = Convert.FromBase64String(exportFile.Salt);
    var exportKey = Crypto.DeriveKeyFromPassphrase(passphrase, salt);

    byte[] plaintext;
    try { plaintext = Crypto.Decrypt(Convert.FromBase64String(exportFile.Ciphertext), exportKey); }
    catch (CryptographicException) { throw new Exception("Decryption failed — wrong passphrase or file tampered"); }
    catch (FormatException) { throw new Exception("Export file is corrupted (base64 decode failed)"); }

    var exportedDb = JsonSerializer.Deserialize(Encoding.UTF8.GetString(plaintext), TswapJsonContext.Default.SecretsDb)
        ?? throw new Exception("Invalid export data");

    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    int imported = 0, skippedExisting = 0, skippedBurned = 0;
    foreach (var (name, secret) in exportedDb.Secrets.OrderBy(kv => kv.Key))
    {
        if (secret.BurnedAt != null)
        {
            Console.WriteLine($"  ⚠ Skipped '{name}' (was burned in source vault)");
            skippedBurned++;
            continue;
        }
        if (db.Secrets.ContainsKey(name))
        {
            Console.WriteLine($"  ⚠ Skipped '{name}' (already exists)");
            skippedExisting++;
            continue;
        }
        db.Secrets[name] = secret;
        imported++;
    }

    storage.SaveSecrets(db, key);
    Console.WriteLine($"\n✓ Imported {imported} secret(s)");
    if (skippedBurned > 0)   Console.WriteLine($"  Skipped {skippedBurned} burned secret(s)");
    if (skippedExisting > 0) Console.WriteLine($"  Skipped {skippedExisting} already-existing secret(s)");
}

void CmdNames()
{
    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

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

    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    if (db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{name}' already exists. Use 'delete' first to rotate.");

    db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
    storage.SaveSecrets(db, key);

    Console.WriteLine($"\n✓ Secret '{name}' ingested from stdin");
    Console.WriteLine("  Value was NOT displayed. Use 'run' to substitute it into commands.");
}

void CmdBurn(string name, string? reason)
{
    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    if (!db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{name}' not found");

    var existing = db.Secrets[name];
    db.Secrets[name] = existing with { BurnedAt = DateTime.UtcNow, BurnReason = reason };
    storage.SaveSecrets(db, key);

    Console.WriteLine($"\n⚠ Secret '{name}' marked as BURNED");
    Console.WriteLine("  This secret should be rotated as soon as possible.");
}

void CmdBurned()
{
    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

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
    Console.WriteLine(Prompt.GetHash(Prefix));
}

void CmdRun(string[] runArgs)
{
    // runArgs[0] is "run", everything after is the command
    if (runArgs.Length < 2)
        throw new Exception($"Usage: {Prefix} run <command> [args...]");

    var commandArgs = runArgs.Skip(1).ToArray();
    var command = string.Join(" ", commandArgs);

    // Find {{tokens}}
    var tokens = Validation.ExtractTokens(command);

    if (tokens.Count == 0)
        throw new Exception("No {{tokens}} found in command");

    // Block obvious attempts to exfiltrate secrets via run
    var blocked = Validation.GetBlockedCommand(commandArgs[0]);
    if (blocked != null)
        throw new Exception(
            $"The command '{blocked}' would expose secret values.\n" +
            "The 'run' command is for programs that *use* secrets, not display them.\n" +
            "Use 'sudo ... get <name>' to view a secret.");

    // Block shell output redirection (secrets could be written to readable files)
    if (Validation.HasPipeOrRedirect(command))
        throw new Exception(
            "Pipes and output redirection are not allowed in 'run' commands.\n" +
            "Secrets could be captured to files or piped to other programs.\n" +
            "Use 'sudo ... get <name>' to retrieve a secret value.");

    if (Verbose) Console.WriteLine($"Found tokens: {string.Join(", ", tokens)}");

    // Unlock and get secrets
    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    // Verify all tokens exist
    foreach (var token in tokens)
    {
        if (!db.Secrets.ContainsKey(token))
            throw new Exception($"Secret '{{{{{token}}}}}' not found");
    }

    // Substitute tokens
    var secretValues = tokens.ToDictionary(t => t, t => db.Secrets[t].Value);
    var substitutedCommand = Validation.SubstituteTokens(command, secretValues);

    // Show sanitized version
    if (Verbose)
    {
        Console.WriteLine($"\nExecuting: {Validation.SanitizeCommand(command)}");
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

void CmdCheck(string path)
{
    var markers = Check.ScanPath(path);

    if (markers.Count == 0)
    {
        Console.WriteLine("No # tswap: markers found.");
        return;
    }

    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    var results = Check.CheckMarkers(markers, db);

    var byFile = results.GroupBy(r => r.Marker.FilePath).OrderBy(g => g.Key);

    int okCount = 0, warnCount = 0, missingCount = 0;

    foreach (var fileGroup in byFile)
    {
        Console.WriteLine($"\n{fileGroup.Key}:");
        foreach (var result in fileGroup.OrderBy(r => r.Marker.LineNumber))
        {
            switch (result.Status)
            {
                case Check.SecretStatus.Ok:
                    Console.WriteLine($"  ✓ {result.Marker.SecretName} (line {result.Marker.LineNumber})");
                    okCount++;
                    break;
                case Check.SecretStatus.Burned:
                    Console.WriteLine($"  ⚠ {result.Marker.SecretName} (line {result.Marker.LineNumber}) — BURNED, needs rotation");
                    warnCount++;
                    break;
                case Check.SecretStatus.Missing:
                    Console.WriteLine($"  ✗ {result.Marker.SecretName} (line {result.Marker.LineNumber}) — NOT FOUND");
                    missingCount++;
                    break;
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

    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

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

    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

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

    var config = storage.LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = storage.LoadSecrets(key);

    var content = File.ReadAllText(filePath);
    var applied = Apply.ApplySecrets(content, db);

    Console.Write(applied);
}

void CmdMigrate()
{
    Console.WriteLine("\n╔════════════════════════════════════════════════════════════════╗");
    Console.WriteLine("║  tswap - Security Configuration Migration                    ║");
    Console.WriteLine("╚════════════════════════════════════════════════════════════════╝\n");

    var config = storage.LoadConfig();

    // Each setting is checked independently so that a partially-migrated or
    // manually-edited config still gets prompted for whichever fields are missing.
    bool needsRngPrompt          = config.RngMode == null;
    bool needsChallengeMigration = config.UnlockChallenge == null;
    bool needsTouchMigration  = config.RequiresTouch != true;
    bool needsReInit          = needsChallengeMigration || needsTouchMigration;

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
        storage.SaveConfig(config);
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

            Console.WriteLine($"Step {step++}: Export all secrets to an encrypted backup (requires sudo)");
            Console.WriteLine("  sudo tswap export ~/tswap-backup.enc");
            Console.WriteLine("  # Choose a strong passphrase — you will need it to import\n");

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

            Console.WriteLine($"Step {step}: Restore secrets from backup");
            Console.WriteLine("  sudo tswap import ~/tswap-backup.enc\n");

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
        Console.WriteLine($"  [sudo] {p} list             List all secrets (names and dates, no values)");
        Console.WriteLine($"  [sudo] {p} delete <name>    Delete a secret");
        Console.WriteLine($"  [sudo] {p} export <file>    Export all secrets to an encrypted backup");
        Console.WriteLine($"  [sudo] {p} import <file>    Import secrets from an encrypted backup");
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
        Console.WriteLine($"  - For [sudo] commands: copy tswap to /usr/local/bin");
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

        case "export":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: sudo {Prefix} export <file>");
            CmdExport(filteredArgs[1]);
            break;

        case "import":
            if (filteredArgs.Count < 2)
                throw new Exception($"Usage: sudo {Prefix} import <file>");
            CmdImport(filteredArgs[1]);
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

