#!/usr/bin/env dotnet-script
/*
 * tswap - YubiKey Secret Manager
 * 
 * Run directly:    dotnet script tswap.cs init
 * Or make executable: chmod +x tswap.cs && ./tswap.cs init
 * 
 * Commands:
 *   Privileged (require sudo to view/modify secrets):
 *     add <name>     - Add a secret interactively
 *     get <name>     - Display a secret (DANGEROUS: prints to console)
 *     list           - List all secret names
 *     delete <name>  - Delete a secret
 *   
 *   Unprivileged (work without sudo):
 *     init           - Initialize with 2 YubiKeys (creates XOR redundancy)
 *     create <name>  - Generate random secret (never displayed)
 *     run <cmd>      - Execute command with {{token}} substitution
 * 
 * Examples:
 *   ./tswap.cs init
 *   ./tswap.cs create api-key
 *   ./tswap.cs run curl -H "Auth: {{api-key}}" https://api.com
 *   sudo ./tswap.cs add manual-password
 *   sudo ./tswap.cs list
 * 
 * Prerequisites:
 *   - .NET 10 SDK
 *   - 2 YubiKeys with slot 2 configured: ykman otp chalresp --generate 2
 *   - dotnet-script (install: dotnet tool install -g dotnet-script)
 */

#r "nuget: Yubico.YubiKey, 1.12.0"

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Yubico.YubiKey;
using Yubico.YubiKey.Otp;
using Yubico.YubiKey.Otp.Operations;

// ============================================================================
// CONFIGURATION
// ============================================================================

var ConfigDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
    "tswap"
);
var ConfigFile = Path.Combine(ConfigDir, "config.json");
var SecretsFile = Path.Combine(ConfigDir, "secrets.json.enc");

// Parse global flags from Args (supports both -- and direct invocation)
var allArgs = Args.ToList();
bool DebugMode = allArgs.Contains("--debug");
bool QuietMode = allArgs.Contains("--quiet");

// Remove flags from args list
allArgs.RemoveAll(a => a == "--debug" || a == "--quiet");

// ============================================================================
// DATA STRUCTURES
// ============================================================================

record Config(List<int> YubiKeySerials, string RedundancyXor, DateTime Created);
record Secret(string Value, DateTime Created, DateTime Modified);
record SecretsDb(Dictionary<string, Secret> Secrets);

// ============================================================================
// PRIVILEGE CHECKING
// ============================================================================

bool IsRunningAsRoot()
{
    if (OperatingSystem.IsWindows())
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
    else
    {
        return Environment.GetEnvironmentVariable("USER") == "root" 
            || Environment.GetEnvironmentVariable("SUDO_USER") != null;
    }
}

void RequireSudo()
{
    if (!IsRunningAsRoot())
    {
        var sudoCmd = OperatingSystem.IsWindows() 
            ? "Run as Administrator" 
            : "sudo";
        
        throw new Exception($"This command requires elevated privileges. Run with: {sudoCmd}");
    }
}

void PreventSudo()
{
    if (IsRunningAsRoot())
    {
        throw new Exception("This command should NOT be run with sudo/administrator privileges.");
    }
}

// ============================================================================
// YUBIKEY OPERATIONS
// ============================================================================

byte[] ChallengeYubiKey(IYubiKeyDevice device, string challenge, bool silent = false)
{
    if (!silent && DebugMode)
        Console.Write($"YubiKey (serial: {device.SerialNumber})... ");
    
    try
    {
        // Pad challenge to 64 bytes
        var challengeBytes = new byte[64];
        var inputBytes = Encoding.UTF8.GetBytes(challenge);
        Array.Copy(inputBytes, challengeBytes, Math.Min(inputBytes.Length, 64));
        
        // Convert to hex
        var hexChallenge = BitConverter.ToString(challengeBytes).Replace("-", "").ToLower();
        
        // Call ykman directly
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "ykman",
            Arguments = $"otp calculate 2 {hexChallenge}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        
        var process = System.Diagnostics.Process.Start(psi);
        if (process == null)
            throw new Exception("Failed to start ykman process");
        
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
        
        if (!silent && DebugMode)
            Console.WriteLine("✓");
        
        return responseBytes;
    }
    catch (Exception ex)
    {
        if (!silent)
            Console.WriteLine($"\nFailed: {ex.Message}");
        throw;
    }
}

IYubiKeyDevice GetYubiKey(int? requiredSerial = null)
{
    var devices = YubiKeyDevice.FindAll().ToList();
    
    if (devices.Count == 0)
        throw new Exception("No YubiKey detected. Please insert YubiKey.");
    
    if (requiredSerial.HasValue)
    {
        var device = devices.FirstOrDefault(d => d.SerialNumber == requiredSerial.Value);
        if (device == null)
            throw new Exception($"YubiKey with serial {requiredSerial} not found.");
        return device;
    }
    
    if (devices.Count > 1 && !QuietMode)
    {
        Console.WriteLine("\nMultiple YubiKeys detected:");
        for (int i = 0; i < devices.Count; i++)
            Console.WriteLine($"  {{i + 1}}. Serial: {{devices[i].SerialNumber}} ");
        Console.Write($"Select YubiKey (1-{{devices.Count}}): ");
        var choice = int.Parse(Console.ReadLine() ?? "1");
        return devices[choice - 1];
    }
    
    return devices[0];
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
    var salt = Encoding.UTF8.GetBytes("tswap-v1");
    
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
        throw new Exception("Not initialized. Run: tswap init");
    
    var json = File.ReadAllText(ConfigFile);
    return JsonSerializer.Deserialize<Config>(json) 
        ?? throw new Exception("Invalid config");
}

void SaveConfig(Config config)
{
    Directory.CreateDirectory(ConfigDir);
    
    var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
    File.WriteAllText(ConfigFile, json);
    
    // Set restrictive permissions
    if (!OperatingSystem.IsWindows())
    {
        try
        {
            File.SetUnixFileMode(ConfigFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            if (DebugMode)
                Console.WriteLine("⚠️  Warning: Could not set restrictive file permissions");
        }
    }
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
    
    // Set restrictive permissions
    if (!OperatingSystem.IsWindows())
    {
        try
        {
            File.SetUnixFileMode(SecretsFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch { }
    }
}

byte[] UnlockWithYubiKey(Config config, bool silent = false)
{
    var device = GetYubiKey();
    var serial = device.SerialNumber ?? 0;
    
    if (!config.YubiKeySerials.Contains(serial))
        throw new Exception($"YubiKey {{serial}} not authorized. Expected: {{string.Join(", ", config.YubiKeySerials)}}");
    
    // Challenge current YubiKey
    var k_current = ChallengeYubiKey(device, "tswap-unlock", silent);
    
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

string ReadPassword(string prompt = null)
{
    if (prompt != null)
        Console.Write(prompt);
    
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

bool IsValidSecretName(string name)
{
    return !string.IsNullOrWhiteSpace(name) 
        && name.Length <= 64 
        && Regex.IsMatch(name, @"^[a-zA-Z0-9_-]+$");
}

void ValidateSecretName(string name)
{
    if (!IsValidSecretName(name))
        throw new Exception($"Invalid secret name: '{{name}}'. Must be 1-64 characters, alphanumeric plus dash/underscore only.");
}

// ============================================================================
// COMMANDS - UNPRIVILEGED (work without sudo)
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
    
    // Challenge first YubiKey
    Console.WriteLine("Insert YubiKey #1 and press Enter...");
    Console.ReadLine();
    var yk1 = GetYubiKey();
    var serial1 = yk1.SerialNumber ?? 0;
    var k1 = ChallengeYubiKey(yk1, "tswap-unlock");
    
    // Challenge second YubiKey
    Console.WriteLine("\nRemove YubiKey #1, insert YubiKey #2, press Enter...");
    Console.ReadLine();
    var yk2 = GetYubiKey();
    var serial2 = yk2.SerialNumber ?? 0;
    
    if (serial1 == serial2)
        throw new Exception("Same YubiKey detected. Please use two different YubiKeys.");
    
    var k2 = ChallengeYubiKey(yk2, "tswap-unlock");
    
    // Compute XOR redundancy
    var xorShare = XorBytes(k1, k2);
    
    // Save config
    var config = new Config(
        new List<int> { serial1, serial2 },
        Convert.ToHexString(xorShare),
        DateTime.UtcNow
    );
    
    SaveConfig(config);
    
    Console.WriteLine("\n╔════════════════════════════════════════╗");
    Console.WriteLine("║  ✓ INITIALIZATION COMPLETE            ║");
    Console.WriteLine("╚════════════════════════════════════════╝\n");
    Console.WriteLine($"YubiKey Serials: {{serial1}}, {{serial2}}");
    Console.WriteLine("\n⚠️  CRITICAL: BACKUP XOR SHARE NOW\n");
    Console.WriteLine("XOR Share (hex):");
    Console.WriteLine(config.RedundancyXor);
    Console.WriteLine("\nBackup locations required:");
    Console.WriteLine("  [ ] Password manager (Bitwarden/1Password)");
    Console.WriteLine("  [ ] Printed copy (home safe)");
    Console.WriteLine("  [ ] Second printed copy (off-site)");
    Console.WriteLine("  [ ] Git repository (safe - see docs)");
    Console.WriteLine($"\nConfig saved to: {{ConfigFile}}\n");
    Console.WriteLine("\n💡 TIP: You can now use 'create' and 'run' without sudo!");
}

void CmdCreate(string name, string[] options)
{
    PreventSudo();
    ValidateSecretName(name);
    
    // Parse options
    int length = 32;
    bool alphanumeric = false;
    
    for (int i = 0; i < options.Length; i++)
    {
        if (options[i] == "--length" && i + 1 < options.Length)
        {
            if (!int.TryParse(options[i + 1], out length) || length < 8 || length > 256)
                throw new Exception("Length must be between 8 and 256");
            i++;
        }
        else if (options[i] == "--alphanumeric")
        {
            alphanumeric = true;
        }
    }
    
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config, silent: !DebugMode);
    var db = LoadSecrets(key);
    
    if (db.Secrets.ContainsKey(name))
    {
        Console.Write($"Secret '{{name}}' exists. Overwrite? (yes/no): ");
        if (Console.ReadLine()?.ToLower() != "yes")
            return;
    }
    
    // Generate cryptographically secure random secret
    string secret;
    if (alphanumeric)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        secret = new string(bytes.Select(b => chars[b % chars.Length]).ToArray());
    }
    else
    {
        var bytes = new byte[(length * 3) / 4 + 1];
        RandomNumberGenerator.Fill(bytes);
        secret = Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")
            .Substring(0, length);
    }
    
    db.Secrets[name] = new Secret(secret, DateTime.UtcNow, DateTime.UtcNow);
    SaveSecrets(db, key);
    
    if (!QuietMode)
        Console.WriteLine($"✓ Secret '{{name}}' created ({{length}} characters)");
}

void CmdRun(string[] args)
{
    PreventSudo();
    
    if (args.Length < 2)
        throw new Exception("Usage: tswap run <command>");
    
    var commandArgs = args.Skip(1).ToArray();
    var command = string.Join(" ", commandArgs);
    
    // Find {{tokens}}
    var tokenRegex = new Regex(@"\{\{([a-zA-Z0-9_-]+)\}\}");
    var matches = tokenRegex.Matches(command);
    var tokens = matches.Select(m => m.Groups[1].Value).Distinct().ToList();
    
    if (tokens.Count == 0)
        throw new Exception("No {{tokens}} found in command");
    
    // Check for dangerous patterns
    var dangerousPatterns = new Dictionary<string, string>
    {
        { "echo", "Echo commands may display secrets in terminal output" },
        { "printf", "Printf commands may display secrets in terminal output" },
        { "> ", "File redirection may write secrets to disk" },
        { ">>", "File redirection may write secrets to disk" },
        { "tee", "Tee command writes output to files" },
        { "export", "Export commands may persist secrets in shell environment" },
        { "set ", "Set commands may persist secrets in shell environment" },
    };
    
    foreach (var (pattern, warning) in dangerousPatterns)
    {
        if (command.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"\n⚠️  WARNING: {{warning}} ");
            Console.Write("Continue? (yes/no): ");
            if (Console.ReadLine()?.ToLower() != "yes")
            {
                Console.WriteLine("Aborted.");
                return;
            }
            break;
        }
    }
    
    if (DebugMode)
        Console.WriteLine($"Found tokens: {{string.Join(", ", tokens)}}");
    
    // Unlock and get secrets
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config, silent: !DebugMode);
    var db = LoadSecrets(key);
    
    // Verify all tokens exist
    foreach (var token in tokens)
    {
        if (!db.Secrets.ContainsKey(token))
            throw new Exception($"Secret '{{{{token}}}}' not found");
    }
    
    // Substitute tokens
    var substitutedCommand = command;
    foreach (var token in tokens)
        substitutedCommand = substitutedCommand.Replace($"{{{{token}}}}", db.Secrets[token].Value);
    
    if (DebugMode)
    {
        var sanitized = tokenRegex.Replace(command, "********");
        Console.WriteLine($"\nExecuting: {{sanitized}} ");
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
            Arguments = $"{shellArg} \"{{substitutedCommand.Replace("\", "\\").Replace(\"\", \\\"\\\")}}\"",
            UseShellExecute = false
        }
    };
    
    process.Start();
    process.WaitForExit();
    
    Environment.Exit(process.ExitCode);
}

// ============================================================================
// COMMANDS - PRIVILEGED (require sudo)
// ============================================================================

void CmdAdd(string name)
{
    RequireSudo();
    ValidateSecretName(name);
    
    var config = LoadConfig();
    
    var value = ReadPassword($"Secret value for '{{name}}': ");
    var confirm = ReadPassword("Confirm value: ");
    
    if (value != confirm)
        throw new Exception("Values don't match");
    
    if (string.IsNullOrEmpty(value))
        throw new Exception("Secret value cannot be empty");
    
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);
    
    db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
    SaveSecrets(db, key);
    
    Console.WriteLine($"\n✓ Secret '{{name}}' added successfully");
}

void CmdGet(string name)
{
    RequireSudo();
    
    Console.WriteLine("\n⚠️  WARNING: This will display the secret in PLAINTEXT on your terminal!");
    Console.WriteLine("⚠️  This may be visible to AI assistants, screen sharing, or terminal history.");
    Console.Write("\nContinue? (yes/no): ");
    
    if (Console.ReadLine()?.ToLower() != "yes")
    {
        Console.WriteLine("Aborted.");
        return;
    }
    
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);
    
    if (!db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{{name}}' not found");
    
    Console.WriteLine($"\n{{db.Secrets[name].Value}} ");
}

void CmdList()
{
    RequireSudo();
    
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);
    
    if (db.Secrets.Count == 0)
    {
        Console.WriteLine("No secrets stored.");
        return;
    }
    
    Console.WriteLine($"\nSecrets ({{db.Secrets.Count}}):");
    Console.WriteLine("NAME                 CREATED              MODIFIED");
    Console.WriteLine("".PadRight(60, '-'));
    
    foreach (var (name, secret) in db.Secrets.OrderBy(s => s.Key))
    {
        Console.WriteLine($"{{name.PadRight(20)}} {{secret.Created:yyyy-MM-dd HH:mm}} {{secret.Modified:yyyy-MM-dd HH:mm}} ");
    }
}

void CmdDelete(string name)
{
    RequireSudo();
    
    var config = LoadConfig();
    var key = UnlockWithYubiKey(config);
    var db = LoadSecrets(key);
    
    if (!db.Secrets.ContainsKey(name))
        throw new Exception($"Secret '{{name}}' not found");
    
    Console.Write($"Delete secret '{{name}}'? This cannot be undone. (yes/no): ");
    if (Console.ReadLine()?.ToLower() != "yes")
    {
        Console.WriteLine("Aborted.");
        return;
    }
    
    db.Secrets.Remove(name);
    SaveSecrets(db, key);
    
    Console.WriteLine($"✓ Secret '{{name}}' deleted");
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

try
{
    if (allArgs.Count == 0)
    {
        Console.WriteLine("tswap - YubiKey Secret Manager");
        Console.WriteLine("\nPrivileged Commands (require sudo to view/modify secrets):");
        Console.WriteLine("  add <name>        Add a secret interactively");
        Console.WriteLine("  get <name>        Display a secret (DANGEROUS)");
        Console.WriteLine("  list              List all secret names");
        Console.WriteLine("  delete <name>     Delete a secret");
        Console.WriteLine("\nUnprivileged Commands (work without sudo):");
        Console.WriteLine("  init              Initialize with 2 YubiKeys");
        Console.WriteLine("  create <name> [--length N] [--alphanumeric]");
        Console.WriteLine("                    Generate random secret (never displayed)");
        Console.WriteLine("  run <command>     Execute with {{token}} substitution");
        Console.WriteLine("\nGlobal Options:");
        Console.WriteLine("  --debug           Show verbose output");
        Console.WriteLine("  --quiet           Suppress non-error output");
        Console.WriteLine("\nExamples:");
        Console.WriteLine("  # Setup (no sudo needed)");
        Console.WriteLine("  tswap init");
        Console.WriteLine("  tswap create api-key");
        Console.WriteLine("  tswap create long-key --length 64");
        Console.WriteLine("  tswap run curl -H 'Auth: {{api-key}}' https://api.com");
        Console.WriteLine("\n  # Managing secrets (requires sudo)");
        Console.WriteLine("  sudo tswap add manual-password");
        Console.WriteLine("  sudo tswap list");
        Console.WriteLine("  sudo tswap get api-key");
        Console.WriteLine("\nSudo-Free Workflow:");
        Console.WriteLine("  Users without sudo can still use tswap for generated secrets!");
        Console.WriteLine("  1. Run 'init' to set up YubiKeys");
        Console.WriteLine("  2. Use 'create' to generate random secrets");
        Console.WriteLine("  3. Use 'run' to inject secrets into commands");
        Console.WriteLine("  (Cannot view/list existing secrets without sudo)");
        Console.WriteLine("\nSecurity Model:");
        Console.WriteLine("  - Sudo required ONLY to view/modify secrets in plaintext");
        Console.WriteLine("  - AI agents without sudo cannot extract secrets");
        Console.WriteLine("  - Generated secrets never appear on screen");
        Console.WriteLine("\nPrerequisites:");
        Console.WriteLine("  - Install dotnet-script: dotnet tool install -g dotnet-script");
        Console.WriteLine("  - Configure YubiKeys: ykman otp chalresp --generate 2");
        Environment.Exit(1);
    }
    
    var command = allArgs[0].ToLower();
    
    switch (command)
    {
        case "init":
            CmdInit();
            break;
        
        case "add":
            if (allArgs.Count < 2)
                throw new Exception("Usage: tswap add <name>");
            CmdAdd(allArgs[1]);
            break;
        
        case "get":
            if (allArgs.Count < 2)
                throw new Exception("Usage: tswap get <name>");
            CmdGet(allArgs[1]);
            break;
        
        case "list":
            CmdList();
            break;
        
        case "delete":
        case "del":
        case "rm":
            if (allArgs.Count < 2)
                throw new Exception("Usage: tswap delete <name>");
            CmdDelete(allArgs[1]);
            break;
        
        case "create":
            if (allArgs.Count < 2)
                throw new Exception("Usage: tswap create <name> [--length N] [--alphanumeric]");
            CmdCreate(allArgs[1], allArgs.Skip(2).ToArray());
            break;
        
        case "run":
            CmdRun(allArgs.ToArray());
            break;
        
        default:
            throw new Exception($"Unknown command: {{command}} ");
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"\n❌ Error: {{ex.Message}} ");
    Environment.Exit(1);
}