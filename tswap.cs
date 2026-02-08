#!/usr/bin/env -S dotnet-script
/*
 * tswap PoC - YubiKey Secret Manager (Single File)
 * 
 * Run directly:    dotnet script tswap.cs -- init
 * Or compile:      dotnet build tswap.cs
 * 
 * Commands:
 *   init                  - Initialize with 2 YubiKeys (creates XOR redundancy)
 *   create <name> [len]   - Generate random secret (never displayed)
 *   names                 - List secret names (no values, AI agent safe)
 *   run <cmd> [args...]   - Execute command with {{token}} substitution
 *   [sudo] add <name>     - Add a secret (user-provided value)
 *   [sudo] get <name>     - Get a secret value
 *   [sudo] list           - List all secret names
 *   [sudo] delete <name>  - Delete a secret
 *
 * Examples:
 *   dotnet script tswap.cs -- init
 *   dotnet script tswap.cs -- create storj-pass
 *   dotnet script tswap.cs -- run echo "Password: {{storj-pass}}"
 *   sudo dotnet script tswap.cs -- get storj-pass
 * 
 * Prerequisites:
 *   - .NET 10 SDK
 *   - 2 YubiKeys with slot 2 configured: ykman otp chalresp --generate 2
 *   - dotnet-script (install: dotnet tool install -g dotnet-script)
 *   - For [sudo] commands: also install as root (sudo dotnet tool install -g dotnet-script)
 *     and add /root/.dotnet/tools to sudo's secure_path:
 *       sudo visudo
 *       # Edit the Defaults secure_path line to include:
 *       Defaults secure_path="...existing paths...:/root/.dotnet/tools"
 */

#r "nuget: Yubico.YubiKey, 1.12.0"

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Yubico.Core.Logging;
using Yubico.YubiKey;
using Yubico.YubiKey.Otp;
using Yubico.YubiKey.Otp.Operations;

// ============================================================================
// CONFIGURATION
// ============================================================================

var Verbose = Args.Any(a => a == "-v" || a == "--verbose");

// Suppress Yubico SDK console logging unless verbose
Log.ConfigureLoggerFactory(builder =>
{
    builder.SetMinimumLevel(Verbose ? LogLevel.Information : LogLevel.None);
});

// When running under sudo, resolve config relative to the invoking user's home
// so that "sudo tswap get" finds the same database as "tswap create"
var sudoUser = Environment.GetEnvironmentVariable("SUDO_USER");
var appDataDir = sudoUser != null
    ? Path.Combine("/home", sudoUser, ".config")
    : Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
var ConfigDir = Path.Combine(appDataDir, "tswap-poc");
var ConfigFile = Path.Combine(ConfigDir, "config.json");
var SecretsFile = Path.Combine(ConfigDir, "secrets.json.enc");

// ============================================================================
// DATA STRUCTURES
// ============================================================================

record Config(List<int> YubiKeySerials, string RedundancyXor, DateTime Created);
record Secret(string Value, DateTime Created, DateTime Modified);
record SecretsDb(Dictionary<string, Secret> Secrets);

// ============================================================================
// YUBIKEY OPERATIONS
// ============================================================================

byte[] ChallengeYubiKey(IYubiKeyDevice device, string challenge)
{
    if (Verbose) Console.Write($"YubiKey (serial: {device.SerialNumber})... ");
    
    try
    {
        // SDK has issues with challenge-response over SmartCard
        // ykman works perfectly, so just use it directly
        
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
        
        using (var process = System.Diagnostics.Process.Start(psi))
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
    
    if (devices.Count > 1)
    {
        Console.WriteLine("\nMultiple YubiKeys detected:");
        for (int i = 0; i < devices.Count; i++)
            Console.WriteLine($"  {i + 1}. Serial: {devices[i].SerialNumber}");
        Console.Write($"Select YubiKey (1-{devices.Count}): ");
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
        throw new Exception("Not initialized. Run: dotnet script tswap.cs -- init");
    
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
    var device = GetYubiKey();
    var serial = device.SerialNumber ?? 0;
    
    if (!config.YubiKeySerials.Contains(serial))
        throw new Exception($"YubiKey {serial} not authorized. Expected: {string.Join(", ", config.YubiKeySerials)}");
    
    // Challenge current YubiKey
    var k_current = ChallengeYubiKey(device, "tswap-unlock");
    
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
            $"Run: sudo dotnet script tswap.cs -- {commandName} ...");
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
    Console.WriteLine("║  tswap PoC - YubiKey Initialization   ║");
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
    Console.WriteLine($"YubiKey Serials: {serial1}, {serial2}");
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

    var bytes = RandomNumberGenerator.GetBytes(length);
    var password = new char[length];
    for (int i = 0; i < length; i++)
        password[i] = charset[bytes[i] % charset.Length];

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
    
    Console.WriteLine($"\nSecrets ({db.Secrets.Count}):");
    Console.WriteLine("NAME                 CREATED              MODIFIED");
    Console.WriteLine("".PadRight(60, '-'));
    
    foreach (var (name, secret) in db.Secrets.OrderBy(s => s.Key))
    {
        Console.WriteLine($"{name.PadRight(20)} {secret.Created:yyyy-MM-dd HH:mm} {secret.Modified:yyyy-MM-dd HH:mm}");
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
        Console.WriteLine(name);
}

void CmdRun(string[] args)
{
    // args[0] is "run", everything after is the command
    if (args.Length < 2)
        throw new Exception("Usage: dotnet script tswap.cs -- run <command> [args...]");
    
    var commandArgs = args.Skip(1).ToArray();
    var command = string.Join(" ", commandArgs);
    
    // Find {{tokens}}
    var tokenRegex = new Regex(@"\{\{([a-zA-Z0-9-]+)\}\}");
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
        substitutedCommand = substitutedCommand.Replace($"{{{{{token}}}}}", db.Secrets[token].Value);
    
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

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

try
{
    if (Args.Count == 0)
    {
        Console.WriteLine("tswap PoC - YubiKey Secret Manager (Single File)");
        Console.WriteLine("\nUsage:");
        Console.WriteLine("  dotnet script tswap.cs -- init                 Initialize with 2 YubiKeys");
        Console.WriteLine("  dotnet script tswap.cs -- create <name> [len]  Generate random secret (no display)");
        Console.WriteLine("  dotnet script tswap.cs -- names                List secret names (no values)");
        Console.WriteLine("  dotnet script tswap.cs -- run <cmd> [args...]   Execute with {{token}} substitution");
        Console.WriteLine("  [sudo] dotnet script tswap.cs -- add <name>    Add a secret (user-provided value)");
        Console.WriteLine("  [sudo] dotnet script tswap.cs -- get <name>    Get a secret value");
        Console.WriteLine("  [sudo] dotnet script tswap.cs -- list          List all secrets");
        Console.WriteLine("  [sudo] dotnet script tswap.cs -- delete <name> Delete a secret");
        Console.WriteLine("\nCommands marked [sudo] require elevated privileges.");
        Console.WriteLine("Add -v or --verbose for detailed YubiKey output.");
        Console.WriteLine("\nExamples:");
        Console.WriteLine("  dotnet script tswap.cs -- create storj-pass");
        Console.WriteLine("  dotnet script tswap.cs -- run echo 'Password: {{storj-pass}}'");
        Console.WriteLine("  sudo dotnet script tswap.cs -- get storj-pass");
        Console.WriteLine("  sudo dotnet script tswap.cs -- list");
        Console.WriteLine("\nPrerequisites:");
        Console.WriteLine("  - Install dotnet-script: dotnet tool install -g dotnet-script");
        Console.WriteLine("  - Configure YubiKeys: ykman otp chalresp --generate 2");
        Console.WriteLine("  - For [sudo] commands: sudo dotnet tool install -g dotnet-script");
        Console.WriteLine("    then add /root/.dotnet/tools to sudo secure_path (sudo visudo)");
        Environment.Exit(1);
    }
    
    var args = Args.Where(a => a != "-v" && a != "--verbose").ToList();
    var command = args[0].ToLower();

    switch (command)
    {
        case "init":
            CmdInit();
            break;
        
        case "create":
            if (args.Count < 2)
                throw new Exception("Usage: dotnet script tswap.cs -- create <name> [length]");
            var createLength = args.Count >= 3 ? int.Parse(args[2]) : 32;
            CmdCreate(args[1], createLength);
            break;

        case "add":
            if (args.Count < 2)
                throw new Exception("Usage: dotnet script tswap.cs -- add <name>");
            CmdAdd(args[1]);
            break;

        case "get":
            if (args.Count < 2)
                throw new Exception("Usage: dotnet script tswap.cs -- get <name>");
            CmdGet(args[1]);
            break;

        case "names":
            CmdNames();
            break;

        case "list":
            CmdList();
            break;

        case "delete":
            if (args.Count < 2)
                throw new Exception("Usage: dotnet script tswap.cs -- delete <name>");
            CmdDelete(args[1]);
            break;

        case "run":
            CmdRun(args.ToArray());
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
