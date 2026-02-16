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

// When running under sudo, resolve config relative to the invoking user's home
// so that "sudo tswap get" finds the same database as "tswap create"
var sudoUser = Environment.GetEnvironmentVariable("SUDO_USER");
var appDataDir = sudoUser != null
    ? Path.Combine("/home", sudoUser, ".config")
    : Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
var ConfigDir = Path.Combine(appDataDir, "tswap-poc");

var PromptText = Prompt.GetText(Prefix);

// Storage instance using shared library
var storage = new Storage(ConfigDir);

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

byte[] UnlockWithYubiKey(Config config)
{
    var serial = GetYubiKey();

    if (!config.YubiKeySerials.Contains(serial))
        throw new Exception($"YubiKey {serial} not authorized. Expected: {string.Join(", ", config.YubiKeySerials)}");

    // Challenge current YubiKey
    var k_current = ChallengeYubiKey(serial, "tswap-unlock");

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
    if (File.Exists(storage.ConfigFile))
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
    var serial1 = GetYubiKey();
    var k1 = ChallengeYubiKey(serial1, "tswap-unlock");

    // Challenge second YubiKey
    Console.WriteLine("\nRemove YubiKey #1, insert YubiKey #2, press Enter...");
    Console.ReadLine();
    var serial2 = GetYubiKey();

    if (serial1 == serial2)
        throw new Exception("Same YubiKey detected. Please use two different YubiKeys.");

    var k2 = ChallengeYubiKey(serial2, "tswap-unlock");

    // Compute XOR redundancy
    var xorShare = Crypto.XorBytes(k1, k2);

    // Save config
    var config = new Config(
        new List<int> { serial1, serial2 },
        Convert.ToHexString(xorShare),
        DateTime.UtcNow
    );

    storage.SaveConfig(config);

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

    var bytes = RandomNumberGenerator.GetBytes(length);
    var password = new char[length];
    for (int i = 0; i < length; i++)
        password[i] = charset[bytes[i] % charset.Length];

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
        Console.WriteLine($"  {p} create <name> [len]     Generate random secret (no display)");
        Console.WriteLine($"  {p} ingest <name>           Pipe secret from stdin (no display)");
        Console.WriteLine($"  {p} names                   List secret names (no values)");
        Console.WriteLine($"  {p} run <cmd> [args...]     Execute with {{{{token}}}} substitution");
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
        Console.WriteLine($"  {p} burn db-pass \"accidentally logged\"");
        Console.WriteLine($"  sudo {p} get storj-pass");
        Console.WriteLine($"  sudo {p} list");
        Console.WriteLine("\nPrerequisites:");
        Console.WriteLine("  - ykman CLI: pip install yubikey-manager");
        Console.WriteLine("  - Configure YubiKeys: ykman otp chalresp --generate 2");
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

