using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Vault;

namespace TswapCli.Commands;

public sealed class InitCommand : ICliCommand
{
    public string Name => "init";
    public string HelpUsage => "init [--secure-enclave|--tpm]";
    public string Description => "Initialize with 2 YubiKeys (or --secure-enclave on macOS, --tpm on Windows/Linux)";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        var c = ctx.Console;

        // Detecting an existing config to prompt about reinitializing (and, further
        // down, backing it up before overwriting) is inherently file-store-specific;
        // a future non-file backend needs its own equivalent, not this one.
        var fileStore = ctx.Storage as IFileVaultStore;

        if (fileStore != null && File.Exists(fileStore.ConfigFile))
        {
            c.Out.Write("Already initialized. Reinitialize? (yes/no): ");
            if (c.ReadLine()?.ToLower() != "yes")
                return 0;
        }

        if (args.Contains("--secure-enclave") && args.Contains("--tpm"))
            throw new UsageException($"{ctx.Prefix} init [--secure-enclave|--tpm] (mutually exclusive)");

        if (args.Contains("--secure-enclave"))
            return ExecuteSecureEnclave(ctx);

        if (args.Contains("--tpm"))
            return ExecuteTpm(ctx);

        if (ctx.TestKey != null)
        {
            // Test mode: create synthetic config without YubiKey interaction
            var testConfig = new Config(
                new List<int> { TestKeyYubiKeyService.Serial1, TestKeyYubiKeyService.Serial2 },
                new string('0', 40), // 20-byte zero XOR share (hex)
                DateTime.UtcNow,
                null,
                RngMode.System,
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32))
            );
            ctx.Storage.SaveConfig(testConfig);
            if (fileStore == null || !File.Exists(fileStore.SecretsFile))
                ctx.Storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>()), ctx.TestKey);
            c.Out.WriteLine("Initialized (test mode)");
            return 0;
        }

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - YubiKey Initialization       ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");

        // Generate a vault-unique unlock challenge so the HMAC response cannot be
        // pre-computed by someone who briefly accesses a YubiKey without the config.
        var unlockChallenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        // Challenge first YubiKey
        c.Out.WriteLine("Insert YubiKey #1 and press Enter...");
        if (!c.IsInputRedirected)
            c.ReadLine();
        var serial1 = ctx.SelectSerial();
        var k1 = ctx.YubiKeys.Challenge(serial1, unlockChallenge);

        // Challenge second YubiKey
        c.Out.WriteLine("\nRemove YubiKey #1, insert YubiKey #2, press Enter...");
        if (!c.IsInputRedirected)
            c.ReadLine();
        var serial2 = ctx.SelectSerial();

        if (serial1 == serial2)
            throw new TswapException("Same YubiKey detected. Please use two different YubiKeys.");

        var k2 = ctx.YubiKeys.Challenge(serial2, unlockChallenge);

        // Detect touch requirement for both keys
        c.Out.WriteLine("\nDetecting YubiKey slot configuration...");
        var touch1 = ctx.YubiKeys.DetectTouchRequirement(serial1);
        var touch2 = ctx.YubiKeys.DetectTouchRequirement(serial2);

        bool? requiresTouch = null;
        if (touch1.HasValue && touch2.HasValue)
        {
            requiresTouch = touch1.Value && touch2.Value;
        }

        // Compute XOR redundancy
        var xorShare = Crypto.XorBytes(k1, k2);

        // Choose RNG mode for secret generation
        c.Out.WriteLine("\nPassword generation entropy source:");
        c.Out.WriteLine("  [1] System RNG  — one YubiKey touch per create (default)");
        c.Out.WriteLine("  [2] YubiKey     — two YubiKey touches per create; hardware-primary, immune to OS RNG compromise");
        c.Out.Write("Choose [1/2, default 1]: ");
        var rngChoice = c.ReadLine()?.Trim();
        var rngMode = rngChoice == "2" ? RngMode.YubiKey : RngMode.System;

        // Save config
        var config = new Config(
            new List<int> { serial1, serial2 },
            Convert.ToHexString(xorShare),
            DateTime.UtcNow,
            requiresTouch,
            rngMode,
            unlockChallenge
        );

        // Re-initialisation generates a new master key (new challenge + new XOR share), so any
        // existing vault is no longer decryptable with it. Back up both files before writing
        // new ones so recovery (restore both .bak files together) remains possible.
        // Config is backed up first — if anything fails mid-init the old config still matches
        // the old vault backup.
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'");
        var newVaultKey = Crypto.DeriveKey(k1, k2);
        // Backing up the previous config/vault before writing over it is a file-store
        // safety net; a non-file backend would need its own equivalent, not this one.
        if (fileStore != null && File.Exists(fileStore.ConfigFile))
        {
            var configBackup = fileStore.ConfigFile + ".bak-" + timestamp;
            File.Copy(fileStore.ConfigFile, configBackup);
        }
        ctx.Storage.SaveConfig(config);
        if (fileStore != null && File.Exists(fileStore.SecretsFile))
        {
            var vaultBackup = fileStore.SecretsFile + ".bak-" + timestamp;
            File.Move(fileStore.SecretsFile, vaultBackup);
            c.SetForeground(ConsoleColor.Yellow);
            c.Out.WriteLine($"\nExisting vault moved to backup: {vaultBackup}");
            c.Out.WriteLine("Previous config backed up alongside it. To recover old secrets:");
            c.Out.WriteLine("  restore both .bak files under their original names.");
            c.ResetColor();
        }
        ctx.Storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>()), newVaultKey);

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  ✓ INITIALIZATION COMPLETE            ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine($"YubiKey Serials: {serial1}, {serial2}");

        // Report touch requirement status
        if (requiresTouch == true)
        {
            c.SetForeground(ConsoleColor.Green);
            c.Out.WriteLine("✓ Touch requirement: ENABLED (recommended)");
            c.ResetColor();
        }
        else if (requiresTouch == false)
        {
            c.SetForeground(ConsoleColor.Yellow);
            c.Out.WriteLine("⚠️  Touch requirement: DISABLED");
            c.Out.WriteLine("\nSECURITY NOTICE: Your YubiKeys are configured without button press");
            c.Out.WriteLine("requirement. Any process with access to inserted keys can unlock vault.");
            c.Out.WriteLine("\nTo enable touch requirement:");
            c.Out.WriteLine("  1. ykman otp delete 2      (for each key)");
            c.Out.WriteLine("  2. ykman otp chalresp --generate --touch 2");
            c.Out.WriteLine("  3. tswap init              (reinitialize)");
            c.ResetColor();
        }

        c.Out.WriteLine($"Entropy mode:    {(rngMode == RngMode.YubiKey ? "YubiKey hardware (two touches per create)" : "System RNG (one touch per create)")}");

        c.Out.WriteLine("\n⚠️  CRITICAL: BACKUP XOR SHARE NOW\n");
        c.Out.WriteLine("XOR Share (hex):");
        c.Out.WriteLine(config.RedundancyXor);
        c.Out.WriteLine("\nBackup locations required:");
        c.Out.WriteLine("  [ ] Password manager (Bitwarden/1Password)");
        c.Out.WriteLine("  [ ] Printed copy (home safe)");
        c.Out.WriteLine("  [ ] Second printed copy (off-site)");
        c.Out.WriteLine("  [ ] Git repository");
        if (fileStore != null)
            c.Out.WriteLine($"\nConfig saved to: {fileStore.ConfigFile}");
        else
            c.Out.WriteLine("\nConfig saved.");
        return 0;
    }

    /// <summary>
    /// Single-machine Secure Enclave enrollment — a workaround to allow end-to-end testing
    /// of the Secure Enclave backend ahead of a real enrollment flow. There is no redundancy
    /// or fleet keyring here: one Mac, one Secure Enclave key, <c>k = 1</c>. Phase 6
    /// (<c>MULTI_MACHINE_KEYING.md</c>) is where a proper multi-factor / multi-machine
    /// enrollment ceremony (and YubiKey counts beyond two) belongs.
    /// </summary>
    private static int ExecuteSecureEnclave(CommandContext ctx)
    {
        if (!OperatingSystem.IsMacOS())
            throw new TswapException("--secure-enclave is only supported on macOS.");
        return ExecuteSecureEnclaveOnMacOS(ctx);
    }

    [SupportedOSPlatform("macos")]
    private static int ExecuteSecureEnclaveOnMacOS(CommandContext ctx)
    {
        var c = ctx.Console;

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - Secure Enclave Initialization ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine("This vault will be protected by this Mac's Secure Enclave — single");
        c.Out.WriteLine("machine only for now (no second factor, no fleet keyring; see");
        c.Out.WriteLine("MULTI_MACHINE_KEYING.md for the planned Phase 6 design).\n");

        var secureEnclave = new SecureEnclaveHardwareService();
        var vaultKey = RandomNumberGenerator.GetBytes(32);
        c.Out.WriteLine("Creating a Secure Enclave key (unlocking later will prompt for Touch ID / presence)...");
        var wrapped = secureEnclave.Wrap(vaultKey);

        var config = new Config(
            YubiKeySerials: [],
            RedundancyXor: "",
            Created: DateTime.UtcNow,
            RequiresTouch: true, // the Secure Enclave key always requires presence to unwrap
            RngMode: RngMode.System,
            Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: Convert.ToBase64String(wrapped));

        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'");
        // Backing up the previous config/vault before writing over it is a file-store
        // safety net; a non-file backend would need its own equivalent, not this one.
        var fileStore = ctx.Storage as IFileVaultStore;
        if (fileStore != null && File.Exists(fileStore.ConfigFile))
        {
            var configBackup = fileStore.ConfigFile + ".bak-" + timestamp;
            File.Copy(fileStore.ConfigFile, configBackup);
        }
        ctx.Storage.SaveConfig(config);
        if (fileStore != null && File.Exists(fileStore.SecretsFile))
        {
            var vaultBackup = fileStore.SecretsFile + ".bak-" + timestamp;
            File.Move(fileStore.SecretsFile, vaultBackup);
            c.SetForeground(ConsoleColor.Yellow);
            c.Out.WriteLine($"\nExisting vault moved to backup: {vaultBackup}");
            c.Out.WriteLine("Previous config backed up alongside it. To recover old secrets:");
            c.Out.WriteLine("  restore both .bak files under their original names.");
            c.ResetColor();
        }
        ctx.Storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>()), vaultKey);

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  ✓ INITIALIZATION COMPLETE            ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine("Backend: Secure Enclave (this Mac only)");
        if (fileStore != null)
            c.Out.WriteLine($"Config saved to: {fileStore.ConfigFile}");
        c.Out.WriteLine("\nThere is no backup share for this backend, unlike the YubiKey XOR share:");
        c.Out.WriteLine("the wrapped key in config.json is meaningless without this machine's");
        c.Out.WriteLine("physical Secure Enclave. Losing this Mac means losing this vault — back");
        c.Out.WriteLine("up secrets some other way (e.g. 'tswap export') if that matters to you.");
        return 0;
    }

    /// <summary>
    /// Single-machine TPM enrollment (Linux via <c>tpm2-tools</c>, Windows via CNG's Platform
    /// Crypto Provider) — a workaround to allow end-to-end testing of the TPM backends ahead of
    /// a real enrollment flow. There is no redundancy or fleet keyring here: one machine, one
    /// TPM, <c>k = 1</c>. Phase 6 (<c>MULTI_MACHINE_KEYING.md</c>) is where a proper
    /// multi-factor / multi-machine enrollment ceremony belongs.
    ///
    /// <b>Status: only tested against a software TPM simulator (swtpm) on Linux and a virtual
    /// TPM in a Parallels VM on Windows — neither has been verified against physical TPM
    /// hardware</b> — see <c>HARDWARE_BACKENDS.md</c>'s Linux/Windows TPM sections.
    /// </summary>
    private static int ExecuteTpm(CommandContext ctx)
    {
        if (OperatingSystem.IsLinux())
            return ExecuteTpmOnLinux(ctx);
        if (OperatingSystem.IsWindows())
            return ExecuteTpmOnWindows(ctx);
        throw new TswapException("--tpm is only supported on Windows and Linux.");
    }

    [SupportedOSPlatform("linux")]
    private static int ExecuteTpmOnLinux(CommandContext ctx)
    {
        var c = ctx.Console;
        PrintTpmInitBanner(c);

        var tpm = new LinuxTpmHardwareService();
        var vaultKey = RandomNumberGenerator.GetBytes(32);
        c.Out.WriteLine("Sealing a new key to this machine's TPM...");
        var sealedKey = tpm.Seal(vaultKey);

        return FinishTpmInit(ctx, vaultKey, sealedKey);
    }

    [SupportedOSPlatform("windows")]
    private static int ExecuteTpmOnWindows(CommandContext ctx)
    {
        var c = ctx.Console;
        PrintTpmInitBanner(c);

        var tpm = new WindowsTpmHardwareService();
        var vaultKey = RandomNumberGenerator.GetBytes(32);
        c.Out.WriteLine("Wrapping a new key to this machine's TPM...");
        var wrapped = tpm.Wrap(vaultKey);

        return FinishTpmInit(ctx, vaultKey, wrapped);
    }

    private static void PrintTpmInitBanner(IConsole c)
    {
        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - TPM Initialization            ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine("This vault will be protected by this machine's TPM — single machine");
        c.Out.WriteLine("only for now (no second factor, no fleet keyring; see");
        c.Out.WriteLine("MULTI_MACHINE_KEYING.md for the planned Phase 6 design).\n");
    }

    /// <summary>
    /// Shared by both TPM platforms: saves the config/vault (with the same backup dance every
    /// other init path uses) and prints the completion banner. <paramref name="sealedOrWrappedKey"/>
    /// is Linux's TPM2-sealed blob or Windows' RSA-OAEP-wrapped blob — opaque here, since
    /// <see cref="Config.TpmSealedKey"/> doesn't care which platform produced it.
    /// </summary>
    private static int FinishTpmInit(CommandContext ctx, byte[] vaultKey, byte[] sealedOrWrappedKey)
    {
        var c = ctx.Console;

        var config = new Config(
            YubiKeySerials: [],
            RedundancyXor: "",
            Created: DateTime.UtcNow,
            RequiresTouch: false,
            RngMode: RngMode.System,
            Backend: HardwareBackend.Tpm,
            TpmSealedKey: Convert.ToBase64String(sealedOrWrappedKey));

        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'");
        // Backing up the previous config/vault before writing over it is a file-store
        // safety net; a non-file backend would need its own equivalent, not this one.
        var fileStore = ctx.Storage as IFileVaultStore;
        if (fileStore != null && File.Exists(fileStore.ConfigFile))
        {
            var configBackup = fileStore.ConfigFile + ".bak-" + timestamp;
            File.Copy(fileStore.ConfigFile, configBackup);
        }
        ctx.Storage.SaveConfig(config);
        if (fileStore != null && File.Exists(fileStore.SecretsFile))
        {
            var vaultBackup = fileStore.SecretsFile + ".bak-" + timestamp;
            File.Move(fileStore.SecretsFile, vaultBackup);
            c.SetForeground(ConsoleColor.Yellow);
            c.Out.WriteLine($"\nExisting vault moved to backup: {vaultBackup}");
            c.Out.WriteLine("Previous config backed up alongside it. To recover old secrets:");
            c.Out.WriteLine("  restore both .bak files under their original names.");
            c.ResetColor();
        }
        ctx.Storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>()), vaultKey);

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  ✓ INITIALIZATION COMPLETE            ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine("Backend: TPM (this machine only)");
        if (fileStore != null)
            c.Out.WriteLine($"Config saved to: {fileStore.ConfigFile}");
        c.Out.WriteLine("\nThere is no backup share for this backend, unlike the YubiKey XOR share:");
        c.Out.WriteLine("the sealed key in config.json is meaningless without this machine's");
        c.Out.WriteLine("physical TPM. Losing this machine (or clearing its TPM) means losing this");
        c.Out.WriteLine("vault — back up secrets some other way (e.g. 'tswap export') if that");
        c.Out.WriteLine("matters to you.");
        return 0;
    }
}


