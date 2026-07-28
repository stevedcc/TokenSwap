using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;

namespace TswapCli.Commands;

public sealed class InitCommand : ICliCommand
{
    public string Name => "init";
    public string HelpUsage => "init [--secure-enclave|--tpm|--keyring]";
    public string Description => "Initialize with 2 YubiKeys (or --secure-enclave on macOS, --tpm on Windows/Linux, --keyring for a random-K_v YubiKey vault)";
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

        var initFlagCount = new[] { "--secure-enclave", "--tpm", "--keyring" }.Count(args.Contains);
        if (initFlagCount > 1)
            throw new UsageException($"{ctx.Prefix} init [--secure-enclave|--tpm|--keyring] (mutually exclusive)");

        if (args.Contains("--secure-enclave"))
            return ExecuteSecureEnclave(ctx);

        if (args.Contains("--tpm"))
            return ExecuteTpm(ctx);

        if (args.Contains("--keyring"))
            return ExecuteKeyring(ctx);

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

        // Every fresh init gets its own random master-key salt rather than the legacy shared
        // constant (see Crypto.MasterKeySalt) — init already mints a brand-new XOR share and
        // challenge per vault, so doing the same for the salt is free and closes off the
        // "every tswap vault uses the identical salt" property without touching any existing
        // vault (those have no MasterKeySalt in config.json and keep using the constant).
        var masterKeySalt = RandomNumberGenerator.GetBytes(32);

        // Save config
        var config = new Config(
            new List<int> { serial1, serial2 },
            Convert.ToHexString(xorShare),
            DateTime.UtcNow,
            requiresTouch,
            rngMode,
            unlockChallenge,
            MasterKeySalt: Convert.ToBase64String(masterKeySalt)
        );

        // Re-initialisation generates a new master key (new challenge + new XOR share), so any
        // existing vault is no longer decryptable with it. Back up both files before writing
        // new ones so recovery (restore both .bak files together) remains possible.
        // Config is backed up first — if anything fails mid-init the old config still matches
        // the old vault backup.
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'");
        var newVaultKey = Crypto.DeriveKey(k1, k2, masterKeySalt);
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
    /// Phase 6 keyring init (issue #119, <c>MULTI_MACHINE_KEYING.md</c> §Implementation ordering
    /// step 1): a random 256-bit <c>K_v</c> wrapped by a single YubiKey-backed slot
    /// (<c>k = 1</c>), instead of <c>K_v</c> being derived directly from the two YubiKeys'
    /// challenge responses the way the default <c>init</c> above does. Same two-YubiKey
    /// enrollment UX as the default flow — this is still "one machine, one enrolled key pair"
    /// for now, not multi-machine (that is issue #121's <c>slot request/approve/accept</c>,
    /// layered on top of the <see cref="Slot"/>/<see cref="Keyring"/> shapes this defines).
    ///
    /// <para>The payoff of the extra indirection: once <c>K_v</c> is a fixed, backend-independent
    /// random value, a future <c>slot approve</c> can wrap it for a brand-new machine's slot
    /// without decrypting-and-re-encrypting anything belonging to this machine — appending a
    /// slot is additive. Under the default flow's derived key, there is no <c>K_v</c> to hand to
    /// another machine at all; a second machine could only ever be added by re-deriving a
    /// completely different master key from scratch (i.e. re-init, losing the old vault).</para>
    /// </summary>
    private static int ExecuteKeyring(CommandContext ctx)
    {
        var c = ctx.Console;

        if (ctx.TestKey != null)
        {
            // Test mode: bypass YubiKey entirely, same idea as the default flow's test branch
            // above. KEK_slot here is ctx.TestKey directly — the exact 32 bytes
            // YubiKeyHardwareService.Unlock returns for *any* config once its overrideKey is
            // set (see that method's first line) — so wrapping the slot payload under
            // ctx.TestKey now is what makes VaultUnlocker's keyring unwrap succeed later, in
            // test mode, without ever touching real hardware.
            var (testConfig, testVaultKey) = BuildKeyringConfig(
                ctx.TestKey,
                new List<int> { TestKeyYubiKeyService.Serial1, TestKeyYubiKeyService.Serial2 },
                new string('0', 40), // 20-byte zero XOR share (hex) — unused in test mode
                requiresTouch: null,
                RngMode.System,
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
                RandomNumberGenerator.GetBytes(32));

            ctx.Storage.SaveConfig(testConfig);
            // Unlike the default test-mode branch, K_v is freshly random on every call (it is
            // never derived from ctx.TestKey), so an existing secrets.json from a prior init
            // would be undecryptable with this run's key — always write a fresh empty vault.
            ctx.Storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>()), testVaultKey);
            c.Out.WriteLine("Initialized (keyring, test mode)");
            return 0;
        }

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - Keyring Initialization        ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine("This vault's master key (K_v) is random and wrapped by this YubiKey");
        c.Out.WriteLine("pair's slot (k = 1), rather than derived from it — see");
        c.Out.WriteLine("MULTI_MACHINE_KEYING.md. Still one machine for now: enrolling a second");
        c.Out.WriteLine("machine's slot ('slot request/approve/accept') is future work (#121).\n");

        var unlockChallenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        c.Out.WriteLine("Insert YubiKey #1 and press Enter...");
        if (!c.IsInputRedirected)
            c.ReadLine();
        var serial1 = ctx.SelectSerial();
        var k1 = ctx.YubiKeys.Challenge(serial1, unlockChallenge);

        c.Out.WriteLine("\nRemove YubiKey #1, insert YubiKey #2, press Enter...");
        if (!c.IsInputRedirected)
            c.ReadLine();
        var serial2 = ctx.SelectSerial();

        if (serial1 == serial2)
            throw new TswapException("Same YubiKey detected. Please use two different YubiKeys.");

        var k2 = ctx.YubiKeys.Challenge(serial2, unlockChallenge);

        c.Out.WriteLine("\nDetecting YubiKey slot configuration...");
        var touch1 = ctx.YubiKeys.DetectTouchRequirement(serial1);
        var touch2 = ctx.YubiKeys.DetectTouchRequirement(serial2);
        bool? requiresTouch = touch1.HasValue && touch2.HasValue ? touch1.Value && touch2.Value : null;

        c.Out.WriteLine("\nPassword generation entropy source:");
        c.Out.WriteLine("  [1] System RNG  — one YubiKey touch per create (default)");
        c.Out.WriteLine("  [2] YubiKey     — two YubiKey touches per create; hardware-primary, immune to OS RNG compromise");
        c.Out.Write("Choose [1/2, default 1]: ");
        var rngChoice = c.ReadLine()?.Trim();
        var rngMode = rngChoice == "2" ? RngMode.YubiKey : RngMode.System;

        var xorShare = Crypto.XorBytes(k1, k2);
        var masterKeySalt = RandomNumberGenerator.GetBytes(32);

        var (config, vaultKey) = BuildKeyringConfig(
            // KEK_slot: exactly the value the default flow above uses as K_v directly
            // (Crypto.DeriveKey(k1, k2, salt)) — here it instead unwraps a random K_v. This is
            // also exactly what YubiKeyHardwareService.Unlock recomputes later from the Config
            // fields this method saves, with no change to that class at all.
            Crypto.DeriveKey(k1, k2, masterKeySalt),
            new List<int> { serial1, serial2 },
            Convert.ToHexString(xorShare),
            requiresTouch,
            rngMode,
            unlockChallenge,
            masterKeySalt);

        // Same re-init backup dance as the default flow: back up config first (if anything
        // fails mid-init the old config still matches the old vault backup), then move the old
        // vault aside rather than overwrite it outright.
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'");
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
        c.Out.WriteLine($"YubiKey Serials: {serial1}, {serial2}");
        c.Out.WriteLine("Backend: YubiKey keyring (k = 1, single slot)");

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
            c.ResetColor();
        }

        c.Out.WriteLine($"Entropy mode:    {(rngMode == RngMode.YubiKey ? "YubiKey hardware (two touches per create)" : "System RNG (one touch per create)")}");

        c.Out.WriteLine("\n⚠️  CRITICAL: BACKUP XOR SHARE NOW\n");
        c.Out.WriteLine("XOR Share (hex):");
        c.Out.WriteLine(config.RedundancyXor);
        c.Out.WriteLine("\nThis share reconstructs this slot's key-encryption key (KEK_slot),");
        c.Out.WriteLine("which unwraps K_v — losing it plus one physical YubiKey still loses");
        c.Out.WriteLine("the vault, exactly as with the default init flow. Backup locations required:");
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
    /// Shared by both the interactive and test-mode <c>--keyring</c> paths (issue #119):
    /// generates a random <c>K_v</c> and this machine's X25519 slot keypair
    /// (<see cref="SlotKeyPair.Generate"/>), wraps <c>(K_v || slot private key)</c>
    /// (<see cref="SlotSecretPayload.Encode"/>) under <paramref name="kekSlot"/> via
    /// <see cref="SlotPayloadWrap.Wrap"/>, and assembles the resulting single-slot,
    /// <c>k = 1</c> <see cref="Keyring"/> plus the <see cref="Config"/> that carries it.
    ///
    /// <para>The returned <see cref="Config"/> still carries the same
    /// <c>YubiKeySerials</c>/<c>RedundancyXor</c>/<c>UnlockChallenge</c>/<c>MasterKeySalt</c>
    /// fields the default flow's config does — so <see cref="VaultUnlocker"/>'s YubiKey backend
    /// recovers this exact <paramref name="kekSlot"/> value again at unlock time, unmodified.
    /// Only <see cref="Config.Keyring"/> being non-null tells <see cref="VaultUnlocker"/> to
    /// treat that recovered value as <c>KEK_slot</c> and unwrap <c>K_v</c>, instead of using it
    /// as the master key directly.</para>
    /// </summary>
    private static (Config Config, byte[] VaultKey) BuildKeyringConfig(
        byte[] kekSlot, List<int> serials, string redundancyXorHex, bool? requiresTouch,
        RngMode rngMode, string unlockChallenge, byte[] masterKeySalt)
    {
        var vaultKey = RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var slotKeyPair = SlotKeyPair.Generate();
        var vaultId = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        const byte k = 1;

        var payload = SlotSecretPayload.Encode(vaultKey, slotKeyPair.PrivateKey);
        var wrapped = SlotPayloadWrap.Wrap(payload, kekSlot, KeyringFormat.KeyringFormatVersion, vaultId, k, slotId);

        var slot = new Slot(slotId, slotKeyPair.PublicKey, wrapped);
        var keyring = new TswapCore.Keyring.Keyring(KeyringFormat.KeyringFormatVersion, vaultId, k, [slot]);
        var keyringBlob = Convert.ToBase64String(KeyringCodec.Encode(keyring));

        var config = new Config(
            serials,
            redundancyXorHex,
            DateTime.UtcNow,
            requiresTouch,
            rngMode,
            unlockChallenge,
            MasterKeySalt: Convert.ToBase64String(masterKeySalt),
            Keyring: keyringBlob
        );

        return (config, vaultKey);
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


