using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;

namespace TswapCli.Commands;

public sealed class InitCommand : ICliCommand
{
    public string Name => "init";
    public string HelpUsage => "init [--keyring] [--tpm|--secure-enclave] [--no-recovery]";
    public string Description => "Initialize with 2 YubiKeys; --keyring for a random-K_v YubiKey keyring vault; --tpm (Windows/Linux) or --secure-enclave (macOS) for a keyring vault on this machine's hardware. Keyring vaults get a recovery slot; --no-recovery opts out";
    public bool RequiresSudo => false;

    /// <summary>The only arguments <c>init</c> accepts, each at most once (#177).</summary>
    private static readonly string[] KnownFlags = ["--keyring", "--tpm", "--secure-enclave", "--no-recovery"];

    public int Execute(CommandContext ctx, string[] args)
    {
        var c = ctx.Console;

        // Issue #177: the argument list must be exactly a combination of the known flags. Checked
        // before anything else (the reinitialise prompt, any hardware), so a typo such as
        // 'init --tmp' never falls through to a YubiKey initialisation.
        var usage = $"{ctx.Prefix} init [--keyring] [--tpm|--secure-enclave] [--no-recovery] " +
                    $"(valid flags: {string.Join(", ", KnownFlags)}; --tpm and --secure-enclave are mutually exclusive)";
        if (args.Any(a => !KnownFlags.Contains(a)) || args.Distinct().Count() != args.Length)
            throw new UsageException(usage);

        var tpm = args.Contains("--tpm");
        var secureEnclave = args.Contains("--secure-enclave");
        var keyring = args.Contains("--keyring");
        var noRecovery = args.Contains("--no-recovery");

        if (tpm && secureEnclave)
            throw new UsageException(usage);

        // --no-recovery (issue #120) only means anything for a keyring vault: the classic
        // derived-key YubiKey vault has no keyring to add a recovery slot to. Reject it there
        // rather than silently ignoring it.
        if (noRecovery && !(keyring || tpm || secureEnclave))
            throw new UsageException($"{ctx.Prefix} init --no-recovery requires --keyring, --tpm or --secure-enclave");

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

        // Brief T2 decision 2: --tpm and --secure-enclave always make a keyring vault (machine
        // slot + recovery slot unless --no-recovery); --keyring is implied and accepted. No flag
        // creates the old single-slot TPM/Secure Enclave form any more; existing single-slot
        // vaults still unlock unchanged (VaultUnlocker reads their single-slot field).
        if (secureEnclave)
            return ExecuteHardwareKeyring(ctx, HardwareBackend.SecureEnclave, includeRecovery: !noRecovery);

        if (tpm)
            return ExecuteHardwareKeyring(ctx, HardwareBackend.Tpm, includeRecovery: !noRecovery);

        if (keyring)
            return ExecuteKeyring(ctx, includeRecovery: !noRecovery);

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
    ///
    /// <para><b>Issue #120:</b> <paramref name="includeRecovery"/> (default-on; <c>--no-recovery</c>
    /// opts out) additionally generates a break-glass recovery slot — see
    /// <see cref="BuildKeyringConfig"/> and <c>MULTI_MACHINE_KEYING.md</c> §The recovery slot.
    /// </para>
    /// </summary>
    private static int ExecuteKeyring(CommandContext ctx, bool includeRecovery)
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
            var (testConfig, testVaultKey, testRecoveryPrivateKey) = BuildKeyringConfig(
                ctx.TestKey,
                new List<int> { TestKeyYubiKeyService.Serial1, TestKeyYubiKeyService.Serial2 },
                new string('0', 40), // 20-byte zero XOR share (hex) — unused in test mode
                requiresTouch: null,
                RngMode.System,
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
                RandomNumberGenerator.GetBytes(32),
                includeRecovery);

            ctx.Storage.SaveConfig(testConfig);
            // Unlike the default test-mode branch, K_v is freshly random on every call (it is
            // never derived from ctx.TestKey), so an existing secrets.json from a prior init
            // would be undecryptable with this run's key — always write a fresh empty vault.
            ctx.Storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>()), testVaultKey);
            c.Out.WriteLine("Initialized (keyring, test mode)");
            PrintRecoveryKeyBackupWarning(c, testRecoveryPrivateKey);
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

        var (config, vaultKey, recoveryPrivateKey) = BuildKeyringConfig(
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
            masterKeySalt,
            includeRecovery);

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
        c.Out.WriteLine(includeRecovery
            ? "Backend: YubiKey keyring (k = 1, 2 slots: machine + recovery)"
            : "Backend: YubiKey keyring (k = 1, 1 slot: machine only)");

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
        PrintRecoveryKeyBackupWarning(c, recoveryPrivateKey);
        if (fileStore != null)
            c.Out.WriteLine($"\nConfig saved to: {fileStore.ConfigFile}");
        else
            c.Out.WriteLine("\nConfig saved.");
        return 0;
    }

    /// <summary>
    /// Displays the recovery slot's private key exactly once (issue #120) — same custody model
    /// as the XOR share block above: tswap never persists this value anywhere (that is the one
    /// hard security invariant of the whole feature), so this call site is the only place it is
    /// ever visible after generation. <paramref name="recoveryPrivateKey"/> is <c>null</c> when
    /// <c>--no-recovery</c> was passed, in which case this prints a short "no recovery slot"
    /// notice instead so the absence of a break-glass option isn't a silent surprise later.
    /// </summary>
    private static void PrintRecoveryKeyBackupWarning(IConsole c, byte[]? recoveryPrivateKey, string hardware = "every enrolled YubiKey")
    {
        if (recoveryPrivateKey == null)
        {
            c.Out.WriteLine($"\nNo recovery slot generated (--no-recovery): losing {hardware}");
            c.Out.WriteLine("means total, unrecoverable vault loss — there is no break-glass option.");
            return;
        }

        c.Out.WriteLine("\n⚠️  CRITICAL: BACKUP RECOVERY PRIVATE KEY NOW\n");
        c.Out.WriteLine($"This is a break-glass credential for total hardware loss ({hardware}");
        c.Out.WriteLine("lost or destroyed). tswap never stores it anywhere — display here is");
        c.Out.WriteLine("the only time you will see it. If this backup is lost too, this recovery");
        c.Out.WriteLine("option is gone for good; your normal hardware unlock is unaffected either way.");
        c.Out.WriteLine("\nRecovery Private Key (base64):");
        c.Out.WriteLine(Convert.ToBase64String(recoveryPrivateKey));
        c.Out.WriteLine("\nBackup locations required:");
        c.Out.WriteLine("  [ ] Password manager (Bitwarden/1Password)");
        c.Out.WriteLine("  [ ] Printed copy (home safe)");
        c.Out.WriteLine("  [ ] Second printed copy (off-site)");
        c.Out.WriteLine("  [ ] Git repository");
    }

    /// <summary>
    /// The YubiKey-shaped wrapper shared by both the interactive and test-mode <c>--keyring</c>
    /// paths (issue #119, extended by #120; split by #151 into this wrapper, which fills the
    /// YubiKey fields, and the backend-neutral <see cref="AssembleKeyring"/>): generates a random <c>K_v</c> and this machine's X25519 slot keypair
    /// (<see cref="SlotKeyPair.Generate"/>), wraps <c>(K_v || slot private key)</c>
    /// (<see cref="SlotSecretPayload.Encode"/>) under <paramref name="kekSlot"/> via
    /// <see cref="SlotPayloadWrap.Wrap"/>, and assembles the resulting <c>k = 1</c>
    /// <see cref="Keyring"/> plus the <see cref="Config"/> that carries it.
    ///
    /// <para>The returned <see cref="Config"/> still carries the same
    /// <c>YubiKeySerials</c>/<c>RedundancyXor</c>/<c>UnlockChallenge</c>/<c>MasterKeySalt</c>
    /// fields the default flow's config does — so <see cref="VaultUnlocker"/>'s YubiKey backend
    /// recovers this exact <paramref name="kekSlot"/> value again at unlock time, unmodified.
    /// Only <see cref="Config.Keyring"/> being non-null tells <see cref="VaultUnlocker"/> to
    /// treat that recovered value as <c>KEK_slot</c> and unwrap <c>K_v</c>, instead of using it
    /// as the master key directly.</para>
    ///
    /// <para><b>Issue #120:</b> when <paramref name="includeRecovery"/> is <c>true</c> (the
    /// default at the CLI layer; <c>--no-recovery</c> passes <c>false</c>), also generates a
    /// fresh recovery keypair (<see cref="SlotKeyPair.Generate"/>) and appends a
    /// <see cref="SlotKind.Recovery"/> slot wrapping the same <c>vaultKey</c> via
    /// <see cref="RecoverySlotWrap.Wrap"/> — see that type's doc comment for the wrap mechanics
    /// and this issue's PR body for the payload-shape/discriminator/storage judgement calls. The
    /// recovery private key is returned (never included in <see cref="Config"/>, never written
    /// anywhere by this method) so the caller can display it exactly once — <c>internal</c>
    /// rather than <c>private</c> specifically so tests can also drive this method directly to
    /// prove the recovery slot round-trips to the same <c>K_v</c> the machine slot does, without
    /// needing to scrape it back out of CLI console output.</para>
    /// </summary>
    internal static (Config Config, byte[] VaultKey, byte[]? RecoveryPrivateKey) BuildKeyringConfig(
        byte[] kekSlot, List<int> serials, string redundancyXorHex, bool? requiresTouch,
        RngMode rngMode, string unlockChallenge, byte[] masterKeySalt, bool includeRecovery = true)
    {
        // The YubiKey backend's own fields, exactly as before the split (issue #151 work item 2):
        // the keyring part below is backend-neutral and only adds Keyring/KeyringSlotId.
        var yubiKeyConfig = new Config(
            serials,
            redundancyXorHex,
            DateTime.UtcNow,
            requiresTouch,
            rngMode,
            unlockChallenge,
            MasterKeySalt: Convert.ToBase64String(masterKeySalt));

        return AssembleKeyring(kekSlot, yubiKeyConfig, includeRecovery);
    }

    /// <summary>
    /// The backend-neutral half of keyring init (issue #151 work item 2): takes only
    /// <paramref name="kekSlot"/> and a <paramref name="backendConfig"/> the backend has already
    /// filled with its own fields (YubiKey's serials/XOR share/challenge/salt, or a TPM/Secure
    /// Enclave vault's <see cref="Config.Backend"/> with <c>YubiKeySerials = []</c> and
    /// <c>RedundancyXor = ""</c>), and returns that config with <see cref="Config.Keyring"/> and
    /// <see cref="Config.KeyringSlotId"/> added and nothing else changed. Generates a random
    /// <c>K_v</c> and this machine's X25519 slot keypair, wraps <c>(K_v || slot private key)</c>
    /// under <paramref name="kekSlot"/> (<see cref="MachineSlotWrap"/>), adds the recovery slot
    /// when <paramref name="includeRecovery"/> is set (<see cref="RecoverySlotWrap"/>), and
    /// encodes the <c>k = 1</c> keyring. The recovery private key is returned, never stored.
    /// </summary>
    internal static (Config Config, byte[] VaultKey, byte[]? RecoveryPrivateKey) AssembleKeyring(
        byte[] kekSlot, Config backendConfig, bool includeRecovery)
    {
        if (backendConfig.Keyring != null || backendConfig.KeyringSlotId != null)
            throw new ArgumentException("The backend's config must not already carry a keyring", nameof(backendConfig));

        var vaultKey = RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var slotKeyPair = SlotKeyPair.Generate();
        var vaultId = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        const byte k = 1;

        // Issue #121: extracted into MachineSlotWrap so 'slot accept' (functionally "the
        // enrollment half of init --keyring" for a second machine) builds its own final slot with
        // the exact same construction, not a re-derived copy.
        var machineSlot = MachineSlotWrap.Wrap(
            vaultKey, slotKeyPair.PrivateKey, slotKeyPair.PublicKey, slotId, kekSlot,
            KeyringFormat.KeyringFormatVersion, vaultId, k);

        var slots = new List<Slot> { machineSlot };
        byte[]? recoveryPrivateKey = null;
        if (includeRecovery)
        {
            var recoveryKeyPair = SlotKeyPair.Generate();
            var recoverySlotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
            var (ephemeralPublicKey, recoveryWrapped) = RecoverySlotWrap.Wrap(
                vaultKey, recoveryKeyPair.PublicKey, KeyringFormat.KeyringFormatVersion, vaultId, k, recoverySlotId);
            slots.Add(new Slot(recoverySlotId, ephemeralPublicKey, recoveryWrapped, SlotKind.Recovery));
            recoveryPrivateKey = recoveryKeyPair.PrivateKey;
        }

        var keyring = new TswapCore.Keyring.Keyring(KeyringFormat.KeyringFormatVersion, vaultId, k, slots);

        var config = backendConfig with
        {
            Keyring = Convert.ToBase64String(KeyringCodec.Encode(keyring)),
            // Issue #121: records which of Keyring's slots is this machine's own, so
            // VaultUnlocker can still find it unambiguously once a second machine's slot is
            // appended via 'slot accept' — see Config.KeyringSlotId's doc comment.
            KeyringSlotId = Convert.ToBase64String(slotId),
        };

        return (config, vaultKey, recoveryPrivateKey);
    }

    /// <summary>
    /// Keyring init on this machine's TPM or Secure Enclave (issue #151, brief T2 decision 2):
    /// the backend's enrollment service (<see cref="HardwareServices.Enrollment"/>: real
    /// hardware, or the simulated backend in test mode) generates <c>KEK_slot</c> and its blob;
    /// <see cref="AssembleKeyring"/> wraps a random <c>K_v</c> under it in a machine slot plus,
    /// unless <c>--no-recovery</c>, a recovery slot. One machine, <c>k = 1</c>; more machines join
    /// with <c>slot request/approve/accept</c>.
    ///
    /// <para>The TPM backends are verified against swtpm (Linux) and a VM's virtual TPM
    /// (Windows) and an Intel PTT (#155); see <c>HARDWARE_BACKENDS.md</c>.</para>
    /// </summary>
    private static int ExecuteHardwareKeyring(CommandContext ctx, HardwareBackend backend, bool includeRecovery)
    {
        var c = ctx.Console;
        // Throws a clear TswapException on an OS without this hardware, before any output.
        var enrollment = HardwareServices.Enrollment(backend, ctx.TestKey);
        var hardware = backend == HardwareBackend.Tpm ? "TPM" : "Secure Enclave";

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine(backend == HardwareBackend.Tpm
            ? "║  tswap - TPM Keyring Initialization    ║"
            : "║  tswap - Secure Enclave Keyring Init   ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine($"This vault's master key (K_v) is random and wrapped by this machine's {hardware}");
        c.Out.WriteLine("slot (k = 1). Other machines can join later with 'slot request/approve/accept'.\n");
        c.Out.WriteLine(backend == HardwareBackend.Tpm
            ? "Sealing a new key to this machine's TPM..."
            : "Creating a Secure Enclave key (unlocking later will prompt for Touch ID / presence)...");

        var (kekSlot, hwBlob) = enrollment.Enroll();

        // The backend's own fields. YubiKeySerials = [] and RedundancyXor = "" as every
        // non-YubiKey vault has always written (issue #151's note: no on-disk change).
        var backendConfig = backend == HardwareBackend.Tpm
            ? new Config(
                YubiKeySerials: [],
                RedundancyXor: "",
                Created: DateTime.UtcNow,
                RequiresTouch: false,
                RngMode: RngMode.System,
                Backend: HardwareBackend.Tpm,
                TpmSealedKey: Convert.ToBase64String(hwBlob))
            : new Config(
                YubiKeySerials: [],
                RedundancyXor: "",
                Created: DateTime.UtcNow,
                RequiresTouch: true, // the Secure Enclave key always requires presence to unwrap
                RngMode: RngMode.System,
                Backend: HardwareBackend.SecureEnclave,
                SecureEnclaveWrappedKey: Convert.ToBase64String(hwBlob));

        var (config, vaultKey, recoveryPrivateKey) = AssembleKeyring(kekSlot, backendConfig, includeRecovery);

        // Same re-init backup dance as every other init path: back up config first (if anything
        // fails mid-init the old config still matches the old vault backup), then move the old
        // vault aside rather than overwrite it.
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
        c.Out.WriteLine(includeRecovery
            ? $"Backend: {hardware} keyring (k = 1, 2 slots: machine + recovery)"
            : $"Backend: {hardware} keyring (k = 1, 1 slot: machine only)");
        if (fileStore != null)
            c.Out.WriteLine($"Config saved to: {fileStore.ConfigFile}");
        c.Out.WriteLine($"\nThe machine slot's blob in config.json is meaningless without this machine's");
        c.Out.WriteLine($"physical {hardware}: losing the machine (or clearing its {hardware}) loses that slot.");
        PrintRecoveryKeyBackupWarning(c, recoveryPrivateKey, $"this machine's {hardware}");
        return 0;
    }
}
