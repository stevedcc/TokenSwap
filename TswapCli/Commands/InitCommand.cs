using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;

namespace TswapCli.Commands;

/// <summary>
/// Brief T16-S1 (ruling 4): <c>init</c> makes a record vault (one file per secret, shareable by
/// sync tools) with one YubiKey slot, or this machine's TPM / Secure Enclave slot, plus a recovery
/// slot: in <c>&lt;config dir&gt;/vault</c>, or in <c>--folder &lt;dir&gt;</c> (absent or empty, e.g. a
/// Syncthing or cloud-drive folder), with the <c>record-format</c> marker, so it writes record
/// format 3 from the start. The two-YubiKey XOR vault can no longer be created (a record store needs
/// a keyring; XOR vaults exist only to be migrated). <c>--keyring</c> is accepted as a no-op so old
/// scripts keep working. On a config folder holding a classic vault <c>init</c> refuses.
/// </summary>
public sealed class InitCommand : ICliCommand
{
    public string Name => "init";
    public string HelpUsage => $"init [--tpm|{SecureEnclaveTouchChoice.Flags}] {VaultPasswordChoice.Flags} [--no-recovery] [--folder <dir>] | init --vault-dir <shared folder>";
    public string Description => "Create a record vault (one file per secret, shareable by sync tools) in <config dir>/vault, or in --folder <dir> (absent or empty, e.g. a sync folder): one YubiKey slot (add keys with 'slot add --yubikey'), or this machine's --tpm (Windows/Linux) or --secure-enclave (macOS; needs --with-touch, Touch ID or password on every unlock, or --no-touch: no prompt, read its warning); plus a recovery slot unless --no-recovery. --password gives the slot a vault password (asked for on a terminal when neither --password nor --no-password is given). --keyring is accepted for old scripts. --vault-dir joins a folder another machine shares";
    public bool RequiresSudo => false;

    /// <summary>Brief T16-S1: init runs on a classic vault's config folder only to refuse with its own message.</summary>
    public bool WorksOnClassicVault => true;

    /// <summary>The only arguments <c>init</c> accepts, each at most once (#177); <c>--folder</c> takes a value.</summary>
    private static readonly string[] KnownFlags = ["--keyring", "--tpm", "--secure-enclave", "--no-recovery"];

    private const string FolderFlag = "--folder";

    public int Execute(CommandContext ctx, string[] args)
    {
        var c = ctx.Console;

        // Brief T6 decision 8: join a vault folder another machine already shares.
        if (args.Contains("--vault-dir"))
        {
            if (args is not ["--vault-dir", var folder] || folder.StartsWith("--"))
                throw new UsageException($"{ctx.Prefix} init --vault-dir <existing shared vault folder> (no other flags)");
            return ExecuteJoin(ctx, folder);
        }

        // Issue #177: the argument list must be exactly a combination of the known flags. Checked
        // before anything else (the reinitialise prompt, any hardware), so a typo such as
        // 'init --tmp' never falls through to a YubiKey initialisation. Brief T11: --secure-enclave
        // needs --with-touch or --no-touch, taken out (and checked) first.
        var usage = $"{ctx.Prefix} init [--tpm|{SecureEnclaveTouchChoice.Flags}] {VaultPasswordChoice.Flags} [--no-recovery] [{FolderFlag} <dir>] " +
                    $"(valid flags: {string.Join(", ", KnownFlags)}, {FolderFlag} <dir>, {SecureEnclaveTouchChoice.WithTouch}, " +
                    $"{SecureEnclaveTouchChoice.NoTouch}, {VaultPasswordChoice.PasswordFlag}, {VaultPasswordChoice.NoPasswordFlag}; " +
                    "--tpm and --secure-enclave are mutually exclusive, and so are --password and --no-password)";
        (args, var newFolder) = SplitFolder(args, usage);
        (args, var requirePresence) = SecureEnclaveTouchChoice.Split(args, usage);
        // Brief T17 ruling 15: --password / --no-password (neither: asked on a terminal).
        (args, var passwordFlag) = VaultPasswordChoice.Split(args, usage);
        if (args.Any(a => !KnownFlags.Contains(a)) || args.Distinct().Count() != args.Length)
            throw new UsageException(usage);

        var tpm = args.Contains("--tpm");
        var secureEnclave = args.Contains("--secure-enclave");
        var noRecovery = args.Contains("--no-recovery");
        // --keyring: every vault init makes is a keyring vault now; accepted so scripts keep working.

        if (tpm && secureEnclave)
            throw new UsageException(usage);

        // Brief T11 decision 7: as soon as the flags are valid, before any prompt or write.
        SecureEnclaveTouchChoice.WarnIfNoTouch(c, requirePresence);

        // A record-store machine's config points at a shared vault folder; a new init here would
        // replace it (and an empty save would tombstone the shared secrets). Refuse up front.
        // Keyed on the config (fix round 2): a record store's config (Store "records"), or any config.json
        // that names a vault folder (VaultDir), wherever that folder is, is refused before any prompt.
        var recordVaultDir = ctx.Storage is RecordVaultStore shared ? shared.LoadConfig().VaultDir : ConfiguredVaultDir(ctx.Storage);
        if (recordVaultDir is not null)
            throw new TswapException(
                $"This machine's {(ctx.Storage as IFileVaultStore)?.ConfigFile ?? "config.json"} belongs to a shared record-store vault ({recordVaultDir}). To set up " +
                "a different vault, use another config folder (TSWAP_CONFIG_DIR) or move config.json aside first.");

        var fileStore = ctx.Storage as IFileVaultStore
            ?? throw new TswapException("'init' needs a file-based config.");

        // Ruling 4: a classic vault here is converted, never initialized over. "Classic vault" is the
        // definition every command's refusal uses (CommandContext.IsClassicVault); any other
        // config.json (a pending 'slot request', say) gets what init always did: ask, back it up.
        if (CommandContext.IsClassicVault(ctx.Storage))
            throw new TswapException(
                $"This config folder holds a classic vault. Convert it with 'sudo {ctx.Prefix} migrate --to-records', or move " +
                "config.json and secrets.json.enc aside to start a new vault.");
        var replacesConfig = fileStore.Owner.FileExists(fileStore.ConfigFile);
        if (replacesConfig)
        {
            c.Out.Write("Already initialized. Reinitialize? (yes/no): ");
            if (c.ReadLine()?.ToLowerInvariant() != "yes")
                return 0;
        }

        // Checked before any hardware is touched, so a refusal enrolls nothing.
        var vaultDir = Path.GetFullPath(newFolder ?? Path.Combine(fileStore.ConfigDir, "vault"));
        RequireAbsentOrEmpty(ctx, fileStore.Owner, vaultDir);
        if (replacesConfig)
            c.Out.WriteLine($"Previous config backed up to: {fileStore.BackupConfig()}");

        // Brief T2 decision 2: --tpm and --secure-enclave make a keyring vault (machine slot +
        // recovery slot unless --no-recovery), as a plain init does with one YubiKey.
        if (secureEnclave)
            return ExecuteHardwareKeyring(ctx, fileStore, vaultDir, HardwareBackend.SecureEnclave, includeRecovery: !noRecovery, passwordFlag, requirePresence: requirePresence!.Value);

        if (tpm)
            return ExecuteHardwareKeyring(ctx, fileStore, vaultDir, HardwareBackend.Tpm, includeRecovery: !noRecovery, passwordFlag);

        return ExecuteKeyring(ctx, fileStore, vaultDir, includeRecovery: !noRecovery, passwordFlag);
    }

    /// <summary>
    /// The vault folder a classic store's config.json names (one that has lost its Store field), or null:
    /// such a config still belongs to a record vault, so init must not reinitialise over it.
    /// </summary>
    private static string? ConfiguredVaultDir(IVaultStore store)
    {
        if (store is not IFileVaultStore fileStore || !fileStore.Owner.FileExists(fileStore.ConfigFile))
            return null;
        try
        {
            return store.LoadConfig().VaultDir;
        }
        catch (Exception ex) when (ex is TswapException or System.Text.Json.JsonException or IOException or UnauthorizedAccessException)
        {
            return null; // unreadable: handled by the steps below as before
        }
    }

    /// <summary>Takes <c>--folder &lt;dir&gt;</c> out of <paramref name="args"/> (at most once, with a value).</summary>
    private static (string[] Remaining, string? Folder) SplitFolder(string[] args, string usage)
    {
        var index = Array.IndexOf(args, FolderFlag);
        if (index < 0)
            return (args, null);
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--") || args.Count(a => a == FolderFlag) > 1)
            throw new UsageException(usage);
        return ([.. args[..index], .. args[(index + 2)..]], args[index + 1]);
    }

    /// <summary>
    /// Ruling 4: a new vault goes into an absent or empty folder only, so <c>init</c> can never mix a
    /// new vault into an existing one (joining a shared folder is <c>init --vault-dir</c>).
    /// </summary>
    internal static void RequireAbsentOrEmpty(CommandContext ctx, DirectoryOwnerMatcher owner, string vaultDir)
    {
        var usable = owner.AsOwner(vaultDir, () =>
            (!Directory.Exists(vaultDir) && !File.Exists(vaultDir))
            || (Directory.Exists(vaultDir) && !Directory.EnumerateFileSystemEntries(vaultDir).Any()));
        if (!usable)
            throw new TswapException(
                $"The vault folder {vaultDir} is not empty. A new vault is created in an absent or empty folder only; to use a " +
                $"folder another machine already shares, run '{ctx.Prefix} init --vault-dir {vaultDir}'.");
    }

    /// <summary>
    /// Ruling 4: writes a new record vault. The vault folder first (the keyring and the
    /// <c>record-format</c> marker, through the file layer), then this machine's <c>config.json</c>
    /// pointing at it (machine fields only, a new origin id), so an interrupted init never leaves a
    /// config naming a folder that isn't there.
    /// </summary>
    /// <param name="vaultPassword">Brief T17: the vault's new <c>vault-password</c> file (its first password
    /// slot), written into the folder after the keyring and the marker and before config.json; or null.</param>
    internal static void CreateRecordVault(CommandContext ctx, IFileVaultStore fileStore, Config config, string vaultDir, VaultPasswordFile? vaultPassword = null)
    {
        var machine = config with
        {
            Keyring = null,
            Store = RecordVaultStore.StoreName,
            VaultDir = vaultDir,
            OriginId = RecordVaultStore.NewOriginId(),
        };
        fileStore.Owner.CreateDirectory(fileStore.ConfigDir);
        var folderStore = RecordVaultStore.ForFolder(vaultDir, machine, fileStore.Owner, ctx.Time);
        folderStore.SaveConfig(machine with { Keyring = config.Keyring });
        folderStore.WriteFormatMarker();
        if (vaultPassword is not null)
            folderStore.WriteVaultPassword(vaultPassword);
        // config.json through the record store: atomic, as the folder's owner, and with decision 10's
        // tightening of the config dir and vault folder (one notice), as init has always done.
        new RecordVaultStore(fileStore.ConfigDir, fileStore.Owner, ctx.Time, ctx.Console.Error).SaveConfig(machine);
    }

    /// <summary>
    /// Keyring init on a YubiKey (issue #119; one key per slot since brief T4 decision 4): a
    /// random 256-bit <c>K_v</c> wrapped by <b>one</b> plugged-in YubiKey's slot (<c>k = 1</c>),
    /// plus a recovery slot unless <c>--no-recovery</c>. The slot's <c>KEK_slot</c> comes from
    /// that key's HMAC-SHA1 response to a random per-slot challenge
    /// (<see cref="YubiKeySlotKek"/>); its serial, challenge, salt and touch policy live in the
    /// slot's hardware blob (<see cref="YubiKeySlotBlob"/>), not in config. Config keeps
    /// <c>YubiKeySerials = []</c>, <c>RedundancyXor = ""</c> and no
    /// <c>UnlockChallenge</c>/<c>MasterKeySalt</c>, the convention for non-pair vaults, and
    /// <see cref="Config.Backend"/> stays null (YubiKey). More keys join with <c>slot add
    /// --yubikey</c>, each as its own slot; there are no new pair enrollments.
    ///
    /// <para>No test-mode branch: in test mode <see cref="TestKeyYubiKeyService"/> answers the
    /// challenge, and unlock challenges it again the same way.</para>
    /// </summary>
    private static int ExecuteKeyring(CommandContext ctx, IFileVaultStore fileStore, string vaultDir, bool includeRecovery, bool? passwordFlag)
    {
        var c = ctx.Console;

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - Keyring Initialization        ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine("This vault's master key (K_v) is random and wrapped by one YubiKey's slot");
        c.Out.WriteLine("(k = 1) — see MULTI_MACHINE_KEYING.md. Add more keys later, each as its own");
        c.Out.WriteLine($"slot that opens the vault alone: sudo {ctx.Prefix} slot add --yubikey\n");

        // Test mode (TSWAP_TEST_KEY, Debug builds only) asks nothing, as its init always did: there is
        // no key to insert, and a test's stdin may never close.
        var testMode = ctx.TestKey is not null;
        // Brief T17 ruling 15: the password is chosen before the key is enrolled (it goes into KEK_slot).
        using var password = NewVaultPassword(ctx, passwordFlag, HardwareBackend.YubiKey);
        c.Out.WriteLine("Insert the YubiKey to enroll and press Enter...");
        if (!c.IsInputRedirected && !testMode)
            c.ReadLine();

        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var (blob, kekSlot) = YubiKeySlotEnrollment.Enroll(ctx, slotId, password: password?.Stretched);
        try
        {
            c.Out.WriteLine("\nPassword generation entropy source:");
            c.Out.WriteLine("  [1] System RNG  — one YubiKey touch per create (default)");
            c.Out.WriteLine("  [2] YubiKey     — two YubiKey touches per create; hardware-primary, immune to OS RNG compromise");
            c.Out.Write("Choose [1/2, default 1]: ");
            var rngChoice = testMode ? null : c.ReadLine()?.Trim();
            var rngMode = rngChoice == "2" ? RngMode.YubiKey : RngMode.System;

            var backendConfig = new Config(
                YubiKeySerials: [],
                RedundancyXor: "",
                Created: ctx.Time.GetUtcNow().UtcDateTime,
                RequiresTouch: blob.RequiresTouch,
                RngMode: rngMode);

            var (config, vaultKey, recoveryPrivateKey) = AssembleKeyring(
                kekSlot, backendConfig, includeRecovery, blob.Encode(), slotId, password?.VaultKey, password?.VaultId);

            config = SecurityWarnings.Acknowledge(config); // brief T7 item 5: explained below
            try
            {
                CreateRecordVault(ctx, fileStore, config, vaultDir, password?.File);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey); // on a failed write too (fix round 1)
            }

            c.Out.WriteLine("\n╔════════════════════════════════════════╗");
            c.Out.WriteLine("║  ✓ INITIALIZATION COMPLETE            ║");
            c.Out.WriteLine("╚════════════════════════════════════════╝\n");
            c.Out.WriteLine($"YubiKey Serial: {blob.Serial}");
            c.Out.WriteLine(includeRecovery
                ? "Backend: YubiKey keyring (k = 1, 2 slots: this key + recovery)"
                : "Backend: YubiKey keyring (k = 1, 1 slot: this key only)");
            YubiKeySlotEnrollment.PrintTouchPolicy(c, blob);
            PrintPasswordLine(c, password);
            c.Out.WriteLine($"Entropy mode:    {(rngMode == RngMode.YubiKey ? "YubiKey hardware (two touches per create)" : "System RNG (one touch per create)")}");
            c.Out.WriteLine("\nThis key alone opens the vault. To enroll a spare key as its own slot, plug it in and run:");
            c.Out.WriteLine($"  sudo {ctx.Prefix} slot add --yubikey");
            PrintRecoveryKeyBackupWarning(c, ctx.Prefix, recoveryPrivateKey, $"YubiKey {blob.Serial} and every key added later");
            PrintVaultFolder(c, fileStore, vaultDir);
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kekSlot);
        }
    }

    /// <summary>Where the new vault went: the shareable folder, and the per-machine config.</summary>
    private static void PrintVaultFolder(IConsole c, IFileVaultStore fileStore, string vaultDir)
    {
        c.Out.WriteLine($"\nVault folder: {vaultDir} (record format {KeyringFormat.RecordFormatVersion}; to share it, sync this folder, never config.json)");
        c.Out.WriteLine($"Config saved to: {fileStore.ConfigFile}");
    }

    /// <summary>
    /// Brief T6 decision 8: points this machine's config at a vault folder another machine
    /// already shares (a sync folder or a share): a record-store config with this machine's own
    /// new origin id and no slot of its own. It opens with any YubiKey that has a slot in that
    /// folder's keyring, or the recovery key; a TPM / Secure Enclave machine joins with
    /// <c>slot request</c> / <c>approve</c> / <c>accept --vault-dir</c> instead. Nothing in the
    /// folder is written. A previous config.json is backed up; a classic secrets file is moved aside.
    /// </summary>
    private static int ExecuteJoin(CommandContext ctx, string folder)
    {
        var c = ctx.Console;
        if (ctx.Storage is not IFileVaultStore fileStore)
            throw new TswapException("'init --vault-dir' needs a file-based config.");
        var vaultDir = Path.GetFullPath(folder);
        var probe = new Config([], "", ctx.Time.GetUtcNow().UtcDateTime, Store: RecordVaultStore.StoreName, VaultDir: vaultDir, OriginId: RecordVaultStore.NewOriginId());
        var folderStore = RecordVaultStore.ForFolder(vaultDir, probe, fileStore.Owner, ctx.Time);
        if (!fileStore.Owner.FileExists(folderStore.KeyringFile))
            throw new TswapException(
                $"{vaultDir} has no keyring, so it is not a shared vault folder (yet). To make a new shareable vault there, run " +
                $"'{ctx.Prefix} init --folder {vaultDir}' (with --tpm or --secure-enclave for this machine's hardware).");
        var keyring = folderStore.ReadKeyring();

        if (fileStore.Owner.FileExists(fileStore.ConfigFile))
        {
            c.Out.Write("Already initialized. Point this machine at the shared folder instead? (yes/no): ");
            if (c.ReadLine()?.ToLowerInvariant() != "yes")
                return 0;
            c.Out.WriteLine($"Previous config backed up to: {fileStore.BackupConfig()}");
        }
        var config = probe with { RngMode = RngMode.System };
        fileStore.Owner.CreateDirectory(fileStore.ConfigDir);
        fileStore.Owner.WriteAtomic(fileStore.ConfigFile, System.Text.Encoding.UTF8.GetBytes(
            System.Text.Json.JsonSerializer.Serialize(config, TswapJsonContext.Default.Config)));
        if (fileStore.Owner.FileExists(fileStore.SecretsFile))
            c.Out.WriteLine($"Previous secrets file moved to: {FileBackup.Move(fileStore.SecretsFile, ctx.Time.GetUtcNow().UtcDateTime, fileStore.Owner)}");

        var yubiKeySlots = keyring.Slots.Count(s => s.Kind == SlotKind.Machine && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob));
        c.Out.WriteLine($"\n✓ This machine now uses the shared vault folder {vaultDir} ({keyring.Slots.Count} slot(s), {yubiKeySlots} of them YubiKeys).");
        c.Out.WriteLine("It opens with any YubiKey that has a slot there, or the recovery key. To give this machine's TPM or Secure");
        c.Out.WriteLine($"Enclave its own slot: '{ctx.Prefix} slot request --tpm <file>' here, 'sudo {ctx.Prefix} slot approve' on an enrolled");
        c.Out.WriteLine($"machine, then '{ctx.Prefix} slot accept <approve-file>' here: the slot goes straight into the shared keyring.");
        c.Out.WriteLine($"Config saved to: {fileStore.ConfigFile} (per machine: never sync it; sync only the vault folder).");
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
    internal static void PrintRecoveryKeyBackupWarning(IConsole c, string prefix, byte[]? recoveryPrivateKey, string hardware = "every enrolled YubiKey")
    {
        if (recoveryPrivateKey is null)
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
        c.Out.WriteLine("\nTo use it, pipe it in on stdin, never on the command line: to enroll new hardware, run");
        c.Out.WriteLine($"  <command printing the key> | sudo {prefix} recover --yubikey   (or --tpm / --secure-enclave)");
        c.Out.WriteLine("or give it to 'slot add --yubikey', 'slot approve' or 'slot merge' with --recovery-key-stdin.");
        c.Out.WriteLine("\nRecovery Private Key (base64):");
        c.Out.WriteLine(Convert.ToBase64String(recoveryPrivateKey));
        c.Out.WriteLine("\nBackup locations required:");
        c.Out.WriteLine("  [ ] Password manager (Bitwarden/1Password)");
        c.Out.WriteLine("  [ ] Printed copy (home safe)");
        c.Out.WriteLine("  [ ] Second printed copy (off-site)");
        c.Out.WriteLine("  [ ] Git repository");
    }

    /// <summary>
    /// <b>Legacy pair layout, written by no command since brief T4</b> (<c>init --keyring</c> now
    /// enrolls one key per slot); kept so tests can still build pair keyrings exactly as they
    /// were made. Was: the YubiKey-shaped wrapper shared by both the interactive and test-mode
    /// <c>--keyring</c> paths (issue #119, extended by #120; split by #151 into this wrapper, which fills the
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
    /// <paramref name="hwBlob"/> (issue #154) is a TPM/Secure Enclave backend's blob for the
    /// machine slot, or a one-key YubiKey slot's <see cref="YubiKeySlotBlob"/> (brief T4); null for
    /// a legacy pair slot. <paramref name="slotId"/> is the machine slot's id when the caller has
    /// already derived <paramref name="kekSlot"/> with it (a one-key YubiKey slot); else random.
    /// </summary>
    /// <para>Brief T17: <paramref name="vaultKey"/> and <paramref name="vaultId"/> are given when the caller
    /// already needed them (a first password slot's <c>vault-password</c> file is keyed to both); else
    /// random. A given <paramref name="vaultKey"/> is copied, so the caller zeroes its own.</para>
    internal static (Config Config, byte[] VaultKey, byte[]? RecoveryPrivateKey) AssembleKeyring(
        byte[] kekSlot, Config backendConfig, bool includeRecovery, byte[]? hwBlob = null, byte[]? slotId = null,
        byte[]? vaultKey = null, byte[]? vaultId = null)
    {
        if (backendConfig.Keyring is not null || backendConfig.KeyringSlotId is not null)
            throw new ArgumentException("The backend's config must not already carry a keyring", nameof(backendConfig));
        if (vaultKey is not null && vaultKey.Length != KeyringFormat.VaultKeySize)
            throw new ArgumentException($"vaultKey must be {KeyringFormat.VaultKeySize} bytes", nameof(vaultKey));
        if (vaultId is not null && vaultId.Length != KeyringFormat.VaultIdSize)
            throw new ArgumentException($"vaultId must be {KeyringFormat.VaultIdSize} bytes", nameof(vaultId));

        vaultKey = vaultKey is null ? RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize) : (byte[])vaultKey.Clone();
        var slotKeyPair = SlotKeyPair.Generate();
        vaultId ??= RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        // A one-key YubiKey slot's KEK_slot is derived with its slot id (brief T4), so the caller
        // picks the id first; every other backend lets this method draw it.
        if (slotId is not null && slotId.Length != KeyringFormat.SlotIdSize)
            throw new ArgumentException($"slotId must be {KeyringFormat.SlotIdSize} bytes", nameof(slotId));
        slotId ??= RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        const byte k = 1;

        // Issue #121: extracted into MachineSlotWrap so 'slot accept' (functionally "the
        // enrollment half of init --keyring" for a second machine) builds its own final slot with
        // the exact same construction, not a re-derived copy.
        var machineSlot = MachineSlotWrap.Wrap(
            vaultKey, slotKeyPair.PrivateKey, slotKeyPair.PublicKey, slotId, kekSlot,
            KeyringFormat.KeyringFormatVersion, vaultId, k) with
        {
            // Issue #154: a TPM/Secure Enclave backend's blob, or a one-key YubiKey slot's
            // parameters (brief T4), lives in its machine slot. Null for a legacy pair slot.
            HwBlob = hwBlob,
        };

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
    private static int ExecuteHardwareKeyring(
        CommandContext ctx, IFileVaultStore fileStore, string vaultDir, HardwareBackend backend, bool includeRecovery, bool? passwordFlag, bool requirePresence = true)
    {
        var c = ctx.Console;
        // Throws a clear TswapException on an OS without this hardware, before any output.
        var enrollment = HardwareServices.Enrollment(backend, ctx.TestKey, ctx.OwnerScope, requirePresence);
        var hardware = backend == HardwareBackend.Tpm ? "TPM" : "Secure Enclave";

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine(backend == HardwareBackend.Tpm
            ? "║  tswap - TPM Keyring Initialization    ║"
            : "║  tswap - Secure Enclave Keyring Init   ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine($"This vault's master key (K_v) is random and wrapped by this machine's {hardware}");
        c.Out.WriteLine("slot (k = 1). Other machines can join later with 'slot request/approve/accept'.\n");
        // Brief T17 ruling 15: chosen before the hardware object is made (the object needs it).
        using var password = NewVaultPassword(ctx, passwordFlag, backend);
        c.Out.WriteLine(backend == HardwareBackend.Tpm
            ? "Sealing a new key to this machine's TPM..."
            : requirePresence
                ? "Creating a Secure Enclave key (unlocking later will prompt for Touch ID / presence)..."
                : "Creating a Secure Enclave key with no presence requirement (--no-touch)...");

        var (kekSlot, hwBlob) = enrollment.Enroll(password?.Stretched);

        // The backend's own fields. YubiKeySerials = [] and RedundancyXor = "" as every
        // non-YubiKey vault has always written (issue #151's note: no on-disk change). The blob
        // goes into the machine slot (issue #154), not into TpmSealedKey/SecureEnclaveWrappedKey,
        // which only single-slot vaults made before keyring vaults use.
        var backendConfig = new Config(
            YubiKeySerials: [],
            RedundancyXor: "",
            Created: ctx.Time.GetUtcNow().UtcDateTime,
            // Brief T11 decision 6: the Secure Enclave key requires presence unless --no-touch (the
            // only record of the key's policy); a TPM key here has no PIN/PCR policy (#133).
            RequiresTouch: backend == HardwareBackend.SecureEnclave && requirePresence,
            RngMode: RngMode.System,
            Backend: backend);

        var (config, vaultKey, recoveryPrivateKey) = AssembleKeyring(
            kekSlot, backendConfig, includeRecovery, hwBlob, vaultKey: password?.VaultKey, vaultId: password?.VaultId);

        try
        {
            CreateRecordVault(ctx, fileStore, config, vaultDir, password?.File);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(vaultKey); // on a failed write too (fix round 1)
        }

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  ✓ INITIALIZATION COMPLETE            ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine(includeRecovery
            ? $"Backend: {hardware} keyring (k = 1, 2 slots: machine + recovery)"
            : $"Backend: {hardware} keyring (k = 1, 1 slot: machine only)");
        if (backend == HardwareBackend.SecureEnclave)
            c.Out.WriteLine(SecureEnclaveTouchChoice.Summary(requirePresence));
        PrintPasswordLine(c, password);
        PrintVaultFolder(c, fileStore, vaultDir);
        c.Out.WriteLine($"\nThe machine slot's hardware blob in the keyring is meaningless without this machine's");
        c.Out.WriteLine($"physical {hardware}: losing the machine (or clearing its {hardware}) loses that slot.");
        if (backend == HardwareBackend.SecureEnclave)
        {
            // Brief T7 item 8 (#159): said where the user sees it, in proportion (HARDWARE_BACKENDS.md).
            c.Out.WriteLine("\nNote: the Secure Enclave slot's wrapping (ephemeral ECDH + HKDF-SHA256 + AES-GCM, a hand-rolled");
            c.Out.WriteLine("ECIES equivalent) has been verified for correctness (round-trips, fails cleanly on denial) but");
            c.Out.WriteLine("has not had an independent cryptographic review. See HARDWARE_BACKENDS.md.");
        }
        PrintRecoveryKeyBackupWarning(c, ctx.Prefix, recoveryPrivateKey, $"this machine's {hardware}");
        return 0;
    }

    /// <summary>
    /// Brief T17 ruling 15: a new vault's first slot. With a password (<see cref="VaultPasswordChoice.Decide"/>),
    /// <c>K_v</c> and the vault id are drawn here, before enrolment, because the <c>vault-password</c> file is
    /// keyed to both; the password is asked for twice. Null without a password.
    /// </summary>
    private static NewPassword? NewVaultPassword(CommandContext ctx, bool? flag, HardwareBackend backend)
    {
        if (!VaultPasswordChoice.Decide(ctx, flag, backend))
            return null;
        var vaultKey = RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var vaultId = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        try
        {
            var (stretched, file) = VaultPasswordChoice.CreateNew(ctx, vaultKey, vaultId, "init");
            return new NewPassword(stretched, file, vaultKey, vaultId);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(vaultKey);
            throw;
        }
    }

    /// <summary>A new vault's password: the stretched bytes, its file, and the <c>K_v</c> and vault id it is keyed to.</summary>
    private sealed record NewPassword(StretchedPassword Stretched, VaultPasswordFile File, byte[] VaultKey, byte[] VaultId) : IDisposable
    {
        public void Dispose()
        {
            Stretched.Dispose();
            CryptographicOperations.ZeroMemory(VaultKey);
        }
    }

    private static void PrintPasswordLine(IConsole c, NewPassword? password)
    {
        if (password is not null)
            c.Out.WriteLine("Vault password:  this slot needs it (or a running 'tswap agent') for every unlock");
    }
}
