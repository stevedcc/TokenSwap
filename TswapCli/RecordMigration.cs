using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;

namespace TswapCli;

/// <summary>Brief T6 item 6 test seams for <see cref="RecordMigration"/>.</summary>
public sealed class RecordMigrationSeams
{
    /// <summary>Changes the read-back secrets before the comparison (forces a mismatch).</summary>
    public Func<SecretsDb, SecretsDb>? TamperReadBack { get; init; }

    /// <summary>Called after steps 1, 3 and 4 with the step number; throwing simulates a crash there.</summary>
    public Action<int>? AfterStep { get; init; }

    /// <summary>Called just before step 3 (the rename) with the step number (fix round 1, A2).</summary>
    public Action<int>? BeforeStep { get; init; }

    /// <summary>Called between the target re-check and the rename itself (fix round 3, item 4).</summary>
    public Action? BeforeRename { get; init; }
}

/// <summary>
/// Brief T6 decision 8: <c>migrate --to-records [--vault-dir &lt;dir&gt;]</c> (sudo) converts a
/// classic vault into the per-secret record store, in an order that leaves a working vault after a
/// crash at any point:
/// <list type="number">
/// <item>unlock; write the keyring and every secret as a record into a new
/// <c>&lt;vault-dir&gt;.tmp-&lt;random&gt;</c> folder next to the target;</item>
/// <item>re-read everything from it and compare (names, values by hash, burned state; for a
/// converted XOR vault also unwrap <c>K_v</c> from every new slot); on a mismatch delete the temp
/// folder, change nothing, and say what differed;</item>
/// <item>rename the temp folder to the vault folder;</item>
/// <item>switch <c>config.json</c> to <c>"Store": "records"</c> (backed up first);</item>
/// <item>only then move <c>secrets.json.enc</c> aside to a timestamped <c>.bak</c>.</item>
/// </list>
/// A plain XOR vault becomes a keyring vault in the same run (owner decision 2026-10-30): <c>K_v</c>
/// stays its derived master key (no secret is re-encrypted for it), a new vault id is minted, every
/// enrolled YubiKey must be plugged in and gets its own one-key slot, and a recovery slot is added
/// and its key shown once. "Already a record store" is decided by <c>config.json</c>'s
/// <c>Store</c> only.
/// </summary>
internal static class RecordMigration
{
    public static int Run(CommandContext ctx, string[] args)
    {
        var usage = $"sudo {ctx.Prefix} migrate --to-records [--vault-dir <dir>]";
        string? vaultDirArg = null;
        switch (args)
        {
            case ["--to-records"]:
                break;
            case ["--to-records", "--vault-dir", var dir] when !dir.StartsWith("--"):
                vaultDirArg = dir;
                break;
            case ["--vault-dir", var dir, "--to-records"] when !dir.StartsWith("--"):
                vaultDirArg = dir;
                break;
            default:
                throw new UsageException(usage);
        }
        var c = ctx.Console;

        // Decrypts every secret: export's sensitivity class.
        ctx.RequireSudo("migrate --to-records");

        if (ctx.Storage is not IFileVaultStore fileStore)
            throw new TswapException("'migrate --to-records' needs a vault stored in files.");
        var owner = fileStore.Owner;
        var config = ctx.Storage.LoadConfig();

        if (ctx.Storage is RecordVaultStore records)
            return FinishOrRefuse(ctx, records, config);

        var vaultDir = Path.GetFullPath(vaultDirArg ?? Path.Combine(fileStore.ConfigDir, "vault"));
        var parent = Path.GetDirectoryName(vaultDir)
            ?? throw new TswapException($"{vaultDir} can't be a vault folder (it has no parent folder).");

        // Everything that can refuse does so before anything is written, touched or unlocked.
        var plainXor = config.Keyring == null;
        if (config.Keyring == null && config.PendingSlotId != null)
            throw new TswapException("This machine has a pending 'slot request'; finish it with 'slot accept' before converting.");
        if (plainXor && (config.Backend is not (null or HardwareBackend.YubiKey) || config.TpmSealedKey != null || config.SecureEnclaveWrappedKey != null))
            throw new TswapException(
                "This is a single-slot TPM / Secure Enclave vault from before keyring vaults; it can't be converted. Create a keyring " +
                $"vault ('{ctx.Prefix} init --tpm' or '--secure-enclave'), move the secrets over with export / import, then convert that.");
        if (plainXor)
        {
            var pluggedIn = ctx.YubiKeys.ListSerials();
            var missing = config.YubiKeySerials.Where(s => !pluggedIn.Contains(s)).ToList();
            if (missing.Count > 0)
                throw new TswapException(
                    $"Plug in every YubiKey enrolled in this vault: missing {string.Join(", ", missing)}. Each one gets its own " +
                    "slot in the converted vault, so all of them must be present. Nothing was changed.");
            if (config.YubiKeySerials.Count == 0)
                throw new TswapException("This vault's config.json names no YubiKeys; it can't be converted.");
        }
        if (owner.AsOwner(vaultDir, () => Directory.Exists(vaultDir) && Directory.EnumerateFileSystemEntries(vaultDir).Any()))
        {
            // Fix round 3, item 4: a crash between step 3 (rename) and step 4 (config switch) leaves
            // this vault's own converted copy there while config.json still names the classic store.
            var copy = LooksLikeOwnConvertedCopy(owner, vaultDir, config);
            if (copy == ConvertedCopy.SameYubiKeys)
                throw new TswapException(
                    $"The target folder {vaultDir} is not empty: it holds what looks like a converted copy of a vault with the " +
                    "same YubiKeys (perhaps this one, left by an interrupted run before it switched config.json; a plain XOR " +
                    "vault's copy can only be recognised by its keys). Your classic vault is intact and still in use; check " +
                    $"before removing it: for example point a separate config folder at it with 'TSWAP_CONFIG_DIR=<new folder> " +
                    $"{ctx.Prefix} init --vault-dir {vaultDir}' and look at '{ctx.Prefix} names'. Then remove the folder and run " +
                    "this again, or keep it and join it with init --vault-dir.");
            if (copy == ConvertedCopy.ThisVault)
                throw new TswapException(
                    $"The target folder {vaultDir} is not empty: it holds this vault's own converted copy, left by an earlier " +
                    "run that was interrupted before it switched config.json. Your classic vault is intact and still in use. " +
                    $"Either remove that folder and run this again, or, if you want to keep that copy, point this machine at it " +
                    $"with '{ctx.Prefix} init --vault-dir {vaultDir}' (changes made to the classic vault since the interrupted run " +
                    "are not in it).");
            throw new TswapException(
                $"The target folder {vaultDir} is not empty. Pick an empty or new folder with --vault-dir. (To use a vault folder " +
                $"another machine already shares, run '{ctx.Prefix} init --vault-dir <folder>' or 'slot accept ... --vault-dir <folder>' " +
                "instead. If the folder is left over from an interrupted conversion and this vault still opens classically, " +
                "remove the folder and run this again.)");
        }

        RemoveStaleTempFolders(c, owner, vaultDir, parent);

        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);

        Keyring keyring;
        byte[]? recoveryPrivateKey = null;
        Config newConfig;
        var origin = RecordVaultStore.NewOriginId();
        if (plainXor)
        {
            (keyring, recoveryPrivateKey) = BuildKeyringForXorVault(ctx, config, key);
            newConfig = config with
            {
                YubiKeySerials = [],
                RedundancyXor = null,
                UnlockChallenge = null,
                MasterKeySalt = null,
                KeyringSlotId = null,
            };
        }
        else
        {
            keyring = SlotCommand.DecodeKeyringOrCorrupt(config);
            newConfig = config;
        }
        newConfig = newConfig with { Keyring = null, Store = RecordVaultStore.StoreName, VaultDir = vaultDir, OriginId = origin, LastHlc = null };

        // Step 1: everything into a temp folder next to the target.
        owner.CreateDirectory(parent);
        var tempDir = $"{vaultDir}.tmp-{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4))}";
        owner.CreateDirectory(tempDir);
        // A failure from here to step 3 leaves the temp folder behind, as a crash would; the classic
        // vault is untouched, and the next run removes the folder (with a notice).
        var temp = RecordVaultStore.ForFolder(tempDir, newConfig, owner);
        temp.SaveConfig(newConfig with { Keyring = Convert.ToBase64String(KeyringCodec.Encode(keyring)) });
        var lastHlc = temp.WriteSnapshot(db, key);
        ctx.MigrationSeams?.AfterStep?.Invoke(1);

        // Step 2: read it all back and compare.
        var problems = Verify(ctx, tempDir, newConfig, owner, keyring, db, key, recoveryPrivateKey, plainXor);
        if (problems.Count > 0)
        {
            owner.DeleteDirectory(tempDir);
            throw new TswapException(
                "The converted copy did not read back the same, so nothing was changed (the temp folder was removed):\n" +
                string.Join("\n", problems.Select(p => "  " + p)));
        }

        // Fix round 1 (A4): the recovery key of a converted XOR vault is shown now, after the
        // verification and before the config switch, so a crash later can't lose it unseen.
        if (plainXor)
        {
            c.Out.WriteLine("\nThe converted copy checked out. Its recovery slot opens the vault without any YubiKey:");
            InitCommand.PrintRecoveryKeyBackupWarning(c, ctx.Prefix, recoveryPrivateKey, "every enrolled YubiKey");
        }

        // Step 3: the temp folder becomes the vault folder. The target is checked again right
        // before the rename and never deleted recursively (fix round 1, A2): absent -> rename; an
        // empty folder -> a non-recursive delete, then rename; anything else -> refuse.
        ctx.MigrationSeams?.BeforeStep?.Invoke(3);
        var target = owner.AsOwner(vaultDir, () => !Directory.Exists(vaultDir) && !File.Exists(vaultDir) ? "absent"
            : Directory.Exists(vaultDir) && new DirectoryInfo(vaultDir).LinkTarget == null && !Directory.EnumerateFileSystemEntries(vaultDir).Any() ? "empty"
            : "occupied");
        try
        {
            if (target == "empty")
                owner.DeleteEmptyDirectory(vaultDir);
            else if (target == "occupied")
                throw new IOException("occupied");
        }
        catch (IOException)
        {
            owner.DeleteDirectory(tempDir);
            throw new TswapException(
                $"The target folder {vaultDir} is not empty any more (something was put there while converting). Nothing was " +
                "changed; the temp folder was removed. Pick an empty folder and run this again.");
        }
        ctx.MigrationSeams?.BeforeRename?.Invoke();
        try
        {
            owner.Move(tempDir, vaultDir);
        }
        catch (IOException)
        {
            // Fix round 3, item 4: the target appeared between the check and the rename.
            // Fix round 4, item 7: a temp folder that can't be removed still gives this reason.
            var tempNote = "the temp folder was removed";
            try
            {
                owner.DeleteDirectory(tempDir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                tempNote = $"the temp folder {tempDir} could not be removed ({ex.Message}); remove it by hand";
            }
            throw new TswapException(
                $"The target folder {vaultDir} is not empty any more (something was put there while converting). Nothing was " +
                $"changed; {tempNote}. Pick an empty folder and run this again.");
        }
        ctx.MigrationSeams?.AfterStep?.Invoke(3);

        // Step 4: config.json names the record store (its keyring now lives in the vault folder).
        var configBackup = fileStore.BackupConfig();
        newConfig = newConfig with { LastHlc = lastHlc.ToString() };
        owner.WriteAtomic(fileStore.ConfigFile, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(newConfig, TswapJsonContext.Default.Config)));
        ctx.MigrationSeams?.AfterStep?.Invoke(4);

        // Step 5: only now the classic file goes aside.
        var secretsBackup = owner.FileExists(fileStore.SecretsFile) ? FileBackup.Move(fileStore.SecretsFile, DateTime.UtcNow, owner) : null;

        c.Out.WriteLine($"\n✓ Converted to the record store: {db.Secrets.Count} secret(s), one file each.");
        c.Out.WriteLine($"Vault folder (share this one, never config.json): {vaultDir}");
        c.Out.WriteLine($"Previous config backed up to: {configBackup}");
        if (secretsBackup != null)
            c.Out.WriteLine($"Previous secrets file moved to: {secretsBackup}");
        if (plainXor)
        {
            c.Out.WriteLine("\nThis vault is now a keyring vault: each YubiKey has its own slot and opens it alone; the XOR share is");
            c.Out.WriteLine("no longer used (it stays in the config backup above). The recovery key was shown above.");
        }
        return 0;
    }

    /// <summary>
    /// <c>config.json</c> already names the record store: finish an interrupted step 5 (the classic
    /// file still beside it) or refuse.
    /// </summary>
    private static int FinishOrRefuse(CommandContext ctx, RecordVaultStore records, Config config)
    {
        if (records.Owner.FileExists(records.SecretsFile))
        {
            var backup = FileBackup.Move(records.SecretsFile, DateTime.UtcNow, records.Owner);
            ctx.Console.Out.WriteLine(
                $"This vault was already converted, but an interrupted run left the classic secrets file behind; it was moved to: {backup}");
            return 0;
        }
        throw new TswapException($"This vault is already a record store (vault folder: {config.VaultDir}). Nothing to convert.");
    }

    /// <summary>What a non-empty target folder's keyring says about where it came from.</summary>
    private enum ConvertedCopy
    {
        /// <summary>Not recognised.</summary>
        None,

        /// <summary>This keyring vault's own vault id: certainly this vault.</summary>
        ThisVault,

        /// <summary>A plain XOR vault's conversion: same YubiKeys plus a recovery slot (a guess).</summary>
        SameYubiKeys,
    }

    /// <summary>
    /// Fix round 3, item 4 / round 4, item 6: whether <paramref name="vaultDir"/>'s keyring looks
    /// like this vault converted. A keyring vault is recognised by its own vault id (certain). A
    /// plain XOR vault's conversion mints a new vault id, so it can only be matched by one YubiKey
    /// slot per enrolled serial plus a recovery slot, which another XOR vault on the same keys also
    /// matches: <see cref="ConvertedCopy.SameYubiKeys"/>.
    /// </summary>
    private static ConvertedCopy LooksLikeOwnConvertedCopy(DirectoryOwnerMatcher owner, string vaultDir, Config config)
    {
        try
        {
            var keyringPath = Path.Combine(vaultDir, RecordVaultStore.KeyringFileName);
            if (!owner.FileExists(keyringPath))
                return ConvertedCopy.None;
            var there = KeyringCodec.Decode(owner.ReadAllBytes(keyringPath));
            if (config.Keyring != null)
                return there.VaultId.AsSpan().SequenceEqual(SlotCommand.DecodeKeyringOrCorrupt(config).VaultId)
                    ? ConvertedCopy.ThisVault
                    : ConvertedCopy.None;
            var serials = there.Slots.Where(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob))
                .Select(s => YubiKeySlotBlob.Decode(s.HwBlob!).Serial).Order().ToList();
            return serials.Count > 0 && serials.SequenceEqual(config.YubiKeySerials.Distinct().Order())
                && there.Slots.Any(s => s.Kind == SlotKind.Recovery)
                ? ConvertedCopy.SameYubiKeys
                : ConvertedCopy.None;
        }
        catch (Exception ex) when (ex is TswapException or IOException or UnauthorizedAccessException)
        {
            return ConvertedCopy.None;
        }
    }

    private static void RemoveStaleTempFolders(IConsole c, DirectoryOwnerMatcher owner, string vaultDir, string parent)
    {
        var stales = owner.AsOwner(parent, () => Directory.Exists(parent)
            ? Directory.GetDirectories(parent, Path.GetFileName(vaultDir) + ".tmp-*")
            : []);
        // Fix round 1 (A2): only a folder untouched for an hour is taken as a crash's leftover; a
        // younger one may belong to a conversion that is still running.
        var cutoff = DateTime.UtcNow.AddHours(-1);
        var young = stales.Where(s => owner.AsOwner(s, () => Directory.GetLastWriteTimeUtc(s)) > cutoff).ToList();
        if (young.Count > 0)
            throw new TswapException(
                $"{string.Join(", ", young)} was changed less than an hour ago: another migration may be running. Nothing was " +
                "changed. If no other conversion is running, remove that folder (or wait an hour) and run this again.");
        foreach (var stale in stales)
        {
            owner.DeleteDirectory(stale);
            c.Out.WriteLine($"Removed a temp folder left by an interrupted conversion: {stale}");
        }
    }

    /// <summary>
    /// The keyring a plain XOR vault becomes: a new vault id, one one-key slot per enrolled YubiKey
    /// (T4's construction, touch as each key is configured) and a recovery slot, all wrapping
    /// <paramref name="masterKey"/> as <c>K_v</c>.
    /// </summary>
    private static (Keyring Keyring, byte[] RecoveryPrivateKey) BuildKeyringForXorVault(CommandContext ctx, Config config, byte[] masterKey)
    {
        const byte k = 1;
        var vaultId = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        var slots = new List<Slot>();
        foreach (var serial in config.YubiKeySerials.Distinct())
        {
            var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
            var (blob, kekSlot) = YubiKeySlotEnrollment.EnrollSerial(ctx, slotId, serial);
            try
            {
                var keyPair = SlotKeyPair.Generate();
                slots.Add(MachineSlotWrap.Wrap(masterKey, keyPair.PrivateKey, keyPair.PublicKey, slotId, kekSlot,
                    KeyringFormat.KeyringFormatVersion, vaultId, k) with { HwBlob = blob.Encode() });
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kekSlot);
            }
        }
        var recovery = SlotKeyPair.Generate();
        var recoverySlotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var (ephemeralPublicKey, wrapped) = RecoverySlotWrap.Wrap(
            masterKey, recovery.PublicKey, KeyringFormat.KeyringFormatVersion, vaultId, k, recoverySlotId);
        slots.Add(new Slot(recoverySlotId, ephemeralPublicKey, wrapped, SlotKind.Recovery));
        return (new Keyring(KeyringFormat.KeyringFormatVersion, vaultId, k, slots), recovery.PrivateKey);
    }

    /// <summary>Unix ms of a stored time (records keep millisecond precision).</summary>
    private static long Ms(DateTime time) =>
        new DateTimeOffset(time.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(time, DateTimeKind.Utc) : time.ToUniversalTime()).ToUnixTimeMilliseconds();

    /// <summary>Step 2: what differs between the temp folder and the classic vault (empty: nothing).</summary>
    private static List<string> Verify(
        CommandContext ctx, string tempDir, Config newConfig, DirectoryOwnerMatcher owner, Keyring keyring,
        SecretsDb expected, byte[] key, byte[]? recoveryPrivateKey, bool checkSlots)
    {
        var problems = new List<string>();
        var reader = RecordVaultStore.ForFolder(tempDir, newConfig, owner);
        var warnings = new StringWriter();
        var readKeyring = reader.ReadKeyring();
        if (!KeyringCodec.Encode(readKeyring).AsSpan().SequenceEqual(KeyringCodec.Encode(keyring)))
            problems.Add("the keyring file differs from the keyring written");
        var actual = reader.LoadSecrets(key, warnings);
        if (ctx.MigrationSeams?.TamperReadBack is { } tamper)
            actual = tamper(actual);
        if (warnings.ToString().Length > 0)
            problems.Add("reading the records back gave warnings: " + warnings.ToString().Trim());

        foreach (var name in expected.Secrets.Keys.Except(actual.Secrets.Keys).Order(StringComparer.Ordinal))
            problems.Add($"'{name}' is missing");
        foreach (var name in actual.Secrets.Keys.Except(expected.Secrets.Keys).Order(StringComparer.Ordinal))
            problems.Add($"'{name}' appeared from nowhere");
        foreach (var (name, secret) in expected.Secrets.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            if (!actual.Secrets.TryGetValue(name, out var got))
                continue;
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(secret.Value)), SHA256.HashData(Encoding.UTF8.GetBytes(got.Value))))
                problems.Add($"'{name}' has a different value");
            if ((secret.BurnedAt != null) != (got.BurnedAt != null) || secret.BurnReason != got.BurnReason
                || (secret.BurnedAt is { } burned && got.BurnedAt is { } gotBurned && Ms(burned) != Ms(gotBurned)))
                problems.Add($"'{name}' has a different burned state");
            if (Ms(secret.Created) != Ms(got.Created))
                problems.Add($"'{name}' has a different creation time");
        }

        if (checkSlots)
        {
            foreach (var slot in readKeyring.Slots)
            {
                byte[] unwrapped;
                try
                {
                    if (slot.Kind == SlotKind.Recovery)
                    {
                        unwrapped = RecoveryKeyUnlock.Unlock(readKeyring with { Slots = [slot] }, recoveryPrivateKey!);
                    }
                    else
                    {
                        var blob = YubiKeySlotBlob.Decode(slot.HwBlob!);
                        var kekSlot = YubiKeySlotKek.Recover(ctx.YubiKeys, blob, slot.SlotId);
                        try
                        {
                            var payload = SlotPayloadWrap.Unwrap(slot.Wrapped, kekSlot, readKeyring.FormatVersion, readKeyring.VaultId, readKeyring.K, slot.SlotId);
                            unwrapped = SlotSecretPayload.Decode(payload).VaultKey;
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(kekSlot);
                        }
                    }
                }
                catch (Exception ex) when (ex is TswapException or CryptographicException)
                {
                    problems.Add($"slot {Convert.ToHexStringLower(slot.SlotId)[..8]} does not open: {ex.Message}");
                    continue;
                }
                if (!CryptographicOperations.FixedTimeEquals(unwrapped, key))
                    problems.Add($"slot {Convert.ToHexStringLower(slot.SlotId)[..8]} opens to a different key");
                CryptographicOperations.ZeroMemory(unwrapped);
            }
        }
        return problems;
    }
}
