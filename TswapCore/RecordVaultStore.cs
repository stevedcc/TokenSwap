using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCore.Fingerprints;
using TswapCore.Keyring;

namespace TswapCore;

/// <summary>
/// The per-secret record store (brief T6, issues #111-#114, #137): <see cref="Config.Store"/> =
/// <c>"records"</c>. The machine's <c>config.json</c> stays in the config dir with machine fields
/// only; the shareable <b>vault folder</b> (<see cref="Config.VaultDir"/>) holds <c>keyring</c>
/// (the <see cref="KeyringCodec"/> bytes) and <c>records/&lt;HMAC(K_names, name) hex&gt;</c>, one
/// file per secret (<see cref="SecretRecordCodec"/>).
/// <para>
/// Commands keep using <see cref="IVaultStore"/>'s whole-database calls: <see cref="LoadConfig"/>
/// composes <see cref="Config.Keyring"/> from the vault folder, <see cref="LoadSecrets"/> reads and
/// merges every record, and <see cref="SaveSecrets"/> writes only the records whose secret changed
/// (a value write, a tombstone for a removed name, or a burn), each with a fresh
/// <see cref="Hlc"/> stamp. Before each write it re-reads the file and refuses when it changed
/// since this command loaded it (decision 6).
/// </para>
/// <para>Every file goes through <see cref="DirectoryOwnerMatcher"/> (decision 10).</para>
/// <para>
/// Brief T16-S1: records are written in format 3 (a metadata section with keyed fingerprints plus
/// value sections encrypted once and then copied) once the vault folder holds the
/// <see cref="RecordFormatMarkerFileName"/> marker or this command read a format 3 record
/// (<see cref="WritesV3"/>), in format 2 before that, so older machines on the folder keep reading
/// it. Every copy of a record is merged in one <see cref="RecordMerge.MergeAll"/> step; a conflict
/// makes that one record unreadable, never the load. <see cref="LoadMetadata"/> reads metadata
/// sections only, for commands that need names, burns or fingerprints but no value.
/// </para>
/// </summary>
public sealed class RecordVaultStore : IFileVaultStore
{
    /// <summary>The <see cref="Config.Store"/> value that selects this store.</summary>
    public const string StoreName = "records";

    /// <summary>The keyring file's name in the vault folder.</summary>
    public const string KeyringFileName = "keyring";

    /// <summary>The records folder's name in the vault folder.</summary>
    public const string RecordsFolderName = "records";

    /// <summary>
    /// Brief T16-S1 (ruling 3): the vault folder's record-format marker. Holding <c>3</c>, every
    /// machine sharing the folder writes format 3 (it lives in the shared folder so they all see it
    /// through the same sync as the records). A higher number refuses every write (a newer tswap
    /// wrote the vault); anything else is a warning and counts as absent, so a sync artefact can't
    /// block all writes. Deleting it can't downgrade a reindexed vault: reading any format 3 record
    /// also selects format 3. Its conflicted copies are ignored.
    /// </summary>
    public const string RecordFormatMarkerFileName = "record-format";

    private readonly DirectoryOwnerMatcher _owner;
    private readonly TimeProvider _time;

    private Config? _machineConfig;
    private readonly bool _detached;
    private bool _modesChecked;
    private Hlc _highestSeen = Hlc.Zero;
    private Dictionary<string, LoadedRecord>? _loaded;
    private TextWriter? _warnings;
    private int? _markerFormat;
    private bool _sawV3;

    /// <param name="configDir">The machine's config dir (holds <c>config.json</c>).</param>
    /// <param name="owner">The file layer (null: <see cref="DirectoryOwnerMatcher.Default"/>).</param>
    /// <param name="time">The clock of HLC stamps and backup names (null: the system clock).</param>
    /// <param name="warnings">Where load-time findings go (conflicted copies, unreadable records); stderr in the CLI.</param>
    public RecordVaultStore(string configDir, DirectoryOwnerMatcher? owner = null, TimeProvider? time = null, TextWriter? warnings = null)
    {
        _warnings = warnings;
        ConfigDir = configDir;
        ConfigFile = Path.Combine(configDir, "config.json");
        SecretsFile = Path.Combine(configDir, "secrets.json.enc");
        _owner = owner ?? DirectoryOwnerMatcher.Default;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>
    /// Brief T6 decision 8: a store over a bare vault folder with an in-memory machine config (no
    /// <c>config.json</c> is read or written): <c>migrate --to-records</c> fills its temp folder
    /// and reads it back through one.
    /// </summary>
    public static RecordVaultStore ForFolder(string vaultDir, Config machineConfig, DirectoryOwnerMatcher? owner = null, TimeProvider? time = null)
    {
        var store = new RecordVaultStore(Path.GetFullPath(vaultDir), owner, time, detached: true);
        store._machineConfig = machineConfig with { Keyring = null, Store = StoreName, VaultDir = Path.GetFullPath(vaultDir) };
        return store;
    }

    private RecordVaultStore(string vaultDir, DirectoryOwnerMatcher? owner, TimeProvider? time, bool detached)
        : this(vaultDir, owner, time)
    {
        _detached = detached;
    }

    public string ConfigDir { get; }

    /// <inheritdoc/>
    public DirectoryOwnerMatcher Owner => _owner;

    public string ConfigFile { get; }

    /// <summary>The classic store's file (absent once a vault is a record store).</summary>
    public string SecretsFile { get; }

    /// <summary>The vault folder, from the loaded config.</summary>
    public string VaultDir => _detached ? ConfigDir : Path.GetFullPath(MachineConfig.VaultDir
        ?? throw new TswapException("Config is corrupted: a record store needs VaultDir. Restore config.json from backup."));

    /// <summary>The keyring file in the vault folder.</summary>
    public string KeyringFile => Path.Combine(VaultDir, KeyringFileName);

    /// <summary>The records folder in the vault folder.</summary>
    public string RecordsDir => Path.Combine(VaultDir, RecordsFolderName);

    /// <summary>
    /// Test seam (brief T8): called with a record file's name each time one is decrypted (a format 2
    /// payload, or a format 3 metadata section).
    /// </summary>
    internal Action<string>? RecordDecrypted { get; set; }

    /// <summary>
    /// Test seam (brief T16-S1): called with the record's file name and the version stamp for every
    /// value decrypted (a format 3 value section, or a value inside a format 2 payload).
    /// </summary>
    internal Action<string, Stamp>? ValueDecrypted { get; set; }

    /// <summary>Test seam (brief T16-S1): called after each record a write writes (the reindex crash test).</summary>
    internal Action? AfterRecordWritten { get; set; }

    /// <summary>Test seam (brief T16-S1): the value sections <see cref="LoadMetadata"/> chose, by record file name.</summary>
    internal IReadOnlyDictionary<string, IReadOnlyDictionary<Stamp, byte[]>>? MetadataSections { get; private set; }

    /// <summary>
    /// Brief T16-S1 (ruling 3), evaluated after a load: true when the vault folder's
    /// <see cref="RecordFormatMarkerFileName"/> holds 3, or this command read a format 3 record (from
    /// this folder, or, in <c>vault merge</c>, from the other copy), so a deleted marker can't
    /// silently downgrade a reindexed vault. Writes are then format 3, otherwise format 2.
    /// </summary>
    public bool WritesV3 => _markerFormat == KeyringFormat.RecordFormatVersion || _sawV3;

    /// <summary>The marker file in the vault folder.</summary>
    public string RecordFormatMarkerFile => Path.Combine(VaultDir, RecordFormatMarkerFileName);

    /// <summary>Test seam: removes a redundant conflicted copy (default: through the file layer).</summary>
    internal Action<string>? DeleteFile { get; init; }

    private Config MachineConfig => _machineConfig ?? ReadMachineConfig();

    public string BackupConfig() => FileBackup.Copy(ConfigFile, _time.GetUtcNow().UtcDateTime, _owner);

    public void WriteFile(string path, string contents) => _owner.WriteAtomic(path, Encoding.UTF8.GetBytes(contents));

    // ---------------------------------------------------------------- config + keyring

    public Config LoadConfig()
    {
        var config = ReadMachineConfig();
        var keyring = ReadKeyring();
        return config with { Keyring = Convert.ToBase64String(KeyringCodec.Encode(keyring)) };
    }

    public void SaveConfig(Config config)
    {
        if (config.Store != StoreName)
            throw new TswapException(
                $"This machine's {ConfigFile} belongs to a shared record-store vault ({MachineConfig.VaultDir}), so it can't be " +
                "replaced by another kind of vault here. To set up a different vault, use another config folder " +
                "(TSWAP_CONFIG_DIR) or move config.json aside first.");
        // Fix round 1 (C): the max with what is on disk now, which another process may have moved on.
        var onDisk = TryReadMachineConfig();
        _machineConfig ??= onDisk;
        var lastHlc = Hlc.Max(Hlc.Max(Hlc.TryParse(config.LastHlc) ?? Hlc.Zero, Hlc.TryParse(_machineConfig?.LastHlc) ?? Hlc.Zero),
            Hlc.TryParse(onDisk?.LastHlc) ?? Hlc.Zero);
        var machine = config with { Keyring = null, LastHlc = lastHlc == Hlc.Zero ? config.LastHlc : lastHlc.ToString() };
        _machineConfig = machine;
        if (config.Keyring is not null)
            WriteKeyring(DecodeKeyring(config.Keyring, "the config to save"));
        WriteMachineConfig(machine);
    }

    private Config ReadMachineConfig()
    {
        if (_detached)
            return _machineConfig!;
        var config = TryReadMachineConfig() ?? throw new TswapException("Not initialized. Run: tswap init");
        if (config.Store != StoreName)
            throw new TswapException($"{ConfigFile} is not a record store's config (Store is not \"{StoreName}\").");
        if (config.Keyring is not null)
            throw new TswapException(
                $"{ConfigFile} is a record store's config but carries its own Keyring; the keyring lives in the vault folder " +
                "only. Restore config.json from backup.");
        _machineConfig = config;
        return config;
    }

    private Config? TryReadMachineConfig()
    {
        if (_detached)
            return _machineConfig;
        if (!_owner.FileExists(ConfigFile))
            return null;
        using var reader = new StreamReader(new MemoryStream(_owner.ReadAllBytes(ConfigFile)), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return JsonSerializer.Deserialize(reader.ReadToEnd(), TswapJsonContext.Default.Config)
            ?? throw new TswapException("Invalid config");
    }

    private void WriteMachineConfig(Config machine)
    {
        if (_detached)
        {
            _machineConfig = machine;
            return;
        }
        TightenModes();
        _owner.CreateDirectory(ConfigDir);
        _owner.WriteAtomic(ConfigFile, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(machine, TswapJsonContext.Default.Config)));
    }

    /// <summary>
    /// Reads the vault folder's keyring (decision 2): the <c>keyring</c> file plus the sync tools'
    /// conflicted copies of it, as a union. A copy that can't be decoded is a warning (it is kept,
    /// never used or deleted); a copy of another vault, or one slot id with different bytes, is
    /// refused.
    /// </summary>
    public Keyring.Keyring ReadKeyring() => ReadKeyringWithCopies().Keyring;

    private (Keyring.Keyring Keyring, List<(string Path, byte[] Bytes)> FoldedCopies) ReadKeyringWithCopies()
    {
        var path = KeyringFile;
        if (!_owner.FileExists(path))
            throw new TswapException(
                $"The vault folder {VaultDir} has no keyring file. If it is synced, wait for the sync to finish; " +
                "otherwise restore the folder from a backup.");
        var keyring = DecodeKeyringBytes(_owner.ReadAllBytes(path), path);
        List<(string, byte[])> folded = [];
        var vaultDir = VaultDir;
        var copies = _owner.AsOwner(vaultDir, () => RecordDirectoryScanner.FindConflictCopies(new DirectoryInfo(vaultDir), KeyringFileName));
        foreach (var copy in copies)
        {
            var copyPath = Path.Combine(vaultDir, copy.ConflictingFilename);
            byte[] bytes;
            Keyring.Keyring copyKeyring;
            try
            {
                bytes = _owner.ReadAllBytes(copyPath);
                copyKeyring = KeyringCodec.Decode(bytes);
            }
            catch (Exception ex) when (ex is TswapException or IOException or UnauthorizedAccessException)
            {
                _warnings?.WriteLine(
                    $"Warning: {copy.ConflictingFilename} ({ToolName(copy.Tool)} conflicted copy of the keyring) can't be read " +
                    $"({ex.Message}); it is kept and not used.");
                continue;
            }
            keyring = KeyringUnion.Union(keyring, copyKeyring, $"the keyring's conflicted copy {copy.ConflictingFilename}");
            folded.Add((copyPath, bytes));
        }
        return (keyring, folded);
    }

    /// <summary>
    /// Writes the keyring as the union of <paramref name="keyring"/> and what is on disk now
    /// (decision 2: a save never drops a slot it didn't know about), atomically and durably. The
    /// conflicted copies folded into it are then redundant and removed (a failed removal is a
    /// warning).
    /// </summary>
    private void WriteKeyring(Keyring.Keyring keyring)
    {
        List<(string Path, byte[] Bytes)> folded = [];
        if (_owner.FileExists(KeyringFile))
        {
            var (onDisk, copies) = ReadKeyringWithCopies();
            KeyringUnion.RequireSameVault(onDisk, keyring, "The keyring to save");
            keyring = KeyringUnion.Union(onDisk, keyring, "the keyring to save");
            folded = copies;
        }
        TightenModes();
        _owner.CreateDirectory(VaultDir);
        _owner.WriteDurable(KeyringFile, KeyringCodec.Encode(keyring));
        RemoveRedundantCopies(folded);
    }

    /// <summary>
    /// Removes conflicted copies whose content is now part of what was just written, if they are
    /// still byte-identical to what was read; a failure (a sync tool or Windows holding the file)
    /// is a warning, never a failed write.
    /// </summary>
    private void RemoveRedundantCopies(IEnumerable<(string Path, byte[] Bytes)> copies)
    {
        foreach (var (path, bytes) in copies)
        {
            try
            {
                var now = _owner.FileExists(path) ? _owner.ReadAllBytes(path) : null;
                if (now is null)
                    continue;
                if (!now.AsSpan().SequenceEqual(bytes))
                {
                    _warnings?.WriteLine($"Warning: {Path.GetFileName(path)} changed while this command ran; it was not removed.");
                    continue;
                }
                (DeleteFile ?? _owner.Delete)(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TswapException)
            {
                _warnings?.WriteLine($"Warning: could not remove the redundant conflicted copy {Path.GetFileName(path)} ({ex.Message}); remove it by hand.");
            }
        }
    }

    private static string ToolName(SyncConflictTool tool) => tool switch
    {
        SyncConflictTool.DropboxOrGoogleDrive => "Dropbox / Google Drive",
        SyncConflictTool.OneDrive => "OneDrive",
        _ => "Syncthing",
    };

    private static Keyring.Keyring DecodeKeyring(string base64, string what)
    {
        try
        {
            return KeyringCodec.Decode(Convert.FromBase64String(base64));
        }
        catch (FormatException)
        {
            throw new TswapException($"Keyring in {what} is not valid base64.");
        }
    }

    private static Keyring.Keyring DecodeKeyringBytes(byte[] bytes, string path)
    {
        try
        {
            return KeyringCodec.Decode(bytes);
        }
        catch (TswapException ex)
        {
            throw new TswapException($"The keyring file {path} can't be read: {ex.Message}. Restore it from a backup or another copy.");
        }
    }

    // ---------------------------------------------------------------- records

    /// <summary>One record file as this command loaded it.</summary>
    /// <param name="FileName">The record's hashed file name.</param>
    /// <param name="MainBytes">The main file's bytes as read (null: absent); the stale-write guard compares against them.</param>
    /// <param name="State">The merged state of the main file and its readable conflicted copies (null: absent or unreadable).</param>
    /// <param name="UnreadableReason">Why the main file can't be read (fail closed), or null.</param>
    /// <param name="FoldedCopies">The conflicted copies merged into <paramref name="State"/>: redundant once it is written.</param>
    /// <param name="MainState">The main file alone, decoded (null: absent or unreadable): its sections decide whether a merge must write.</param>
    /// <param name="Inputs">Every decoded copy merged into <paramref name="State"/> (main first): <c>vault merge</c> merges the incoming state with all of them at once.</param>
    private sealed record LoadedRecord(
        string FileName, byte[]? MainBytes, SecretRecord? State, string? UnreadableReason,
        IReadOnlyList<(string Path, byte[] Bytes)>? FoldedCopies = null, SecretRecord? MainState = null,
        IReadOnlyList<SecretRecord>? Inputs = null);

    public SecretsDb LoadSecrets(byte[] key, TextWriter? warnings = null)
    {
        warnings ??= _warnings;
        _warnings = warnings;
        var loaded = LoadRecords(key, warnings);
        Dictionary<string, Secret> secrets = [];
        foreach (var record in loaded.Values)
        {
            if (record.State is not { Type: not RecordType.Tombstone } state)
                continue;
            secrets[state.Name] = ToSecret(state);
        }
        var unreadable = loaded.Values.Where(r => r.UnreadableReason is not null).Select(r => r.FileName).ToHashSet(StringComparer.Ordinal);
        var namesKey = RecordKeyDerivation.DeriveNamesKey(key);
        return new SecretsDb(secrets)
        {
            KeepsPreviousValues = true,
            UnreadableFiles = unreadable.Count == 0 ? null : unreadable.Order(StringComparer.Ordinal).ToList(),
            UnreadableRecord = unreadable.Count == 0
                ? null
                : name =>
                {
                    var file = FilenameHasher.ComputeFilename(namesKey, name);
                    return unreadable.Contains(file) ? file : null;
                },
        };
    }

    /// <summary>
    /// Brief T8 (owner decision, fix round 1): the current value of ONE secret, decrypting only its
    /// record (<c>records/HMAC(K_names, name)</c>) and that record's sync-conflict copies, folded by
    /// the merge rules; no other record is read. Returns null when the secret doesn't exist (no
    /// record, or a tombstone), or <paramref name="previous"/> is asked and there is no previous
    /// value. A record that can't be read or authenticated, or whose copies can't be merged, is a
    /// <see cref="TswapException"/> (fail closed). Keys are zeroed before returning, and every value
    /// byte array except the copy returned (the caller zeroes that).
    /// <para>
    /// Brief T16-S1: when every file of the record is format 3, only the metadata sections and the
    /// one value section asked for are decrypted (the current value, or with
    /// <paramref name="previous"/> the value a rotation replaced, for a <c>name:previous</c> token),
    /// and the copies are folded on the metadata path (<see cref="RecordMerge.MergeAllMetadata"/>).
    /// A format 2 file has no separate sections, so such a record is decoded whole and merged by
    /// <see cref="RecordMerge.MergeAll"/>, as before.
    /// </para>
    /// </summary>
    public byte[]? ReadSecretValue(string name, byte[] vaultKey, bool previous = false)
    {
        var namesKey = RecordKeyDerivation.DeriveNamesKey(vaultKey);
        string fileName;
        try
        {
            fileName = FilenameHasher.ComputeFilename(namesKey, name);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(namesKey);
        }
        var recordsDir = RecordsDir;
        if (!_owner.AsOwner(recordsDir, () => Directory.Exists(recordsDir)))
            return null;
        var mainPath = Path.Combine(recordsDir, fileName);
        var copies = _owner.AsOwner(recordsDir, () => RecordDirectoryScanner.Scan(recordsDir)).Conflicts
            .Where(c => c.RecordFilename == fileName)
            .OrderBy(c => c.ConflictingFilename, StringComparer.Ordinal)
            .ToList();
        var mainExists = _owner.FileExists(mainPath);
        if (!mainExists && copies.Count == 0)
            return null;

        List<(string File, byte[] Bytes, bool IsMain)> files = [];
        var allV3 = true;
        try
        {
            if (mainExists)
                files.Add((fileName, _owner.ReadAllBytes(mainPath), true));
            foreach (var copy in copies)
                files.Add((copy.ConflictingFilename, _owner.ReadAllBytes(Path.Combine(recordsDir, copy.ConflictingFilename)), false));
            allV3 = files.All(f => SecretRecordCodec.FormatVersionOf(f.Bytes) == KeyringFormat.RecordFormatVersion);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TswapException)
        {
            allV3 = false; // the full path reports what can't be read, as it always has
        }
        return allV3
            ? ReadValueFromMetadata(name, fileName, files, vaultKey, previous)
            : ReadValueFull(name, fileName, copies, mainExists, vaultKey, previous);
    }

    private byte[]? ReadValueFull(string name, string fileName, List<ConflictWarning> copies, bool mainExists, byte[] vaultKey, bool previous)
    {
        LoadedRecord? main = mainExists ? ReadRecord(fileName, vaultKey) : null;
        using (var fingerprintKeys = FingerprintKeys.Derive(vaultKey))
            main = FoldConflictCopies(fileName, copies, main, vaultKey, fingerprintKeys, _warnings);
        if (main.UnreadableReason is { } reason)
            throw new TswapException($"The record of '{name}' can't be read ({reason}).");
        if (main.State is not { } state)
            throw new TswapException($"The record of '{name}' can't be read (no readable copy).");
        try
        {
            if (state.Type == RecordType.Tombstone)
                return null;
            var value = previous ? state.Previous?.Value : state.Value;
            return value is null ? null : (byte[])value.Clone();
        }
        finally
        {
            foreach (var record in (main.Inputs ?? []).Append(state))
            {
                CryptographicOperations.ZeroMemory(record.Value);
                if (record.Previous is { } p)
                    CryptographicOperations.ZeroMemory(p.Value);
            }
        }
    }

    private byte[]? ReadValueFromMetadata(string name, string fileName, List<(string File, byte[] Bytes, bool IsMain)> files, byte[] vaultKey, bool previous)
    {
        List<(RecordMetadata, IReadOnlyDictionary<Stamp, byte[]>)> inputs = [];
        foreach (var (file, bytes, isMain) in files)
        {
            try
            {
                RecordDecrypted?.Invoke(file);
                var decoded = SecretRecordCodec.DecodeMetadataAndSections(bytes, vaultKey)
                    ?? throw new TswapException("it is not a format 3 record");
                if (FilenameHasher.ToFilename(decoded.Metadata.RecordId) != fileName)
                    throw new TswapException(isMain ? "its record id does not match its file name" : "its record id belongs to another record");
                inputs.Add(decoded);
            }
            catch (Exception ex) when (ex is TswapException or CryptographicException)
            {
                var reason = ex is CryptographicException ? "it fails authentication" : ex.Message;
                if (isMain)
                    throw new TswapException($"The record of '{name}' can't be read ({reason}).");
                _warnings?.WriteLine(
                    $"Warning: {file} (conflicted copy of record {fileName}) can't be used ({reason}). " +
                    "It is kept as it is and never chosen; remove it once you no longer need it.");
            }
        }
        if (inputs.Count == 0)
            throw new TswapException($"The record of '{name}' can't be read (no readable copy).");

        RecordMetadata metadata;
        IReadOnlyDictionary<Stamp, byte[]> sections;
        try
        {
            (metadata, sections) = RecordMerge.MergeAllMetadata(inputs);
        }
        catch (RecordConflictException ex)
        {
            throw new TswapException(
                $"The record of '{name}' can't be read: its copies can't be merged ({ex.Message}). Remove the damaged conflicted copy.");
        }
        if (metadata.Type == RecordType.Tombstone)
            return null;
        var version = previous ? metadata.PreviousVersion : metadata.Version;
        if (version is null)
            return null;
        var fingerprints = previous ? metadata.PreviousFingerprints : metadata.Fingerprints;

        ValueDecrypted?.Invoke(fileName, version);
        byte[] value;
        try
        {
            value = SecretRecordCodec.OpenSealed(metadata.RecordId, version, sections[version], vaultKey);
        }
        catch (Exception ex) when (ex is TswapException or CryptographicException)
        {
            throw new TswapException(
                $"The record of '{name}' can't be read ({(ex is CryptographicException ? "a value section fails authentication" : ex.Message)}).");
        }
        // The one plaintext at hand is checked against its stored fingerprints, as a full load checks
        // every copy (ruling 11, validation per input).
        if (fingerprints is { } stored && stored.VariantSetVersion == SecretVariants.CurrentSetVersion)
        {
            using var fingerprintKeys = FingerprintKeys.Derive(vaultKey);
            if (!Fingerprinter.Compute(value, fingerprintKeys).Equals(stored))
            {
                CryptographicOperations.ZeroMemory(value);
                throw new TswapException($"The record of '{name}' can't be read (its fingerprints don't match its value).");
            }
        }
        return value;
    }

    private static Secret ToSecret(SecretRecord state)
    {
        var outstanding = state.OutstandingBurn;
        var history = state.Burns
            .Where(b => !ReferenceEquals(b, outstanding))
            .OrderBy(b => b.Burn)
            .Select(b => new PastBurn(Hlc.ToDisplayDate(b.Burn.Hlc.PhysicalMs), b.Reason))
            .ToList();
        return new Secret(
            Encoding.UTF8.GetString(state.Value),
            Hlc.ToDisplayDate(state.CreatedMs),
            Hlc.ToDisplayDate(state.Version.Hlc.PhysicalMs),
            outstanding is null ? null : Hlc.ToDisplayDate(outstanding.Burn.Hlc.PhysicalMs),
            outstanding?.Reason)
        {
            History = history.Count == 0 ? null : history,
            PreviousValue = state.Previous is null ? null : Encoding.UTF8.GetString(state.Previous.Value),
            PreviousBurned = state.Previous is not null && state.Burns.Any(b => b.Version.Equals(state.Previous.Version)),
        };
    }

    private Dictionary<string, LoadedRecord> LoadRecords(byte[] key, TextWriter? warnings)
    {
        _highestSeen = Hlc.TryParse(MachineConfig.LastHlc) ?? Hlc.Zero;
        _sawV3 = false;
        ReadMarker(warnings);
        var loaded = new Dictionary<string, LoadedRecord>(StringComparer.Ordinal);
        var recordsDir = RecordsDir;
        if (!_owner.AsOwner(recordsDir, () => Directory.Exists(recordsDir)))
        {
            _loaded = loaded;
            return loaded;
        }

        // Do NOT order by filesystem mtime anywhere here: sync tools rewrite it freely. The only
        // ordering authority is the (HLC, origin) stamp inside each record.
        var scan = _owner.AsOwner(recordsDir, () => RecordDirectoryScanner.Scan(recordsDir));
        var mains = scan.ValidRecordFilenames.ToHashSet(StringComparer.Ordinal);
        var copiesByRecord = scan.Conflicts.GroupBy(c => c.RecordFilename, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.OrderBy(c => c.ConflictingFilename, StringComparer.Ordinal).ToList(), StringComparer.Ordinal);
        using (var fingerprintKeys = FingerprintKeys.Derive(key))
        {
            foreach (var fileName in mains.Concat(copiesByRecord.Keys).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
            {
                var main = mains.Contains(fileName) ? ReadRecord(fileName, key) : null;
                loaded[fileName] = FoldConflictCopies(fileName, copiesByRecord.GetValueOrDefault(fileName) ?? [], main, key, fingerprintKeys, warnings);
            }
        }

        foreach (var record in loaded.Values.Where(r => r.UnreadableReason is not null))
            warnings?.WriteLine(
                $"Warning: record {record.FileName} can't be read ({record.UnreadableReason}). Its secret is kept as " +
                "present but unknown: commands that need it stop, and nothing overwrites or deletes it. Restore the file " +
                "from a backup or another copy, or wait for the sync to finish.");
        var unreadableCount = loaded.Values.Count(r => r.UnreadableReason is not null);
        if (unreadableCount > 0)
            warnings?.WriteLine($"Warning: {unreadableCount} unreadable record(s) in {recordsDir}.");

        // Decision 3, absurd stamps: accepted (merge needs a total order) but reported.
        var nowMs = _time.GetUtcNow().ToUnixTimeMilliseconds();
        const long year = 365L * 24 * 60 * 60 * 1000;
        var yearAhead = nowMs > long.MaxValue - year ? long.MaxValue : nowMs + year;
        foreach (var record in loaded.Values.Where(r => r.State is not null && MaxPhysical(r.State) > yearAhead))
            warnings?.WriteLine(
                $"Warning: record {record.FileName} carries a time stamp more than a year ahead of this machine's clock " +
                "(a machine with a wrong clock wrote it). It still orders correctly; check that machine's clock.");

        _loaded = loaded;
        return loaded;
    }

    private static long MaxPhysical(SecretRecord state) =>
        state.Burns.Select(b => b.Burn.Hlc.PhysicalMs).Append(state.Write.Hlc.PhysicalMs).Append(state.Version.Hlc.PhysicalMs).Max();

    /// <summary>
    /// Decision 4: folds a record's sync-conflict copies into its main file by the merge rules. A
    /// copy that can't be decrypted or authenticated is a warning and is never chosen or deleted. A
    /// main file that can't be read stays unreadable (fail closed): its copies are not used, since
    /// the main file may hold the newest version.
    /// <para>
    /// Brief T16-S1 (ruling 11): every decoded copy (the main file first) is validated
    /// (<see cref="RecordMerge.ValidateFingerprints"/>) and all of them are merged in one
    /// <see cref="RecordMerge.MergeAll"/> call. A conflict there makes the <b>record</b> unreadable
    /// (warned, never merged or overwritten; the main file's bytes are kept for the stale-write
    /// guard). It is deliberately handled apart from the per-copy decode failures below, which only
    /// mean "this copy can't be used" and leave the record readable.
    /// </para>
    /// </summary>
    private LoadedRecord FoldConflictCopies(
        string fileName, List<ConflictWarning> copies, LoadedRecord? main, byte[] key, FingerprintKeys fingerprintKeys, TextWriter? warnings)
    {
        main ??= new LoadedRecord(fileName, null, null, null);
        List<SecretRecord> inputs = main.State is null ? [] : [main.State];
        List<(string Path, byte[] Bytes)> folded = [];
        foreach (var copy in copies)
        {
            var path = Path.Combine(RecordsDir, copy.ConflictingFilename);
            var tool = ToolName(copy.Tool);
            byte[] bytes;
            SecretRecord copyState;
            try
            {
                bytes = _owner.ReadAllBytes(path);
                copyState = DecodeFull(copy.ConflictingFilename, bytes, key);
                if (FilenameHasher.ToFilename(copyState.RecordId) != fileName)
                    throw new TswapException("its record id belongs to another record");
            }
            catch (Exception ex) when (ex is TswapException or CryptographicException or IOException or UnauthorizedAccessException)
            {
                var reason = ex is CryptographicException ? "it can't be decrypted or authenticated" : ex.Message;
                warnings?.WriteLine(
                    $"Warning: {copy.ConflictingFilename} ({tool} conflicted copy of record {fileName}) can't be used ({reason}). " +
                    "It is kept as it is and never chosen; remove it once you no longer need it.");
                continue;
            }
            ObserveAll(copyState);
            if (main.UnreadableReason is not null)
                continue;
            warnings?.WriteLine(
                $"Note: record {fileName} has a {tool} conflicted copy ({copy.ConflictingFilename}): version {copyState.Version} " +
                $"vs {(main.State is null ? "no main file" : $"version {main.State.Version}")}. Combined by the merge rules; the copy is " +
                "removed the next time this record is written.");
            inputs.Add(copyState);
            folded.Add((path, bytes));
        }
        if (main.UnreadableReason is not null || inputs.Count == 0)
            return main with { FoldedCopies = folded };

        // Outside the per-copy catch above: a conflict is about the record, not one copy.
        try
        {
            foreach (var input in inputs)
                RecordMerge.ValidateFingerprints(input, fingerprintKeys);
            return main with { State = RecordMerge.MergeAll(inputs), FoldedCopies = folded, MainState = main.State, Inputs = inputs };
        }
        catch (RecordConflictException ex)
        {
            return main with
            {
                State = null,
                UnreadableReason = $"its copies can't be merged: {ex.Message}; remove the damaged conflicted copy",
                FoldedCopies = null,
                MainState = main.State,
                Inputs = null,
            };
        }
    }

    private LoadedRecord ReadRecord(string fileName, byte[] key)
    {
        var path = Path.Combine(RecordsDir, fileName);
        byte[] bytes;
        try
        {
            bytes = _owner.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is TswapException or IOException or UnauthorizedAccessException)
        {
            return new LoadedRecord(fileName, null, null, ex.Message);
        }
        // Fix round 1 (A1): stamps move this machine's clock only once the record authenticates
        // (ObserveAll below); a planted header could otherwise push LastHlc anywhere.
        try
        {
            var state = DecodeFull(fileName, bytes, key);
            if (FilenameHasher.ToFilename(state.RecordId) != fileName)
                return new LoadedRecord(fileName, bytes, null, "its record id does not match its file name");
            ObserveAll(state);
            return new LoadedRecord(fileName, bytes, state, null, MainState: state);
        }
        catch (Exception ex) when (ex is TswapException or CryptographicException)
        {
            return new LoadedRecord(fileName, bytes, null, ex is CryptographicException ? "it fails authentication" : ex.Message);
        }
    }

    /// <summary>
    /// Decodes a whole record file (every value it holds), noting a format 3 file for
    /// <see cref="WritesV3"/> and reporting the decryptions to the test seams.
    /// </summary>
    private SecretRecord DecodeFull(string file, byte[] bytes, byte[] key)
    {
        if (SecretRecordCodec.FormatVersionOf(bytes) == KeyringFormat.RecordFormatVersion)
            _sawV3 = true;
        RecordDecrypted?.Invoke(file);
        var state = SecretRecordCodec.Decode(bytes, key);
        if (ValueDecrypted is { } seam)
        {
            if (state.Type != RecordType.Tombstone)
                seam(file, state.Version);
            if (state.Previous is { } previous)
                seam(file, previous.Version);
        }
        return state;
    }

    /// <summary>
    /// Ruling 3: reads the vault folder's <see cref="RecordFormatMarkerFileName"/> (a UTF-8 BOM and
    /// surrounding whitespace, CR/LF included, are ignored). A number of 3 or more is kept; anything
    /// else is a warning with a repair hint and counts as absent.
    /// </summary>
    private void ReadMarker(TextWriter? warnings)
    {
        _markerFormat = null;
        var path = RecordFormatMarkerFile;
        if (!_owner.FileExists(path))
            return;
        string text;
        try
        {
            ReadOnlySpan<byte> bytes = _owner.ReadAllBytes(path);
            if (bytes.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
                bytes = bytes[3..];
            text = Encoding.UTF8.GetString(bytes).Trim();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TswapException)
        {
            warnings?.WriteLine($"Warning: the vault folder's {RecordFormatMarkerFileName} marker can't be read ({ex.Message}); it is ignored.");
            return;
        }
        if (int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var format) && format >= KeyringFormat.RecordFormatVersion)
        {
            _markerFormat = format;
            return;
        }
        warnings?.WriteLine(
            $"Warning: the vault folder's {RecordFormatMarkerFileName} marker ({path}) doesn't hold a record format this tswap " +
            "understands, so it is ignored (records are written in format 2 unless a format 3 record is read). If this vault " +
            "was reindexed, write 3 into it; otherwise delete it.");
    }

    /// <summary>
    /// Ruling 3: the record format the vault folder's marker names (3, or a newer one), or null when
    /// it is absent or not understood (warned about on <paramref name="warnings"/>). Reads only.
    /// </summary>
    public int? ReadFormatMarker(TextWriter? warnings = null)
    {
        ReadMarker(warnings ?? _warnings);
        return _markerFormat;
    }

    /// <summary>
    /// Ruling 3: writes the vault folder's marker (<c>3</c>) through the file layer (as the folder's
    /// owner, mode 0600, atomically and durably). From then on every machine sharing the folder
    /// writes format 3. <c>vault reindex</c> writes it after every record succeeded; <c>init</c> and
    /// <c>migrate --to-records</c> create new vaults with it; <c>vault merge</c> copies it from a
    /// reindexed copy.
    /// </summary>
    public void WriteFormatMarker()
    {
        TightenModes();
        _owner.CreateDirectory(VaultDir);
        _owner.WriteDurable(RecordFormatMarkerFile, Encoding.UTF8.GetBytes($"{KeyringFormat.RecordFormatVersion}\n"));
        _markerFormat = KeyringFormat.RecordFormatVersion;
    }

    /// <summary>
    /// Brief T16-S1 (<c>sudo tswap vault reindex</c>): rewrites every record that isn't already
    /// current as format 3 with fingerprints, each with a new write stamp, so it merges like any other
    /// write; tombstones become format 3 metadata-only records. A record is current (ruling 9) when its
    /// main file is format 3, it has no conflicted copies, its retained values carry fingerprint sets of
    /// this build's variant-set version (or newer), and its merged state and sections equal the main
    /// file's: anything else is rewritten, which also folds a lingering format 2 copy and converges two
    /// machines' sections. Value sections are copied where they exist; a value read from format 2 is
    /// sealed now. Refuses before writing anything when a record can't be read. The marker is written
    /// last, so "marker present" means a reindex finished once; a run interrupted midway is finished by
    /// running it again (the records already rewritten are current by then).
    /// </summary>
    public ReindexResult Reindex(byte[] vaultKey)
    {
        var loaded = LoadRecords(vaultKey, _warnings);
        if (_markerFormat > KeyringFormat.RecordFormatVersion)
            throw NewerFormatMarker();
        var unreadable = loaded.Values.Where(r => r.UnreadableReason is not null).Select(r => r.FileName).Order(StringComparer.Ordinal).ToList();
        if (unreadable.Count > 0)
            throw new TswapException(
                $"Refusing to reindex: {unreadable.Count} record(s) can't be read ({string.Join(", ", unreadable)}). Restore each from a " +
                "backup or another copy, wait for the sync to finish, or delete it, then run the reindex again. Nothing was written.");

        List<(string FileName, SecretRecord State)> writes = [];
        int alreadyCurrent = 0, tombstones = 0;
        foreach (var record in loaded.Values.OrderBy(r => r.FileName, StringComparer.Ordinal))
        {
            if (record.State is not { } state)
                continue; // no main file and no usable copy: nothing to rewrite
            if (state.Type == RecordType.Tombstone)
                tombstones++;
            if (IsCurrent(record))
            {
                alreadyCurrent++;
                continue;
            }
            writes.Add((record.FileName, state));
        }
        WriteRecords(writes, vaultKey, loaded, reindex: true);
        if (_markerFormat != KeyringFormat.RecordFormatVersion)
            WriteFormatMarker();
        return new ReindexResult(writes.Count, alreadyCurrent, tombstones);
    }

    /// <summary>Ruling 9: a record <see cref="Reindex"/> leaves as it is.</summary>
    private static bool IsCurrent(LoadedRecord record)
    {
        if (record.FoldedCopies is { Count: > 0 } || record.MainBytes is null || record.MainState is not { } main || record.State is not { } state)
            return false;
        if (SecretRecordCodec.FormatVersionOf(record.MainBytes) != KeyringFormat.RecordFormatVersion)
            return false;
        if (!state.SameState(main) || !SameSections(state.Sealed, main.Sealed))
            return false;
        if (state.Type == RecordType.Tombstone)
            return true;
        return CurrentSet(state.Fingerprints) && (state.Previous is null || CurrentSet(state.Previous.Fingerprints));

        static bool CurrentSet(FingerprintSet? set) => set is not null && set.VariantSetVersion >= SecretVariants.CurrentSetVersion;
    }

    private TswapException NewerFormatMarker() => new(
        $"This vault folder was written by a newer tswap: its {RecordFormatMarkerFileName} marker says record format " +
        $"{_markerFormat}, and this build writes formats {KeyringFormat.RecordFormatVersionV2} and {KeyringFormat.RecordFormatVersion} " +
        "only. Upgrade tswap before changing this vault; nothing was written.");

    private void Observe(Hlc hlc) => _highestSeen = Hlc.Max(_highestSeen, hlc);

    private void ObserveAll(SecretRecord state)
    {
        Observe(state.Write.Hlc);
        Observe(state.Version.Hlc);
        foreach (var burn in state.Burns)
            Observe(burn.Burn.Hlc);
    }

    public void SaveSecrets(SecretsDb db, byte[] key)
    {
        var loaded = _loaded ?? LoadRecords(key, _warnings);
        // Fix round 2: a secret missing from the database passed in becomes a tombstone. One per save
        // is a 'delete'; more looks like an empty or partial database being saved by mistake, which
        // would delete the shared vault, so it is refused before anything is written.
        var missing = loaded.Values.Count(r => r.State is { Type: not RecordType.Tombstone } s && !db.Secrets.ContainsKey(s.Name));
        if (missing > 1)
            throw new TswapException(
                $"Refusing to save: this would delete {missing} secrets at once, which looks like an empty or partial database " +
                "being saved, not a deliberate delete. Nothing was written. Delete secrets one at a time with 'sudo tswap delete <name>'.");

        var origin = OriginId();
        var namesKey = RecordKeyDerivation.DeriveNamesKey(key);
        List<(string FileName, SecretRecord State)> writes = [];

        Stamp NextStamp()
        {
            var hlc = Hlc.Next(_highestSeen, _time.GetUtcNow().ToUnixTimeMilliseconds());
            _highestSeen = hlc;
            return new Stamp(hlc, origin);
        }

        foreach (var (name, secret) in db.Secrets.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var fileName = FilenameHasher.ComputeFilename(namesKey, name);
            loaded.TryGetValue(fileName, out var current);
            if (current?.UnreadableReason is not null)
                throw Unreadable(name, fileName);
            var state = current?.State;
            var value = Encoding.UTF8.GetBytes(secret.Value);
            SecretRecord? next = null;
            if (state is null || state.Type == RecordType.Tombstone || secret.Rotated || !state.Value.AsSpan().SequenceEqual(value))
            {
                // A new value version (create, add, rotate, import): it supersedes the old version,
                // so an outstanding burn of that version becomes history.
                var version = NextStamp();
                var burns = (state?.Burns ?? []).ToList();
                // Fix round 1, B: the value this version replaces is kept (one level).
                var live = state is { Type: not RecordType.Tombstone };
                // Brief T16-S1: the replaced value keeps its fingerprints and its sealed section
                // (copied, never encrypted again).
                var previous = live ? new PreviousValue(state!.Version, state.Value, state.Fingerprints) : null;
                IReadOnlyDictionary<Stamp, byte[]>? sealedPrevious = live && state!.Sealed is { } sealedSections
                    && sealedSections.TryGetValue(state.Version, out var previousSection)
                        ? new Dictionary<Stamp, byte[]> { [state.Version] = previousSection }
                        : null;
                // restore: the previous value comes back with its burn outstanding again (it is
                // still compromised), keeping the original burn's time and reason.
                if (secret.Restored && live && state!.Previous is { } restoredFrom)
                    foreach (var burn in state.Burns.Where(b => b.Version.Equals(restoredFrom.Version)).ToList())
                        burns.Add(new BurnEntry(version, burn.Burn, burn.Reason));
                // An imported burned secret keeps its original burn time (fix round 1, C).
                if (secret.BurnedAt is { } burnedAt)
                    burns.Add(new BurnEntry(version, new Stamp(new Hlc(UnixMs(burnedAt), 0), origin), secret.BurnReason));
                var createdMs = state is { Type: not RecordType.Tombstone }
                    ? state.CreatedMs
                    : new DateTimeOffset(DateTime.SpecifyKind(secret.Created, DateTimeKind.Utc)).ToUnixTimeMilliseconds();
                next = new SecretRecord(
                    FilenameHasher.ComputeRecordId(namesKey, name), Stamp.Zero, RecordType.Value, version, name, createdMs, value, burns, previous)
                {
                    Extensions = state?.Extensions ?? [], // ruling 6: unknown extensions survive every rewrite
                    Sealed = sealedPrevious,
                };
            }
            else if (secret.BurnedAt is not null && state.OutstandingBurn is null)
            {
                next = state with { Burns = [.. state.Burns, new BurnEntry(state.Version, NextStamp(), secret.BurnReason)] };
            }
            if (next is not null)
                writes.Add((fileName, RecordMerge.Normalize(next)));
        }

        foreach (var current in loaded.Values)
        {
            if (current.State is not { Type: not RecordType.Tombstone } state || db.Secrets.ContainsKey(state.Name))
                continue;
            var tombstone = state with
            {
                Type = RecordType.Tombstone, Version = NextStamp(), Value = [], Previous = null, Fingerprints = null, Sealed = null,
            };
            writes.Add((current.FileName, RecordMerge.Normalize(tombstone)));
        }

        WriteRecords(writes, key, loaded);
    }

    /// <summary>
    /// Brief T6 decision 8: writes every secret of <paramref name="db"/> as a record into an empty
    /// records folder, keeping its times: the version stamp's physical part is the secret's
    /// <see cref="Secret.Modified"/>, a burn's is its <see cref="Secret.BurnedAt"/>, with this
    /// machine's origin id. Returns the highest HLC written (the new config's <c>LastHlc</c>).
    /// </summary>
    public Hlc WriteSnapshot(SecretsDb db, byte[] key)
    {
        var loaded = LoadRecords(key, _warnings);
        if (loaded.Count > 0)
            throw new InvalidOperationException("WriteSnapshot needs an empty records folder.");
        var origin = OriginId();
        var namesKey = RecordKeyDerivation.DeriveNamesKey(key);
        List<(string FileName, SecretRecord State)> writes = [];
        foreach (var (name, secret) in db.Secrets.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var version = new Stamp(new Hlc(UnixMs(secret.Modified), 0), origin);
            Observe(version.Hlc);
            List<BurnEntry> burns = [];
            if (secret.BurnedAt is { } burnedAt)
            {
                var burn = new Stamp(new Hlc(UnixMs(burnedAt), 0), origin);
                Observe(burn.Hlc);
                burns.Add(new BurnEntry(version, burn, secret.BurnReason));
            }
            var recordId = FilenameHasher.ComputeRecordId(namesKey, name);
            writes.Add((FilenameHasher.ToFilename(recordId), RecordMerge.Normalize(new SecretRecord(
                recordId, Stamp.Zero, RecordType.Value, version, name, UnixMs(secret.Created), Encoding.UTF8.GetBytes(secret.Value), burns))));
        }
        WriteRecords(writes, key, loaded);
        return _highestSeen;
    }

    private static long UnixMs(DateTime time) =>
        new DateTimeOffset(time.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(time, DateTimeKind.Utc) : time.ToUniversalTime())
            .ToUnixTimeMilliseconds();

    /// <summary>
    /// Brief T16-S1: every record's metadata, decrypting metadata sections only and no value section
    /// (<see cref="SecretRecordCodec.DecodeMetadata"/>). Conflicted copies fold in all at once by
    /// <see cref="RecordMerge.MergeAllMetadata"/> (the value sections are read from the framing,
    /// still encrypted, and compared by bytes and fingerprints). A record whose main file or any
    /// conflicted copy is format 2 counts as not fingerprinted without that file being decrypted
    /// (ruling 12: its version stamp is inside its payload, so this path can't tell whether it is the
    /// newer version). A record that can't be read, or whose copies can't be merged here, is listed
    /// in <see cref="VaultMetadata.Unreadable"/> and warned about. Reads only.
    /// </summary>
    public VaultMetadata LoadMetadata(byte[] vaultKey, TextWriter? warnings = null)
    {
        warnings ??= _warnings;
        List<RecordMetadata> records = [];
        List<string> unreadable = [];
        Dictionary<string, IReadOnlyDictionary<Stamp, byte[]>> chosenSections = new(StringComparer.Ordinal);
        int notFingerprinted = 0, olderVariantSet = 0;
        var recordsDir = RecordsDir;
        if (!_owner.AsOwner(recordsDir, () => Directory.Exists(recordsDir)))
        {
            MetadataSections = chosenSections;
            return new VaultMetadata(records, 0, 0, unreadable);
        }

        var scan = _owner.AsOwner(recordsDir, () => RecordDirectoryScanner.Scan(recordsDir));
        var mains = scan.ValidRecordFilenames.ToHashSet(StringComparer.Ordinal);
        var copiesByRecord = scan.Conflicts.GroupBy(c => c.RecordFilename, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.OrderBy(c => c.ConflictingFilename, StringComparer.Ordinal).ToList(), StringComparer.Ordinal);
        foreach (var fileName in mains.Concat(copiesByRecord.Keys).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            List<(RecordMetadata, IReadOnlyDictionary<Stamp, byte[]>)> inputs = [];
            if (mains.Contains(fileName))
            {
                var problem = ReadMainMetadata(fileName, vaultKey, inputs, out var isV2);
                if (isV2)
                {
                    notFingerprinted++;
                    continue;
                }
                if (problem is not null)
                {
                    unreadable.Add(fileName);
                    warnings?.WriteLine(
                        $"Warning: record {fileName} can't be read ({problem}). Its secret is kept as present but unknown: " +
                        "restore the file from a backup or another copy, or wait for the sync to finish.");
                    continue;
                }
            }

            var copies = copiesByRecord.GetValueOrDefault(fileName) ?? [];
            List<(string Name, byte[] Bytes)> copyBytes = [];
            foreach (var copy in copies)
            {
                try
                {
                    copyBytes.Add((copy.ConflictingFilename, _owner.ReadAllBytes(Path.Combine(recordsDir, copy.ConflictingFilename))));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TswapException)
                {
                    warnings?.WriteLine($"Warning: {copy.ConflictingFilename} (conflicted copy of record {fileName}) can't be read ({ex.Message}); it is not used.");
                }
            }
            // Ruling 12: a format 2 copy is never decrypted here; the record is not fingerprinted.
            if (copyBytes.Any(c => SecretRecordCodec.FormatVersionOf(c.Bytes) == KeyringFormat.RecordFormatVersionV2))
            {
                notFingerprinted++;
                continue;
            }
            foreach (var (copyName, bytes) in copyBytes)
            {
                try
                {
                    RecordDecrypted?.Invoke(copyName);
                    var decoded = SecretRecordCodec.DecodeMetadataAndSections(bytes, vaultKey)
                        ?? throw new TswapException("it is not a format 3 record");
                    if (FilenameHasher.ToFilename(decoded.Metadata.RecordId) != fileName)
                        throw new TswapException("its record id belongs to another record");
                    inputs.Add(decoded);
                }
                catch (Exception ex) when (ex is TswapException or CryptographicException)
                {
                    var reason = ex is CryptographicException ? "it can't be decrypted or authenticated" : ex.Message;
                    warnings?.WriteLine(
                        $"Warning: {copyName} (conflicted copy of record {fileName}) can't be used ({reason}). " +
                        "It is kept as it is and never chosen; remove it once you no longer need it.");
                }
            }
            if (inputs.Count == 0)
                continue;

            (RecordMetadata Metadata, IReadOnlyDictionary<Stamp, byte[]> Sealed) merged;
            try
            {
                merged = RecordMerge.MergeAllMetadata(inputs);
            }
            catch (RecordConflictException ex)
            {
                unreadable.Add(fileName);
                warnings?.WriteLine(
                    $"Warning: record {fileName} can't be read: its copies can't be merged ({ex.Message}). Remove the damaged " +
                    "conflicted copy; a full load (any command that writes this record) may still be able to merge them.");
                continue;
            }
            records.Add(merged.Metadata);
            chosenSections[fileName] = merged.Sealed;
            var retained = merged.Metadata.RetainedVersions().ToList();
            if (retained.Any(v => v.Fingerprints is null))
                notFingerprinted++;
            if (retained.Any(v => v.Fingerprints is { } set && set.VariantSetVersion < SecretVariants.CurrentSetVersion))
                olderVariantSet++;
        }
        if (unreadable.Count > 0)
            warnings?.WriteLine($"Warning: {unreadable.Count} unreadable record(s) in {recordsDir}.");
        MetadataSections = chosenSections;
        return new VaultMetadata(records, notFingerprinted, olderVariantSet, unreadable.Order(StringComparer.Ordinal).ToList());
    }

    /// <summary>
    /// <see cref="LoadMetadata"/>'s main file: adds its metadata to <paramref name="inputs"/>, or
    /// returns why it can't be read. A format 2 main file sets <paramref name="isV2"/> and is not decrypted.
    /// </summary>
    private string? ReadMainMetadata(string fileName, byte[] vaultKey, List<(RecordMetadata, IReadOnlyDictionary<Stamp, byte[]>)> inputs, out bool isV2)
    {
        isV2 = false;
        byte[] bytes;
        try
        {
            bytes = _owner.ReadAllBytes(Path.Combine(RecordsDir, fileName));
        }
        catch (Exception ex) when (ex is TswapException or IOException or UnauthorizedAccessException)
        {
            return ex.Message;
        }
        if (SecretRecordCodec.FormatVersionOf(bytes) == KeyringFormat.RecordFormatVersionV2)
        {
            isV2 = true;
            return null;
        }
        try
        {
            RecordDecrypted?.Invoke(fileName);
            var decoded = SecretRecordCodec.DecodeMetadataAndSections(bytes, vaultKey)
                ?? throw new TswapException("it is not a format 3 record");
            if (FilenameHasher.ToFilename(decoded.Metadata.RecordId) != fileName)
                return "its record id does not match its file name";
            inputs.Add(decoded);
            return null;
        }
        catch (Exception ex) when (ex is TswapException or CryptographicException)
        {
            return ex is CryptographicException ? "it fails authentication" : ex.Message;
        }
    }

    /// <summary>
    /// Brief T6 decision 5 (<c>vault merge</c>): every readable record of this vault folder as its
    /// merged state (conflicted copies folded in), by hashed file name, plus the file names of
    /// records that can't be read. Reads only.
    /// </summary>
    public (IReadOnlyDictionary<string, SecretRecord> States, IReadOnlyList<string> Unreadable) LoadRecordStates(byte[] key, TextWriter? warnings = null)
    {
        var loaded = LoadRecords(key, warnings);
        return (
            loaded.Values.Where(r => r.State is not null).ToDictionary(r => r.FileName, r => r.State!, StringComparer.Ordinal),
            loaded.Values.Where(r => r.UnreadableReason is not null).Select(r => r.FileName).Order(StringComparer.Ordinal).ToList());
    }

    /// <summary>
    /// Brief T6 decision 5 (<c>vault merge</c>): merges <paramref name="incoming"/> states (another
    /// copy of this vault) into this folder by <see cref="RecordMerge"/>, writing only records whose
    /// state changes (a new write stamp; version and burn stamps are kept, so merging in either
    /// direction gives the same states). A record that can't be read here is never overwritten
    /// (a warning). Call after <see cref="LoadSecrets"/> or <see cref="LoadRecordStates"/>; the
    /// stale-write guard applies. Returns how many records were written.
    /// </summary>
    /// <param name="beforeWrite">
    /// Fix round 1 (C): runs after every record's stale-write guard passed and before any record is
    /// written (vault merge saves the keyring there), so a refusal really writes nothing.
    /// </param>
    public int MergeRecords(IReadOnlyDictionary<string, SecretRecord> incoming, byte[] key, Action? beforeWrite = null)
    {
        var loaded = _loaded ?? LoadRecords(key, _warnings);
        List<(string FileName, SecretRecord State)> writes = [];
        foreach (var (fileName, state) in incoming.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            ObserveAll(state);
            // Brief T16-S1: format 3 state merged in is written as format 3, so its sections and
            // fingerprints aren't dropped (and the next merge doesn't rewrite it again).
            if (state.Sealed is not null)
                _sawV3 = true;
            loaded.TryGetValue(fileName, out var current);
            if (current?.UnreadableReason is not null)
            {
                _warnings?.WriteLine($"Warning: record {fileName} can't be read here, so the other copy's version was not merged into it.");
                continue;
            }
            // Ruling 11: the main file, its conflicted copies and the incoming state, all at once.
            SecretRecord merged;
            try
            {
                merged = RecordMerge.MergeAll([.. current?.Inputs ?? [], state]);
            }
            catch (RecordConflictException ex)
            {
                _warnings?.WriteLine(
                    $"Warning: record {fileName} can't be merged with the other copy's version ({ex.Message}); it was skipped and " +
                    "left as it is. Find the damaged copy (here or in the other folder) and remove it, then merge again.");
                continue;
            }
            // Write when the state differs, when the sections differ from the main file's (so both
            // folders converge on one section), or to remove the conflicted copies folded in.
            if (current?.State is not null && merged.SameState(current.State)
                && SameSections(merged.Sealed, current.MainState?.Sealed) && current.FoldedCopies is not { Count: > 0 })
                continue;
            writes.Add((fileName, merged));
        }
        CheckUnchanged(writes, loaded);
        beforeWrite?.Invoke();
        WriteRecords(writes, key, loaded);
        return writes.Count;
    }

    private static bool SameSections(IReadOnlyDictionary<Stamp, byte[]>? a, IReadOnlyDictionary<Stamp, byte[]>? b)
    {
        if ((a?.Count ?? 0) != (b?.Count ?? 0))
            return false;
        return a is null || b is null || a.All(kv => b.TryGetValue(kv.Key, out var other) && other.AsSpan().SequenceEqual(kv.Value));
    }

    private static TswapException Unreadable(string name, string fileName) => new(
        $"The record holding '{name}' ({fileName}) can't be read: it is damaged, truncated, or still being synced. " +
        "Restore that file from a backup or another copy, or wait for the sync to finish; nothing was changed.");

    /// <summary>
    /// Writes <paramref name="writes"/>: every file is re-read and compared with what this command
    /// loaded first, and any change refuses the whole save before anything is written (decision 6).
    /// Each record gets its own write stamp; <c>LastHlc</c> is saved afterwards.
    /// </summary>
    /// <param name="reindex">
    /// <c>vault reindex</c>: format 3 regardless of the marker, and fingerprint sets of an older
    /// variant-set version are recomputed.
    /// </param>
    private void WriteRecords(List<(string FileName, SecretRecord State)> writes, byte[] key, Dictionary<string, LoadedRecord> loaded, bool reindex = false)
    {
        if (writes.Count == 0)
            return;
        // Ruling 3: a vault folder marked by a newer tswap is never written by this one.
        if (_markerFormat > KeyringFormat.RecordFormatVersion)
            throw NewerFormatMarker();
        var recordsDir = RecordsDir;
        CheckUnchanged(writes, loaded);

        TightenModes();
        _owner.CreateDirectory(VaultDir);
        _owner.CreateDirectory(recordsDir);
        var origin = OriginId();
        using var fingerprintKeys = WritesV3 || reindex ? FingerprintKeys.Derive(key) : null;
        foreach (var (fileName, state) in writes)
        {
            var hlc = Hlc.Next(_highestSeen, _time.GetUtcNow().ToUnixTimeMilliseconds());
            _highestSeen = hlc;
            var written = state with { Write = new Stamp(hlc, origin) };
            byte[] bytes;
            if (fingerprintKeys is not null)
            {
                written = PrepareV3(written, fingerprintKeys, recomputeOlderSets: reindex);
                bytes = SecretRecordCodec.Encode(written, key, KeyringFormat.RecordFormatVersion);
                written = written with { Sealed = written.Type == RecordType.Tombstone ? null : SecretRecordCodec.SectionsOf(bytes, written) };
            }
            else
            {
                bytes = SecretRecordCodec.Encode(written, key, KeyringFormat.RecordFormatVersionV2);
                // What format 2 holds: no fingerprints, extensions or sections.
                written = written with
                {
                    Fingerprints = null, Previous = written.Previous is { } p ? p with { Fingerprints = null } : null, Extensions = [], Sealed = null,
                };
            }
            _owner.WriteDurable(Path.Combine(recordsDir, fileName), bytes);
            // Decision 4: the copies merged into what was just written are redundant now.
            if (loaded.TryGetValue(fileName, out var before) && before.FoldedCopies is { Count: > 0 } copies)
                RemoveRedundantCopies(copies);
            loaded[fileName] = new LoadedRecord(fileName, bytes, written, null, MainState: written, Inputs: [written]);
            AfterRecordWritten?.Invoke();
        }

        var machine = MachineConfig with { LastHlc = _highestSeen.ToString() };
        _machineConfig = machine;
        WriteMachineConfig(machine);
    }

    /// <summary>
    /// Brief T16-S1: a record ready for format 3. A retained value without a fingerprint set gets one
    /// computed now from its plaintext (known from the load); with <paramref name="recomputeOlderSets"/>
    /// (<c>vault reindex</c>) so does one with an older variant set. A version that already has a
    /// sealed section keeps it (copied, never encrypted again); one without (new, or read from
    /// format 2) is sealed by the codec. Sections of versions no longer retained are dropped.
    /// </summary>
    private static SecretRecord PrepareV3(SecretRecord record, FingerprintKeys keys, bool recomputeOlderSets)
    {
        if (record.Type == RecordType.Tombstone)
            return record with { Fingerprints = null, Previous = null, Sealed = null };
        FingerprintSet For(byte[] value, FingerprintSet? stored) =>
            stored is not null && !(recomputeOlderSets && stored.VariantSetVersion < SecretVariants.CurrentSetVersion)
                ? stored
                : Fingerprinter.Compute(value, keys);
        var previous = record.Previous is { } p ? p with { Fingerprints = For(p.Value, p.Fingerprints) } : null;
        Dictionary<Stamp, byte[]> sealedSections = [];
        if (record.Sealed is { } existing)
        {
            if (existing.TryGetValue(record.Version, out var current))
                sealedSections[record.Version] = current;
            if (previous is not null && existing.TryGetValue(previous.Version, out var old))
                sealedSections[previous.Version] = old;
        }
        return record with
        {
            Fingerprints = For(record.Value, record.Fingerprints),
            Previous = previous,
            Sealed = sealedSections.Count == 0 ? null : sealedSections,
        };
    }

    /// <summary>
    /// Decision 10 (#194): before this command's first write, narrows the config dir, the vault
    /// folder and records/ to 0700 and their files (config.json, the keyring, records, conflicted
    /// copies) to 0600 where they are wider, with one notice naming what changed. Never on a read;
    /// never through a symlink; Windows: no change.
    /// </summary>
    private void TightenModes()
    {
        if (_modesChecked || _detached || OperatingSystem.IsWindows())
            return;
        _modesChecked = true;
        var candidates = new List<string> { ConfigDir, ConfigFile };
        if (_machineConfig?.VaultDir is not null)
        {
            var vaultDir = VaultDir;
            var recordsDir = RecordsDir;
            candidates.Add(vaultDir);
            candidates.AddRange(_owner.AsOwner(vaultDir, () => Directory.Exists(vaultDir) ? Directory.GetFiles(vaultDir) : []));
            candidates.Add(recordsDir);
            candidates.AddRange(_owner.AsOwner(recordsDir, () => Directory.Exists(recordsDir) ? Directory.GetFiles(recordsDir) : []));
        }
        List<string> changed = [];
        foreach (var path in candidates)
        {
            try
            {
                if (_owner.Tighten(path))
                    changed.Add(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _warnings?.WriteLine($"Warning: could not narrow the permissions of {path} ({ex.Message}).");
            }
        }
        if (changed.Count > 0)
            _warnings?.WriteLine(
                $"Notice: tightened permissions (folders 0700, files 0600; they were readable by others) on: {string.Join(", ", changed)}");
    }

    /// <summary>Decision 6: every record about to be written is unchanged since this command loaded it.</summary>
    private void CheckUnchanged(List<(string FileName, SecretRecord State)> writes, Dictionary<string, LoadedRecord> loaded)
    {
        foreach (var (fileName, _) in writes)
        {
            var path = Path.Combine(RecordsDir, fileName);
            var onDisk = _owner.FileExists(path) ? TryRead(path) : null;
            loaded.TryGetValue(fileName, out var current);
            GenerationGuard.CheckUnchanged(fileName, current?.MainBytes, onDisk);
        }
    }

    private byte[]? TryRead(string path)
    {
        try
        {
            return _owner.ReadAllBytes(path);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }

    private byte[] OriginId()
    {
        try
        {
            var origin = Convert.FromBase64String(MachineConfig.OriginId
                ?? throw new TswapException("Config is corrupted: a record store needs OriginId. Restore config.json from backup."));
            if (origin.Length != KeyringFormat.OriginIdSize)
                throw new FormatException();
            return origin;
        }
        catch (FormatException)
        {
            throw new TswapException("Config is corrupted: OriginId is not 16 bytes of base64. Restore config.json from backup.");
        }
    }

    /// <summary>A new random origin id (base64) for a machine config (decision 1).</summary>
    public static string NewOriginId() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyringFormat.OriginIdSize));
}

/// <summary>
/// Brief T16-S1: what <see cref="RecordVaultStore.Reindex"/> did. <paramref name="Rewritten"/> and
/// <paramref name="AlreadyCurrent"/> together count every record; <paramref name="Tombstones"/> says
/// how many of them are deletes (in either group).
/// </summary>
public sealed record ReindexResult(int Rewritten, int AlreadyCurrent, int Tombstones);
