using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
/// </summary>
public sealed class RecordVaultStore : IFileVaultStore
{
    /// <summary>The <see cref="Config.Store"/> value that selects this store.</summary>
    public const string StoreName = "records";

    /// <summary>The keyring file's name in the vault folder.</summary>
    public const string KeyringFileName = "keyring";

    /// <summary>The records folder's name in the vault folder.</summary>
    public const string RecordsFolderName = "records";

    private readonly DirectoryOwnerMatcher _owner;
    private readonly Func<DateTimeOffset> _clock;

    private Config? _machineConfig;
    private readonly bool _detached;
    private bool _modesChecked;
    private Hlc _highestSeen = Hlc.Zero;
    private Dictionary<string, LoadedRecord>? _loaded;
    private TextWriter? _warnings;

    /// <param name="configDir">The machine's config dir (holds <c>config.json</c>).</param>
    /// <param name="owner">The file layer (null: <see cref="DirectoryOwnerMatcher.Default"/>).</param>
    /// <param name="clock">The time seam for HLC stamps (null: the system clock).</param>
    /// <param name="warnings">Where load-time findings go (conflicted copies, unreadable records); stderr in the CLI.</param>
    public RecordVaultStore(string configDir, DirectoryOwnerMatcher? owner = null, Func<DateTimeOffset>? clock = null, TextWriter? warnings = null)
    {
        _warnings = warnings;
        ConfigDir = configDir;
        ConfigFile = Path.Combine(configDir, "config.json");
        SecretsFile = Path.Combine(configDir, "secrets.json.enc");
        _owner = owner ?? DirectoryOwnerMatcher.Default;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Brief T6 decision 8: a store over a bare vault folder with an in-memory machine config (no
    /// <c>config.json</c> is read or written): <c>migrate --to-records</c> fills its temp folder
    /// and reads it back through one.
    /// </summary>
    public static RecordVaultStore ForFolder(string vaultDir, Config machineConfig, DirectoryOwnerMatcher? owner = null, Func<DateTimeOffset>? clock = null)
    {
        var store = new RecordVaultStore(Path.GetFullPath(vaultDir), owner, clock, detached: true);
        store._machineConfig = machineConfig with { Keyring = null, Store = StoreName, VaultDir = Path.GetFullPath(vaultDir) };
        return store;
    }

    private RecordVaultStore(string vaultDir, DirectoryOwnerMatcher? owner, Func<DateTimeOffset>? clock, bool detached)
        : this(vaultDir, owner, clock)
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

    /// <summary>Test seam: removes a redundant conflicted copy (default: through the file layer).</summary>
    internal Action<string>? DeleteFile { get; init; }

    private Config MachineConfig => _machineConfig ?? ReadMachineConfig();

    public string BackupConfig() => FileBackup.Copy(ConfigFile, DateTime.UtcNow, _owner);

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
        if (config.Keyring != null)
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
        if (config.Keyring != null)
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
        var folded = new List<(string, byte[])>();
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
        var folded = new List<(string Path, byte[] Bytes)>();
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
                if (now == null)
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
    private sealed record LoadedRecord(
        string FileName, byte[]? MainBytes, SecretRecord? State, string? UnreadableReason,
        IReadOnlyList<(string Path, byte[] Bytes)>? FoldedCopies = null);

    public SecretsDb LoadSecrets(byte[] key, TextWriter? warnings = null)
    {
        warnings ??= _warnings;
        _warnings = warnings;
        var loaded = LoadRecords(key, warnings);
        var secrets = new Dictionary<string, Secret>();
        foreach (var record in loaded.Values)
        {
            if (record.State is not { Type: not RecordType.Tombstone } state)
                continue;
            secrets[state.Name] = ToSecret(state);
        }
        var unreadable = loaded.Values.Where(r => r.UnreadableReason != null).Select(r => r.FileName).ToHashSet(StringComparer.Ordinal);
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
            outstanding == null ? null : Hlc.ToDisplayDate(outstanding.Burn.Hlc.PhysicalMs),
            outstanding?.Reason)
        {
            History = history.Count == 0 ? null : history,
            PreviousValue = state.Previous == null ? null : Encoding.UTF8.GetString(state.Previous.Value),
        };
    }

    private Dictionary<string, LoadedRecord> LoadRecords(byte[] key, TextWriter? warnings)
    {
        _highestSeen = Hlc.TryParse(MachineConfig.LastHlc) ?? Hlc.Zero;
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
        foreach (var fileName in scan.ValidRecordFilenames.Order(StringComparer.Ordinal))
            loaded[fileName] = ReadRecord(fileName, key);

        foreach (var group in scan.Conflicts.GroupBy(c => c.RecordFilename).OrderBy(g => g.Key, StringComparer.Ordinal))
            loaded[group.Key] = FoldConflictCopies(group.Key, group.OrderBy(c => c.ConflictingFilename, StringComparer.Ordinal).ToList(),
                loaded.GetValueOrDefault(group.Key), key, warnings);

        foreach (var record in loaded.Values.Where(r => r.UnreadableReason != null))
            warnings?.WriteLine(
                $"Warning: record {record.FileName} can't be read ({record.UnreadableReason}). Its secret is kept as " +
                "present but unknown: commands that need it stop, and nothing overwrites or deletes it. Restore the file " +
                "from a backup or another copy, or wait for the sync to finish.");
        var unreadableCount = loaded.Values.Count(r => r.UnreadableReason != null);
        if (unreadableCount > 0)
            warnings?.WriteLine($"Warning: {unreadableCount} unreadable record(s) in {recordsDir}.");

        // Decision 3, absurd stamps: accepted (merge needs a total order) but reported.
        var nowMs = _clock().ToUnixTimeMilliseconds();
        const long year = 365L * 24 * 60 * 60 * 1000;
        var yearAhead = nowMs > long.MaxValue - year ? long.MaxValue : nowMs + year;
        foreach (var record in loaded.Values.Where(r => r.State != null && MaxPhysical(r.State) > yearAhead))
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
    /// </summary>
    private LoadedRecord FoldConflictCopies(
        string fileName, List<ConflictWarning> copies, LoadedRecord? main, byte[] key, TextWriter? warnings)
    {
        main ??= new LoadedRecord(fileName, null, null, null);
        var state = main.State;
        var folded = new List<(string Path, byte[] Bytes)>();
        foreach (var copy in copies)
        {
            var path = Path.Combine(RecordsDir, copy.ConflictingFilename);
            var tool = ToolName(copy.Tool);
            byte[] bytes;
            SecretRecord copyState;
            try
            {
                bytes = _owner.ReadAllBytes(path);
                copyState = SecretRecordCodec.Decode(bytes, key);
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
            if (main.UnreadableReason != null)
                continue;
            warnings?.WriteLine(
                $"Note: record {fileName} has a {tool} conflicted copy ({copy.ConflictingFilename}): version {copyState.Version} " +
                $"vs {(state == null ? "no main file" : $"version {state.Version}")}. Combined by the merge rules; the copy is " +
                "removed the next time this record is written.");
            state = state == null ? copyState : RecordMerge.Merge(state, copyState);
            folded.Add((path, bytes));
        }
        return main with { State = state, FoldedCopies = folded };
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
            var state = SecretRecordCodec.Decode(bytes, key);
            if (FilenameHasher.ToFilename(state.RecordId) != fileName)
                return new LoadedRecord(fileName, bytes, null, "its record id does not match its file name");
            ObserveAll(state);
            return new LoadedRecord(fileName, bytes, state, null);
        }
        catch (Exception ex) when (ex is TswapException or CryptographicException)
        {
            return new LoadedRecord(fileName, bytes, null, ex is CryptographicException ? "it fails authentication" : ex.Message);
        }
    }

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
        var origin = OriginId();
        var namesKey = RecordKeyDerivation.DeriveNamesKey(key);
        var writes = new List<(string FileName, SecretRecord State)>();

        Stamp NextStamp()
        {
            var hlc = Hlc.Next(_highestSeen, _clock().ToUnixTimeMilliseconds());
            _highestSeen = hlc;
            return new Stamp(hlc, origin);
        }

        foreach (var (name, secret) in db.Secrets.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var fileName = FilenameHasher.ComputeFilename(namesKey, name);
            loaded.TryGetValue(fileName, out var current);
            if (current?.UnreadableReason != null)
                throw Unreadable(name, fileName);
            var state = current?.State;
            var value = Encoding.UTF8.GetBytes(secret.Value);
            SecretRecord? next = null;
            if (state == null || state.Type == RecordType.Tombstone || secret.Rotated || !state.Value.AsSpan().SequenceEqual(value))
            {
                // A new value version (create, add, rotate, import): it supersedes the old version,
                // so an outstanding burn of that version becomes history.
                var version = NextStamp();
                var burns = (state?.Burns ?? []).ToList();
                // Fix round 1, B: the value this version replaces is kept (one level).
                var live = state is { Type: not RecordType.Tombstone };
                var previous = live ? new PreviousValue(state!.Version, state.Value) : null;
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
                    FilenameHasher.ComputeRecordId(namesKey, name), Stamp.Zero, RecordType.Value, version, name, createdMs, value, burns, previous);
            }
            else if (secret.BurnedAt != null && state.OutstandingBurn == null)
            {
                next = state with { Burns = [.. state.Burns, new BurnEntry(state.Version, NextStamp(), secret.BurnReason)] };
            }
            if (next != null)
                writes.Add((fileName, RecordMerge.Normalize(next)));
        }

        foreach (var current in loaded.Values)
        {
            if (current.State is not { Type: not RecordType.Tombstone } state || db.Secrets.ContainsKey(state.Name))
                continue;
            var tombstone = state with { Type = RecordType.Tombstone, Version = NextStamp(), Value = [], Previous = null };
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
        var writes = new List<(string FileName, SecretRecord State)>();
        foreach (var (name, secret) in db.Secrets.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var version = new Stamp(new Hlc(UnixMs(secret.Modified), 0), origin);
            Observe(version.Hlc);
            var burns = new List<BurnEntry>();
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
    /// Brief T6 decision 5 (<c>vault merge</c>): every readable record of this vault folder as its
    /// merged state (conflicted copies folded in), by hashed file name, plus the file names of
    /// records that can't be read. Reads only.
    /// </summary>
    public (IReadOnlyDictionary<string, SecretRecord> States, IReadOnlyList<string> Unreadable) LoadRecordStates(byte[] key, TextWriter? warnings = null)
    {
        var loaded = LoadRecords(key, warnings);
        return (
            loaded.Values.Where(r => r.State != null).ToDictionary(r => r.FileName, r => r.State!, StringComparer.Ordinal),
            loaded.Values.Where(r => r.UnreadableReason != null).Select(r => r.FileName).Order(StringComparer.Ordinal).ToList());
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
        var writes = new List<(string FileName, SecretRecord State)>();
        foreach (var (fileName, state) in incoming.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            ObserveAll(state);
            loaded.TryGetValue(fileName, out var current);
            if (current?.UnreadableReason != null)
            {
                _warnings?.WriteLine($"Warning: record {fileName} can't be read here, so the other copy's version was not merged into it.");
                continue;
            }
            var merged = current?.State == null ? RecordMerge.Normalize(state) : RecordMerge.Merge(current.State, state);
            if (current?.State != null && merged.SameState(current.State) && current.FoldedCopies is not { Count: > 0 })
                continue;
            writes.Add((fileName, merged));
        }
        CheckUnchanged(writes, loaded);
        beforeWrite?.Invoke();
        WriteRecords(writes, key, loaded);
        return writes.Count;
    }

    private static TswapException Unreadable(string name, string fileName) => new(
        $"The record holding '{name}' ({fileName}) can't be read: it is damaged, truncated, or still being synced. " +
        "Restore that file from a backup or another copy, or wait for the sync to finish; nothing was changed.");

    /// <summary>
    /// Writes <paramref name="writes"/>: every file is re-read and compared with what this command
    /// loaded first, and any change refuses the whole save before anything is written (decision 6).
    /// Each record gets its own write stamp; <c>LastHlc</c> is saved afterwards.
    /// </summary>
    private void WriteRecords(List<(string FileName, SecretRecord State)> writes, byte[] key, Dictionary<string, LoadedRecord> loaded)
    {
        if (writes.Count == 0)
            return;
        var recordsDir = RecordsDir;
        CheckUnchanged(writes, loaded);

        TightenModes();
        _owner.CreateDirectory(VaultDir);
        _owner.CreateDirectory(recordsDir);
        var origin = OriginId();
        foreach (var (fileName, state) in writes)
        {
            var hlc = Hlc.Next(_highestSeen, _clock().ToUnixTimeMilliseconds());
            _highestSeen = hlc;
            var written = state with { Write = new Stamp(hlc, origin) };
            var bytes = SecretRecordCodec.Encode(written, key);
            _owner.WriteDurable(Path.Combine(recordsDir, fileName), bytes);
            // Decision 4: the copies merged into what was just written are redundant now.
            if (loaded.TryGetValue(fileName, out var before) && before.FoldedCopies is { Count: > 0 } copies)
                RemoveRedundantCopies(copies);
            loaded[fileName] = new LoadedRecord(fileName, bytes, written, null);
        }

        var machine = MachineConfig with { LastHlc = _highestSeen.ToString() };
        _machineConfig = machine;
        WriteMachineConfig(machine);
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
        if (_machineConfig?.VaultDir != null)
        {
            var vaultDir = VaultDir;
            var recordsDir = RecordsDir;
            candidates.Add(vaultDir);
            candidates.AddRange(_owner.AsOwner(vaultDir, () => Directory.Exists(vaultDir) ? Directory.GetFiles(vaultDir) : []));
            candidates.Add(recordsDir);
            candidates.AddRange(_owner.AsOwner(recordsDir, () => Directory.Exists(recordsDir) ? Directory.GetFiles(recordsDir) : []));
        }
        var changed = new List<string>();
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
