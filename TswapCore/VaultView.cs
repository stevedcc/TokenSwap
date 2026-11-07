using System.Security.Cryptography;
using System.Text;
using TswapCore.Fingerprints;
using TswapCore.Keyring;

namespace TswapCore;

/// <summary>
/// Brief T16-S2: the vault as the reading commands see it, decrypting no value they don't use.
/// Lookups come from metadata: <see cref="LoadAll"/> (every record's metadata), or one record at a
/// time through <see cref="RecordVaultStore.OpenSecret(string, byte[])"/> when nothing is loaded or
/// the record wasn't (a format 2 record under <see cref="FormatTwoRecords.Skip"/>). Only
/// <see cref="ResolveToken"/> decrypts, one value version per distinct token, once. The answers and
/// exception texts are <see cref="SecretsDb"/>'s (<see cref="ISecretLookup"/>); an unreadable record
/// names its hashed file (<see cref="SecretsDb.UnreadableRecordText"/>).
/// <para>
/// The view holds a reference to <paramref name="vaultKey"/> (no copy): it works only while the
/// caller keeps the key. <see cref="Dispose"/> zeroes the opened entries (a format 2 record's
/// decoded values) and the names key. Resolved values are strings and can't be zeroed, as before.
/// </para>
/// </summary>
/// <param name="warnings">Where <see cref="LoadAll"/>'s load-time findings go (stderr in the CLI).</param>
public sealed class VaultView(RecordVaultStore store, byte[] vaultKey, TextWriter? warnings) : ISecretLookup, IDisposable
{
    /// <summary>One opened record: its entry (null: no record), or the hashed file of a record that can't be read.</summary>
    private sealed record Opened(SecretEntry? Entry, string? UnreadableFile);

    private readonly Dictionary<string, Opened> _opened = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _resolved = new(StringComparer.Ordinal);
    private readonly HashSet<string> _formatTwoFiles = new(StringComparer.Ordinal);
    private byte[]? _namesKey;
    private bool _scanned;
    private DirectoryScanResult? _scan;
    private VaultMetadata? _metadata;
    private FormatTwoRecords _loadedWith;
    private Dictionary<string, RecordMetadata>? _byName;
    private HashSet<string>? _unreadable;
    private bool _disposed;

    /// <summary>
    /// Every record's metadata (<see cref="RecordVaultStore.LoadMetadata"/>), loaded once per policy:
    /// with <see cref="FormatTwoRecords.Skip"/> no value is decrypted; with
    /// <see cref="FormatTwoRecords.Decode"/> only the records that have a format 2 file are decoded whole.
    /// </summary>
    public VaultMetadata LoadAll(FormatTwoRecords formatTwo)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_metadata is not null && _loadedWith == formatTwo)
            return _metadata;
        var metadata = store.LoadMetadata(vaultKey, warnings, formatTwo);
        _metadata = metadata;
        _loadedWith = formatTwo;
        // Names are unique: every format binds a record's name to its record id, and the id to its file.
        _byName = metadata.Records.ToDictionary(r => r.Name, StringComparer.Ordinal);
        _unreadable = metadata.Unreadable.ToHashSet(StringComparer.Ordinal);
        return metadata;
    }

    /// <summary>
    /// The secret <paramref name="name"/>, or null when there is none (no record, a tombstone, or a
    /// record that can't be read: <see cref="ThrowIfUnreadable"/> tells those apart). From
    /// <see cref="LoadAll"/>'s metadata when it holds the record, otherwise from that one record.
    /// Decrypts no value, except a format 2 record's, which can only be read whole.
    /// </summary>
    public SecretInfo? Find(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_byName is not null)
        {
            if (_byName.TryGetValue(name, out var metadata))
                return SecretInfo.From(metadata);
            // Decode loaded every readable record; Skip left out only records with a format 2 file.
            if (_loadedWith == FormatTwoRecords.Decode || _unreadable!.Contains(FileOf(name)))
                return null;
        }
        return Open(name).Entry?.Info;
    }

    /// <summary>
    /// <see cref="SecretsDb.ThrowIfAnyUnreadable"/>'s check over <see cref="LoadAll"/>'s metadata
    /// (loaded with <see cref="FormatTwoRecords.Skip"/> when nothing is loaded yet).
    /// </summary>
    public void ThrowIfAnyUnreadable(string command)
    {
        var metadata = _metadata ?? LoadAll(FormatTwoRecords.Skip);
        if (metadata.Unreadable.Count > 0)
            throw new TswapException(SecretsDb.AnyUnreadableText(command, metadata.Unreadable));
    }

    /// <summary>
    /// The fingerprints <c>redact</c> and <c>tocomment</c> match with: every retained value version
    /// (current as <c>name</c>, previous as <c>name:previous</c>) of every record that still holds
    /// value sections, i.e. every non-tombstone record, burned ones included (burned values stay
    /// masked). Versions without a fingerprint set are left out; the commands refuse before that
    /// (<see cref="VaultMetadata.NotFingerprinted"/>). From <see cref="LoadAll"/>'s metadata
    /// (loaded with <see cref="FormatTwoRecords.Skip"/> when nothing is loaded yet); decrypts nothing.
    /// The index refers to <paramref name="keys"/>, which the caller keeps undisposed while it is used.
    /// </summary>
    public FingerprintIndex BuildIndex(FingerprintKeys keys)
    {
        var metadata = _metadata ?? LoadAll(FormatTwoRecords.Skip);
        return FingerprintIndex.Build(
            from record in metadata.Records
            from version in record.RetainedVersions()
            where version.Fingerprints is not null
            select (record.Name, version.IsPrevious, version.Fingerprints!),
            keys);
    }

    /// <summary>True when <paramref name="name"/>'s current value has an outstanding burn (from metadata).</summary>
    public bool IsBurned(string name) => Find(name)?.BurnedAt is not null;

    /// <summary>
    /// Records decoded whole because they have a format 2 file, so far: the count the format 2
    /// warning reports. After <see cref="LoadAll"/> with <see cref="FormatTwoRecords.Decode"/>, that
    /// load's count (every later read of such a record is one of them); otherwise the distinct
    /// format 2 records opened one at a time.
    /// </summary>
    public int FormatTwoDecoded =>
        _metadata is not null && _loadedWith == FormatTwoRecords.Decode ? _metadata.FormatTwoDecoded : _formatTwoFiles.Count;

    /// <inheritdoc/>
    public bool Contains(string name) => Find(name) is not null;

    /// <inheritdoc/>
    public bool HasPreviousValue(string name) => Find(name)?.HasPrevious ?? false;

    /// <inheritdoc/>
    public bool IsBurnedToken(string token)
    {
        var (name, previous) = Split(token);
        return Find(name) is { } info && (previous ? info.PreviousBurned : info.BurnedAt.HasValue);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Existence and <c>:previous</c> come from metadata (so the errors are the same, in the same
    /// order, without a decryption); the value is then decrypted once for this token (one value
    /// section on format 3), kept as a string, and its bytes zeroed.
    /// </remarks>
    public string ResolveToken(string token, string? where = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var (name, previous) = Split(token);
        if (Find(name) is not { } info)
        {
            ThrowIfUnreadable(name);
            throw new TswapException($"Secret '{name}' not found{where}");
        }
        if (previous && !info.HasPrevious)
            throw new TswapException(
                $"'{token}': secret '{name}' has no previous value (it has not been rotated since it was created).");
        if (_resolved.TryGetValue(token, out var cached))
            return cached;

        var opened = Open(name);
        if (opened.UnreadableFile is { } file)
            throw new TswapException(SecretsDb.UnreadableRecordText(name, file));
        byte[]? bytes;
        try
        {
            bytes = opened.Entry?.DecryptValue(previous);
        }
        catch (UnreadableRecordException ex)
        {
            throw new TswapException(SecretsDb.UnreadableRecordText(name, ex.FileName));
        }
        if (bytes is null) // the record changed since its metadata was read
            throw new TswapException($"Secret '{name}' not found{where}");
        try
        {
            var value = Encoding.UTF8.GetString(bytes);
            _resolved[token] = value;
            return value;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <inheritdoc/>
    public void ThrowIfUnreadable(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var file = FileOf(name);
        if (_unreadable?.Contains(file) == true)
            throw new TswapException(SecretsDb.UnreadableRecordText(name, file));
        if (_byName is not null && (_byName.ContainsKey(name) || _loadedWith == FormatTwoRecords.Decode))
            return;
        if (Open(name).UnreadableFile is { } unreadable)
            throw new TswapException(SecretsDb.UnreadableRecordText(name, unreadable));
    }

    /// <summary>Zeroes every opened entry and the names key.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        foreach (var opened in _opened.Values)
            opened.Entry?.Dispose();
        if (_namesKey is not null)
            CryptographicOperations.ZeroMemory(_namesKey);
    }

    /// <summary>One record, read once per view (one folder scan per view).</summary>
    private Opened Open(string name)
    {
        if (_opened.TryGetValue(name, out var opened))
            return opened;
        if (!_scanned)
        {
            _scan = store.ScanRecords();
            _scanned = true;
        }
        try
        {
            var entry = store.OpenSecret(name, vaultKey, _scan);
            if (entry is { IsFormatTwo: true })
                _formatTwoFiles.Add(entry.FileName);
            opened = new Opened(entry, null);
        }
        catch (UnreadableRecordException ex)
        {
            opened = new Opened(null, ex.FileName);
        }
        _opened[name] = opened;
        return opened;
    }

    private string FileOf(string name)
    {
        _namesKey ??= RecordKeyDerivation.DeriveNamesKey(vaultKey);
        return FilenameHasher.ComputeFilename(_namesKey, name);
    }

    private static (string Name, bool Previous) Split(string token)
    {
        var previous = token.EndsWith(SecretsDb.PreviousSuffix, StringComparison.Ordinal);
        return (previous ? token[..^SecretsDb.PreviousSuffix.Length] : token, previous);
    }
}
