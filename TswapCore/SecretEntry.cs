using System.Security.Cryptography;
using TswapCore.Keyring;

namespace TswapCore;

/// <summary>
/// Brief T16-S2: a record that can't be read, opened through <see cref="RecordVaultStore.OpenSecret"/>
/// (fail closed). <see cref="Exception.Message"/> is the text <see cref="RecordVaultStore.ReadSecretValue"/>
/// has always thrown (the broker shows it); commands show <see cref="SecretsDb.UnreadableRecordText"/>
/// instead, which names the hashed <see cref="FileName"/>.
/// </summary>
public sealed class UnreadableRecordException(string name, string fileName, string reason, string? message = null)
    : TswapException(message ?? $"The record of '{name}' can't be read ({reason}).")
{
    /// <summary>The secret's name.</summary>
    public string Name { get; } = name;

    /// <summary>The record's hashed file name.</summary>
    public string FileName { get; } = fileName;

    /// <summary>Why it can't be read.</summary>
    public string Reason { get; } = reason;
}

/// <summary>
/// Brief T16-S2: one secret's record as <see cref="RecordVaultStore.OpenSecret"/> read it: the
/// merged metadata of its main file and conflicted copies. For format 3 no value is decrypted until
/// <see cref="DecryptValue"/> asks for one version. A format 2 record keeps name and both value
/// versions in one encrypted block, so it was decoded whole (<see cref="IsFormatTwo"/>); its values
/// are held only until <see cref="Dispose"/>, which zeroes them.
/// </summary>
public sealed class SecretEntry : IDisposable
{
    private readonly RecordVaultStore _store;
    private readonly string _name;
    private readonly byte[] _vaultKey;
    private readonly IReadOnlyDictionary<Stamp, byte[]>? _sections;
    private readonly SecretRecord? _decoded;
    private readonly IReadOnlyList<SecretRecord> _decodedInputs;
    private bool _disposed;

    /// <summary>
    /// Brief T16-S2b, for a write (<see cref="RecordVaultStore.OpenForWrite"/>): the main file's
    /// bytes as read (null: no main file), the stale-write guard's reference.
    /// </summary>
    internal byte[]? MainBytes { get; init; }

    /// <summary>
    /// Brief T16-S2b, for a write: the conflicted copies folded into this entry, with their bytes as
    /// read; redundant once the record is written (removed if still byte-identical).
    /// </summary>
    internal IReadOnlyList<(string Path, byte[] Bytes)> FoldedCopies { get; init; } = [];

    /// <summary>Brief T16-S2b: the held value sections of a format 3 entry (null: decoded whole).</summary>
    internal IReadOnlyDictionary<Stamp, byte[]>? Sections => _sections;

    /// <summary>Brief T16-S2b: the merged state of an entry decoded whole (null: format 3, metadata only).</summary>
    internal SecretRecord? Decoded => _decoded;

    /// <summary>A format 3 record: its merged metadata and the chosen value section of each retained version.</summary>
    internal SecretEntry(RecordVaultStore store, string name, string fileName, byte[] vaultKey,
        RecordMetadata metadata, IReadOnlyDictionary<Stamp, byte[]> sections)
    {
        _store = store;
        _name = name;
        _vaultKey = vaultKey;
        FileName = fileName;
        Metadata = metadata;
        _sections = sections;
        _decodedInputs = [];
    }

    /// <summary>
    /// A record decoded whole: the merged state and every decoded copy (zeroed on dispose). That is a
    /// format 2 record (<paramref name="formatTwo"/>), or (brief T16-S2b, writes only) a format 3
    /// record whose copies only plaintext can merge.
    /// </summary>
    internal SecretEntry(RecordVaultStore store, string name, string fileName, byte[] vaultKey,
        SecretRecord decoded, IReadOnlyList<SecretRecord> decodedInputs, bool formatTwo = true)
    {
        IsFormatTwo = formatTwo;
        _store = store;
        _name = name;
        _vaultKey = vaultKey;
        FileName = fileName;
        Metadata = RecordVaultStore.MetadataOf(decoded);
        _decoded = decoded;
        _decodedInputs = decodedInputs;
    }

    /// <summary>The record's hashed file name.</summary>
    public string FileName { get; }

    /// <summary>The merged metadata; may be a tombstone. A format 2 record's carries no fingerprints.</summary>
    public RecordMetadata Metadata { get; }

    /// <summary>The secret, or null for a tombstone.</summary>
    public SecretInfo? Info => SecretInfo.From(Metadata);

    /// <summary>
    /// True when the record has a format 2 file (main or conflicted copy, by its cleartext format byte),
    /// so it was decoded whole. <see cref="RecordVaultStore.OpenSecret(string, byte[])"/> takes the
    /// whole-record path for that reason only; an unreadable or unusable file never sends it there.
    /// (A write also decodes a format 3 record whole when only plaintext can merge its copies; that
    /// entry is not format 2.)
    /// </summary>
    public bool IsFormatTwo { get; }

    /// <summary>
    /// The current value (or with <paramref name="previous"/> the value a rotation replaced), or
    /// null when there is none (a tombstone, or no previous value). Format 3: decrypts that one value
    /// section and checks it against its stored fingerprints; format 2: a copy of the decoded value.
    /// The caller zeroes the array. A section that can't be opened is an <see cref="UnreadableRecordException"/>.
    /// </summary>
    public byte[]? DecryptValue(bool previous)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_decoded is { } state)
        {
            if (state.Type == RecordType.Tombstone)
                return null;
            var value = previous ? state.Previous?.Value : state.Value;
            return value is null ? null : (byte[])value.Clone();
        }
        if (Metadata.Type == RecordType.Tombstone)
            return null;
        var version = previous ? Metadata.PreviousVersion : Metadata.Version;
        if (version is null)
            return null;
        return _store.OpenValueSection(_name, FileName, Metadata, version,
            previous ? Metadata.PreviousFingerprints : Metadata.Fingerprints, _sections!, _vaultKey);
    }

    /// <summary>Zeroes a format 2 record's decoded values and the held value sections.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        foreach (var record in _decodedInputs.Concat(_decoded is null ? [] : [_decoded]))
        {
            CryptographicOperations.ZeroMemory(record.Value);
            if (record.Previous is { } p)
                CryptographicOperations.ZeroMemory(p.Value);
        }
        foreach (var section in _sections?.Values ?? [])
            CryptographicOperations.ZeroMemory(section);
    }
}
