using System.Security.Cryptography;
using System.Text;
using TswapCore.Keyring;

namespace TswapCore;

/// <summary>
/// Brief T16-S2b: the vault as the write commands see it, decrypting no value they don't use. Each
/// name is opened once (<see cref="RecordVaultStore.OpenForWrite"/>: that record only, from its
/// metadata on format 3); operations are staged and written together by <see cref="Commit"/>,
/// which applies <see cref="RecordVaultStore.SaveSecrets"/>' rules record by record. The answers
/// and exception texts are <see cref="SecretsDb"/>'s.
/// <para>
/// <b>Unreadable records, one rule.</b> <see cref="Find"/> returns null for them, as
/// <see cref="SecretsDb"/> does; <see cref="ThrowIfUnreadable"/> and <see cref="Restore"/> throw
/// <see cref="SecretsDb.UnreadableRecordText"/> naming the file at once; <see cref="SetValue"/>,
/// <see cref="Burn"/> and <see cref="Delete"/> stage nothing for them and <see cref="Commit"/>
/// throws the first in ordinal name order before any write, as <see cref="RecordVaultStore.SaveSecrets"/>
/// throws while building its writes. Such a record is never skipped as absent or overwritten.
/// </para>
/// <para>
/// The writer holds a reference to the vault key (no copy). <see cref="Dispose"/> zeroes the opened
/// entries (held sections, a decoded record's values) and the values staged.
/// </para>
/// </summary>
public sealed class VaultWriter : IDisposable
{
    /// <summary>One opened record: its entry (null: no file), or the hashed file of a record that can't be read.</summary>
    private sealed record Opened(SecretEntry? Entry, string? UnreadableFile);

    private readonly RecordVaultStore _store;
    private readonly RecordVaultStore.WriteSession _session;
    private readonly Dictionary<string, Opened> _opened = new(StringComparer.Ordinal);
    private readonly Dictionary<string, PendingWrite> _staged = new(StringComparer.Ordinal);
    private readonly SortedDictionary<string, string> _unreadableStaged = new(StringComparer.Ordinal);
    private readonly List<byte[]> _values = [];
    private bool _committed;
    private bool _disposed;

    /// <param name="warnings">Where this command's findings about its records go (stderr in the CLI).</param>
    public VaultWriter(RecordVaultStore store, byte[] vaultKey, TextWriter? warnings)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(vaultKey);
        _store = store;
        _session = store.BeginWrite(vaultKey, warnings);
    }

    /// <summary>
    /// The secret <paramref name="name"/> from its record's metadata, or null when there is none (no
    /// record, a tombstone, or a record that can't be read: <see cref="ThrowIfUnreadable"/> tells
    /// those apart). Decrypts no value, except a format 2 record's, which can only be read whole.
    /// </summary>
    public SecretInfo? Find(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Open(name).Entry?.Info;
    }

    /// <summary><see cref="SecretsDb.ThrowIfUnreadable"/>: throws, naming the file, when <paramref name="name"/>'s record can't be read.</summary>
    public void ThrowIfUnreadable(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Open(name).UnreadableFile is { } file)
            throw new TswapException(SecretsDb.UnreadableRecordText(name, file));
    }

    /// <summary>
    /// Stages <paramref name="value"/> for <paramref name="name"/>: a new version when there is no
    /// live record, when <paramref name="always"/> (<c>rotate</c>, <c>ingest --rotate</c>), or
    /// when the value differs from the current one (<c>add</c>, decided at <see cref="Commit"/> from
    /// the stored fingerprints where they can tell). <paramref name="created"/> is used only when
    /// there is no live record; an imported burn is kept on the new version with its own time.
    /// </summary>
    public void SetValue(string name, string value, DateTime created, bool always = false,
        DateTime? importedBurnAt = null, string? importedBurnReason = null)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (Stageable(name) is not { } opened)
            return;
        var bytes = Encoding.UTF8.GetBytes(value);
        _values.Add(bytes);
        Stage(new ValueWrite(name, opened.Entry, bytes, always, Restored: false, created, importedBurnAt, importedBurnReason));
    }

    /// <summary>Stages a burn of <paramref name="name"/>'s current value (nothing is written when it is burned already).</summary>
    public void Burn(string name, string? reason)
    {
        if (Stageable(name) is { Entry: { } entry })
            Stage(new BurnWrite(name, entry, reason));
    }

    /// <summary>Stages a delete of <paramref name="name"/>: one tombstone for one name.</summary>
    public void Delete(string name)
    {
        if (Stageable(name) is { Entry: { } entry })
            Stage(new DeleteWrite(name, entry));
    }

    /// <summary>
    /// Stages <c>restore</c>: the previous value becomes the current one as a new version, its burns
    /// outstanding again. Throws <see cref="SecretsDb.ResolveToken"/>'s errors for <c>name:previous</c>,
    /// in its order (an unreadable record named at once, "not found", "no previous value"); then
    /// decrypts that one value (format 3: the previous value section only).
    /// </summary>
    public void Restore(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var opened = Open(name);
        if (opened.Entry?.Info is not { } info)
        {
            ThrowIfUnreadable(name);
            throw new TswapException($"Secret '{name}' not found");
        }
        if (!info.HasPrevious)
            throw new TswapException(
                $"'{name}{SecretsDb.PreviousSuffix}': secret '{name}' has no previous value (it has not been rotated since it was created).");
        byte[]? previous;
        try
        {
            previous = opened.Entry.DecryptValue(previous: true);
        }
        catch (UnreadableRecordException ex)
        {
            throw new TswapException(SecretsDb.UnreadableRecordText(name, ex.FileName));
        }
        if (previous is null)
            throw new TswapException($"Secret '{name}' not found");
        _values.Add(previous);
        Stage(new ValueWrite(name, opened.Entry, previous, Always: true, Restored: true, DateTime.UnixEpoch));
    }

    /// <summary>
    /// Writes everything staged: first the unreadable-record refusal (the ordinally first name),
    /// then every record checked against its bytes as opened, then the writes (nothing on any
    /// refusal). Returns the states written, by name (null: a tombstone); a name whose write
    /// changed nothing (<c>add</c> of the same value, a burn of a burned value) is absent.
    /// </summary>
    public IReadOnlyDictionary<string, SecretInfo?> Commit()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_committed)
            throw new InvalidOperationException("A vault writer commits once.");
        _committed = true;
        if (_unreadableStaged.Count > 0)
        {
            var (name, file) = _unreadableStaged.First();
            throw new TswapException(SecretsDb.UnreadableRecordText(name, file));
        }
        var written = _store.CommitWrites(_session, [.. _staged.Values]);
        ZeroValues();
        return written.ToDictionary(m => m.Name, SecretInfo.From, StringComparer.Ordinal);
    }

    /// <summary>
    /// Records opened so far whose files include a format 2 one, so they were decoded whole: the
    /// count the format 2 warning reports. A format 3 record decoded whole because only plaintext
    /// could merge its copies is not counted.
    /// </summary>
    public int FormatTwoDecoded => _opened.Values.Count(o => o.Entry is { IsFormatTwo: true });

    /// <summary>Zeroes every opened entry and every staged value.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        foreach (var opened in _opened.Values)
            opened.Entry?.Dispose();
        ZeroValues();
    }

    private void ZeroValues()
    {
        foreach (var value in _values)
            CryptographicOperations.ZeroMemory(value);
    }

    /// <summary>The opened record of a name that may be staged, or null when it can't be read (the error is kept for <see cref="Commit"/>).</summary>
    private Opened? Stageable(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_committed)
            throw new InvalidOperationException("This vault writer has committed already.");
        var opened = Open(name);
        if (opened.UnreadableFile is { } file)
        {
            _unreadableStaged.TryAdd(name, file);
            return null;
        }
        return opened;
    }

    private void Stage(PendingWrite write)
    {
        if (!_staged.TryAdd(write.Name, write))
            throw new InvalidOperationException($"'{write.Name}' is staged already.");
    }

    private Opened Open(string name)
    {
        if (_opened.TryGetValue(name, out var opened))
            return opened;
        try
        {
            opened = new Opened(_store.OpenForWrite(_session, name), null);
        }
        catch (UnreadableRecordException ex)
        {
            opened = new Opened(null, ex.FileName);
        }
        _opened[name] = opened;
        return opened;
    }
}
