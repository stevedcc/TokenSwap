using TswapCore.Keyring;

namespace TswapCore.Fields;

/// <summary>
/// The registry of record extension types (<see cref="RecordExtension.Type"/>). Every type a build
/// defines is listed here, so a new one can't collide with it.
/// <list type="bullet">
/// <item><c>0x0100</c> <see cref="Type"/>: a secret's plain fields (issue #311, <see cref="FieldsCodec"/>).</item>
/// <item><c>0x0101</c> <see cref="TswapCore.Totp.ValueKinds.Type"/>: which retained versions are otpauth values (brief T58, #374).</item>
/// </list>
/// Taken by tests as types no build defines (they must stay unknown): <c>0x0001</c>, <c>0x0002</c>,
/// <c>0x0005</c>, <c>0x0102</c>, <c>0x7000</c>, <c>0x7777</c>, <c>0xFFFF</c>.
/// </summary>
public static class FieldsExtension
{
    /// <summary>The <c>Fields</c> extension: one <see cref="FieldSet"/>, encoded by <see cref="FieldsCodec"/>.</summary>
    public const ushort Type = 0x0100;
}

/// <summary>
/// Who made a field change, as far as tswap can tell (spec guard rail 3): a history, not an
/// authentication.
/// </summary>
/// <param name="Origin">The machine's origin id, short form: its first 8 hex digits, as <see cref="Stamp.ToString"/> shows it.</param>
/// <param name="User">The operating-system user name (under sudo, the invoking user), or null when unknown.</param>
/// <param name="Elevated">Whether the process ran elevated (sudo or Administrator).</param>
/// <param name="Terminal">Whether a terminal was attached.</param>
/// <param name="By">The self-asserted <c>--by</c> label, or null.</param>
public sealed record FieldWho(string Origin, string? User, bool Elevated, bool Terminal, string? By);

/// <summary>
/// A replaced state of a field: the value it had (null: it was a delete marker), the stamp that value
/// was set at and who set it. Its identity is (<see cref="Changed"/>, <see cref="FieldWho.Origin"/>).
/// </summary>
public sealed record FieldChange(string? OldValue, Stamp Changed, FieldWho Who);

/// <summary>
/// One field of a secret, or the marker of a deleted one (<see cref="Deleted"/>, <see cref="Value"/>
/// null), with its change stamp, who changed it and its last replaced states, newest first (at most
/// <see cref="FieldsCodec.MaxHistory"/>).
/// </summary>
public sealed record FieldEntry(string Name, string? Value, bool Deleted, Stamp Changed, FieldWho Who, IReadOnlyList<FieldChange> History)
{
    public bool Equals(FieldEntry? other) =>
        other is not null && Name == other.Name && Value == other.Value && Deleted == other.Deleted
        && Changed.Equals(other.Changed) && Who.Equals(other.Who) && History.SequenceEqual(other.History);

    public override int GetHashCode() => HashCode.Combine(Name, Value, Deleted, Changed, Who, History.Count);
}

/// <summary>
/// The fields of one secret (issue #311): the lineage stamp <see cref="Since"/> (the
/// <see cref="SecretRecord.Version"/> the secret was created at; entries stamped before it belong to
/// an earlier life of the name) and the entries, delete markers included.
/// </summary>
public sealed record FieldSet(Stamp Since, IReadOnlyList<FieldEntry> Entries)
{
    /// <summary>The fields that have a value (no delete markers).</summary>
    public IEnumerable<FieldEntry> Live => Entries.Where(e => !e.Deleted);

    /// <summary>The entry named <paramref name="name"/>, a delete marker included, or null.</summary>
    public FieldEntry? Get(string name) => Entries.FirstOrDefault(e => e.Name == name);

    public bool Equals(FieldSet? other) =>
        other is not null && Since.Equals(other.Since) && Entries.SequenceEqual(other.Entries);

    public override int GetHashCode() => HashCode.Combine(Since, Entries.Count);
}
