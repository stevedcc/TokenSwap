using TswapCore.Fingerprints;

namespace TswapCore.Keyring;

/// <summary>
/// One burn of one value version (brief T6 decision 4): the version it was issued against (that
/// value's <see cref="SecretRecord.Version"/> stamp), its own burn stamp (the burn time is the
/// stamp's physical part) and the reason. A burn of the version that is still the winner is the
/// secret's outstanding burn; any other burn is history.
/// </summary>
public sealed record BurnEntry(Stamp Version, Stamp Burn, string? Reason)
{
    public bool Equals(BurnEntry? other) =>
        other is not null && Version.Equals(other.Version) && Burn.Equals(other.Burn) && Reason == other.Reason;

    public override int GetHashCode() => HashCode.Combine(Version, Burn, Reason);
}

/// <summary>
/// Fix round 1, B (owner decision 2026-10-30): the value a rotation replaced, one level, with that
/// value's version stamp (so a restore can find its burn). Inside the encrypted payload.
/// Brief T16-S1: <paramref name="Fingerprints"/> are that value's fingerprints (record format v3),
/// or null when it has none yet (read from a v2 record, or not computed).
/// </summary>
public sealed record PreviousValue(Stamp Version, byte[] Value, FingerprintSet? Fingerprints = null)
{
    public bool Equals(PreviousValue? other) =>
        other is not null && Version.Equals(other.Version) && Value.AsSpan().SequenceEqual(other.Value)
        && Equals(Fingerprints, other.Fingerprints);

    public override int GetHashCode() => HashCode.Combine(Version, Value.Length);
}

/// <summary>
/// Brief T16-S1 (ruling 6): one entry of a v3 metadata section's extension list. This build defines
/// no extension type; it keeps the ones it doesn't know byte for byte on every rewrite, so data a
/// later build adds (tags, #221) survives an older machine's merges and burns.
/// </summary>
public sealed record RecordExtension(ushort Type, byte[] Data)
{
    public bool Equals(RecordExtension? other) =>
        other is not null && Type == other.Type && Data.AsSpan().SequenceEqual(other.Data);

    public override int GetHashCode() => HashCode.Combine(Type, Data.Length);

    public override string ToString() => $"RecordExtension(0x{Type:x4}, {Data.Length} bytes)";
}

/// <summary>
/// One decoded per-secret record (issues #111-#113, brief T6 decisions 3 and 4): the whole merged
/// state of one secret, so one file is enough to merge against any other copy of it.
/// <see cref="SecretRecordCodec"/> owns the exact on-disk byte layout.
/// </summary>
/// <param name="RecordId">
/// Raw 32-byte <c>HMAC(K_names, name)</c>, shared with the filename (issue #114); also the HKDF
/// salt prefix of the per-record key (issue #113b).
/// </param>
/// <param name="Write">
/// The stamp of this file write (any action: value, delete, burn, or a merge). In the cleartext
/// header and authenticated as associated data, because the per-record key is derived from it.
/// Never consulted to decide which value wins: that is <paramref name="Version"/>.
/// </param>
/// <param name="Type">
/// <see cref="RecordType.Tombstone"/> when the winning version is a delete;
/// <see cref="RecordType.Burned"/> when it is a value with an outstanding burn; otherwise
/// <see cref="RecordType.Value"/>. Inside the encrypted payload, never visible to the transport.
/// </param>
/// <param name="Version">
/// The stamp of the value or delete that decides existence (decision 4: the last action wins by
/// (HLC, origin), for values and tombstones alike).
/// </param>
/// <param name="Name">The plaintext secret name (inside the encrypted payload only).</param>
/// <param name="CreatedMs">When the secret was first created (display only, Unix ms).</param>
/// <param name="Value">The secret bytes (UTF-8); empty for a tombstone.</param>
/// <param name="Burns">
/// The outstanding burn (if any) and the bounded burn history (at most
/// <see cref="RecordMerge.MaxBurns"/> entries), in canonical order (see <see cref="RecordMerge"/>).
/// </param>
/// <param name="Previous">
/// The value this version replaced (fix round 1, B), or null (a first value, or a tombstone).
/// It travels with its version in a merge: no merge rule of its own.
/// </param>
public sealed record SecretRecord(
    byte[] RecordId,
    Stamp Write,
    RecordType Type,
    Stamp Version,
    string Name,
    long CreatedMs,
    byte[] Value,
    IReadOnlyList<BurnEntry> Burns,
    PreviousValue? Previous = null)
{
    /// <summary>
    /// Brief T16-S1: the fingerprints of <see cref="Version"/>'s value (record format v3), or null
    /// when it has none (a tombstone, a record read from format 2, or not computed yet).
    /// </summary>
    public FingerprintSet? Fingerprints { get; init; }

    /// <summary>Brief T16-S1 (ruling 6): the metadata extensions, kept byte for byte (default none).</summary>
    public IReadOnlyList<RecordExtension> Extensions { get; init; } = [];

    /// <summary>
    /// Brief T16-S1 (ruling 1): the v3 value sections as read, by version stamp (each one's
    /// <c>nonce | tag | ciphertext</c>), or null. A write copies a retained version's section from
    /// here byte for byte instead of encrypting it again, so a value section is encrypted once by
    /// the machine that creates (or converts) its version. Not part of <see cref="SameState"/>: two
    /// sections of one plaintext are the same state (<see cref="RecordMerge.MergeAll"/> picks one).
    /// </summary>
    public IReadOnlyDictionary<Stamp, byte[]>? Sealed { get; init; }

    /// <summary>The outstanding burn: a burn of the winning version, when that version is a value.</summary>
    public BurnEntry? OutstandingBurn =>
        Type == RecordType.Tombstone ? null : Burns.FirstOrDefault(b => b.Version.Equals(Version));

    /// <summary>
    /// True when <paramref name="other"/> holds the same secret state (everything but the write
    /// stamp and the sealed sections): what <c>vault merge</c> and the store compare to decide
    /// whether to write. Brief T16-S1: fingerprints (current and previous) and extensions are state.
    /// </summary>
    public bool SameState(SecretRecord other) =>
        RecordId.AsSpan().SequenceEqual(other.RecordId)
        && Type == other.Type
        && Version.Equals(other.Version)
        && Name == other.Name
        && CreatedMs == other.CreatedMs
        && Value.AsSpan().SequenceEqual(other.Value)
        && Burns.SequenceEqual(other.Burns)
        && Equals(Previous, other.Previous)
        && Equals(Fingerprints, other.Fingerprints)
        && Extensions.SequenceEqual(other.Extensions);
}
