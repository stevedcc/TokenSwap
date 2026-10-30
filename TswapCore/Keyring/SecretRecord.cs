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
public sealed record SecretRecord(
    byte[] RecordId,
    Stamp Write,
    RecordType Type,
    Stamp Version,
    string Name,
    long CreatedMs,
    byte[] Value,
    IReadOnlyList<BurnEntry> Burns)
{
    /// <summary>The outstanding burn: a burn of the winning version, when that version is a value.</summary>
    public BurnEntry? OutstandingBurn =>
        Type == RecordType.Tombstone ? null : Burns.FirstOrDefault(b => b.Version.Equals(Version));

    /// <summary>
    /// True when <paramref name="other"/> holds the same secret state (everything but the write
    /// stamp): what <c>vault merge</c> and the store compare to decide whether to write.
    /// </summary>
    public bool SameState(SecretRecord other) =>
        RecordId.AsSpan().SequenceEqual(other.RecordId)
        && Type == other.Type
        && Version.Equals(other.Version)
        && Name == other.Name
        && CreatedMs == other.CreatedMs
        && Value.AsSpan().SequenceEqual(other.Value)
        && Burns.SequenceEqual(other.Burns);
}
