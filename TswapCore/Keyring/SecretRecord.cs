namespace TswapCore.Keyring;

/// <summary>
/// One decoded per-secret record (issue #111/#112). This is the in-memory shape;
/// <see cref="SecretRecordCodec"/> owns the exact on-disk byte layout.
/// </summary>
/// <param name="RecordId">
/// Raw (non-hex) 32-byte identifier, shared with the filename hash (issue #114): both are
/// <c>HMAC(K_names, secretName)</c>. Reusing the same bytes avoids inventing a second
/// per-secret identifier, and lets the per-record key derivation (issue #113b) key off exactly
/// the value that already ties two synced copies of the same secret together.
/// </param>
/// <param name="WriteCounter">
/// The ordering authority (issue #112) — a per-item write counter, <b>not</b> a wall-clock
/// timestamp. Combined with <paramref name="OriginId"/> as a tiebreak, this is a Lamport clock:
/// UTC timestamps are unsafe across machines (clock skew, VM suspend/resume, manual clock
/// changes), but a counter+id pair is not, and it makes v2's HLC work an additive refinement
/// rather than a format break. Also feeds the per-record key derivation (issue #113b), which is
/// why it must be readable <i>before</i> decryption — see <see cref="SecretRecordCodec"/>.
/// </param>
/// <param name="OriginId">
/// Opaque 16-byte id of the machine/slot that produced this write — the tiebreak half of the
/// ordering authority, and the "last-writer id" a future generation-counter feature (issue
/// #118, not implemented here) can reuse rather than inventing its own field.
/// </param>
/// <param name="Timestamp">
/// Wall-clock time for <b>human display only</b> (e.g. <c>names</c> output) — never consulted
/// for ordering. See <see cref="WriteCounter"/> for why.
/// </param>
/// <param name="Type">Which of the three record kinds this is (issue #112).</param>
/// <param name="Value">
/// Type-dependent payload: the secret bytes for <see cref="RecordType.Value"/>, empty for
/// <see cref="RecordType.Tombstone"/>, the burn reason for <see cref="RecordType.Burned"/>.
/// </param>
/// <param name="GenerationCounter">
/// Reserved, always 0 in this format version. Placeholder field for the vault generation
/// counter (issue #118, a later wave) so that feature lands as an additive use of an
/// already-present field rather than a header layout change.
/// </param>
public sealed record SecretRecord(
    byte[] RecordId,
    ulong WriteCounter,
    byte[] OriginId,
    DateTimeOffset Timestamp,
    RecordType Type,
    byte[] Value,
    uint GenerationCounter = 0);
