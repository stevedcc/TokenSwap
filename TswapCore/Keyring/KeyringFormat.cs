namespace TswapCore.Keyring;

/// <summary>
/// Shared constants for the Phase 6 per-secret record wire format (design: see
/// <c>MULTI_MACHINE_KEYING.md</c> and <c>REFACTORING_PLAN.md</c> §Phase 6).
///
/// Deliberately fixed-binary, length-prefixed, explicitly-ordered — not
/// <see cref="System.Text.Json"/>. JSON gives no byte-stability guarantee across versions or
/// property reordering, and an incidental reordering would silently change every derived-key
/// and AAD computation downstream, bricking every vault written in this format with no
/// diagnosable cause. See <see cref="SecretRecordCodec"/> for the actual layout.
///
/// This is a NEW, separate format from the existing single-blob <see cref="Config"/> /
/// <see cref="Storage"/> vault (config.json + secrets.json.enc) — it does not replace or
/// change that format. Wiring a new <see cref="IVaultStore"/> implementation on top of this
/// format is a later wave (#119/#124); this module only defines the bytes.
/// </summary>
public static class KeyringFormat
{
    /// <summary>
    /// Format version of the per-secret record envelope (see <see cref="SecretRecordCodec"/>).
    /// Present from day one (issue #111) so a v2 layout change is an additive new version
    /// value, not a breaking rewrite of this constant's meaning.
    /// </summary>
    public const byte RecordFormatVersion = 1;

    /// <summary>
    /// 4-byte sanity marker at the start of every record file/blob. Distinguishes a
    /// corrupted/truncated file or a wrong-format file from a genuine decode failure, and is
    /// stable across format-version bumps (the version field, not the magic, carries version
    /// information) so old and new readers agree on where the real header starts.
    /// </summary>
    public static readonly byte[] RecordMagic = "TSR1"u8.ToArray();

    /// <summary>
    /// Every record's plaintext is padded to the next multiple of this many bytes before
    /// encryption (issue #113a), so raw ciphertext length reveals only a size bucket, not the
    /// exact secret length — and so a <see cref="RecordType.Tombstone"/> or
    /// <see cref="RecordType.Burned"/> record lands in the same buckets as a live
    /// <see cref="RecordType.Value"/> record of similar padded size, making deletion/burn
    /// events indistinguishable from ordinary edits by file size alone (issue #112).
    /// </summary>
    public const int PaddingBucketSize = 256;

    /// <summary>Byte length of a record id (raw HMAC-SHA256 output — see <see cref="FilenameHasher"/>).</summary>
    public const int RecordIdSize = 32;

    /// <summary>Byte length of an origin id (opaque per-machine/per-slot tiebreak identifier).</summary>
    public const int OriginIdSize = 16;
}
