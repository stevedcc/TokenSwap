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

    /// <summary>
    /// Byte length of a vault id (opaque, randomly generated once at vault init — see
    /// <see cref="Keyring.SlotPayloadWrap"/>'s AAD binding, issue #117). 16 bytes (128 bits) is
    /// not a security boundary — a vaultId is not secret, and each slot's AEAD binding already
    /// means an attacker can't substitute a different vault's slot without possessing that
    /// slot's <c>KEK_slot</c> — it is sized purely so two independently-created vaults collide
    /// with negligible probability, the same reasoning as a random UUID/GUID (also 16 bytes).
    /// </summary>
    public const int VaultIdSize = 16;

    /// <summary>
    /// Byte length of a slot id (opaque per-slot identifier, generated once when a slot is
    /// enrolled — see <see cref="Keyring.SlotPayloadWrap"/>'s AAD binding, issue #117). Same
    /// size and rationale as <see cref="OriginIdSize"/>, whose doc comment already anticipates
    /// this exact "per-slot identifier" use; kept as its own constant rather than reusing
    /// <see cref="OriginIdSize"/> directly because the two name different things at different
    /// layers — a slot id identifies an AEAD-bound keyring entry, an origin id identifies a
    /// per-record last-writer tiebreak — and nothing requires their sizes to move together if
    /// either one changes later.
    /// </summary>
    public const int SlotIdSize = 16;

    /// <summary>
    /// Format version of the Phase 6 keyring envelope (<see cref="Keyring"/>/<see cref="Slot"/>,
    /// issue #119) — the value stored in <see cref="Keyring.FormatVersion"/> and fed into
    /// <see cref="Keyring.SlotPayloadWrap"/>'s AAD as its <c>formatVersion</c> parameter.
    /// Deliberately a separate constant from <see cref="RecordFormatVersion"/>: that one
    /// versions the per-secret record envelope (issues #111-#115), a completely different wire
    /// format this issue does not touch — bumping one must never accidentally bump the other.
    /// </summary>
    public const byte KeyringFormatVersion = 1;

    /// <summary>
    /// Byte length of the vault master key <c>K_v</c> — 256 bits, the same size as
    /// <see cref="Keyring.SlotKeyPair.KeySize"/> (an X25519 key) and the AES-256 key
    /// <see cref="SecretRecordCodec"/> already uses elsewhere. Not a coincidence:
    /// <see cref="Keyring.SlotSecretPayload"/> relies on both halves of its payload being
    /// exactly 32 bytes so <c>vaultKey || slotPrivateKey</c> concatenates into one unambiguous
    /// fixed-width blob with no length prefix needed.
    /// </summary>
    public const int VaultKeySize = 32;
}
