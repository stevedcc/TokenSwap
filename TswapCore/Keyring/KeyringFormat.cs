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
    ///
    /// <para><b>Bumped 1 -> 2 (issue #120).</b> Issue #120 appends a per-slot <c>kind</c> byte
    /// to <see cref="KeyringCodec"/>'s slot layout (see that type's "kind (issue #120)" doc
    /// section). That change is additive at the <em>type</em> level — <see cref="Slot"/>'s
    /// <c>Kind</c> field has a default, so existing 3-argument <c>Slot(...)</c> call sites keep
    /// compiling — but it is <em>not</em> additive at the serialized-<em>byte</em> level: every
    /// slot, including one that only ever used #119's original fields, now has one extra
    /// trailing byte it did not have before. A reader built against #119's original layout
    /// (pre-#120) would misinterpret or truncate-fail on #120-shaped bytes, and vice versa, so
    /// this is a breaking wire-format change requiring a version bump like any other, not merely
    /// an additive one that could keep version 1. <see cref="KeyringCodec.Decode"/> checks this
    /// constant explicitly (mirroring <see cref="SecretRecordCodec.Decode"/>'s existing
    /// <c>formatVersion</c> check) so a future format change is never silently misread again.
    /// </para>
    ///
    /// <para><b>Bumped 2 -> 3 (issue #154, brief T2 decision 3).</b> Each slot gains a trailing
    /// length-prefixed <c>hwBlob</c> (see <see cref="KeyringCodec"/>'s layout): the TPM or Secure
    /// Enclave backend's sealed/wrapped <c>KEK_slot</c>, moved out of the unversioned
    /// <see cref="Config.TpmSealedKey"/>/<see cref="Config.SecureEnclaveWrappedKey"/> fields so it is
    /// versioned by this value, which every slot's AEAD binds. Like #120's change this is breaking
    /// at the byte level, so it is a version bump. Unlike #120's, the previous version stays
    /// readable: YubiKey keyring vaults made since Phase 6 are version 2 and in use, so
    /// <see cref="KeyringCodec.Decode"/> reads <see cref="KeyringFormatVersionWithoutHwBlob"/> (2)
    /// and this version, and <see cref="KeyringCodec.Encode"/> writes either. A keyring keeps its
    /// version for life, since the version is in every slot's associated data (see
    /// <see cref="KeyringCodec"/>); new keyrings are created as this version.</para>
    /// </summary>
    public const byte KeyringFormatVersion = 3;

    /// <summary>
    /// The previous keyring format version (issues #120 to #123): the same layout as
    /// <see cref="KeyringFormatVersion"/> minus the per-slot <c>hwBlob</c> column. Such a keyring
    /// only ever has YubiKey machine slots and recovery slots. Still read and written (for vaults
    /// that already use it), never chosen for a new keyring.
    /// </summary>
    public const byte KeyringFormatVersionWithoutHwBlob = 2;

    /// <summary>
    /// Upper bound on a slot's hwBlob accepted from a hand-carried approve file. The largest real
    /// blob is the Secure Enclave's, about 560 bytes (a ~430-byte key <c>dataRepresentation</c>,
    /// a 4-byte prefix, and a 125-byte ECIES package); the Windows PCP bundle is about 310 bytes
    /// and the Linux TPM sealed public + private about 300. 4096 leaves roughly 7x headroom.
    /// </summary>
    public const int MaxHwBlobSize = 4096;

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
