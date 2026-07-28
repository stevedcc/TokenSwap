using System.Buffers.Binary;

namespace TswapCore.Keyring;

/// <summary>
/// Which role a <see cref="Slot"/> plays (issue #120, added on top of #119's single-kind
/// keyring). Explicit numeric values because <see cref="KeyringCodec"/> persists this as a raw
/// byte — never rely on declaration order.
/// </summary>
public enum SlotKind : byte
{
    /// <summary>An enrolled machine's slot (issue #119): wraps <c>K_v</c> plus that machine's
    /// own re-wrap-capable X25519 keypair (<see cref="SlotSecretPayload"/>) under a
    /// hardware-recovered <c>KEK_slot</c>.</summary>
    Machine = 0,

    /// <summary>A break-glass recovery slot (issue #120): wraps <c>K_v</c> alone to a bare X25519
    /// keypair's public key, no hardware and no PKI involved — see
    /// <see cref="RecoverySlotWrap"/> and <c>MULTI_MACHINE_KEYING.md</c> §The recovery slot.
    /// </summary>
    Recovery = 1,
}

/// <summary>
/// One entry in a vault's <see cref="Keyring"/> (issue #119, design: <c>MULTI_MACHINE_KEYING.md</c>
/// §The model / §Two-layer slot wrap / §Per-slot X25519 keypair). A slot is one machine's share
/// of the vault: an opaque identifier, an X25519 public key kept in the clear (so any holder of
/// <c>K_v</c> can wrap a fresh slot for this device offline — see the design doc), and the
/// AEAD-wrapped payload (<see cref="SlotPayloadWrap"/> around a <see cref="SlotSecretPayload"/>)
/// that recovers <c>K_v</c> plus this slot's own X25519 private key once its <c>KEK_slot</c> is
/// available.
///
/// <para><b><see cref="Kind"/> (issue #120).</b> Added additively — exactly the kind of change
/// this type's original doc comment anticipated ("appending a new field after
/// <see cref="Wrapped"/>... is a mechanical, backward-compatible change, not a redesign").
/// Defaults to <see cref="SlotKind.Machine"/> so every existing 3-argument <c>Slot(...)</c> call
/// site (#119's tests, <c>InitCommand</c>'s machine-slot construction) keeps compiling and keeps
/// meaning exactly what it meant before this field existed.</para>
///
/// <para><b><see cref="PublicKey"/> means something different per <see cref="Kind"/>.</b> For a
/// <see cref="SlotKind.Machine"/> slot it is that machine's own long-lived X25519 public key (as
/// #119 defined it). For a <see cref="SlotKind.Recovery"/> slot it is instead the
/// <b>wrap-time ephemeral</b> X25519 public key <see cref="RecoverySlotWrap.Wrap"/> generates and
/// discards the private half of — stored here so the recovery private key's holder can redo the
/// same ECDH later (see <see cref="RecoverySlotWrap.Unwrap"/>). The two meanings never collide
/// because a given slot is only ever one kind, and repurposing the field this way avoids adding a
/// second 32-byte column that would sit empty for every other slot kind.</para>
///
/// <para><b>No per-slot hardware blob field.</b> The design doc's slot sketch includes a
/// <c>hwBlob: backendWrap(KEK_slot)</c> field alongside <c>wrapped</c>. For this issue
/// (YubiKey only, one slot), that role is already filled by <see cref="Config"/>'s existing
/// <c>YubiKeySerials</c>/<c>RedundancyXor</c>/<c>UnlockChallenge</c>/<c>MasterKeySalt</c>
/// fields — <see cref="Vault.YubiKeyHardwareService.Unlock"/> already recovers
/// <c>KEK_slot</c> from those (see <c>HARDWARE_BACKENDS.md</c>'s "no interface change needed"
/// point). Adding a redundant per-slot <c>hwBlob</c> here would just duplicate what
/// <see cref="Config"/> already carries at the vault level. A second, non-YubiKey backend
/// (design doc's v0 step 2) is exactly where a real per-slot <c>hwBlob</c> becomes necessary,
/// since Config has no vault-wide equivalent for a TPM/Secure-Enclave-wrapped KEK_slot — that
/// is deliberately deferred, not overlooked. A recovery slot has no hardware at all, by design.
/// </para>
///
/// <para><b>Deliberately minimal otherwise.</b> No <c>label</c>/<c>backend</c>/<c>enrolledAt</c>
/// fields. Every field a future <c>slots</c> listing (#123) or fingerprint display (#122) would
/// want is either derivable from context that doesn't exist yet (there is exactly one machine,
/// one backend, per vault right now) or is an additive field this format can grow later without
/// touching what's already here — appending a new field after <see cref="Wrapped"/> in
/// <see cref="KeyringCodec"/>'s slot layout is a mechanical, backward-compatible change, not a
/// redesign.</para>
/// </summary>
public sealed record Slot(byte[] SlotId, byte[] PublicKey, byte[] Wrapped, SlotKind Kind = SlotKind.Machine);

/// <summary>
/// A vault's keyring (issue #119): the format version and vault id that feed every slot's AEAD
/// associated data (see <see cref="SlotPayloadWrap.BuildAad"/>), the unlock threshold <c>k</c>
/// (always 1 in v0 — see <c>MULTI_MACHINE_KEYING.md</c> §Why not k >= 2), and the list of slots
/// (always exactly one in v0, this machine's; #121 is where a second machine's slot gets
/// appended via hand-carried enrollment).
/// </summary>
public sealed record Keyring(byte FormatVersion, byte[] VaultId, byte K, IReadOnlyList<Slot> Slots);

/// <summary>
/// Encodes/decodes a <see cref="Keyring"/> to/from the fixed-binary blob stored (base64) in
/// <see cref="Config.Keyring"/>. Fixed-binary, length-prefixed, explicitly ordered — not JSON —
/// for the exact reason <see cref="KeyringFormat"/>'s doc comment gives for the per-secret
/// record format: this structure's own bytes (<c>vaultId</c>, <c>k</c>, each slot's
/// <c>slotId</c>) directly feed <see cref="SlotPayloadWrap"/>'s AAD, so an incidental JSON
/// reordering or whitespace change would silently change every AAD computation and brick every
/// keyring vault on disk with no diagnosable cause.
///
/// <para><b>On-disk layout</b> (all multi-byte integers little-endian, matching
/// <see cref="SecretRecordCodec"/>'s convention):</para>
/// <code>
/// formatVersion   1 byte    KeyringFormat.KeyringFormatVersion
/// vaultId         KeyringFormat.VaultIdSize bytes (16)
/// k               1 byte
/// slotCount       4 bytes
/// slots[slotCount]:
///   slotId          KeyringFormat.SlotIdSize bytes (16)
///   publicKey       SlotKeyPair.KeySize bytes (32)
///   wrappedLength   4 bytes
///   wrapped         wrappedLength bytes
///   kind            1 byte    SlotKind (issue #120)
/// </code>
///
/// <para>v0 always writes exactly one slot; <c>slotCount</c> is still explicit (not assumed to
/// be 1) so a future multi-slot keyring (#121) is purely an additive change to how many times
/// the slot loop below runs, not a format bump.</para>
///
/// <para><b><c>kind</c> (issue #120):</b> appended after <c>wrapped</c> rather than inserted
/// earlier in the per-slot layout, exactly the additive placement <see cref="Slot"/>'s own doc
/// comment anticipated. This is a deliberate, called-out change to bytes #119's
/// <c>KeyringCodecTests</c> golden-byte assertions pinned — not a silent drift — see this
/// issue's PR body for why: a discriminator became necessary once a keyring could hold more than
/// one kind of slot, and there was no way to add it without changing what <see cref="Encode"/>
/// emits for every slot, including #119's original single-machine-slot shape.</para>
/// </summary>
public static class KeyringCodec
{
    // formatVersion(1) + vaultId + k(1) + slotCount(4)
    private const int HeaderSize = 1 + KeyringFormat.VaultIdSize + 1 + 4;

    // slotId + publicKey + wrappedLength(4)
    private const int SlotHeaderSize = KeyringFormat.SlotIdSize + SlotKeyPair.KeySize + 4;

    // kind, appended after the variable-length wrapped bytes.
    private const int SlotKindSize = 1;

    /// <summary>
    /// Encodes <paramref name="keyring"/>. Throws <see cref="ArgumentException"/> (a programmer
    /// error, not a data-corruption case) if <see cref="Keyring.VaultId"/> or any slot's
    /// <see cref="Slot.SlotId"/>/<see cref="Slot.PublicKey"/> is the wrong fixed width.
    /// </summary>
    public static byte[] Encode(Keyring keyring)
    {
        if (keyring.VaultId.Length != KeyringFormat.VaultIdSize)
            throw new ArgumentException($"VaultId must be {KeyringFormat.VaultIdSize} bytes", nameof(keyring));

        var totalSize = HeaderSize;
        foreach (var slot in keyring.Slots)
        {
            if (slot.SlotId.Length != KeyringFormat.SlotIdSize)
                throw new ArgumentException($"SlotId must be {KeyringFormat.SlotIdSize} bytes", nameof(keyring));
            if (slot.PublicKey.Length != SlotKeyPair.KeySize)
                throw new ArgumentException($"PublicKey must be {SlotKeyPair.KeySize} bytes", nameof(keyring));
            totalSize += SlotHeaderSize + slot.Wrapped.Length + SlotKindSize;
        }

        var result = new byte[totalSize];
        var span = result.AsSpan();
        span[0] = keyring.FormatVersion;
        keyring.VaultId.CopyTo(span.Slice(1, KeyringFormat.VaultIdSize));
        span[1 + KeyringFormat.VaultIdSize] = keyring.K;
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(2 + KeyringFormat.VaultIdSize, 4), (uint)keyring.Slots.Count);

        var offset = HeaderSize;
        foreach (var slot in keyring.Slots)
        {
            slot.SlotId.CopyTo(span.Slice(offset, KeyringFormat.SlotIdSize));
            offset += KeyringFormat.SlotIdSize;
            slot.PublicKey.CopyTo(span.Slice(offset, SlotKeyPair.KeySize));
            offset += SlotKeyPair.KeySize;
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), (uint)slot.Wrapped.Length);
            offset += 4;
            slot.Wrapped.CopyTo(span.Slice(offset, slot.Wrapped.Length));
            offset += slot.Wrapped.Length;
            span[offset] = (byte)slot.Kind;
            offset += SlotKindSize;
        }

        return result;
    }

    /// <summary>
    /// Decodes a keyring previously produced by <see cref="Encode"/>. Throws
    /// <see cref="TswapException"/> — never a raw slicing/index exception — for a truncated
    /// header, a truncated slot header, or a length prefix (<c>slotCount</c> implied bytes, or
    /// an individual slot's <c>wrappedLength</c>) that exceeds the data actually available.
    /// Bounds checks are subtraction-based, not addition-based (<c>x > bytes.Length - offset</c>,
    /// not <c>offset + x > bytes.Length</c>) — see <see cref="SecretRecordCodec.Decode"/>'s own
    /// comment on why an addition-based check can overflow and silently pass for an
    /// attacker-controlled length near <see cref="uint.MaxValue"/>.
    /// </summary>
    public static Keyring Decode(byte[] bytes)
    {
        if (bytes.Length < HeaderSize)
            throw new TswapException("Malformed keyring: shorter than the header");

        var formatVersion = bytes[0];
        var vaultId = bytes.AsSpan(1, KeyringFormat.VaultIdSize).ToArray();
        var k = bytes[1 + KeyringFormat.VaultIdSize];
        var slotCount = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(2 + KeyringFormat.VaultIdSize, 4));

        var slots = new List<Slot>();
        var offset = HeaderSize;
        for (uint i = 0; i < slotCount; i++)
        {
            if (SlotHeaderSize > bytes.Length - offset)
                throw new TswapException("Malformed keyring: truncated slot header");

            var slotId = bytes.AsSpan(offset, KeyringFormat.SlotIdSize).ToArray();
            offset += KeyringFormat.SlotIdSize;
            var publicKey = bytes.AsSpan(offset, SlotKeyPair.KeySize).ToArray();
            offset += SlotKeyPair.KeySize;
            var wrappedLength = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
            offset += 4;

            if (wrappedLength > bytes.Length - offset)
                throw new TswapException("Malformed keyring: wrapped-slot length prefix exceeds available data");

            var wrapped = bytes.AsSpan(offset, (int)wrappedLength).ToArray();
            offset += (int)wrappedLength;

            if (SlotKindSize > bytes.Length - offset)
                throw new TswapException("Malformed keyring: truncated slot kind");

            var kindByte = bytes[offset];
            if (kindByte != (byte)SlotKind.Machine && kindByte != (byte)SlotKind.Recovery)
                throw new TswapException($"Malformed keyring: unknown slot kind {kindByte}");
            offset += SlotKindSize;

            slots.Add(new Slot(slotId, publicKey, wrapped, (SlotKind)kindByte));
        }

        return new Keyring(formatVersion, vaultId, k, slots);
    }
}
