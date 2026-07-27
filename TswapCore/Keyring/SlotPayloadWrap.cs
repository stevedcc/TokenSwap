using System.Security.Cryptography;

namespace TswapCore.Keyring;

/// <summary>
/// The AEAD "wrap" half of the Phase 6 two-layer slot scheme (issues #116/#117 — see
/// <c>MULTI_MACHINE_KEYING.md</c> §Two-layer slot wrap and §AAD binding).
///
/// <para>Given a 32-byte per-slot key-encryption-key (<c>KEK_slot</c> — recovered however a
/// backend's own wrap/seal primitive or <see cref="Vault.IHardwareKeyService.Unlock"/> produces
/// it; this layer neither knows nor cares) and an opaque payload (in v0, eventually <c>K_v</c>
/// itself, but nothing here assumes a specific payload shape or length), this type AES-256-GCM
/// encrypts/decrypts the payload with associated data binding <c>formatVersion</c>,
/// <c>vaultId</c>, <c>k</c>, and <c>slotId</c> — see <see cref="BuildAad"/> for the exact
/// layout. Binding these fields into the AEAD is the <b>primary</b> defense against threshold
/// downgrade: an attacker holding the synced files plus one enrolled device cannot silently
/// rewrite <c>k = 2 -&gt; k = 1</c> (or swap in a different vault's slot, or replay an old
/// <c>formatVersion</c>) because a mismatch on any bound field makes the AEAD unwrap itself
/// fail, and fixing that up requires re-wrapping every slot — which needs every enrolled device
/// physically present.</para>
///
/// <para><b>Why AES-256-GCM called directly here, not <see cref="Crypto.Encrypt"/>/
/// <see cref="Crypto.Decrypt"/>:</b> those two do not expose <see cref="AesGcm"/>'s
/// associated-data parameter at all (they call the no-AAD overload) and remain unchanged for
/// their existing callers (the single-blob vault format, export/import) — this type calls
/// <see cref="AesGcm"/>'s associated-data overloads directly instead of touching them.</para>
///
/// <para><b>Why not XOR:</b> XOR only made sense while <c>K_v</c> was itself *derived* from
/// hardware (today's YubiKey-pair scheme, see <see cref="Crypto.DeriveKey"/>). Under two-layer
/// slots — where each slot independently wraps a fresh, unrelated <c>KEK_slot</c> — XOR would
/// need a public <c>K1 ⊕ K2</c> share alongside it, which is isomorphic to wrapping <c>K_v</c>
/// directly per slot plus an extra derivation step and a one-time-pad reuse hazard on rotation
/// (see the design doc's "The landmine"). AES-256-GCM is strictly less code with no such
/// hazard, so this type never touches <see cref="Crypto.XorBytes"/>.</para>
/// </summary>
public static class SlotPayloadWrap
{
    /// <summary>Required length of <c>KEK_slot</c>, the AES-256 key this layer wraps under.</summary>
    public const int KekSlotSize = 32;

    /// <summary>
    /// AES-256-GCM encrypts <paramref name="payload"/> under <paramref name="kekSlot"/>, with
    /// associated data built from <paramref name="formatVersion"/>, <paramref name="vaultId"/>,
    /// <paramref name="k"/>, and <paramref name="slotId"/> (see <see cref="BuildAad"/>).
    ///
    /// <para>Output layout mirrors <see cref="Crypto.Encrypt"/>: <c>nonce(12) || tag(16) ||
    /// ciphertext</c>, both nonce and tag at AES-GCM's max sizes, nonce freshly random per
    /// call.</para>
    /// </summary>
    public static byte[] Wrap(byte[] payload, byte[] kekSlot, byte formatVersion, byte[] vaultId, byte k, byte[] slotId)
    {
        ValidateKekSlot(kekSlot);
        var aad = BuildAad(formatVersion, vaultId, k, slotId);

        var nonceSize = AesGcm.NonceByteSizes.MaxSize;
        var tagSize = AesGcm.TagByteSizes.MaxSize;
        using var aes = new AesGcm(kekSlot, tagSize);

        var result = new byte[nonceSize + tagSize + payload.Length];
        var nonce = result.AsSpan(0, nonceSize);
        var tag = result.AsSpan(nonceSize, tagSize);
        var ciphertext = result.AsSpan(nonceSize + tagSize);

        RandomNumberGenerator.Fill(nonce);
        aes.Encrypt(nonce, payload, ciphertext, tag, aad);
        return result;
    }

    /// <summary>
    /// Decrypts and authenticates a value previously produced by <see cref="Wrap"/>. Throws
    /// <see cref="TswapException"/> — never a raw BCL exception — for:
    /// <list type="bullet">
    /// <item><paramref name="wrapped"/> shorter than AES-GCM's fixed nonce+tag overhead (checked
    /// before any AesGcm call is reached, the same lesson <see cref="SecretRecordCodec.Decode"/>
    /// already applies to its own length-prefixed payload field);</item>
    /// <item>a wrong <paramref name="kekSlot"/>, tampered ciphertext, or any AAD-bound field
    /// (<paramref name="formatVersion"/>, <paramref name="vaultId"/>, <paramref name="k"/>,
    /// <paramref name="slotId"/>) not matching what <see cref="Wrap"/> was called with — these
    /// all surface identically as an AES-GCM authentication failure by design: an attacker
    /// rewriting a bound field (e.g. downgrading <c>k</c>) cannot distinguish "wrong key" from
    /// "tampered AAD" from the failure alone (see the design doc's "The landmine").</item>
    /// </list>
    /// </summary>
    public static byte[] Unwrap(byte[] wrapped, byte[] kekSlot, byte formatVersion, byte[] vaultId, byte k, byte[] slotId)
    {
        ValidateKekSlot(kekSlot);

        var nonceSize = AesGcm.NonceByteSizes.MaxSize;
        var tagSize = AesGcm.TagByteSizes.MaxSize;
        var minSize = nonceSize + tagSize;

        if (wrapped.Length < minSize)
            throw new TswapException("Malformed slot wrap: shorter than AES-GCM's minimum nonce+tag overhead");

        var aad = BuildAad(formatVersion, vaultId, k, slotId);

        var nonce = wrapped.AsSpan(0, nonceSize);
        var tag = wrapped.AsSpan(nonceSize, tagSize);
        var ciphertext = wrapped.AsSpan(minSize);

        var payload = new byte[ciphertext.Length];
        using var aes = new AesGcm(kekSlot, tagSize);

        try
        {
            aes.Decrypt(nonce, ciphertext, tag, payload, aad);
        }
        catch (CryptographicException ex)
        {
            throw new TswapException(
                "Slot unwrap failed: authentication check failed (wrong kekSlot, tampered ciphertext, " +
                "or a formatVersion/vaultId/k/slotId mismatch)", ex.HResult);
        }

        return payload;
    }

    /// <summary>
    /// Builds the fixed-binary associated data for the slot AEAD layer (issue #117):
    /// <c>formatVersion(1) || vaultId(<see cref="KeyringFormat.VaultIdSize"/>) || k(1) ||
    /// slotId(<see cref="KeyringFormat.SlotIdSize"/>)</c>, explicit field order, deliberately not
    /// JSON — see <see cref="KeyringFormat"/>'s doc comment for why (an incidental reordering
    /// would silently change every AAD computation with no diagnosable cause).
    ///
    /// <para>Every field here has a fixed, format-version-pinned width (a single byte, or a
    /// byte array whose exact length <see cref="KeyringFormat"/> constants pin), so — unlike
    /// <see cref="SecretRecordCodec"/>'s envelope, which has genuinely variable-length fields
    /// and needs explicit length prefixes to stay unambiguous — concatenating these fixed-width
    /// fields in a fixed order already has exactly one possible decomposition. No length-prefix
    /// bytes are added inside the AAD itself; that is a judgement call, not an oversight.</para>
    ///
    /// <para>Deliberately excludes the generation/epoch counter (issue #118, a separate PR):
    /// anything in the AAD can only change if every slot is re-wrapped, which needs every
    /// enrolled device physically present — the right property for <c>k</c> (see the design
    /// doc's "The landmine") and exactly the wrong one for a counter that bumps on every write.
    /// Also excludes <c>fleetSigPub</c>, which doesn't exist until v1.</para>
    /// </summary>
    internal static byte[] BuildAad(byte formatVersion, byte[] vaultId, byte k, byte[] slotId)
    {
        if (vaultId.Length != KeyringFormat.VaultIdSize)
            throw new ArgumentException($"vaultId must be {KeyringFormat.VaultIdSize} bytes", nameof(vaultId));
        if (slotId.Length != KeyringFormat.SlotIdSize)
            throw new ArgumentException($"slotId must be {KeyringFormat.SlotIdSize} bytes", nameof(slotId));

        var aad = new byte[1 + KeyringFormat.VaultIdSize + 1 + KeyringFormat.SlotIdSize];
        var span = aad.AsSpan();
        span[0] = formatVersion;
        vaultId.CopyTo(span.Slice(1, KeyringFormat.VaultIdSize));
        span[1 + KeyringFormat.VaultIdSize] = k;
        slotId.CopyTo(span.Slice(2 + KeyringFormat.VaultIdSize, KeyringFormat.SlotIdSize));
        return aad;
    }

    private static void ValidateKekSlot(byte[] kekSlot)
    {
        if (kekSlot.Length != KekSlotSize)
            throw new ArgumentException($"kekSlot must be {KekSlotSize} bytes", nameof(kekSlot));
    }
}
