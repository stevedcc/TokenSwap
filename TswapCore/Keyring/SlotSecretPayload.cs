namespace TswapCore.Keyring;

/// <summary>
/// The plaintext payload wrapped by <see cref="SlotPayloadWrap"/> inside a <see cref="Slot"/>
/// (issue #119): the vault master key <c>K_v</c> and this slot's own X25519 private key (see
/// <see cref="SlotKeyPair"/>), concatenated into one fixed-width blob and protected by a single
/// AEAD call rather than two independent ones.
///
/// <para><b>Why one wrap, not two:</b> both values are protected by the exact same
/// <c>KEK_slot</c> and the exact same AAD (<c>formatVersion</c>/<c>vaultId</c>/<c>k</c>/
/// <c>slotId</c>) — splitting them into two independent <see cref="SlotPayloadWrap.Wrap"/>
/// calls would mean two nonces, two tags, and twice the bookkeeping for no additional
/// isolation: compromising <c>KEK_slot</c> exposes both values under either scheme. This is the
/// judgement call issue #119's design section calls out explicitly.</para>
///
/// <para><b>Why no length prefix:</b> both fields are fixed-width —
/// <see cref="KeyringFormat.VaultKeySize"/> and <see cref="SlotKeyPair.KeySize"/> are both 32
/// bytes today, pinned constants rather than incidental — so <c>vaultKey || slotPrivateKey</c>
/// has exactly one possible decomposition. A length prefix would only earn its keep if either
/// field's width could vary independently of a format-version bump, which neither does.</para>
/// </summary>
public static class SlotSecretPayload
{
    /// <summary>Total encoded length: <see cref="KeyringFormat.VaultKeySize"/> + <see cref="SlotKeyPair.KeySize"/>.</summary>
    public const int EncodedSize = KeyringFormat.VaultKeySize + SlotKeyPair.KeySize;

    /// <summary>
    /// Concatenates <paramref name="vaultKey"/> and <paramref name="slotPrivateKey"/> — the
    /// payload later handed to <see cref="SlotPayloadWrap.Wrap"/>. Throws
    /// <see cref="ArgumentException"/> (a programmer error — both inputs are freshly generated
    /// by this codebase, never attacker-controlled) if either is not exactly its fixed width.
    /// </summary>
    public static byte[] Encode(byte[] vaultKey, byte[] slotPrivateKey)
    {
        if (vaultKey.Length != KeyringFormat.VaultKeySize)
            throw new ArgumentException($"vaultKey must be {KeyringFormat.VaultKeySize} bytes", nameof(vaultKey));
        if (slotPrivateKey.Length != SlotKeyPair.KeySize)
            throw new ArgumentException($"slotPrivateKey must be {SlotKeyPair.KeySize} bytes", nameof(slotPrivateKey));

        var result = new byte[EncodedSize];
        vaultKey.CopyTo(result, 0);
        slotPrivateKey.CopyTo(result, KeyringFormat.VaultKeySize);
        return result;
    }

    /// <summary>
    /// Decodes a payload previously produced by <see cref="Encode"/> — normally the output of
    /// <see cref="SlotPayloadWrap.Unwrap"/>. Throws <see cref="TswapException"/> (not a raw
    /// slicing exception) when the length doesn't match: since the AEAD layer above this already
    /// authenticated the bytes, a wrong length here means either a bug (this codec's own
    /// <see cref="EncodedSize"/> changed without a matching format-version bump) or a
    /// same-vintage payload that was tampered with in a way that happened to keep the AEAD tag
    /// consistent under a *different* key — either way this must fail loudly, not silently
    /// truncate or overrun.
    /// </summary>
    public static (byte[] VaultKey, byte[] SlotPrivateKey) Decode(byte[] payload)
    {
        if (payload.Length != EncodedSize)
            throw new TswapException($"Malformed slot payload: expected {EncodedSize} bytes, got {payload.Length}");

        var vaultKey = payload.AsSpan(0, KeyringFormat.VaultKeySize).ToArray();
        var slotPrivateKey = payload.AsSpan(KeyringFormat.VaultKeySize, SlotKeyPair.KeySize).ToArray();
        return (vaultKey, slotPrivateKey);
    }
}
