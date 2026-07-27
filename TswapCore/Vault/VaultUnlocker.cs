using TswapCore.Keyring;

namespace TswapCore.Vault;

/// <summary>
/// Selects the hardware backend for a vault from <see cref="Config.Backend"/> and
/// delegates unlock to it. YubiKey is the default and the only backend for a null
/// <see cref="Config.Backend"/> — i.e. every vault created before this seam existed, so
/// existing vaults are unaffected. Register additional <see cref="IHardwareKeyService"/>
/// implementations (TPM, Secure Enclave) through the constructor as they land; unlocking
/// a vault whose backend is not registered fails with a clear, actionable error rather
/// than a crash.
///
/// <paramref name="overrideKey"/> (test mode) is wired only into <see cref="YubiKeyHardwareService"/>
/// — a vault whose <see cref="Config.Backend"/> selects a different backend (e.g.
/// <c>secure-enclave</c>) always goes through real hardware regardless of <paramref name="overrideKey"/>,
/// since that backend has no override seam of its own.
/// </summary>
public sealed class VaultUnlocker
{
    /// <summary>The challenge used by configs created before vault-unique challenges.</summary>
    public const string LegacyChallenge = YubiKeyHardwareService.LegacyChallenge;

    private readonly Dictionary<HardwareBackend, IHardwareKeyService> _backends;
    private readonly YubiKeyHardwareService _yubiKey;

    /// <summary>
    /// Builds an unlocker with the YubiKey backend always registered, plus any
    /// <paramref name="additionalBackends"/> (TPM, Secure Enclave) supplied by the
    /// composition root. <paramref name="overrideKey"/> is the test-mode master key.
    /// </summary>
    public VaultUnlocker(
        IYubiKeyService yubiKeys,
        byte[]? overrideKey = null,
        IEnumerable<IHardwareKeyService>? additionalBackends = null)
    {
        _yubiKey = new YubiKeyHardwareService(yubiKeys, overrideKey);
        _backends = new Dictionary<HardwareBackend, IHardwareKeyService>
        {
            [HardwareBackend.YubiKey] = _yubiKey,
        };
        if (additionalBackends != null)
            foreach (var backend in additionalBackends)
                // TryAdd, not indexer assignment: a duplicate Backend value (including
                // HardwareBackend.YubiKey, already registered above) would otherwise silently
                // replace an existing entry — e.g. desyncing this dictionary from the _yubiKey
                // field still used by SelectConnectedSerial below, and quietly dropping
                // overrideKey's effect. That's a composition-root wiring bug; fail loudly.
                if (!_backends.TryAdd(backend.Backend, backend))
                    throw new ArgumentException(
                        $"Duplicate hardware backend registration for '{backend.Backend.DisplayName()}' " +
                        "— a backend for this value is already registered.", nameof(additionalBackends));
    }

    /// <summary>
    /// Unlocks the vault and returns the 32-byte master key, routing to the backend named
    /// by <see cref="Config.Backend"/> (YubiKey when unset).
    /// </summary>
    /// <param name="config">Vault configuration.</param>
    /// <param name="chooseSerial">
    /// Called with the connected serials when more than one YubiKey is present; ignored by
    /// single-device backends. Never called for zero or one connected key.
    /// </param>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
    {
        var backend = config.Backend ?? HardwareBackend.YubiKey;
        if (!_backends.TryGetValue(backend, out var service))
            throw new TswapException(
                $"This vault uses the '{backend.DisplayName()}' hardware backend, which this build of tswap does not support. " +
                "Use a build that includes it, or restore a vault created with a supported backend.");

        var recovered = service.Unlock(config, chooseSerial);

        // A keyring vault (issue #119, 'tswap init --keyring'): `recovered` is this machine's
        // slot key-encryption key (KEK_slot), not the vault master key directly — unwrap K_v
        // from the keyring. This check is backend-agnostic and sits after backend dispatch on
        // purpose: whichever backend recovered the 32 bytes, a keyring vault always needs this
        // same extra unwrap step (see MULTI_MACHINE_KEYING.md §Two-layer slot wrap), so a future
        // second backend (v0 step 2) needs no change here at all.
        return config.Keyring == null ? recovered : UnlockKeyring(config, recovered);
    }

    /// <summary>
    /// Decodes <see cref="Config.Keyring"/> and unwraps this machine's slot (always the
    /// keyring's first and, in v0, only slot) to recover <c>K_v</c>. <paramref name="kekSlot"/>
    /// is the 32 bytes the hardware backend just recovered. The slot's own X25519 private key
    /// (the payload's other half — see <see cref="SlotSecretPayload"/>) is decoded but unused
    /// until #121 adds slot request/approve/accept.
    ///
    /// <para>Throws <see cref="TswapException"/> — never a raw crash — for a non-base64
    /// <see cref="Config.Keyring"/>, a malformed keyring blob (<see cref="KeyringCodec.Decode"/>),
    /// an empty slot list, or a slot that fails to unwrap (<see cref="SlotPayloadWrap.Unwrap"/>:
    /// wrong KEK_slot, tampered ciphertext, or a tampered AAD-bound field).</para>
    /// </summary>
    private static byte[] UnlockKeyring(Config config, byte[] kekSlot)
    {
        byte[] keyringBytes;
        try
        {
            keyringBytes = Convert.FromBase64String(config.Keyring!);
        }
        catch (FormatException)
        {
            throw new TswapException(
                "Config is corrupted: Keyring is not valid base64. Restore config.json from backup or re-run 'tswap init --keyring'.");
        }

        var keyring = KeyringCodec.Decode(keyringBytes);

        if (keyring.Slots.Count == 0)
            throw new TswapException(
                "Config is corrupted: keyring has no slots. Restore config.json from backup or re-run 'tswap init --keyring'.");

        // v0 is single-slot only: the keyring's first slot is always this machine's. #121 adds
        // real slot identity/lookup once a keyring can hold more than one.
        var slot = keyring.Slots[0];
        var payload = SlotPayloadWrap.Unwrap(slot.Wrapped, kekSlot, keyring.FormatVersion, keyring.VaultId, keyring.K, slot.SlotId);
        var (vaultKey, _slotPrivateKey) = SlotSecretPayload.Decode(payload);
        return vaultKey;
    }

    /// <summary>
    /// Resolves which connected YubiKey to use for enrollment/entropy flows (init,
    /// create's hardware-entropy path). YubiKey-specific: other backends have no serials.
    /// </summary>
    public int SelectConnectedSerial(Func<IReadOnlyList<int>, int> chooseSerial, int? requiredSerial = null)
        => _yubiKey.SelectConnectedSerial(chooseSerial, requiredSerial);
}
