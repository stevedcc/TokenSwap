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
        // Issue #121 pending-enrollment guard: a machine that has run 'slot request' but not yet
        // 'slot accept' has real, working hardware fields (YubiKeySerials/RedundancyXor/etc.) but
        // no finalized Keyring — its hardware-recovered bytes are a KEK_slot with nothing real to
        // unwrap yet, not a usable vault key. Without this check that KEK_slot would silently be
        // treated as the vault master key directly (the same code path a legacy non-keyring vault
        // uses), letting a command write secrets under a key that 'slot accept' is about to make
        // permanently unrecoverable once it recovers the *real* K_v from another machine's
        // approve file and overwrites Config.Keyring. See Config.PendingSlotId's doc comment.
        if (config.Keyring == null && config.PendingSlotId != null)
            throw new TswapException(
                "This machine has a pending 'slot request' enrollment that has not been completed yet. " +
                "Run 'tswap slot accept <approve-file>' (using the approve file from an already-enrolled " +
                "machine) before using this vault.");

        var recovered = UnlockHardware(config, chooseSerial);

        // A keyring vault (issue #119, 'tswap init --keyring'): `recovered` is this machine's
        // slot key-encryption key (KEK_slot), not the vault master key directly — unwrap K_v
        // from the keyring. This check is backend-agnostic and sits after backend dispatch on
        // purpose: whichever backend recovered the 32 bytes, a keyring vault always needs this
        // same extra unwrap step (see MULTI_MACHINE_KEYING.md §Two-layer slot wrap), so a future
        // second backend (v0 step 2) needs no change here at all.
        return config.Keyring == null ? recovered : UnlockKeyring(config, recovered);
    }

    /// <summary>
    /// Recovers this machine's hardware-backed key material — <c>KEK_slot</c> for a keyring
    /// vault, or the vault master key directly for a classic non-keyring vault — without
    /// attempting any keyring unwrap and without the pending-enrollment guard <see cref="Unlock"/>
    /// applies. Exposed publicly for <c>slot accept</c> (issue #121), which needs to recompute its
    /// own <c>KEK_slot</c> from a still-pending config (<see cref="Config.Keyring"/> is still null
    /// at that point by design — see <see cref="Config.PendingSlotId"/>) precisely in the
    /// situation <see cref="Unlock"/> refuses to proceed for every other caller.
    /// </summary>
    public byte[] UnlockHardware(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
    {
        var backend = config.Backend ?? HardwareBackend.YubiKey;
        if (!_backends.TryGetValue(backend, out var service))
            throw new TswapException(
                $"This vault uses the '{backend.DisplayName()}' hardware backend, which this build of tswap does not support. " +
                "Use a build that includes it, or restore a vault created with a supported backend.");

        return service.Unlock(config, chooseSerial);
    }

    /// <summary>
    /// Decodes <see cref="Config.Keyring"/> and unwraps this machine's slot to recover
    /// <c>K_v</c>. <paramref name="kekSlot"/> is the 32 bytes the hardware backend just
    /// recovered — always this machine's <c>KEK_slot</c>, never a recovery credential (recovery
    /// is a separate, offline, non-hardware path — see <see cref="RecoverySlotWrap"/> — not
    /// something <see cref="Unlock"/>'s normal dispatch ever exercises). The slot's own X25519
    /// private key (the payload's other half — see <see cref="SlotSecretPayload"/>) is decoded
    /// but unused until #121 adds slot request/approve/accept.
    ///
    /// <para><b>Issue #120:</b> a keyring can now hold more than one slot kind (a
    /// <see cref="SlotKind.Recovery"/> slot alongside the machine slot), so this method looks up
    /// a <see cref="SlotKind.Machine"/> slot explicitly rather than assuming the keyring's
    /// first entry is always this machine's, the way #119's single-slot-only version did.</para>
    ///
    /// <para><b>Issue #121:</b> a keyring can now hold <em>more than one</em>
    /// <see cref="SlotKind.Machine"/> slot (a second machine's, appended via <c>slot accept</c>),
    /// so "the first Machine slot" is no longer necessarily this device's own. When
    /// <see cref="Config.KeyringSlotId"/> is set, this method looks up that exact slot by id;
    /// only when it is null (a keyring predating this field, which is guaranteed to hold at most
    /// one Machine slot) does it fall back to #120's original "first Machine slot" heuristic —
    /// exact in that case, not a guess, since there is only ever one candidate.</para>
    ///
    /// <para>Throws <see cref="TswapException"/> — never a raw crash — for a non-base64
    /// <see cref="Config.Keyring"/>, a malformed keyring blob (<see cref="KeyringCodec.Decode"/>),
    /// an empty slot list, a keyring with no matching machine slot, or a slot that fails to
    /// unwrap (<see cref="SlotPayloadWrap.Unwrap"/>: wrong KEK_slot, tampered ciphertext, or a
    /// tampered AAD-bound field).</para>
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

        Slot? slot;
        if (config.KeyringSlotId != null)
        {
            byte[] ownSlotId;
            try
            {
                ownSlotId = Convert.FromBase64String(config.KeyringSlotId);
            }
            catch (FormatException)
            {
                throw new TswapException(
                    "Config is corrupted: KeyringSlotId is not valid base64. Restore config.json from backup or re-run 'tswap init --keyring'.");
            }
            slot = keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine && s.SlotId.AsSpan().SequenceEqual(ownSlotId));
        }
        else
        {
            slot = keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine);
        }

        if (slot == null)
            throw new TswapException(
                "Config is corrupted: keyring has no machine slot matching this machine. Restore config.json from backup or re-run 'tswap init --keyring'.");

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
