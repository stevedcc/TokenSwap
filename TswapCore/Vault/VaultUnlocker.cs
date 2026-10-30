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
    private readonly IYubiKeyService _yubiKeys;

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
        _yubiKeys = yubiKeys;
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
    ///
    /// <para>A keyring vault (brief T4 decision 3) tries its own backend first (TPM, Secure
    /// Enclave, or a legacy YubiKey pair slot), unchanged. When that backend isn't available or
    /// has no usable slot, or when the vault's own slot is itself a one-key YubiKey slot, it tries
    /// every one-key YubiKey slot (<see cref="YubiKeySlotBlob"/>) whose key is plugged in; the
    /// first slot that authenticates wins. Those slots need no <see cref="Config.KeyringSlotId"/>.
    /// </para>
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

        // A classic vault (no keyring): the backend recovers the master key itself. Unchanged.
        if (config.Keyring == null)
            return UnlockHardware(config, chooseSerial);

        // Brief T4 decision 3: a keyring may also hold one-key YubiKey slots (a machine slot whose
        // hwBlob is a YubiKeySlotBlob), any one of which opens the vault on its own, on any
        // machine that has the vault files and that key.
        var keyring = DecodeKeyring(config);
        var yubiKeySlots = keyring.Slots
            .Where(s => s.Kind == SlotKind.Machine && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob))
            .ToList();

        // A YubiKey vault whose own slot is a one-key slot has no other backend path to try.
        if (!OwnSlotIsAYubiKeySlot(config, keyring))
        {
            // First the vault's own backend: TPM, Secure Enclave, or a legacy YubiKey pair slot.
            // With no one-key slots to fall back to this is exactly the path (and the errors) of
            // every keyring vault before brief T4.
            if (yubiKeySlots.Count == 0)
                return OwnBackend(config, chooseSerial);
            try
            {
                return OwnBackend(config, chooseSerial);
            }
            catch (TswapException ownBackendError)
            {
                // Its backend isn't available here (not in this build, another machine's TPM, no
                // enrolled pair key plugged in) or has no usable slot: try the one-key slots.
                return UnlockWithYubiKeySlot(keyring, yubiKeySlots, chooseSerial, ownBackendError);
            }
        }

        return UnlockWithYubiKeySlot(keyring, yubiKeySlots, chooseSerial, ownBackendError: null);
    }

    /// <summary>
    /// The vault's own backend for a keyring vault: recover this machine's <c>KEK_slot</c> and
    /// unwrap this machine's slot (issue #119). Backend-agnostic: whichever backend recovered the
    /// 32 bytes, a keyring vault always needs this same extra unwrap step (see
    /// MULTI_MACHINE_KEYING.md §Two-layer slot wrap).
    /// </summary>
    private byte[] OwnBackend(Config config, Func<IReadOnlyList<int>, int> chooseSerial) =>
        UnlockKeyring(config, UnlockHardware(config, chooseSerial));

    /// <summary>
    /// True for a YubiKey vault whose own machine slot (by <see cref="Config.KeyringSlotId"/>, or
    /// the first machine slot when that is null) carries a <see cref="YubiKeySlotBlob"/>. A
    /// YubiKey machine slot without one is a legacy pair slot, unlocked through
    /// <see cref="YubiKeyHardwareService"/> and the per-machine pair fields.
    /// </summary>
    private static bool OwnSlotIsAYubiKeySlot(Config config, Keyring.Keyring keyring)
    {
        if ((config.Backend ?? HardwareBackend.YubiKey) != HardwareBackend.YubiKey)
            return false;
        var own = FindOwnMachineSlot(config, keyring);
        return own != null && YubiKeySlotBlob.IsYubiKeyBlob(own.HwBlob);
    }

    /// <summary>
    /// Opens the vault with a one-key YubiKey slot (brief T4 decision 3): of the slots whose key
    /// is plugged in, <paramref name="chooseSerial"/> picks the key when several match; that key
    /// is challenged for each of its slots in keyring order, and the first slot that authenticates
    /// wins. <paramref name="ownBackendError"/> is the vault's own backend's failure, if it was
    /// tried, and is kept in the error message. A slot whose YubiKey blob fails to decode is
    /// skipped (security review of T4: one corrupt slot must not block the others) and named in
    /// the final error only if no other slot unlocks.
    /// </summary>
    private byte[] UnlockWithYubiKeySlot(
        Keyring.Keyring keyring, List<Slot> yubiKeySlots, Func<IReadOnlyList<int>, int> chooseSerial,
        TswapException? ownBackendError)
    {
        var candidates = new List<(Slot Slot, YubiKeySlotBlob Blob)>();
        var corruptSlotIds = new List<string>();
        foreach (var s in yubiKeySlots)
        {
            try
            {
                candidates.Add((s, YubiKeySlotBlob.Decode(s.HwBlob!)));
            }
            catch (TswapException)
            {
                corruptSlotIds.Add(Convert.ToHexString(s.SlotId).ToLowerInvariant()[..8]);
            }
        }
        var slotSerials = candidates.Select(c => c.Blob.Serial).Distinct().ToList();
        var ownFailure = (ownBackendError == null ? "" : $" (The vault's own backend failed too: {ownBackendError.Message})") +
            (corruptSlotIds.Count == 0 ? "" :
                $" Skipped slot(s) {string.Join(", ", corruptSlotIds)}: their YubiKey slot blob is corrupt; restore config.json from backup.");

        IReadOnlyList<int> pluggedIn;
        try
        {
            pluggedIn = _yubiKeys.ListSerials();
        }
        catch (Exception ex) when (ex is not TswapException)
        {
            throw new TswapException($"Could not list the plugged-in YubiKeys: {ex.Message}. Is ykman installed?{ownFailure}");
        }

        var matching = pluggedIn.Where(slotSerials.Contains).Distinct().ToList();
        if (matching.Count == 0)
            throw new TswapException(
                "No plugged-in YubiKey matches a slot of this vault. " +
                (slotSerials.Count == 0 ? "This vault has no readable YubiKey slot; " :
                    $"This vault's YubiKey slots are for serial(s) {string.Join(", ", slotSerials)}; ") +
                (pluggedIn.Count == 0 ? "no YubiKey is plugged in." : $"plugged in: {string.Join(", ", pluggedIn)}.") +
                " Plug in one of those keys and try again." + ownFailure);

        var serial = matching.Count == 1 ? matching[0] : chooseSerial(matching);
        if (!matching.Contains(serial))
            throw new TswapException($"Selected YubiKey serial {serial} is not among the plugged-in keys with a slot in this vault ({string.Join(", ", matching)}).");

        foreach (var (slot, blob) in candidates.Where(c => c.Blob.Serial == serial))
        {
            var kekSlot = YubiKeySlotKek.Recover(_yubiKeys, blob, slot.SlotId);
            try
            {
                return UnwrapSlot(keyring, slot, kekSlot);
            }
            catch (TswapException)
            {
                // This slot didn't authenticate under this key; the key may have another slot.
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(kekSlot);
            }
        }

        throw new TswapException(
            $"YubiKey {serial} did not open any of its slots in this vault: its response did not authenticate " +
            "(the key's HMAC secret was reprogrammed, or config.json is damaged). Restore config.json from backup " +
            "or use another enrolled key." + ownFailure);
    }

    /// <summary>
    /// Decodes <see cref="Config.Keyring"/>, with the same "Config is corrupted" message for bad
    /// base64 as <see cref="UnlockKeyring"/>.
    /// </summary>
    private static Keyring.Keyring DecodeKeyring(Config config)
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
        return KeyringCodec.Decode(keyringBytes);
    }

    /// <summary>
    /// This machine's own machine slot: by <see cref="Config.KeyringSlotId"/>, or the first machine
    /// slot when that is null; null when there is none. Throws for a non-base64 slot id.
    /// </summary>
    private static Slot? FindOwnMachineSlot(Config config, Keyring.Keyring keyring)
    {
        if (config.KeyringSlotId == null)
            return keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine);

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
        return keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine && s.SlotId.AsSpan().SequenceEqual(ownSlotId));
    }

    /// <summary>Unwraps one machine slot under <paramref name="kekSlot"/> and returns <c>K_v</c>.</summary>
    private static byte[] UnwrapSlot(Keyring.Keyring keyring, Slot slot, byte[] kekSlot)
    {
        var payload = SlotPayloadWrap.Unwrap(slot.Wrapped, kekSlot, keyring.FormatVersion, keyring.VaultId, keyring.K, slot.SlotId);
        var (vaultKey, _slotPrivateKey) = SlotSecretPayload.Decode(payload);
        return vaultKey;
    }

    /// <summary>
    /// Recovers this machine's hardware-backed key material — <c>KEK_slot</c> for a keyring
    /// vault, or the vault master key directly for a classic non-keyring vault — without
    /// attempting any keyring unwrap and without the pending-enrollment guard <see cref="Unlock"/>
    /// applies. Exposed for <c>slot accept</c> (issue #121) until brief T4, whose one-key slot
    /// request keeps the slot's <see cref="YubiKeySlotBlob"/> and re-derives <c>KEK_slot</c> from it
    /// instead; now only <see cref="Unlock"/> calls it.
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
