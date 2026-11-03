using TswapCore.Keyring;
using TswapCore.VaultPassword;

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
        if (additionalBackends is not null)
            foreach (var backend in additionalBackends)
                // TryAdd, not indexer assignment: a duplicate Backend value (including
                // HardwareBackend.YubiKey, already registered above) would otherwise silently
                // replace an existing entry — e.g. desyncing this dictionary from the _yubiKey
                // field still used by SelectConnectedSerial below, and quietly dropping
                // overrideKey's effect. That's a composition-root wiring bug; fail loudly.
                if (!_backends.TryAdd(backend.Backend, backend))
                    throw new ArgumentException(
                        $"Duplicate hardware backend registration for '{backend.Backend.DisplayName}' " +
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
        => Unlock(config, YubiKeySelection.FromChooser(chooseSerial));

    /// <summary>
    /// <see cref="Unlock(Config, Func{IReadOnlyList{int}, int})"/> with a <see cref="YubiKeySelection"/>
    /// (brief T7 item 4): unattended, it never asks and tries the plugged-in keys in turn. No agent and no
    /// prompt (<see cref="UnlockSources.None"/>): a slot that needs the vault password is unavailable.
    /// </summary>
    public byte[] Unlock(Config config, YubiKeySelection selection) => Unlock(config, selection, UnlockSources.None);

    /// <summary>
    /// Unlocks in three passes (brief T17 ruling 13). Before any pass, every candidate slot is classified
    /// with <see cref="SlotPassword.Classify"/>; slots that need a newer tswap or are corrupt are set aside
    /// and only named in the error (ruling 3).
    /// <list type="number">
    /// <item><b>Pass 1:</b> every password-free candidate, in today's order: the vault's own backend
    /// (TPM, Secure Enclave or a legacy YubiKey pair slot) unless its slot has the password, then the
    /// password-free one-key YubiKey slots whose key is plugged in. No source is touched.</item>
    /// <item><b>Pass 2:</b> only if pass 1 opened nothing and <see cref="CouldNeedPassword"/> holds:
    /// <see cref="UnlockSources.AskAgent"/>.</item>
    /// <item><b>Pass 3:</b> only if the agent gave nothing: <see cref="UnlockSources.Prompt"/>, called once;
    /// every password candidate gets a provider of clones of that one password, which is disposed when the
    /// pass ends.</item>
    /// </list>
    /// A vault without password slots runs pass 1 only, with today's calls and today's errors (Goal 4).
    /// When every pass fails, the error is pass 1's (the own backend's message with
    /// <see cref="ForeignHardwareSlotHint"/>, the YubiKey slots' failures), then pass 3's, then the agent's.
    /// </summary>
    public byte[] Unlock(Config config, YubiKeySelection selection, UnlockSources sources)
    {
        // Issue #121 pending-enrollment guard: a machine that has run 'slot request' but not yet
        // 'slot accept' has real, working hardware fields (YubiKeySerials/RedundancyXor/etc.) but
        // no finalized Keyring — its hardware-recovered bytes are a KEK_slot with nothing real to
        // unwrap yet, not a usable vault key. Without this check that KEK_slot would silently be
        // treated as the vault master key directly (the same code path a legacy non-keyring vault
        // uses), letting a command write secrets under a key that 'slot accept' is about to make
        // permanently unrecoverable once it recovers the *real* K_v from another machine's
        // approve file and overwrites Config.Keyring. See Config.PendingSlotId's doc comment.
        if (config.Keyring is null && config.PendingSlotId is not null)
            throw new TswapException(
                "This machine has a pending 'slot request' enrollment that has not been completed yet. " +
                "Run 'tswap slot accept <approve-file>' (using the approve file from an already-enrolled " +
                "machine) before using this vault.");

        // A classic vault (no keyring): the backend recovers the master key itself. Unchanged; classic
        // vaults can't carry a vault password (brief T17 ruling 3).
        if (config.Keyring is null)
            return UnlockHardware(config, selection, password: null);

        // Brief T4 decision 3: a keyring may also hold one-key YubiKey slots (a machine slot whose
        // hwBlob is a YubiKeySlotBlob), any one of which opens the vault on its own, on any
        // machine that has the vault files and that key.
        var keyring = DecodeKeyring(config);
        var plan = Classify(config, keyring);
        var plugged = new PluggedInKeys(_yubiKeys);

        // ---- Pass 1: password-free candidates only.
        TswapException? ownError = null;
        if (plan.OwnKind == SlotPasswordKind.None && plan.OwnPath)
        {
            // With no one-key slots to fall back to this is exactly the path (and the errors) of
            // every keyring vault before brief T4.
            if (plan.YubiKeySlotCount == 0)
                return OwnBackend(config, selection, password: null);
            try
            {
                return OwnBackend(config, selection, password: null);
            }
            catch (TswapException ownBackendError) when (ownBackendError is not OwnerSwitchException)
            {
                // (T12 fix round 1: a failed switch to the vault folder's owner is a hard stop.)
                // Its backend isn't available here (not in this build, another machine's TPM, no
                // enrolled pair key plugged in) or has no usable slot: try the one-key slots.
                ownError = ownBackendError;
            }
        }
        else if (plan.OwnPath && plan.OwnKind != SlotPasswordKind.Password && plan.YubiKeySlotCount == 0)
        {
            // The own slot is set aside (newer tswap, corrupt) and nothing else could open the vault.
            throw new TswapException("This machine's slot of this vault can't be used." + plan.SetAsideSuffix);
        }

        // Without password candidates, pass 1 is today's whole unlock, so its errors carry the
        // set-aside suffix themselves; otherwise it goes at the very end of the combined error.
        var pass1Suffix = plan.HasPasswordCandidates ? "" : plan.SetAsideSuffix;
        TswapException? pass1Error = ownError;
        if (plan.YubiKeySlotCount > 0)
        {
            try
            {
                var key = UnlockWithYubiKeySlot(keyring, plan.YubiKeyCandidates, selection, ownError, pass1Suffix,
                    passwordPass: false, password: null, plugged);
                if (key is not null)
                    return key;
            }
            catch (TswapException ex) when (plan.HasPasswordCandidates && ex is not OwnerSwitchException)
            {
                pass1Error = ex;
            }
        }

        var couldNeedPassword = (plan.OwnPath && plan.OwnKind == SlotPasswordKind.Password)
            || (plan.PasswordSerials.Count > 0 && plugged.TryGet().Any(plan.PasswordSerials.Contains));
        if (!couldNeedPassword)
            throw WithSuffix(pass1Error ?? new TswapException("No slot of this vault can be used on this machine."), plan.SetAsideSuffix);

        // ---- Pass 2: the agent.
        string? agentFailure = null;
        if (sources.AskAgent is { } askAgent)
        {
            try
            {
                if (askAgent() is { } agentKey)
                    return agentKey;
            }
            catch (AgentUnlockFailedException ex)
            {
                agentFailure = ex.Message;
            }
        }

        // ---- Pass 3: the prompt, called once.
        if (sources.Prompt is null)
            throw new VaultPasswordUnavailableException(VaultPasswordMessages.NoTerminal +
                (agentFailure is null ? "" : " " + VaultPasswordMessages.AgentAlsoFailed(agentFailure)));
        using var original = sources.Prompt();
        VaultPasswordProvider provider = original.Clone;

        TswapException? pass3Error = null;
        if (plan.OwnPath && plan.OwnKind == SlotPasswordKind.Password)
        {
            try
            {
                return OwnBackend(config, selection, provider);
            }
            catch (TswapException ex) when (ex is not OwnerSwitchException)
            {
                pass3Error = ex;
            }
        }
        if (plan.PasswordSerials.Count > 0 && plugged.TryGet().Any(plan.PasswordSerials.Contains))
        {
            try
            {
                var key = UnlockWithYubiKeySlot(keyring, plan.YubiKeyCandidates, selection, pass3Error, "",
                    passwordPass: true, provider, plugged);
                if (key is not null)
                    return key;
            }
            catch (TswapException ex) when (ex is not OwnerSwitchException)
            {
                pass3Error = ex;
            }
        }

        // A pass 1 failure is shown only now, when the later passes failed too.
        if (pass1Error is null && agentFailure is null && plan.SetAsideSuffix.Length == 0 && pass3Error is not null)
            throw pass3Error;
        List<string> parts = [];
        if (pass1Error is not null)
            parts.Add(pass1Error.Message);
        if (pass3Error is not null)
            parts.Add(pass3Error.Message);
        if (agentFailure is not null)
            parts.Add(VaultPasswordMessages.AgentAlsoFailed(agentFailure));
        if (parts.Count == 0)
            parts.Add("No slot of this vault opened with the vault password on this machine.");
        throw new TswapException(string.Join(" ", parts) + plan.SetAsideSuffix, pass3Error?.ExitCode ?? 1);
    }

    private static TswapException WithSuffix(TswapException ex, string suffix) =>
        suffix.Length == 0 || ex.Message.EndsWith(suffix, StringComparison.Ordinal)
            ? ex
            : new TswapException(ex.Message + suffix, ex.ExitCode);

    /// <summary>
    /// Brief T17 ruling 13: true when a <b>password</b> candidate is reachable on this machine: the own
    /// machine slot (TPM, Secure Enclave) has the password, or a password YubiKey slot's key is in
    /// <paramref name="pluggedIn"/>. A vault without password slots is always false, so it never
    /// contacts an agent (Goal 4). Never throws: a config it can't read is false.
    /// </summary>
    public static bool CouldNeedPassword(Config config, IReadOnlyList<int> pluggedIn)
    {
        if (config.Keyring is null)
            return false;
        try
        {
            var plan = Classify(config, DecodeKeyring(config));
            return (plan.OwnPath && plan.OwnKind == SlotPasswordKind.Password) || plan.PasswordSerials.Any(pluggedIn.Contains);
        }
        catch (TswapException)
        {
            return false;
        }
    }

    /// <summary>The candidates of one unlock, classified before any pass runs (brief T17 ruling 3).</summary>
    private sealed record UnlockPlan(
        bool OwnPath,
        SlotPasswordKind OwnKind,
        int YubiKeySlotCount,
        List<(Slot Slot, YubiKeySlotBlob Blob)> YubiKeyCandidates,
        HashSet<int> PasswordSerials,
        string SetAsideSuffix)
    {
        public bool HasPasswordCandidates => (OwnPath && OwnKind == SlotPasswordKind.Password) || PasswordSerials.Count > 0;
    }

    private static UnlockPlan Classify(Config config, Keyring.Keyring keyring)
    {
        List<string> corrupt = [];
        List<string> newer = [];

        // The own backend path: TPM, Secure Enclave, or a legacy YubiKey pair slot. A YubiKey vault
        // whose own slot is a one-key slot has no other backend path to try.
        var ownPath = !OwnSlotIsAYubiKeySlot(config, keyring);
        var ownKind = SlotPasswordKind.None;
        if (ownPath)
        {
            Slot? own;
            try
            {
                own = FindOwnMachineSlot(config, keyring);
            }
            catch (TswapException)
            {
                own = null; // the own backend reports the damaged slot id itself, as before
            }
            if (own is not null && !YubiKeySlotBlob.IsYubiKeyBlob(own.HwBlob))
            {
                (ownKind, var error) = SlotPassword.Describe(own);
                if (ownKind == SlotPasswordKind.Corrupt)
                    corrupt.Add(Id8(own));
                else if (ownKind == SlotPasswordKind.NeedsNewerTswap)
                    newer.Add($"Slot {Id8(own)}: {error}");
            }
        }

        var yubiKeySlots = keyring.Slots
            .Where(s => s.Kind == SlotKind.Machine && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob))
            .ToList();
        List<(Slot Slot, YubiKeySlotBlob Blob)> candidates = [];
        foreach (var s in yubiKeySlots)
        {
            // A slot whose blob doesn't decode is set aside (security review of T4: one bad slot must
            // not block the others) and named in the final error only if no other slot unlocks.
            var (blob, kind, error) = YubiKeySlotBlob.Parse(s.HwBlob!);
            if (blob is not null)
                candidates.Add((s, blob));
            else if (kind == SlotPasswordKind.NeedsNewerTswap)
                newer.Add($"Slot {Id8(s)}: {error}");
            else
                corrupt.Add(Id8(s));
        }

        var suffix = (corrupt.Count == 0 ? "" :
                $" Skipped slot(s) {string.Join(", ", corrupt)}: their slot blob is corrupt; restore config.json from backup.") +
            string.Concat(newer.Select(n => " " + n));
        return new UnlockPlan(
            ownPath, ownKind, yubiKeySlots.Count, candidates,
            candidates.Where(c => c.Blob.RequiresPassword).Select(c => c.Blob.Serial).ToHashSet(),
            suffix);
    }

    private static string Id8(Slot slot) => Convert.ToHexString(slot.SlotId).ToLowerInvariant()[..8];

    /// <summary>The plugged-in YubiKeys, listed at most once per unlock.</summary>
    private sealed class PluggedInKeys(IYubiKeyService yubiKeys)
    {
        private IReadOnlyList<int>? _serials;
        private Exception? _failure;

        /// <summary>Lists them (throwing what <see cref="IYubiKeyService.ListSerials"/> throws), then caches either.</summary>
        public IReadOnlyList<int> Get()
        {
            if (_serials is not null)
                return _serials;
            if (_failure is not null)
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(_failure);
            try
            {
                return _serials = yubiKeys.ListSerials();
            }
            catch (Exception ex)
            {
                _failure = ex;
                throw;
            }
        }

        /// <summary>As <see cref="Get"/>, but an empty list when listing fails (pass 1 already reported it).</summary>
        public IReadOnlyList<int> TryGet()
        {
            try
            {
                return Get();
            }
            catch (Exception)
            {
                return [];
            }
        }
    }

    /// <summary>
    /// The vault's own backend for a keyring vault: recover this machine's <c>KEK_slot</c> and
    /// unwrap this machine's slot (issue #119). Backend-agnostic: whichever backend recovered the
    /// 32 bytes, a keyring vault always needs this same extra unwrap step (see
    /// MULTI_MACHINE_KEYING.md §Two-layer slot wrap). <paramref name="password"/> reaches the backend
    /// for a password slot (brief T17).
    /// </summary>
    private byte[] OwnBackend(Config config, YubiKeySelection selection, VaultPasswordProvider? password)
    {
        try
        {
            return UnlockKeyring(config, UnlockHardware(config, selection, password));
        }
        catch (TswapException ex) when ((config.Backend is HardwareBackend.Tpm or HardwareBackend.SecureEnclave)
            && ex is not OwnerSwitchException // T12 fix round 1: a failed owner switch passes unchanged
            && ex is not VaultPasswordRefusedException and not VaultPasswordUnavailableException) // T17: the slot is this machine's
        {
            // Brief T5 (security review): a TPM / Secure Enclave slot opens only in its own
            // machine's config; other machines' hardware slots are never tried here (a config.json
            // writer could plant a Secure Enclave slot, and each try costs TPM dictionary-attack
            // exposure, time or a Touch ID prompt). Say what to do instead.
            throw new TswapException(ex.Message + " " + ForeignHardwareSlotHint, ex.ExitCode);
        }
    }

    /// <summary>
    /// Appended to a failed TPM / Secure Enclave unlock: the fleet model is one config per machine,
    /// brought together with <c>slot merge</c>; a copied config only opens with a YubiKey or
    /// recovery slot.
    /// </summary>
    public const string ForeignHardwareSlotHint =
        "This config's own slot belongs to another machine or its hardware is unavailable. On this machine, use its " +
        "own config.json (bring other machines' slots in with 'tswap slot merge'), or open this copy with a YubiKey " +
        "slot or the recovery key ('tswap recover').";

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
        return own is not null && YubiKeySlotBlob.IsYubiKeyBlob(own.HwBlob);
    }

    /// <summary>
    /// Opens the vault with a one-key YubiKey slot (brief T4 decision 3): of the plugged-in keys that
    /// have a slot, <paramref name="selection"/> decides (brief T7 item 4): an explicit serial, the
    /// user's choice on a terminal, or unattended every such key in the order no-touch, unknown,
    /// touch-required (the posture recorded in each slot's blob). Each key is challenged for each of
    /// its slots in keyring order, and the first slot that authenticates wins; unattended, a key that
    /// doesn't answer or opens none of its slots passes to the next. <paramref name="ownBackendError"/>
    /// is the vault's own backend's failure, if it was tried, and is kept in the error message, followed
    /// by <paramref name="setAsideSuffix"/> (slots set aside before the passes, brief T17 ruling 3).
    ///
    /// <para><b>Brief T17:</b> one pass tries only the slots of its kind: password-free ones in pass 1
    /// (<paramref name="passwordPass"/> false), password ones with <paramref name="password"/> in pass 3.
    /// The "no plugged-in key matches" message still lists every slot. Null when a plugged-in key has a
    /// slot, but none of this pass's kind: nothing to try in this pass.</para>
    /// </summary>
    private byte[]? UnlockWithYubiKeySlot(
        Keyring.Keyring keyring, List<(Slot Slot, YubiKeySlotBlob Blob)> candidates, YubiKeySelection selection,
        TswapException? ownBackendError, string setAsideSuffix, bool passwordPass, VaultPasswordProvider? password,
        PluggedInKeys plugged)
    {
        var slotSerials = candidates.Select(c => c.Blob.Serial).Distinct().ToList();
        var ownFailure = (ownBackendError is null ? "" : $" (The vault's own backend failed too: {ownBackendError.Message})") +
            setAsideSuffix;

        IReadOnlyList<int> pluggedIn;
        try
        {
            pluggedIn = plugged.Get();
        }
        catch (Exception ex) when (ex is not TswapException)
        {
            throw new TswapException($"Could not list the plugged-in YubiKeys: {ex.Message}. Is ykman installed?{ownFailure}");
        }

        var matching = pluggedIn.Where(slotSerials.Contains).Distinct().ToList();
        if (matching.Count == 0 && selection.Serial is null)
            throw new TswapException(
                "No plugged-in YubiKey matches a slot of this vault. " +
                (slotSerials.Count == 0 ? "This vault has no readable YubiKey slot; " :
                    $"This vault's YubiKey slots are for serial(s) {string.Join(", ", slotSerials)}; ") +
                (pluggedIn.Count == 0 ? "no YubiKey is plugged in." : $"plugged in: {string.Join(", ", pluggedIn)}.") +
                " Plug in one of those keys and try again." + ownFailure);

        // This pass's slots only (brief T17 ruling 13).
        var tryable = candidates.Where(c => c.Blob.RequiresPassword == passwordPass).ToList();
        var tryableSerials = tryable.Select(c => c.Blob.Serial).Distinct().ToList();
        var matchingTryable = matching.Where(tryableSerials.Contains).ToList();
        if (selection.Serial is int wanted
                ? pluggedIn.Contains(wanted) && slotSerials.Contains(wanted) && !tryableSerials.Contains(wanted)
                : matchingTryable.Count == 0)
            return null;

        // A key's posture: the most permissive of its slots' recorded postures (a key has one slot 2).
        var postures = matchingTryable
            .Select(serial => tryable.Where(c => c.Blob.Serial == serial)
                .Select(c => c.Blob.RequiresTouch)
                .MinBy(YubiKeySelection.UnattendedRank))
            .ToList();
        var order = selection.Order(matchingTryable, postures, pluggedIn);

        List<string> failures = [];
        foreach (var serial in order)
        {
            var failure = TryKey(keyring, tryable, serial, order.Count > 1, password, out var vaultKey);
            if (vaultKey is not null)
                return vaultKey;
            failures.Add(failure!);
        }

        if (order.Count == 1)
            throw passwordPass
                ? new TswapException($"YubiKey {order[0]}: {VaultPasswordMessages.WrongPasswordKdf}{ownFailure}")
                : new TswapException(
                    $"YubiKey {order[0]} did not open any of its slots in this vault: its response did not authenticate " +
                    "(the key's HMAC secret was reprogrammed, its slot's password flag was removed, or config.json is damaged). " +
                    "Restore config.json from backup or use another enrolled key." + ownFailure);
        throw new TswapException(
            $"None of the plugged-in YubiKeys with a slot in this vault ({string.Join(", ", order)}) opened it: " +
            string.Join("; ", failures) + "." + ownFailure);
    }

    /// <summary>
    /// Challenges <paramref name="serial"/> for each of its slots; the vault key, or null with why
    /// not. A challenge that fails (busy key, touch timed out) is rethrown unless
    /// <paramref name="moreToTry"/>. A password slot gets <paramref name="password"/> (brief T17).
    /// </summary>
    private string? TryKey(Keyring.Keyring keyring, List<(Slot Slot, YubiKeySlotBlob Blob)> candidates, int serial,
        bool moreToTry, VaultPasswordProvider? password, out byte[]? vaultKey)
    {
        vaultKey = null;
        var withPassword = false;
        foreach (var (slot, blob) in candidates.Where(c => c.Blob.Serial == serial))
        {
            withPassword |= blob.RequiresPassword;
            byte[] kekSlot;
            try
            {
                kekSlot = YubiKeySlotKek.Recover(_yubiKeys, blob, slot.SlotId, password);
            }
            catch (TswapException ex) when (moreToTry && ex is not VaultPasswordUnavailableException)
            {
                return $"{serial} did not answer ({ex.Message})";
            }
            try
            {
                vaultKey = UnwrapSlot(keyring, slot, kekSlot);
                return null;
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
        return withPassword
            ? $"{serial}: {VaultPasswordMessages.WrongPasswordKdf.TrimEnd('.')}"
            : $"{serial} opened none of its slots (its response did not authenticate)";
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
        if (config.KeyringSlotId is null)
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
    /// applies. <c>slot accept</c> calls it for a pending <c>slot request --tpm</c> /
    /// <c>--secure-enclave</c> (brief T5), whose blob <see cref="HardwareBlobLocator"/> reads from
    /// <see cref="Config.PendingSlotHwBlob"/>; a one-key YubiKey request re-derives <c>KEK_slot</c>
    /// from its <see cref="YubiKeySlotBlob"/> instead (brief T4).
    /// </summary>
    public byte[] UnlockHardware(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
        => UnlockHardware(config, YubiKeySelection.FromChooser(chooseSerial), password: null);

    /// <summary><see cref="UnlockHardware(Config, Func{IReadOnlyList{int}, int})"/> with a <see cref="YubiKeySelection"/>.</summary>
    public byte[] UnlockHardware(Config config, YubiKeySelection selection) => UnlockHardware(config, selection, password: null);

    /// <summary>
    /// As above, with the stretched vault password for a password slot (brief T17: <c>slot accept</c> of a
    /// password request). The backend calls <paramref name="password"/> only when its blob says so.
    /// </summary>
    public byte[] UnlockHardware(Config config, YubiKeySelection selection, VaultPasswordProvider? password)
    {
        var backend = config.Backend ?? HardwareBackend.YubiKey;
        if (!_backends.TryGetValue(backend, out var service))
            throw new TswapException(
                $"This vault uses the '{backend.DisplayName}' hardware backend, which this build of tswap does not support. " +
                "Use a build that includes it, or restore a vault created with a supported backend.");

        // Single-device backends (TPM, Secure Enclave) never choose a serial.
        return backend == HardwareBackend.YubiKey
            ? _yubiKey.Unlock(config, selection)
            : service.Unlock(config, serials => selection.Order(serials, serials.Select(_ => (bool?)null).ToList(), serials)[0], password);
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
        if (config.KeyringSlotId is not null)
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

        if (slot is null)
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
