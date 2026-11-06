using System.Security.Cryptography;
using TswapCore.Keyring;
using TswapCore.Vault.Fido2;
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
    private readonly IFido2Service? _fido2;

    /// <summary>
    /// Builds an unlocker with the YubiKey backend always registered, plus any
    /// <paramref name="additionalBackends"/> (TPM, Secure Enclave) supplied by the
    /// composition root. <paramref name="overrideKey"/> is the test-mode master key. <paramref name="fido2"/> (FIDO2
    /// plan, task 7) opens FIDO2 slots in pass 4; without it they fail with <see cref="Fido2Texts.Unavailable"/>.
    /// </summary>
    public VaultUnlocker(
        IYubiKeyService yubiKeys,
        byte[]? overrideKey = null,
        IEnumerable<IHardwareKeyService>? additionalBackends = null,
        IFido2Service? fido2 = null)
    {
        _yubiKey = new YubiKeyHardwareService(yubiKeys, overrideKey);
        _yubiKeys = yubiKeys;
        _fido2 = fido2;
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
    /// Unlocks in four passes (brief T17 ruling 13; FIDO2 plan, task 7). Before any pass, every candidate slot is classified
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
    /// <item><b>Pass 4</b> (FIDO2 plan, task 7): the FIDO2 slots, last, because PIN tries are limited. Every exit
    /// that would end the unlock reaches it while the vault has one (after the deferred OTP slots, which need no PIN).
    /// No terminal (<see cref="UnlockSources.Fido2Pin"/> null): skipped with no key call. Linux and macOS probe each
    /// slot silently and ask one PIN for a found one; Windows runs one ceremony over every FIDO2 slot. A FIDO2 password
    /// slot reuses the password typed in pass 3 or asks for it (at most one prompt per run); it is left out when a TPM
    /// or Secure Enclave password slot refused that password in pass 3 (controller ruling A). One PIN request per run.
    /// Pass 3 still prompts only for non-FIDO2 password candidates.</item>
    /// </list>
    /// A vault without password or FIDO2 slots runs pass 1 only, with today's calls and today's errors (Goal 4).
    /// When every pass fails, the error is pass 1's (the own backend's message with
    /// <see cref="ForeignHardwareSlotHint"/>, the YubiKey slots' failures), then pass 3's, the deferred slots', pass 4's,
    /// then the agent's.
    /// </summary>
    /// <remarks>
    /// YubiKey SDK stage 1, task 4b: with <see cref="UnlockSources.Remembered"/>, each key's slots are tried with the
    /// slot it last opened the vault with first (then keyring order; a slot that answers wrongly is passed, a touch that
    /// times out stops that key as before), and the one-key slot that opens it is remembered. A failed write of that
    /// hint never fails the unlock. <see cref="YubiKeySelection.ExcludeSerial"/> leaves a key out entirely.
    /// </remarks>
    public byte[] Unlock(Config config, YubiKeySelection selection, UnlockSources sources)
    {
        var trace = new SlotTrace(sources.Remembered);
        var key = Unlock(config, selection, sources, trace);
        if (trace.Opened is { } opened)
        {
            if (sources.RememberLater is { } later)
                later(opened.VaultId, opened.Serial, opened.SlotId);
            else
                sources.Remembered?.TryRemember(opened.VaultId, opened.Serial, opened.SlotId);
        }
        return key;
    }

    /// <summary>
    /// Task 4b: the remembered slots of one unlock (read once, and only when a key with several slots is tried) and
    /// the one-key slot that opened the vault.
    /// </summary>
    private sealed class SlotTrace(RememberedYubiKeySlots? remembered)
    {
        private IReadOnlyDictionary<int, byte[]>? _hints;

        public (byte[] VaultId, int Serial, byte[] SlotId)? Opened { get; set; }

        public byte[]? RememberedSlot(byte[] vaultId, int serial) =>
            remembered is null ? null : (_hints ??= remembered.ForVault(vaultId)).GetValueOrDefault(serial);
    }

    private byte[] Unlock(Config config, YubiKeySelection selection, UnlockSources sources, SlotTrace trace)
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
        var plan = Classify(config, keyring, selection.ExcludeSerial);
        var plugged = new PluggedInKeys(_yubiKeys);

        // FIDO2 plan, task 7: FIDO2 slots are pass 4's, tried last (PIN tries are limited). Every exit below that
        // would end the unlock reaches pass 4 first while the vault has one.
        var hasFido2 = plan.Fido2Candidates.Count > 0;

        // ---- Pass 1: password-free candidates only.
        TswapException? ownError = null;
        if (plan.OwnKind == SlotPasswordKind.None && plan.OwnPath)
        {
            // With no one-key slots to fall back to this is exactly the path (and the errors) of
            // every keyring vault before brief T4.
            if (plan.YubiKeySlotCount == 0 && !hasFido2)
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
            // The own slot is set aside (newer tswap, corrupt); without FIDO2 slots nothing else could open the vault.
            if (!hasFido2)
                throw new TswapException(OwnSlotSetAsideText + plan.SetAsideSuffix);
            ownError = new TswapException(OwnSlotSetAsideText);
        }

        // Without password or FIDO2 candidates, pass 1 is today's whole unlock, so its errors carry the
        // set-aside suffix themselves; otherwise it goes at the very end of the combined error.
        var pass1Suffix = plan.HasPasswordCandidates || hasFido2 ? "" : plan.SetAsideSuffix;
        TswapException? pass1Error = ownError;
        // Task 4b fix round: a key whose remembered slot needs the password keeps its password-free slots (older,
        // likely dead since it was re-enrolled) out of pass 1; they are tried last, only if the password pass fails or
        // can't run, so they stay reachable.
        var deferred = DeferredPasswordFreeSlots(keyring, plan.YubiKeyCandidates, trace);
        var pass1Candidates = deferred.Count == 0 ? plan.YubiKeyCandidates : plan.YubiKeyCandidates.Where(c => !deferred.Contains(c)).ToList();
        // Final review (p6-I2): the deferred slots' failure (a busy, hidden or unplugged key, a dead slot) is kept and
        // becomes part of the error when the unlock fails overall.
        TswapException? deferredError = null;
        byte[]? TryDeferred()
        {
            if (deferred.Count == 0)
                return null;
            try
            {
                return UnlockWithYubiKeySlot(keyring, deferred, selection, null, "", passwordPass: false, password: null, plugged, trace);
            }
            catch (TswapException ex) when (ex is not OwnerSwitchException)
            {
                deferredError = ex;
                return null;
            }
        }
        string DeferredSuffix() => deferredError is null ? "" : " " + deferredError.Message;
        if (plan.YubiKeySlotCount > 0)
        {
            try
            {
                var key = UnlockWithYubiKeySlot(keyring, pass1Candidates, selection, ownError, pass1Suffix,
                    passwordPass: false, password: null, plugged, trace);
                if (key is not null)
                    return key;
            }
            catch (TswapException ex) when ((plan.HasPasswordCandidates || hasFido2) && ex is not OwnerSwitchException)
            {
                pass1Error = ex;
            }
        }

        // The vault password of this run: asked at most once, by pass 3 or (for a FIDO2 password slot) by pass 4.
        using var runPassword = new RunPassword(sources.Prompt);
        Fido2Outcome? pass4 = null;
        byte[]? Pass4()
        {
            if (!hasFido2)
                return null;
            var key = TryFido2Slots(keyring, plan.Fido2Candidates, sources, runPassword, out var outcome);
            pass4 = outcome;
            return key;
        }
        string Pass4Suffix() => pass4 is null ? "" : " " + pass4.Message;

        var couldNeedPassword = (plan.OwnPath && plan.OwnKind == SlotPasswordKind.Password)
            || (plan.PasswordSerials.Count > 0 && plugged.TryGet().Any(plan.PasswordSerials.Contains));
        if (!couldNeedPassword)
        {
            if (!hasFido2)
                throw WithSuffix(pass1Error ?? new TswapException("No slot of this vault can be used on this machine."), plan.SetAsideSuffix);
            // (a) No deferred slot can open here: a deferred key has a password slot, and no such key is plugged in.
            if (Pass4() is { } fido2Key)
                return fido2Key;
            // Review Focus 3: a vault whose only way in is FIDO2 (or a FIDO2 password slot), with no terminal or no
            // password, refuses as a missing vault password does.
            if (pass1Error is null && pass4!.PasswordUnavailable)
                throw new VaultPasswordUnavailableException(pass4.Message + plan.SetAsideSuffix);
            throw new TswapException(
                string.Join(" ", new[] { pass1Error?.Message, pass4!.Message }.OfType<string>()) + plan.SetAsideSuffix);
        }

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
        {
            // (b)
            if (TryDeferred() is { } deferredKey)
                return deferredKey;
            if (Pass4() is { } fido2Key)
                return fido2Key;
            throw new VaultPasswordUnavailableException(VaultPasswordMessages.NoTerminal +
                (agentFailure is null ? "" : " " + VaultPasswordMessages.AgentAlsoFailed(agentFailure)) + DeferredSuffix() + Pass4Suffix());
        }
        if (runPassword.Get() is not { } typed)
        {
            // (c) No password to be had (no terminal, no vault-password file).
            var unavailable = runPassword.Failure!;
            if (TryDeferred() is { } deferredKey)
                return deferredKey;
            if (Pass4() is { } fido2Key)
                return fido2Key;
            if (agentFailure is null && deferredError is null && pass4 is null)
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(unavailable);
            // Still say why the agent, the deferred slots and the FIDO2 slots failed.
            throw new VaultPasswordUnavailableException(unavailable.Message +
                (agentFailure is null ? "" : " " + VaultPasswordMessages.AgentAlsoFailed(agentFailure)) + DeferredSuffix() + Pass4Suffix());
        }
        var opened = TryPasswordCandidates(config, selection, keyring, plan, plugged, typed.Clone, out var pass3Error, out var refuted, trace)
            ?? TryDeferred();
        if (opened is not null)
            return opened;
        // Controller ruling A (task 7): a TPM or Secure Enclave password slot's definite "wrong password" refutes the
        // typed password for this run, so pass 4 spends no PIN or touch on FIDO2 password slots.
        runPassword.Refuted = refuted;
        // (d)
        if (Pass4() is { } fido2Opened)
            return fido2Opened;

        // A pass 1 failure is shown only now, when the later passes failed too.
        if (pass1Error is null && agentFailure is null && deferredError is null && pass4 is null && plan.SetAsideSuffix.Length == 0 && pass3Error is not null)
            throw pass3Error;
        List<string> parts = [];
        if (pass1Error is not null)
            parts.Add(pass1Error.Message);
        if (pass3Error is not null)
            parts.Add(pass3Error.Message);
        if (deferredError is not null)
            parts.Add(deferredError.Message);
        if (pass4 is not null)
            parts.Add(pass4.Message);
        if (agentFailure is not null)
            parts.Add(VaultPasswordMessages.AgentAlsoFailed(agentFailure));
        if (parts.Count == 0)
            parts.Add("No slot of this vault opened with the vault password on this machine.");
        throw new TswapException(string.Join(" ", parts) + plan.SetAsideSuffix, pass3Error?.ExitCode ?? 1);
    }

    private const string OwnSlotSetAsideText = "This machine's slot of this vault can't be used.";

    /// <summary>
    /// The vault password of one unlock (FIDO2 plan, task 7): <see cref="UnlockSources.Prompt"/> called at most once,
    /// by pass 3 or by pass 4, and the answer kept for both; disposed when the unlock ends.
    /// </summary>
    private sealed class RunPassword(VaultPasswordProvider? prompt) : IDisposable
    {
        private StretchedPassword? _typed;

        public bool Asked { get; private set; }

        /// <summary>Why no password could be had, once <see cref="Get"/> returned null.</summary>
        public VaultPasswordUnavailableException? Failure { get; private set; }

        /// <summary>Controller ruling A: a TPM or Secure Enclave password slot refused the typed password in pass 3.</summary>
        public bool Refuted { get; set; }

        /// <summary>The typed password (asked on the first call), or null with <see cref="Failure"/>.</summary>
        public StretchedPassword? Get()
        {
            if (Asked)
                return _typed;
            Asked = true;
            if (prompt is null)
            {
                Failure = new VaultPasswordUnavailableException(VaultPasswordMessages.NoTerminal);
                return null;
            }
            try
            {
                return _typed = prompt();
            }
            catch (VaultPasswordUnavailableException ex)
            {
                Failure = ex;
                return null;
            }
        }

        public void Dispose() => _typed?.Dispose();
    }

    /// <summary>
    /// Why pass 4 opened nothing: its text, and whether that is only a missing terminal or vault password (the
    /// refusal of a vault whose only way in is FIDO2 is then a <see cref="VaultPasswordUnavailableException"/>).
    /// </summary>
    private sealed record Fido2Outcome(string Message, bool PasswordUnavailable);

    /// <summary>
    /// Pass 4 (FIDO2 plan, task 7): the vault's FIDO2 slots, with at most one PIN request in the run. No terminal
    /// (<see cref="UnlockSources.Fido2Pin"/> null): no key call. Password slots are left out when
    /// <paramref name="password"/> was refuted (ruling A). Linux and macOS probe each slot silently first and ask a PIN
    /// only for a found one; Windows runs one ceremony over every remaining slot. The KEK is the global constraints':
    /// <c>Fido2SlotKek.Derive(output, blob.PrfInput, slotId)</c>, or <c>DeriveV2</c> with the vault password; the
    /// output is zeroed after.
    /// </summary>
    private byte[]? TryFido2Slots(Keyring.Keyring keyring, List<(Slot Slot, Fido2SlotBlob Blob)> candidates,
        UnlockSources sources, RunPassword password, out Fido2Outcome outcome)
    {
        if (_fido2 is not { } fido2)
        {
            outcome = new(Fido2Texts.Unavailable, PasswordUnavailable: false);
            return null;
        }
        if (sources.Fido2Pin is not { } pin)
        {
            outcome = new(Fido2Texts.NoTerminal, PasswordUnavailable: true);
            return null;
        }

        List<string> notes = [];
        var tryable = candidates;
        if (password.Refuted)
        {
            notes.AddRange(candidates.Where(c => c.Blob.RequiresPassword).Select(c => Fido2Texts.LeftOutPasswordRefused(fido2.KeyName(c.Blob))));
            tryable = [.. candidates.Where(c => !c.Blob.RequiresPassword)];
        }

        return fido2.CanList
            ? TryLocatedFido2Slot(fido2, keyring, tryable, pin, sources.Fido2Notice, password, notes, out outcome)
            : TryFido2Ceremony(fido2, keyring, tryable, pin, sources.Fido2Notice, password, notes, out outcome);
    }

    /// <summary>
    /// Linux and macOS: <see cref="IFido2Service.Locate"/> each slot (no PIN, no touch); a probe that fails (a busy key)
    /// ends the pass. Of the found slots, one is opened, the password-free ones first.
    /// </summary>
    private static byte[]? TryLocatedFido2Slot(IFido2Service fido2, Keyring.Keyring keyring, List<(Slot Slot, Fido2SlotBlob Blob)> tryable,
        Fido2Pin pin, Action<string>? notice, RunPassword password, List<string> notes, out Fido2Outcome outcome)
    {
        List<(Slot Slot, Fido2SlotBlob Blob, Fido2KeyInfo Key)> found = [];
        foreach (var (slot, blob) in tryable)
        {
            Fido2Locate located;
            try
            {
                located = fido2.Locate(blob);
            }
            catch (Fido2Exception ex)
            {
                notes.Add(ex.Message);
                outcome = new(string.Join(" ", notes), PasswordUnavailable: false);
                return null;
            }
            if (located is Fido2Locate.Found hit)
                found.Add((slot, blob, hit.Key));
            else if (Fido2Texts.Describe(located) is { } text)
                notes.Add(text);
        }
        if (found.Count == 0)
        {
            outcome = new(string.Join(" ", notes), PasswordUnavailable: false);
            return null;
        }

        var (pickSlot, pickBlob, pickKey) = found.OrderBy(f => f.Blob.RequiresPassword ? 1 : 0).First();
        var name = fido2.KeyName(pickKey);
        var othersFound = found.Count > 1;
        StretchedPassword? typed = null;
        if (pickBlob.RequiresPassword && (typed = password.Get()) is null)
        {
            notes.Add(Fido2Texts.PasswordUnavailable(name, password.Failure!.Message));
            outcome = new(string.Join(" ", notes), PasswordUnavailable: notes.Count == 1);
            return null;
        }

        Fido2Opened opened;
        try
        {
            opened = fido2.Open([pickBlob], pickKey, TouchLineAfterPin(pin, notice));
        }
        catch (Fido2Exception ex)
        {
            notes.Add(ex.Message);
            if (othersFound)
                notes.Add(Fido2Texts.OtherSlotNotTried);
            outcome = new(string.Join(" ", notes), PasswordUnavailable: false);
            return null;
        }
        var vaultKey = UnwrapFido2Slot(keyring, pickSlot, opened, typed);
        if (vaultKey is null)
        {
            notes.Add(Fido2Texts.UnwrapFailed(name, pickBlob.RequiresPassword));
            if (othersFound)
                notes.Add(Fido2Texts.OtherSlotNotTried);
            outcome = new(string.Join(" ", notes), PasswordUnavailable: false);
            return null;
        }
        outcome = new("", PasswordUnavailable: false);
        return vaultKey;
    }

    /// <summary>
    /// Linux and macOS (FIDO2 plan, task 8): <see cref="Fido2Texts.TouchLine"/> said once the PIN is typed, so it comes
    /// after the PIN prompt, as the key then waits for the touch; nothing when the prompt was cancelled. (Windows' dialog
    /// asks for the PIN itself: its line comes before the ceremony.)
    /// </summary>
    public static Fido2Pin TouchLineAfterPin(Fido2Pin pin, Action<string>? notice) => request =>
    {
        var answer = pin(request);
        if (answer.Length > 0)
            notice?.Invoke(Fido2Texts.TouchLine);
        return answer;
    };

    /// <summary>
    /// Windows: one ceremony with every remaining FIDO2 slot in the allow list; the credential that answers picks the
    /// slot. A password slot's vault password is asked before the dialog; without one, the password slots are left out.
    /// </summary>
    private static byte[]? TryFido2Ceremony(IFido2Service fido2, Keyring.Keyring keyring, List<(Slot Slot, Fido2SlotBlob Blob)> tryable,
        Fido2Pin pin, Action<string>? notice, RunPassword password, List<string> notes, out Fido2Outcome outcome)
    {
        var allowed = tryable;
        StretchedPassword? typed = null;
        if (allowed.Any(c => c.Blob.RequiresPassword) && (typed = password.Get()) is null)
        {
            notes.AddRange(allowed.Where(c => c.Blob.RequiresPassword)
                .Select(c => Fido2Texts.PasswordUnavailable(fido2.KeyName(c.Blob), password.Failure!.Message)));
            allowed = [.. allowed.Where(c => !c.Blob.RequiresPassword)];
        }
        if (allowed.Count == 0)
        {
            // Only password slots, and no password: the dialog is skipped.
            outcome = new(string.Join(" ", notes), PasswordUnavailable: !password.Refuted);
            return null;
        }

        notice?.Invoke(Fido2Texts.WindowsTouchLine);
        Fido2Opened opened;
        try
        {
            opened = fido2.Open([.. allowed.Select(c => c.Blob)], null, pin);
        }
        catch (Fido2Exception ex)
        {
            // The left-out slots are named too, so a key holding only such a slot isn't just told it holds none.
            outcome = new(string.Join(" ", [ex.Message, .. notes]), PasswordUnavailable: false);
            return null;
        }
        var (slot, blob) = allowed.First(c => c.Blob.CredentialId.AsSpan().SequenceEqual(opened.Blob.CredentialId));
        var vaultKey = UnwrapFido2Slot(keyring, slot, opened, blob.RequiresPassword ? typed : null);
        if (vaultKey is null)
        {
            outcome = new(string.Join(" ", [Fido2Texts.UnwrapFailed(fido2.KeyName(blob), blob.RequiresPassword), .. notes]), PasswordUnavailable: false);
            return null;
        }
        outcome = new("", PasswordUnavailable: false);
        return vaultKey;
    }

    /// <summary>
    /// <c>KEK_slot</c> from the opened key's output (zeroed here) and the slot's unwrap: <c>K_v</c>, or null when the
    /// slot didn't authenticate under it. <paramref name="typed"/> is the vault password for a password slot.
    /// </summary>
    private static byte[]? UnwrapFido2Slot(Keyring.Keyring keyring, Slot slot, Fido2Opened opened, StretchedPassword? typed)
    {
        byte[] kekSlot;
        try
        {
            kekSlot = opened.Blob.RequiresPassword
                ? Fido2SlotKek.DeriveV2(opened.Output, typed ?? throw new InvalidOperationException("a FIDO2 password slot needs the vault password"),
                    opened.Blob.PrfInput, slot.SlotId)
                : Fido2SlotKek.Derive(opened.Output, opened.Blob.PrfInput, slot.SlotId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(opened.Output);
        }
        try
        {
            return UnwrapSlot(keyring, slot, kekSlot);
        }
        catch (TswapException)
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kekSlot);
        }
    }

    /// <summary>
    /// Pass 3's candidates (ruling 13): the own backend's slot if it has the password, then the password
    /// YubiKey slots whose key is plugged in, each with <paramref name="provider"/>. The vault key, or null
    /// with the last failure in <paramref name="error"/>. <paramref name="refuted"/> (FIDO2 plan, task 7, controller
    /// ruling A): the own TPM or Secure Enclave slot definitely refused the password (a wrong password); an OTP password
    /// slot's failed unwrap is ambiguous and never refutes it.
    /// </summary>
    private byte[]? TryPasswordCandidates(Config config, YubiKeySelection selection, Keyring.Keyring keyring,
        UnlockPlan plan, PluggedInKeys plugged, VaultPasswordProvider provider, out TswapException? error, out bool refuted,
        SlotTrace? trace = null)
    {
        error = null;
        refuted = false;
        if (plan.OwnPath && plan.OwnKind == SlotPasswordKind.Password)
        {
            try
            {
                return OwnBackend(config, selection, provider);
            }
            catch (TswapException ex) when (ex is not OwnerSwitchException)
            {
                error = ex;
                refuted = config.Backend is HardwareBackend.Tpm or HardwareBackend.SecureEnclave
                    && ex is VaultPasswordRefusedException { Reason: VaultPasswordRefusal.WrongPassword };
            }
        }
        if (plan.PasswordSerials.Count > 0 && plugged.TryGet().Any(plan.PasswordSerials.Contains))
        {
            try
            {
                var key = UnlockWithYubiKeySlot(keyring, plan.YubiKeyCandidates, selection, error, "",
                    passwordPass: true, provider, plugged, trace);
                if (key is not null)
                    return key;
            }
            catch (TswapException ex) when (ex is not OwnerSwitchException)
            {
                error = ex;
            }
        }
        return null;
    }

    /// <summary>
    /// The proof of <c>agent start</c> (ruling 10) and of <c>broker unlock</c> (ruling 14): opens the vault
    /// only through this machine's <b>password</b> slots (the own TPM / Secure Enclave slot if it has the
    /// password, then the password YubiKey slots whose key is plugged in), with <paramref name="password"/>.
    /// No password-free slot is tried, no agent is asked and nothing is prompted, so the hardware itself
    /// checks the password even on a mixed vault whose password-free slot would open it. Each candidate gets
    /// a clone of <paramref name="password"/>, which stays the caller's. The caller still checks the
    /// <c>vault-password</c> verifier.
    /// </summary>
    public byte[] UnlockWithPasswordSlots(Config config, YubiKeySelection selection, StretchedPassword password)
    {
        if (config.Keyring is null)
            throw new TswapException(NoPasswordSlotHereText);
        var keyring = DecodeKeyring(config);
        var plan = Classify(config, keyring, selection.ExcludeSerial);
        var plugged = new PluggedInKeys(_yubiKeys);
        var reachable = (plan.OwnPath && plan.OwnKind == SlotPasswordKind.Password)
            || (plan.PasswordSerials.Count > 0 && plugged.TryGet().Any(plan.PasswordSerials.Contains));
        if (!reachable)
            throw WithSuffix(new TswapException(NoPasswordSlotHereText), plan.SetAsideSuffix);

        var key = TryPasswordCandidates(config, selection, keyring, plan, plugged, password.Clone, out var error, out _);
        return key ?? throw WithSuffix(error ?? new TswapException(NoPasswordSlotHereText), plan.SetAsideSuffix);
    }

    /// <summary><see cref="UnlockWithPasswordSlots"/> found no password slot of this vault usable on this machine.</summary>
    public const string NoPasswordSlotHereText =
        "No slot of this vault on this machine that needs the vault password can be used right now, so the password can't be proven here.";

    /// <summary>
    /// <paramref name="ex"/> with the set-aside suffix, of the same kind: a refused password, an unavailable
    /// password or an agent failure stays one (review T17 p1 I2), so a caller can still tell them apart.
    /// </summary>
    private static TswapException WithSuffix(TswapException ex, string suffix) =>
        suffix.Length == 0 || ex.Message.EndsWith(suffix, StringComparison.Ordinal)
            ? ex
            : ex switch
            {
                VaultPasswordRefusedException refused => new VaultPasswordRefusedException(ex.Message + suffix, refused.Reason),
                VaultPasswordUnavailableException => new VaultPasswordUnavailableException(ex.Message + suffix),
                AgentUnlockFailedException => new AgentUnlockFailedException(ex.Message + suffix),
                _ => new TswapException(ex.Message + suffix, ex.ExitCode),
            };

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
            var plan = Classify(config, DecodeKeyring(config), excludeSerial: null);
            return (plan.OwnPath && plan.OwnKind == SlotPasswordKind.Password) || plan.PasswordSerials.Any(pluggedIn.Contains);
        }
        catch (TswapException)
        {
            return false;
        }
    }

    /// <summary>
    /// FIDO2 plan, task 7: whether the vault's keyring holds a FIDO2 slot (so an unlock may reach pass 4 and need the
    /// terminal's PIN source). Never throws: no keyring, or one it can't read, is false.
    /// </summary>
    public static bool HasFido2Slots(Config config)
    {
        if (config.Keyring is null)
            return false;
        try
        {
            return DecodeKeyring(config).Slots.Any(s => s.Kind == SlotKind.Machine && YubiKeySlotKinds.Classify(s.HwBlob) is YubiKeySlotKind.Fido2);
        }
        catch (TswapException)
        {
            return false;
        }
    }

    /// <summary>
    /// Brief T17 ruling 14: how this machine's own slot of the vault (by <see cref="Config.KeyringSlotId"/>,
    /// or the first machine slot) classifies, for <c>broker serve</c> (locked at start on
    /// <see cref="SlotPasswordKind.Password"/>) and <c>broker unlock|lock|status</c> (refused before
    /// connecting otherwise). <see cref="OwnSlotStanding.Error"/> is ruling 3's text for
    /// <see cref="SlotPasswordKind.NeedsNewerTswap"/> and <see cref="SlotPasswordKind.Corrupt"/>, without the
    /// slot id. Never throws: no keyring, or no own slot, is <see cref="SlotPasswordKind.None"/>.
    /// </summary>
    public static OwnSlotStanding OwnSlotPassword(Config config)
    {
        if (config.Keyring is null)
            return new(SlotPasswordKind.None, null, null);
        try
        {
            var own = FindOwnMachineSlot(config, DecodeKeyring(config));
            if (own is null)
                return new(SlotPasswordKind.None, null, null);
            var (kind, error) = SlotPassword.Describe(own);
            return new(kind, Id8(own), kind == SlotPasswordKind.Corrupt ? SlotPassword.CorruptText : error);
        }
        catch (TswapException)
        {
            return new(SlotPasswordKind.None, null, null); // the unlock reports a damaged config itself
        }
    }

    /// <summary>
    /// The candidates of one unlock, classified before any pass runs (brief T17 ruling 3). FIDO2 plan, task 2: FIDO2
    /// slots are <see cref="Fido2Candidates"/> only (task 7 tries them), never OTP candidates, never counted in
    /// <see cref="YubiKeySlotCount"/> and never set aside as needing a newer tswap.
    /// </summary>
    internal sealed record UnlockPlan(
        bool OwnPath,
        SlotPasswordKind OwnKind,
        int YubiKeySlotCount,
        List<(Slot Slot, YubiKeySlotBlob Blob)> YubiKeyCandidates,
        HashSet<int> PasswordSerials,
        string SetAsideSuffix,
        List<(Slot Slot, Fido2SlotBlob Blob)> Fido2Candidates)
    {
        public bool HasPasswordCandidates => (OwnPath && OwnKind == SlotPasswordKind.Password) || PasswordSerials.Count > 0;
    }

    /// <param name="excludeSerial">Task 4b: a key whose one-key slots are left out (<see cref="YubiKeySelection.ExcludeSerial"/>).</param>
    internal static UnlockPlan Classify(Config config, Keyring.Keyring keyring, int? excludeSerial)
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
            if (own is not null && !YubiKeySlotKinds.IsYubiKey(own.HwBlob))
            {
                (ownKind, var error) = SlotPassword.Describe(own);
                if (ownKind == SlotPasswordKind.Corrupt)
                    corrupt.Add(Id8(own));
                else if (ownKind == SlotPasswordKind.NeedsNewerTswap)
                    newer.Add($"Slot {Id8(own)}: {error}");
            }
        }

        List<(Slot Slot, YubiKeySlotBlob Blob)> candidates = [];
        List<(Slot Slot, Fido2SlotBlob Blob)> fido2Candidates = [];
        var yubiKeySlotCount = 0;
        var excluded = 0;
        foreach (var s in keyring.Slots.Where(s => s.Kind == SlotKind.Machine))
        {
            // A slot whose blob doesn't decode is set aside (security review of T4: one bad slot must
            // not block the others) and named in the final error only if no other slot unlocks.
            switch (YubiKeySlotKinds.Classify(s.HwBlob))
            {
                case YubiKeySlotKind.None:
                    continue;
                case YubiKeySlotKind.Fido2(var fido2):
                    fido2Candidates.Add((s, fido2)); // whatever excludeSerial says: it names OTP slots only
                    continue;
                case YubiKeySlotKind.Otp(var blob) when blob.Serial == excludeSerial:
                    excluded++; // task 4b: the key being re-enrolled
                    break;
                case YubiKeySlotKind.Otp(var blob):
                    candidates.Add((s, blob));
                    break;
                case YubiKeySlotKind.NeedsNewerTswap(var error):
                    newer.Add($"Slot {Id8(s)}: {error}");
                    break;
                default:
                    corrupt.Add(Id8(s));
                    break;
            }
            yubiKeySlotCount++;
        }

        var suffix = (corrupt.Count == 0 ? "" :
                $" Skipped slot(s) {string.Join(", ", corrupt)}: their slot blob is corrupt; restore config.json from backup.") +
            string.Concat(newer.Select(n => " " + n));
        return new UnlockPlan(
            ownPath, ownKind, yubiKeySlotCount - excluded, candidates,
            candidates.Where(c => c.Blob.RequiresPassword).Select(c => c.Blob.Serial).ToHashSet(),
            suffix, fido2Candidates);
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
    /// docs/design/multi-machine-keying.md §Two-layer slot wrap). <paramref name="password"/> reaches the backend
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
    /// the first machine slot when that is null) carries a <c>TSYK</c> blob: a <see cref="YubiKeySlotBlob"/>, or a
    /// <see cref="Fido2SlotBlob"/> (<c>init --fido2</c>, FIDO2 plan task 2), or one this build can't read. A
    /// YubiKey machine slot without one is a legacy pair slot, unlocked through
    /// <see cref="YubiKeyHardwareService"/> and the per-machine pair fields.
    /// </summary>
    private static bool OwnSlotIsAYubiKeySlot(Config config, Keyring.Keyring keyring)
    {
        if ((config.Backend ?? HardwareBackend.YubiKey) != HardwareBackend.YubiKey)
            return false;
        var own = FindOwnMachineSlot(config, keyring);
        return own is not null && YubiKeySlotKinds.IsYubiKey(own.HwBlob);
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
        PluggedInKeys plugged, SlotTrace? trace)
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
            throw new TswapException($"Could not list the plugged-in YubiKeys: {ex.Message}.{ownFailure}");
        }

        var matching = pluggedIn.Where(slotSerials.Contains).Distinct().ToList();
        if (matching.Count == 0 && selection.Serial is null)
            throw new TswapException(
                "No plugged-in YubiKey matches a slot of this vault. " +
                (slotSerials.Count == 0 ? "This vault has no readable YubiKey slot; " :
                    $"This vault's YubiKey slots are for serial(s) {string.Join(", ", slotSerials)}; ") +
                (pluggedIn.Count == 0 ? "no YubiKey is plugged in." : $"plugged in: {string.Join(", ", pluggedIn)}.") +
                (_yubiKeys.DescribeUnreachable() is { } unreachable ? " " + unreachable : "") +
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
            var failure = TryKey(keyring, tryable, serial, order.Count > 1, password, out var vaultKey, trace);
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
    /// Task 4b: the slot <paramref name="trace"/> remembers for this key goes first, then keyring order; the slot that
    /// opens is recorded in it.
    /// </summary>
    private string? TryKey(Keyring.Keyring keyring, List<(Slot Slot, YubiKeySlotBlob Blob)> candidates, int serial,
        bool moreToTry, VaultPasswordProvider? password, out byte[]? vaultKey, SlotTrace? trace = null)
    {
        vaultKey = null;
        var withPassword = false;
        foreach (var (slot, blob) in RememberedFirst(keyring, candidates.Where(c => c.Blob.Serial == serial).ToList(), serial, trace))
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
                if (trace is not null)
                    trace.Opened = (keyring.VaultId, serial, slot.SlotId);
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
    /// Task 4b: one key's slots with the remembered one first, the rest in keyring order. The hint is read only when
    /// the key has more than one slot here (with one, the order can't change).
    /// </summary>
    private static List<(Slot Slot, YubiKeySlotBlob Blob)> RememberedFirst(
        Keyring.Keyring keyring, List<(Slot Slot, YubiKeySlotBlob Blob)> slots, int serial, SlotTrace? trace)
    {
        if (slots.Count < 2 || trace?.RememberedSlot(keyring.VaultId, serial) is not { } remembered)
            return slots;
        return [.. slots.Where(s => s.Slot.SlotId.AsSpan().SequenceEqual(remembered)),
            .. slots.Where(s => !s.Slot.SlotId.AsSpan().SequenceEqual(remembered))];
    }

    /// <summary>
    /// Task 4b fix round: the password-free slots of each key whose remembered slot is one of its password slots (a key
    /// re-enrolled with the password over a password-free slot). The hint is read only when some key has slots of
    /// both kinds.
    /// </summary>
    private static List<(Slot Slot, YubiKeySlotBlob Blob)> DeferredPasswordFreeSlots(
        Keyring.Keyring keyring, List<(Slot Slot, YubiKeySlotBlob Blob)> candidates, SlotTrace trace)
    {
        List<(Slot Slot, YubiKeySlotBlob Blob)> deferred = [];
        foreach (var group in candidates.GroupBy(c => c.Blob.Serial))
        {
            if (!group.Any(c => c.Blob.RequiresPassword) || group.All(c => c.Blob.RequiresPassword))
                continue;
            if (trace.RememberedSlot(keyring.VaultId, group.Key) is not { } remembered)
                continue;
            if (group.Any(c => c.Blob.RequiresPassword && c.Slot.SlotId.AsSpan().SequenceEqual(remembered)))
                deferred.AddRange(group.Where(c => !c.Blob.RequiresPassword));
        }
        return deferred;
    }

    /// <summary>
    /// Task 4b, for <c>slot add --yubikey</c>'s check and <c>yubikey setup --replace</c>'s: the one-key slots of one
    /// key in the order an unlock tries them, the slot <paramref name="remembered"/> holds for it first.
    /// </summary>
    public static List<(Slot Slot, YubiKeySlotBlob Blob)> RememberedFirst(
        Keyring.Keyring keyring, IEnumerable<(Slot Slot, YubiKeySlotBlob Blob)> slots, int serial, RememberedYubiKeySlots? remembered) =>
        RememberedFirst(keyring, slots.ToList(), serial, new SlotTrace(remembered));

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
                "Config is corrupted: Keyring is not valid base64. Restore config.json from backup or re-run 'tswap init'.");
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
                "Config is corrupted: KeyringSlotId is not valid base64. Restore config.json from backup or re-run 'tswap init'.");
        }
        return keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine && s.SlotId.AsSpan().SequenceEqual(ownSlotId));
    }

    /// <summary>
    /// YubiKey SDK stage 1, task 4 (<c>yubikey setup --replace</c>): whether one one-key YubiKey slot opens the vault
    /// now. Its key is challenged (<paramref name="password"/> is called for a password slot) and the slot unwrapped;
    /// the vault key is zeroed at once, never returned, and nothing else is unlocked. False: the slot didn't
    /// authenticate under the key's answer (a definite wrong answer). A failed challenge (the key busy, no answer, not
    /// reachable) or no password is thrown as it is.
    /// </summary>
    public bool YubiKeySlotOpens(Keyring.Keyring keyring, Slot slot, YubiKeySlotBlob blob, VaultPasswordProvider? password)
    {
        var kekSlot = YubiKeySlotKek.Recover(_yubiKeys, blob, slot.SlotId, password);
        try
        {
            var vaultKey = UnwrapSlot(keyring, slot, kekSlot);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(vaultKey);
            return true;
        }
        catch (TswapException)
        {
            return false;
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(kekSlot);
        }
    }

    /// <summary>
    /// FIDO2 plan, task 8 (<c>yubikey setup --replace</c>): whether one of <paramref name="slots"/> (the vault's FIDO2
    /// slots) opens the vault now, as pass 4 opens them: the key's PIN and a touch (<see cref="UnlockSources.Fido2Pin"/>;
    /// null, no terminal: no key call), the vault password from <see cref="UnlockSources.Prompt"/> for a password slot,
    /// then the slot unwrapped. The vault key is zeroed at once. Null when a slot opened, else why none did (a wrong
    /// PIN, a cancelled prompt, no terminal, the key not plugged in), in pass 4's words.
    /// </summary>
    public string? Fido2SlotOpens(Keyring.Keyring keyring, IReadOnlyList<(Slot Slot, Fido2SlotBlob Blob)> slots, UnlockSources sources)
    {
        using var password = new RunPassword(sources.Prompt);
        var vaultKey = TryFido2Slots(keyring, [.. slots], sources, password, out var outcome);
        if (vaultKey is null)
            return outcome.Message;
        CryptographicOperations.ZeroMemory(vaultKey);
        return null;
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
                "Config is corrupted: Keyring is not valid base64. Restore config.json from backup or re-run 'tswap init'.");
        }

        var keyring = KeyringCodec.Decode(keyringBytes);

        if (keyring.Slots.Count == 0)
            throw new TswapException(
                "Config is corrupted: keyring has no slots. Restore config.json from backup or re-run 'tswap init'.");

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
                    "Config is corrupted: KeyringSlotId is not valid base64. Restore config.json from backup or re-run 'tswap init'.");
            }
            slot = keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine && s.SlotId.AsSpan().SequenceEqual(ownSlotId));
        }
        else
        {
            slot = keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine);
        }

        if (slot is null)
            throw new TswapException(
                "Config is corrupted: keyring has no machine slot matching this machine. Restore config.json from backup or re-run 'tswap init'.");

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
