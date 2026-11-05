using System.Globalization;
using System.Text.Json;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;

namespace TswapCli.Commands;

/// <summary>
/// <c>tswap yubikey setup (--touch|--no-touch) [--serial N] [--replace]</c> (YubiKey SDK stage 1, task 4; design
/// "tswap yubikey setup"): programs slot 2 of a plugged-in YubiKey for HMAC-SHA1 challenge-response with a fresh
/// secret, with the flags of Yubico's own challenge-response tooling (HMAC_LT64 on, touch per flag), and checks that it answers. It never needs sudo, never
/// writes the vault, and only ever touches slot 2. Its refusals keep a vault from losing its way in:
/// <list type="bullet">
/// <item>a configured slot 2 is refused without <c>--replace</c> (nothing is challenged or written);</item>
/// <item>with <c>--replace</c> (on a configured slot only: an empty one has nothing to lose) the user types the key's
/// serial at a terminal, and the vault tswap is pointed at is read (its keyring's slot list, no unlock): refused unless
/// a slot that opens the vault by itself is left (a TPM, Secure Enclave or recovery slot; or a one-key YubiKey slot of
/// another key, which must be plugged in and open now), and refused when a classic pair vault uses the key; a vault
/// that can't be read gets a warning and setup goes on (owner-approved design).</item>
/// </list>
/// </summary>
public sealed class YubiKeyCommand : ICliCommand
{
    public string Name => "yubikey";
    public string HelpUsage => "yubikey setup (--touch|--no-touch) [--serial N] [--replace]";
    public string Description => "Prepare a YubiKey's slot 2 for challenge-response (a configured slot is overwritten only with --replace)";
    public bool RequiresSudo => false;

    /// <summary>It opens the vault only to check <c>--replace</c>, and works without one.</summary>
    public bool NeedsVault => false;

    internal const string InterruptionNote =
        "If this is interrupted, slot 2 may be left programmed but unchecked: enrol it with `slot add --yubikey` " +
        "(which checks it before enrolling it), or run setup again with --replace.";

    internal const string TouchPrompt = "touch the key when it flashes (to check the new slot)";

    internal const string CouldNotCheck = "couldn't check whether a vault depends on this key";

    private string Usage(CommandContext ctx) => $"{ctx.Prefix} {HelpUsage} (exactly one of --touch and --no-touch)";

    public int Execute(CommandContext ctx, string[] args)
    {
        var (touch, serial, replace) = Parse(ctx, args);
        var keys = ctx.YubiKeys.FindKeys();
        if (ctx.Verbose)
            ListKeys(ctx, keys);

        var chosen = ChooseKey(ctx, keys, serial);
        var state = ctx.YubiKeys.GetSlot2State(chosen); // a failed read stops here: it is never Empty
        if (state == Slot2State.Configured)
        {
            if (!replace)
                throw new TswapException(
                    $"slot 2 of YubiKey {chosen} is already set up (touch: unknown — the key doesn't report it); a vault using " +
                    "this key would no longer open if it were replaced. Use --replace to overwrite it; after reprogramming, enrol it " +
                    $"again with {ElevatedCommand.For(ctx.Prefix, "slot add --yubikey")}.");
            ConfirmSerial(ctx, chosen);
            CheckVault(ctx, chosen, keys);
        }

        Program(ctx, chosen, touch);
        return 0;
    }

    private (bool Touch, int? Serial, bool Replace) Parse(CommandContext ctx, string[] args)
    {
        if (args is not ["setup", .. var rest])
            throw new UsageException(Usage(ctx));
        bool withTouch = false, noTouch = false, replace = false;
        int? serial = null;
        for (var i = 0; i < rest.Length; i++)
        {
            switch (rest[i])
            {
                case "--touch" when !withTouch:
                    withTouch = true;
                    break;
                case "--no-touch" when !noTouch:
                    noTouch = true;
                    break;
                case "--replace" when !replace:
                    replace = true;
                    break;
                case "--serial" when serial is null && i + 1 < rest.Length
                    && int.TryParse(rest[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out var n):
                    serial = n;
                    i++;
                    break;
                default:
                    throw new UsageException(Usage(ctx));
            }
        }
        if (withTouch == noTouch)
            throw new UsageException(Usage(ctx));
        return (withTouch, serial, replace);
    }

    /// <summary>
    /// <c>-v</c>: the PC/SC strategy (Linux only; chosen at the SDK's first PC/SC call, so after the enumeration),
    /// then every key the SDK sees, in its order, with its transports.
    /// </summary>
    private static void ListKeys(CommandContext ctx, IReadOnlyList<YubiKeyInfo> keys)
    {
        var o = ctx.Console.Out;
        if (OperatingSystem.IsLinux())
            o.WriteLine($"PC/SC (smart-card) access: {PcscStrategy.Describe()}");
        foreach (var key in keys)
        {
            var name = key.Serial is { } s ? $"YubiKey {s}" : "YubiKey (serial can't be read)";
            var reach = key.KeyboardReachable ? "keyboard interface reachable" : "keyboard interface not reachable";
            o.WriteLine($"  {name}: {key.Transports} ({reach})");
        }
    }

    /// <summary>
    /// <c>--serial N</c>; else the one plugged-in key; else, at a terminal, the prompt (keyboard-reachable keys with a
    /// serial only, naming the others). A key that is plugged in but hidden gets the per-OS explanation, never
    /// "not plugged in", and is explained here, before the SDK is asked anything about it.
    /// </summary>
    private static int ChooseKey(CommandContext ctx, IReadOnlyList<YubiKeyInfo> keys, int? serial)
    {
        var os = YubiKeyAccessTexts.CurrentOs();
        if (serial is { } wanted)
        {
            var key = keys.FirstOrDefault(k => k.Serial == wanted);
            if (key is null)
            {
                var message = $"YubiKey {wanted} is not plugged in.";
                // A hidden key whose serial can't be read may be the one asked for.
                if (keys.Any(k => !k.KeyboardReachable && k.Serial is null))
                    message += Environment.NewLine + YubiKeyAccessTexts.ExplainHidden(null, os);
                throw new TswapException(message);
            }
            if (!key.KeyboardReachable)
                throw new TswapException(YubiKeyAccessTexts.ExplainHidden(wanted, os));
            return wanted;
        }

        if (keys.Count == 0)
            throw new TswapException("No YubiKey detected. Please insert YubiKey.");

        var offered = keys.Where(k => k.KeyboardReachable && k.Serial is not null).Select(k => k.Serial!.Value).ToList();
        var hidden = keys.Where(k => !k.KeyboardReachable).ToList();
        var noSerial = keys.Where(k => k.KeyboardReachable && k.Serial is null).ToList();
        if (offered.Count == 0)
        {
            if (noSerial.Count > 0)
                throw new TswapException("a YubiKey was found but its serial number can't be read; tswap needs it");
            throw new TswapException(string.Join(Environment.NewLine, hidden.Select(k => YubiKeyAccessTexts.ExplainHidden(k.Serial, os))));
        }
        if (keys.Count == 1)
            return offered[0];

        // Several keys: the user picks, at a terminal only (a script names the key with --serial).
        if (ctx.Console.IsInputRedirected || ctx.Console.IsOutputRedirected)
            throw new TswapException("Several YubiKeys are plugged in: name the one to set up with --serial N.");
        List<string> notes = [.. hidden.Select(k => "Not offered: " + YubiKeyAccessTexts.ExplainHidden(k.Serial, os))];
        if (noSerial.Count > 0)
            notes.Add("Not offered: a YubiKey whose serial number can't be read.");
        return ctx.PromptForSerial(offered, notes.Count == 0 ? null : string.Join(Environment.NewLine, notes));
    }

    /// <summary><c>--replace</c> on a configured slot: the user types the key's serial at a terminal.</summary>
    private static void ConfirmSerial(CommandContext ctx, int serial)
    {
        var c = ctx.Console;
        if (c.IsInputRedirected || c.IsOutputRedirected)
            throw new TswapException(
                $"--replace needs a terminal: you confirm it by typing the serial of YubiKey {serial}. Nothing was changed.");
        c.Error.WriteLine($"Replacing slot 2 of YubiKey {serial} destroys its current secret: a vault slot made with it will no longer open.");
        c.Error.Write($"Type the key's serial ({serial}) to confirm: ");
        var typed = c.ReadLine()?.Trim();
        if (typed != serial.ToString(CultureInfo.InvariantCulture))
            throw new TswapException($"The serial typed doesn't match YubiKey {serial}. Nothing was changed.");
    }

    /// <summary>
    /// <c>--replace</c> on a configured slot: refuses when the vault tswap is pointed at would lose its only way in.
    /// "Read" is the keyring's slot list, as <c>tswap slots</c> reads it: no sudo, no unlock, no prompt. No vault, or
    /// one that can't be read: a warning, and setup goes on (design, owner-approved). Only a slot that opens the vault
    /// by itself counts as another way in (amended 2026-11-05 after review): a TPM or Secure Enclave slot of any
    /// machine and a recovery slot count as they are; a one-key YubiKey slot of another key counts only when that key
    /// is plugged in and its slot opens now (<see cref="CheckAnotherKey"/>).
    /// </summary>
    private static void CheckVault(CommandContext ctx, int serial, IReadOnlyList<YubiKeyInfo> keys)
    {
        Config config;
        try
        {
            // A look at the config only: a classic vault is read too (setup must see a pair vault that uses this key),
            // and this command opens the store for nothing else.
            ctx.ClassicVaultAllowed = true;
            config = ctx.Storage.LoadConfig();
        }
        catch (Exception e) when (e is TswapException or JsonException or IOException or UnauthorizedAccessException)
        {
            Warn(ctx, e.Message);
            return;
        }

        if (config.Keyring is null)
        {
            if (config.YubiKeySerials?.Contains(serial) == true)
                throw new TswapException(
                    $"Refusing: the classic two-YubiKey vault in {ctx.Env.ConfigDir} uses YubiKey {serial}, and it always needs " +
                    "both keys, so replacing this key's slot 2 would lock the vault. Nothing was changed.");
            if (config.YubiKeySerials is { Count: > 0 } || config.TpmSealedKey is not null || config.SecureEnclaveWrappedKey is not null)
                return; // a vault that doesn't use this key: its config says which keys it uses
            Warn(ctx, $"{ctx.Env.ConfigDir} holds no vault");
            return;
        }

        Keyring keyring;
        try
        {
            keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring));
        }
        catch (Exception e) when (e is TswapException or FormatException or ArgumentException)
        {
            Warn(ctx, $"its keyring can't be read: {e.Message}");
            return;
        }

        // The rule applies only when this key has a slot here: otherwise nothing on the key is at risk.
        if (!keyring.Slots.Any(s => MayBeThisKeys(config, keyring, s, serial)))
            return;

        List<(Slot Slot, YubiKeySlotBlob Blob)> otherKeys = [];
        foreach (var slot in keyring.Slots)
        {
            switch (Classify(slot, serial))
            {
                case WayIn.ByItself:
                    return;
                case WayIn.OtherYubiKey:
                    otherKeys.Add((slot, YubiKeySlotBlob.Decode(slot.HwBlob!)));
                    break;
            }
        }
        if (otherKeys.Count == 0)
            throw new TswapException(
                $"Refusing: YubiKey {serial} is the only way into the vault in {ctx.Env.ConfigDir} (its keyring has no slot " +
                "that opens it without this key), so replacing its slot 2 would lock the vault. Add another way in first " +
                "(another YubiKey, a TPM or Secure Enclave slot, or a recovery slot), then run this again. Nothing was changed.");
        CheckAnotherKey(ctx, config, keyring, serial, otherKeys, keys);
    }

    private enum WayIn { No, ByItself, OtherYubiKey }

    /// <summary>
    /// A blob recognised as a TPM or Secure Enclave slot's, as their unlockers read it: a <c>TSTP</c>/<c>TSSE</c> header
    /// that classifies as valid (<see cref="SlotPassword.Classify"/> None or Password, so not corrupt and not from a newer
    /// tswap), or a headerless package in the shape every legacy TPM (Windows, Linux) and Secure Enclave package has: a
    /// 4-byte little-endian length, that many bytes, at least one more (the unlockers' own length check). Anything else
    /// (an unknown magic, a damaged header or length) is not a way in (fail closed).
    /// </summary>
    private static bool IsTpmOrSecureEnclaveSlot(Slot slot)
    {
        var blob = slot.HwBlob!;
        if (TpmSlotBlob.HasHeader(blob) || SecureEnclaveSlotBlob.HasHeader(blob))
            return SlotPassword.Classify(slot) is SlotPasswordKind.None or SlotPasswordKind.Password;
        if (blob.Length < 4)
            return false;
        var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(blob);
        return length >= 0 && length < blob.Length - 4;
    }

    /// <summary>
    /// Whether <paramref name="slot"/> may be a slot on YubiKey <paramref name="serial"/>: a one-key YubiKey slot of this
    /// serial, or one whose serial can't be read (fail closed); this machine's legacy pair slot when its pair (the
    /// config's pair serials) includes this key; another machine's legacy pair slot, whose pair isn't known here (fail
    /// closed). Recovery, TPM and Secure Enclave slots and other keys' slots are not.
    /// </summary>
    private static bool MayBeThisKeys(Config config, Keyring keyring, Slot slot, int serial)
    {
        if (slot.Kind == SlotKind.Recovery)
            return false;
        if (slot.HwBlob is not { Length: > 0 })
            return IsOwnSlot(config, keyring, slot) ? config.YubiKeySerials?.Contains(serial) == true : true;
        if (!YubiKeySlotBlob.IsYubiKeyBlob(slot.HwBlob))
            return false;
        try
        {
            return YubiKeySlotBlob.Decode(slot.HwBlob).Serial == serial;
        }
        catch (TswapException)
        {
            return true;
        }
    }

    /// <summary>This machine's own slot: by <see cref="Config.KeyringSlotId"/>, or the first machine slot when that is null (as the unlocker finds it).</summary>
    private static bool IsOwnSlot(Config config, Keyring keyring, Slot slot) =>
        config.KeyringSlotId is { } id
            ? Convert.ToBase64String(slot.SlotId) == id
            : ReferenceEquals(keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine), slot);

    /// <summary>
    /// What a slot is for <c>--replace</c> on YubiKey <paramref name="serial"/>: a recovery slot, or a machine slot
    /// with a hardware blob that isn't a YubiKey's (a TPM or Secure Enclave of any machine), opens the vault by itself;
    /// a one-key YubiKey slot of another serial (compared as integers) does if its key answers. Never this serial's
    /// slots, never a YubiKey slot whose serial can't be read (fail closed), never a legacy pair slot (a machine slot
    /// without a hardware blob: it needs both keys of the pair).
    /// </summary>
    private static WayIn Classify(Slot slot, int serial)
    {
        if (slot.Kind == SlotKind.Recovery)
            return WayIn.ByItself;
        if (slot.HwBlob is not { Length: > 0 })
            return WayIn.No;
        if (!YubiKeySlotBlob.IsYubiKeyBlob(slot.HwBlob))
            return IsTpmOrSecureEnclaveSlot(slot) ? WayIn.ByItself : WayIn.No;
        try
        {
            return YubiKeySlotBlob.Decode(slot.HwBlob).Serial != serial ? WayIn.OtherYubiKey : WayIn.No;
        }
        catch (TswapException)
        {
            return WayIn.No;
        }
    }

    /// <summary>
    /// The only other ways in are other keys' YubiKey slots: one of those keys must be plugged in (reachable over the
    /// keyboard interface) and one of its slots must open the vault now (challenged and unwrapped; a password slot asks
    /// for the vault password at the terminal). A definite wrong answer, or no such key plugged in, refuses; so does a
    /// key that is busy or doesn't answer (the device's own wording).
    /// </summary>
    private static void CheckAnotherKey(CommandContext ctx, Config config, Keyring keyring, int serial,
        List<(Slot Slot, YubiKeySlotBlob Blob)> otherKeys, IReadOnlyList<YubiKeyInfo> keys)
    {
        var otherSerials = otherKeys.Select(k => k.Blob.Serial).Distinct().ToList();
        var names = string.Join(" or ", otherSerials.Select(s => $"YubiKey {s}"));
        var plugged = keys.Where(k => k.KeyboardReachable && k.Serial is not null).Select(k => k.Serial!.Value).ToHashSet();
        // Task 4b: each key's slots with the one it last opened the vault with on this machine first.
        var remembered = ctx.RememberedSlots;
        var candidates = otherSerials.Where(plugged.Contains)
            .SelectMany(s => VaultUnlocker.RememberedFirst(keyring, otherKeys.Where(k => k.Blob.Serial == s), s, remembered))
            .ToList();
        if (candidates.Count == 0)
        {
            // Carried from task 4: a key that is plugged in but hidden from the keyboard interface gets the per-OS text.
            var os = YubiKeyAccessTexts.CurrentOs();
            var hidden = keys.Where(k => !k.KeyboardReachable && k.Serial is { } s && otherSerials.Contains(s))
                .Select(k => YubiKeyAccessTexts.ExplainHidden(k.Serial, os) + Environment.NewLine);
            throw new TswapException(
                string.Concat(hidden) +
                $"Refusing: apart from YubiKey {serial}, only {names} can open the vault in {ctx.Env.ConfigDir}, and none of " +
                $"them can be checked here: plug in {names} so its slot can be checked, or leave this key as it is. Nothing was changed.");
        }

        // The vault password is asked at most once (only a password slot asks), and dropped at the end.
        StretchedPasswordCache password = new(TerminalPasswordProvider.For(ctx, config));
        try
        {
            // The remembered slot first, then keyring order (task 4b). A definite wrong answer is kept
            // apart from a key that was busy or didn't answer: when no slot opens, the latter decides the message,
            // since that key may still open the vault.
            string? didntOpen = null, transient = null;
            foreach (var (slot, blob) in candidates)
            {
                ctx.Console.Error.WriteLine($"Checking that YubiKey {blob.Serial}'s slot still opens the vault (touch it if it flashes)...");
                try
                {
                    if (ctx.Unlocker.YubiKeySlotOpens(keyring, slot, blob, password.Provide))
                        return;
                    didntOpen ??= DidntOpen(blob);
                }
                catch (TswapCore.VaultPassword.VaultPasswordUnavailableException e)
                {
                    throw new TswapException($"Refusing: YubiKey {blob.Serial}'s slot needs the vault password to be checked: {e.Message} Nothing was changed.");
                }
                catch (TswapException e)
                {
                    // By the failure's kind: busy keeps the device's text (Task 2's wording); an empty slot 2 was
                    // reprogrammed or cleared, so its slot didn't open; anything else (a touch that timed out, the key
                    // pulled mid-check, no answer) is "didn't answer", with the device's message after it.
                    switch ((e as YubiKeyDeviceException)?.Kind)
                    {
                        case OtpFailure.Busy:
                            transient ??= e.Message;
                            break;
                        case OtpFailure.Slot2Empty:
                            didntOpen ??= DidntOpen(blob);
                            break;
                        default:
                            transient ??= $"YubiKey {blob.Serial} didn't answer; plug it in and touch it when it flashes. ({e.Message})";
                            break;
                    }
                }
            }
            throw new TswapException($"Refusing: {transient ?? didntOpen} Nothing was changed.");
        }
        finally
        {
            password.Dispose();
        }
    }

    /// <summary>A definite wrong answer (or an emptied slot 2); a password slot may also have had the wrong password.</summary>
    private static string DidntOpen(YubiKeySlotBlob blob) =>
        $"YubiKey {blob.Serial}'s slot didn't open (it may have been reprogrammed{(blob.RequiresPassword ? ", or the vault password was mistyped" : "")}); " +
        "this key may be the vault's only working YubiKey, so it's left as it is.";

    /// <summary>A password provider that asks its source once and hands out clones.</summary>
    private sealed class StretchedPasswordCache(TswapCore.VaultPassword.VaultPasswordProvider source) : IDisposable
    {
        private TswapCore.VaultPassword.StretchedPassword? _password;

        public TswapCore.VaultPassword.StretchedPassword Provide() => (_password ??= source()).Clone();

        public void Dispose() => _password?.Dispose();
    }

    private static void Warn(CommandContext ctx, string reason) =>
        ctx.Console.Error.WriteLine($"Warning: {CouldNotCheck} ({reason}).");

    /// <summary>Programs and proves slot 2, wording each failure for what it leaves behind.</summary>
    private static void Program(CommandContext ctx, int serial, bool touch)
    {
        var e = ctx.Console.Error;
        e.WriteLine(InterruptionNote);
        if (touch)
            e.WriteLine(TouchPrompt);
        try
        {
            ctx.YubiKeys.ProgramSlot2(serial, touch);
        }
        catch (YubiKeyProgramException ex)
        {
            var detail = string.IsNullOrEmpty(ex.Detail) ? "" : $" ({ex.Detail})";
            throw new TswapException(ex.Kind switch
            {
                OtpFailure.VerifyWrong =>
                    $"slot 2 of YubiKey {serial} was programmed but is configured wrongly{detail}: its answer differs, so a vault " +
                    "enrolled on it would not open as expected, or its touch setting differs, so it would open without the touch " +
                    "asked for, or the other way round (a settings mismatch, or another setup or programming tool ran on this key " +
                    "at the same time). A vault enrolled on it would not open the way a correctly programmed challenge-response " +
                    $"slot does. Run `{ctx.Prefix} yubikey setup --replace` again (with --touch or --no-touch), or report it.",
                OtpFailure.VerifyNoAnswer =>
                    $"slot 2 of YubiKey {serial} is programmed, but its check failed{detail}: it didn't answer the check " +
                    $"challenge (a touch that timed out counts). `{ctx.Prefix} yubikey setup` refuses an occupied slot, so check " +
                    $"it by enrolling it: {ElevatedCommand.For(ctx.Prefix, "slot add --yubikey")}, which checks it before enrolling it " +
                    $"(or `{ctx.Prefix} init --yubikey` for a new vault).",
                _ =>
                    $"Programming failed{detail}: slot 2 of YubiKey {serial} may now be empty or half-written (or, if the " +
                    "failure came before anything was written, unchanged). Don't enrol it as it is: run " +
                    $"`{ctx.Prefix} yubikey setup --replace` again (with --touch or --no-touch).",
            });
        }
        ctx.Console.Out.WriteLine($"YubiKey {serial} slot 2: HMAC-SHA1 challenge-response, {(touch ? "touch required" : "no touch required")}");
    }
}
