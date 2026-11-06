using System.Globalization;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Fido2;
using TswapCore.VaultPassword;

namespace TswapCli;

/// <summary>
/// FIDO2 plan, task 6: enrols a YubiKey's FIDO2 credential as a keyring slot, shared by <c>slot add --fido2</c> and
/// <c>init --fido2</c>. Two key operations, each a PIN at the terminal and a touch: make-credential
/// (<see cref="IFido2Service.Enrol"/>), then one assertion of the new credential (<see cref="IFido2Service.Open"/>) whose
/// output gives <c>KEK_slot = Fido2SlotKek.Derive(output, blob.PrfInput, slotId)</c> (or <c>DeriveV2</c> with the
/// vault password). The output is zeroed after the derivation; the caller writes only after both calls succeeded.
/// </summary>
internal static class Fido2SlotEnrollment
{
    public const string SerialFlag = "--serial";

    /// <summary>Said after each PIN prompt on Linux and macOS (the device layer has no touch callback).</summary>
    public const string TouchLine = Fido2Texts.TouchLine;

    /// <summary>Said once on Windows, before the first key operation.</summary>
    public const string WindowsDialogLine =
        "Windows will ask for the key's PIN and a touch (twice). If the key has no FIDO2 PIN yet, Windows asks you to create one.";

    /// <summary>Said before each key operation on Windows.</summary>
    public const string WindowsTouchLine = Fido2Texts.WindowsTouchLine;

    public const string WindowsSerialRefusal = "--serial: on Windows, Windows' dialog picks the key.";

    public const string Unavailable = Fido2Texts.Unavailable;

    /// <summary>Said when the second key operation fails: the first made a credential, but nothing was written.</summary>
    public const string RetrySafeText =
        "No slot was added and nothing was written. The key may keep an unused credential (a YubiKey stores nothing for " +
        "it: its id is the wrapped key; other brands may differ), so running this again is safe.";

    /// <summary>The closing line of every OTP enrolment, on every OS (<see cref="YubiKeySlotEnrollment.PrintTouchPolicy"/>).</summary>
    public const string MultiOsHint =
        "Note: an OTP slot needs Input Monitoring on a Mac and Yubico's udev rule on Linux. If this key will be used on a " +
        "Mac, give it a FIDO2 slot too: `tswap slot add --fido2` (with sudo, or from an elevated prompt on Windows).";

    /// <summary>What a FIDO2 reset does to the slot of <paramref name="keyName"/>: said after every FIDO2 enrolment.</summary>
    public static string ResetWarning(string keyName) =>
        $"A FIDO2 reset of {keyName} deletes this slot's credential and kills the slot: it can't open the vault again. " +
        "Then re-enrol the key with `tswap slot add --fido2`, opening the vault another way.";

    /// <summary>Takes <c>--serial N</c> out of <paramref name="args"/> (at most once, a positive number).</summary>
    public static (string[] Remaining, int? Serial) SplitSerial(string[] args, string usage)
    {
        var index = Array.IndexOf(args, SerialFlag);
        if (index < 0)
            return (args, null);
        if (index + 1 >= args.Length || args.Count(a => a == SerialFlag) > 1
            || !int.TryParse(args[index + 1], NumberStyles.None, CultureInfo.InvariantCulture, out var serial) || serial <= 0)
            throw new UsageException(usage);
        return ([.. args[..index], .. args[(index + 2)..]], serial);
    }

    /// <summary>
    /// The FIDO2 service, once the checks that need no key have passed: one is wired here, a person is at a terminal
    /// (<see cref="Fido2Texts.NoTerminal"/> otherwise, on every OS), and <c>--serial</c> isn't given on Windows. Called
    /// before the vault is unlocked and before any key call.
    /// </summary>
    public static IFido2Service Require(CommandContext ctx, int? serial)
    {
        var fido2 = ctx.Fido2 ?? throw new TswapException(Unavailable);
        if (!Fido2PinPrompt.HasTerminal(ctx))
            throw new Fido2Exception(Fido2Failure.NoTerminal, serial, null, Fido2Texts.NoTerminal);
        if (!fido2.CanList && serial is not null)
            throw new TswapException(WindowsSerialRefusal);
        return fido2;
    }

    /// <summary>
    /// The key to enrol: on Windows null (the dialog picks it; <see cref="WindowsDialogLine"/> is said). Elsewhere the
    /// plugged-in YubiKey with <paramref name="serial"/>, the only one, or the one the person picks at the terminal; a
    /// key without a FIDO2 PIN is offered one (asked twice), the one PIN write tswap makes, and "no" stops.
    /// </summary>
    public static Fido2KeyInfo? ChooseKey(CommandContext ctx, int? serial)
    {
        var key = PickKey(ctx, serial);
        return key is null ? null : EnsurePin(ctx, key);
    }

    /// <summary>
    /// <see cref="ChooseKey"/> without the PIN offer: on Windows null (and <see cref="WindowsDialogLine"/> is said),
    /// elsewhere the key picked by <paramref name="serial"/>, as the only one, or at the terminal. No PIN, no touch.
    /// </summary>
    public static Fido2KeyInfo? PickKey(CommandContext ctx, int? serial)
    {
        var fido2 = Require(ctx, serial);
        if (!fido2.CanList)
        {
            ctx.Console.Out.WriteLine(WindowsDialogLine);
            return null;
        }

        var keys = fido2.ListYubiKeys();
        if (keys.Count == 0)
            throw new TswapException("No YubiKey with FIDO2 detected. Please insert YubiKey.");
        if (serial is { } wanted)
            return keys.FirstOrDefault(k => k.Serial == wanted)
                ?? throw new TswapException($"YubiKey {wanted} is not plugged in (plugged in: {string.Join(", ", keys.Select(fido2.KeyName))}).");
        return keys.Count == 1 ? keys[0] : AskWhich(ctx, fido2, keys);
    }

    /// <summary><paramref name="key"/>, after offering it a FIDO2 PIN when it has none (<see cref="OfferPin"/>).</summary>
    public static Fido2KeyInfo EnsurePin(CommandContext ctx, Fido2KeyInfo key) =>
        key.PinSet ? key : OfferPin(ctx, Require(ctx, key.Serial), key);

    /// <summary>The FIDO2 slots of <paramref name="keyring"/> (readable without the vault key).</summary>
    public static List<Fido2SlotBlob> VaultFido2Slots(Keyring keyring) => [.. keyring.Slots
        .Where(s => s.Kind == SlotKind.Machine)
        .Select(s => YubiKeySlotKinds.Classify(s.HwBlob))
        .OfType<YubiKeySlotKind.Fido2>()
        .Select(f => f.Blob)];

    /// <summary>
    /// Linux and macOS: refuses <paramref name="key"/> when the silent probe finds one of
    /// <paramref name="vaultFido2Slots"/> on it (no PIN, no touch), so <c>slot add --fido2</c> can refuse before the
    /// vault is unlocked. (Windows can't probe: there the exclude list refuses, after the unlock.)
    /// </summary>
    public static void RefuseIfEnrolled(IFido2Service fido2, Fido2KeyInfo key, IReadOnlyList<Fido2SlotBlob> vaultFido2Slots)
    {
        foreach (var blob in vaultFido2Slots)
            if (fido2.Locate(blob) is Fido2Locate.Found found && found.Key.Key == key.Key)
                throw new Fido2Exception(Fido2Failure.CredentialExcluded, key.Serial, null, Fido2Texts.AlreadyHasSlot(fido2.KeyName(key)));
    }

    private static Fido2KeyInfo AskWhich(CommandContext ctx, IFido2Service fido2, IReadOnlyList<Fido2KeyInfo> keys)
    {
        using var terminal = ctx.Terminal?.Invoke() ?? throw new Fido2Exception(Fido2Failure.NoTerminal, null, null, Fido2Texts.NoTerminal);
        var list = string.Concat(keys.Select((k, i) => $"  {i + 1}. {fido2.KeyName(k)}\n"));
        terminal.Write($"\nSeveral YubiKeys are plugged in:\n{list}Select YubiKey (1-{keys.Count}): ");
        var input = terminal.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(input))
            return keys[0]; // blank or end of input: the first, as the OTP prompt does
        if (!int.TryParse(input, out var choice) || choice < 1 || choice > keys.Count)
            throw new TswapException($"Invalid selection. Enter a number between 1 and {keys.Count}.");
        return keys[choice - 1];
    }

    /// <summary>A key without a FIDO2 PIN: offers to set one (asked twice), the one PIN write tswap makes; "no" stops.</summary>
    internal static Fido2KeyInfo OfferPin(CommandContext ctx, IFido2Service fido2, Fido2KeyInfo key)
    {
        var name = fido2.KeyName(key);
        using (var terminal = ctx.Terminal?.Invoke() ?? throw new Fido2Exception(Fido2Failure.NoTerminal, key.Serial, null, Fido2Texts.NoTerminal))
        {
            terminal.Write($"{Fido2Texts.NoPin(name)} Set a FIDO2 PIN on it now? (yes/no): ");
            if (terminal.ReadLine()?.Trim().ToLowerInvariant() is not ("yes" or "y"))
                throw new TswapException($"{Fido2Texts.NoPin(name)} No PIN was set. No slot was added.");
        }
        fido2.SetPin(key, Fido2PinPrompt.For(ctx));
        ctx.Console.Out.WriteLine($"✓ {name} has a FIDO2 PIN now.");
        return fido2.ListYubiKeys().FirstOrDefault(k => k.Key == key.Key)
            ?? throw new TswapException(Fido2Texts.NotPluggedIn(name));
    }

    /// <summary>
    /// Builds a new FIDO2 slot for <paramref name="keyring"/> in memory (<c>slot add --fido2</c>): draws the slot id,
    /// enrols <paramref name="key"/> with the keyring's FIDO2 credentials as the exclude list, wraps
    /// <paramref name="vaultKey"/> (K_v) for it and zeroes <c>KEK_slot</c>.
    /// </summary>
    public static (Slot Slot, Fido2SlotBlob Blob) EnrollAsSlot(
        CommandContext ctx, Fido2KeyInfo? key, byte[] vaultKey, Keyring keyring, StretchedPassword? password)
    {
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var (blob, kekSlot) = Enroll(ctx, key, slotId, VaultFido2Slots(keyring), password);
        try
        {
            var slotKeyPair = SlotKeyPair.Generate();
            var slot = MachineSlotWrap.Wrap(
                vaultKey, slotKeyPair.PrivateKey, slotKeyPair.PublicKey, slotId, kekSlot,
                keyring.FormatVersion, keyring.VaultId, keyring.K) with { HwBlob = blob.Encode() };
            return (slot, blob);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kekSlot);
        }
    }

    /// <summary>
    /// The two key operations for the slot <paramref name="slotId"/>: make-credential, then one assertion of the new
    /// credential, whose output gives <c>KEK_slot</c> (zeroed here; the caller zeroes the returned KEK). A failure of
    /// the second says <see cref="RetrySafeText"/>.
    /// </summary>
    public static (Fido2SlotBlob Blob, byte[] KekSlot) Enroll(
        CommandContext ctx, Fido2KeyInfo? key, byte[] slotId, IReadOnlyList<Fido2SlotBlob> vaultFido2Slots, StretchedPassword? password)
    {
        var fido2 = ctx.Fido2 ?? throw new TswapException(Unavailable);
        var c = ctx.Console;
        var pin = Fido2PinPrompt.For(ctx);
        // Linux and macOS: the touch line once each PIN is typed (task 8), as the key then waits for the touch.
        // Windows: its dialog line before each operation (the dialog asks for the PIN).
        if (fido2.CanList && pin is not null)
            pin = VaultUnlocker.TouchLineAfterPin(pin, c.Out.WriteLine);

        c.Out.WriteLine(key is null
            ? "\nEnrolling a FIDO2 credential on the key you pick in Windows' dialog..."
            : $"\nEnrolling a FIDO2 credential on {fido2.KeyName(key)} (its PIN and a touch, twice)...");
        if (!fido2.CanList)
            c.Out.WriteLine(WindowsTouchLine);
        var blob = fido2.Enrol(key, password is not null, vaultFido2Slots, pin);

        if (!fido2.CanList)
            c.Out.WriteLine(WindowsTouchLine);
        Fido2Opened opened;
        try
        {
            opened = fido2.Open([blob], key, pin);
        }
        catch (TswapException e)
        {
            throw new TswapException($"{e.Message} {RetrySafeText}", e.ExitCode);
        }
        try
        {
            return (opened.Blob, password is null
                ? Fido2SlotKek.Derive(opened.Output, opened.Blob.PrfInput, slotId)
                : Fido2SlotKek.DeriveV2(opened.Output, password, opened.Blob.PrfInput, slotId));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(opened.Output);
        }
    }

    /// <summary>After a FIDO2 enrolment: what a reset does.</summary>
    public static void PrintResetWarning(IConsole c, string keyName) => c.Out.WriteLine(ResetWarning(keyName));
}
