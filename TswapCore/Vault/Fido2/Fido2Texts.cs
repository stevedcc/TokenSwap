using TswapCore.Keyring;

namespace TswapCore.Vault.Fido2;

/// <summary>
/// Every FIDO2 message tswap shows (FIDO2 plan, task 3), in one place. <c>name</c> is a key's display name
/// (<see cref="Fido2SlotBlob.DisplayName"/>: "YubiKey N", else the model) or <see cref="PickedKey"/> on Windows
/// before the key has answered. The PIN texts state CTAP2's two rules: 8 wrong PINs in all block the key's FIDO2, and
/// after three wrong in a row the key takes no more until it is re-inserted.
/// </summary>
public static class Fido2Texts
{
    /// <summary>The key on Windows, where the dialog picked it and tswap doesn't know which it is yet.</summary>
    public const string PickedKey = "The key you picked";

    /// <summary>A key while listing or probing, before any one key is meant.</summary>
    public const string AnyKey = "A FIDO2 key";

    public const string NoTerminal =
        "A FIDO2 slot needs a person at a terminal to type the key's PIN and touch the key; there is no terminal here, so the key was not used.";

    /// <summary>Said after the PIN is typed for each FIDO2 key operation on Linux and macOS (the device layer has no touch callback).</summary>
    public const string TouchLine = "Touch your YubiKey when it blinks.";

    /// <summary>Said before each FIDO2 key operation on Windows.</summary>
    public const string WindowsTouchLine = "Follow Windows' security key dialog: the key's PIN, then a touch.";

    /// <summary>No FIDO2 service in this build or on this OS.</summary>
    public const string Unavailable = "FIDO2 slots aren't available in this build or on this OS.";

    /// <summary>Unlock: one PIN per run, so a FIDO2 slot found after the one tried was not tried.</summary>
    public const string OtherSlotNotTried =
        "Another FIDO2 slot of this vault wasn't tried: tswap asks for one FIDO2 PIN per run. Run the command again with that key.";

    /// <summary>Unlock (controller ruling A): a TPM or Secure Enclave password slot refused the vault password in this run.</summary>
    public static string LeftOutPasswordRefused(string name) =>
        $"The FIDO2 slot of {name} was left out: the vault password didn't match.";

    /// <summary>Unlock: the slot mixes in the vault password, and none can be had (<paramref name="reason"/>).</summary>
    public static string PasswordUnavailable(string name, string reason) =>
        $"The FIDO2 slot of {name} needs the vault password too, and none could be had: {reason}";

    /// <summary>Unlock: the key answered (its PIN was right), but its slot didn't unwrap.</summary>
    public static string UnwrapFailed(string name, bool requiresPassword) => requiresPassword
        ? $"{name}: the key that answered doesn't open the vault; the vault password may be wrong (the key's PIN was right, so no PIN try was lost)."
        : $"{name}: the key that answered doesn't open the vault (its slot didn't unwrap: config.json may be damaged; restore it from backup).";

    public const string WindowsNoAaguid =
        "Windows didn't report which key this is (its FIDO2 model id came back as zeros), so tswap can't check that it is a YubiKey. No slot was added.";

    private const string AllowsEight = "a key allows 8 wrong PINs in all";

    private const string EnrolAgain = "enrol the key again with `tswap slot add --fido2`";

    /// <summary><paramref name="aaguid"/>: the key's model id, when known.</summary>
    public static string NotAYubiKey(Guid? aaguid) =>
        $"This security key is not a YubiKey{(aaguid is { } id ? $" (its FIDO2 model id is {id})" : "")}: FIDO2 slots work with YubiKeys only for now (other keys: issue #193). No slot was added.";

    public static string NoPin(string name) => $"{name} has no FIDO2 PIN; a FIDO2 slot needs one.";

    public static string PinAlreadySet(string name) => $"{name} already has a FIDO2 PIN; tswap never changes an existing PIN.";

    public static string PinWrong(string name, int? retriesLeft) => retriesLeft is { } left
        ? $"{name}: wrong FIDO2 PIN; {Tries(left)} left before this key's FIDO2 is blocked ({AllowsEight}). After three wrong PINs in a row, unplug the key and plug it in again before the next try."
        : $"{name}: wrong FIDO2 PIN. A key allows 8 wrong PINs in all before its FIDO2 is blocked; after three wrong PINs in a row, unplug the key and plug it in again before the next try.";

    public static string PinNeedsReinsert(string name, int? retriesLeft) => retriesLeft is { } left
        ? $"{name}: three wrong FIDO2 PINs in a row. Unplug the key and plug it in again before the next try; {Tries(left)} left before this key's FIDO2 is blocked ({AllowsEight})."
        : $"{name}: three wrong FIDO2 PINs in a row. Unplug the key and plug it in again before the next try ({AllowsEight} before its FIDO2 is blocked).";

    public static string PinBlocked(string name) =>
        $"{name}: its FIDO2 PIN is blocked (8 wrong PINs). Only a FIDO2 reset unblocks it, and a reset deletes every FIDO2 credential on the key: its FIDO2 slots in this and any other vault, and every passkey or security-key login it holds. tswap never resets a key. Open the vault another way; after a reset, {EnrolAgain}.";

    /// <summary>The key was probed or picked by its handle (Linux, macOS) and no longer holds the slot's credential.</summary>
    public static string CredentialGone(string name) =>
        $"{name} no longer holds this slot's credential (a FIDO2 reset deletes it, and the slot can't be opened again); {EnrolAgain}.";

    /// <summary>Windows: the key picked in the dialog holds none of the credentials asked for (no probe, so no certainty).</summary>
    public const string PickedHoldsNone =
        $"The key you picked holds none of this vault's FIDO2 credentials: another key, or a FIDO2 reset deleted it (then {EnrolAgain}).";

    public static string AlreadyHasSlot(string name) =>
        $"{name}: this key already has a FIDO2 slot in this vault (one per key; `tswap slots` lists them). No slot was added.";

    public static string MadeWithoutUv(string name) =>
        $"{name} made the credential without verifying the PIN (no user verification); a FIDO2 slot needs the PIN and a touch, so no slot was added.";

    public static string AnsweredWithoutUv(string name) =>
        $"{name} answered without verifying the PIN (no user verification); tswap doesn't use such an answer.";

    public static string BadOutput(string name, int length) =>
        $"{name} answered without a usable hmac-secret output ({length} bytes; a FIDO2 slot needs 32). On Windows, Windows' WebAuthn API may be too old for FIDO2 slots (they need version 4).";

    public static string ForeignCredential(string name) =>
        $"{name} answered with a credential that is none of the FIDO2 slots asked for.";

    public static string BadCredentialId(string name, int length) =>
        $"{name} returned a credential id of {length} bytes, which a FIDO2 slot can't hold ({Fido2SlotBlob.MinCredentialIdSize} to {Fido2SlotBlob.MaxCredentialIdSize}). No slot was added.";

    public static string Cancelled(string name) => $"{name}: the FIDO2 PIN or touch was cancelled.";

    public static string TimedOut(string name) => $"{name}: timed out waiting for the FIDO2 PIN or a touch.";

    public static string Busy(string name) => $"{name} is busy: another program is using it. Try again when it's done.";

    public static string NotPluggedIn(string name) => $"{name} is not plugged in.";

    /// <summary>A plugged-in key the listing couldn't read (Linux, macOS): left out, with its problem's status name.</summary>
    public static string KeyLeftOut(string problem) =>
        $"A plugged-in key's FIDO2 interface couldn't be read ({problem}), so it is left out of the list.";

    /// <summary><paramref name="detail"/>: the API version Windows reported, when the device layer knows it.</summary>
    public static string Unsupported(string? detail) => detail is null
        ? "Windows' WebAuthn API on this machine is too old for FIDO2 slots (needs version 4)."
        : $"Windows' WebAuthn API on this machine is too old for FIDO2 slots (version {detail}; needs 4).";

    public static string Other(string name, string? detail) =>
        detail is null ? $"{name}: the FIDO2 operation failed." : $"{name}: the FIDO2 operation failed ({detail}).";

    /// <summary>The slot's key isn't plugged in (Review Focus 2).</summary>
    public static string PlugIn(string name) => $"The FIDO2 slot of {name}: plug it in.";

    /// <summary>
    /// The text for a <see cref="IFido2Service.Locate"/> result that didn't find the credential; null for
    /// <see cref="Fido2Locate.Found"/> and <see cref="Fido2Locate.Unknown"/>, which need none.
    /// </summary>
    public static string? Describe(Fido2Locate located) => located switch
    {
        Fido2Locate.ResetOrOtherKey { SerialMatched: true } reset =>
            $"{Name(reset.PluggedKey)} is plugged in but no longer holds this slot's credential: a FIDO2 reset deleted it, and the slot can't be opened again. Enrol the key again with `tswap slot add --fido2`.",
        Fido2Locate.ResetOrOtherKey reset =>
            $"{Name(reset.PluggedKey)} is plugged in but doesn't hold this slot's credential: another key of the same model, or a FIDO2 reset deleted it (then {EnrolAgain}).",
        Fido2Locate.NotPluggedIn absent => PlugIn(absent.KeyName),
        _ => null,
    };

    /// <summary>
    /// Brief T19, decision 7: under sudo only a root-owned libfido2 is loaded, and none usable was found (or the loader's
    /// environment wasn't clean). Names the root-owned way to install it and the alternative; never suggests copying a
    /// library into place.
    /// </summary>
    public static string Libfido2SudoRefusal(bool macOs) =>
        "Security keys other than YubiKeys need libfido2, and under sudo tswap loads it only from a root-owned install " +
        "(the library and everything it loads), with no LD_ or DYLD_ variable set; none was found, so those keys are left out. " +
        (macOs
            ? "Install it from MacPorts: `sudo port install libfido2`. "
            : "Install your distribution's libfido2 package (Fedora: libfido2; Debian, Ubuntu: libfido2-1). ") +
        "Or add the slot on another machine that has a root-owned libfido2, or on Windows; in a shared vault folder the " +
        "slot then opens here without sudo.";

    private static string Name(Fido2KeyInfo key) => Fido2SlotBlob.DisplayName(key.Serial, key.Aaguid);

    private static string Tries(int left) => left == 1 ? "1 try" : $"{left} tries";
}
