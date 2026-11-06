using TswapCore.Keyring;

namespace TswapCore.Vault.Fido2;

/// <summary>
/// What commands and the unlocker call for FIDO2 slots (FIDO2 plan, task 3); every message is composed here
/// (<see cref="Fido2Texts"/>), over the device seam <see cref="IFido2Keys"/>. Failures are <see cref="Fido2Exception"/>s.
///
/// <para><b>PIN policy:</b> a null <see cref="Fido2Pin"/> means no terminal: <see cref="Fido2Failure.NoTerminal"/>
/// before any key call. One PIN request per key operation and never a retry: a wrong PIN ends the operation. An
/// empty answer at the prompt is <see cref="Fido2Failure.Cancelled"/>, with no PIN sent. When <see cref="CanList"/>
/// is false (Windows) the service never calls <see cref="IFido2Keys.Find"/>, <see cref="IFido2Keys.FindHolder"/> or
/// <see cref="IFido2Keys.SetPin"/>.</para>
/// </summary>
public interface IFido2Service
{
    /// <summary>Whether keys can be listed and addressed (false on Windows: the dialog picks the key).</summary>
    bool CanList { get; }

    /// <summary>The plugged-in YubiKeys (other brands left out); empty when <see cref="CanList"/> is false.</summary>
    IReadOnlyList<Fido2KeyInfo> ListYubiKeys();

    /// <summary>
    /// Makes a credential and returns the new slot's blob (not yet in any keyring). <paramref name="key"/> is null
    /// exactly when <see cref="CanList"/> is false. On Linux/macOS a key that is not a YubiKey is refused before
    /// make-credential, a key without a PIN is refused, and a key that already holds one of
    /// <paramref name="vaultFido2Slots"/> is refused by a silent probe before any PIN. On every OS the vault's FIDO2
    /// credential ids are the exclude list (<see cref="Fido2Failure.CredentialExcluded"/>: "this key already has a
    /// FIDO2 slot in this vault"), and the made credential is refused when made without user verification, when its
    /// AAGUID is not Yubico's (#193), or (Windows) when it is zero.
    /// </summary>
    Fido2SlotBlob Enrol(Fido2KeyInfo? key, bool requiresPassword, IReadOnlyList<Fido2SlotBlob> vaultFido2Slots, Fido2Pin? pin);

    /// <summary>
    /// One user-verified assertion: Linux/macOS with exactly one blob (the located one) on <paramref name="key"/>;
    /// Windows (<paramref name="key"/> null) with every FIDO2 slot of the vault in one ceremony, the answering
    /// credential picking the slot. Returns the slot and its 32-byte output (the caller zeroes it after deriving the
    /// KEK). An output made without user verification, or not 32 bytes, is refused.
    /// </summary>
    Fido2Opened Open(IReadOnlyList<Fido2SlotBlob> blobs, Fido2KeyInfo? key, Fido2Pin? pin);

    /// <summary>
    /// Which plugged-in key holds <paramref name="blob"/>'s credential, by a silent probe (no PIN, no touch):
    /// <see cref="Fido2Locate.Unknown"/> when <see cref="CanList"/> is false. <see cref="Fido2Texts.Describe"/> gives
    /// the text for a result that isn't <see cref="Fido2Locate.Found"/>.
    /// </summary>
    Fido2Locate Locate(Fido2SlotBlob blob);

    /// <summary>
    /// Sets the FIDO2 PIN of a key that has none (one <see cref="Fido2PinRequest"/> with <c>NewPin</c>; the terminal
    /// provider asks twice and compares). Refuses a key that has a PIN: tswap never changes an existing PIN. Only when
    /// <see cref="CanList"/> (Windows' dialog sets a PIN itself).
    /// </summary>
    void SetPin(Fido2KeyInfo key, Fido2Pin? pin);

    /// <summary>"YubiKey N", else the model name (<see cref="Fido2SlotBlob.DisplayName"/>).</summary>
    string KeyName(Fido2SlotBlob blob);

    /// <summary>"YubiKey N", else the model name (<see cref="Fido2SlotBlob.DisplayName"/>).</summary>
    string KeyName(Fido2KeyInfo key);
}

/// <summary>
/// The caller's PIN source: the PIN as UTF-8 bytes, zeroed by the caller (the device layer) after use; empty means
/// the person cancelled (empty input or end of input). A null delegate means no terminal. One request per key
/// operation. For a new PIN (<see cref="Fido2PinRequest.NewPin"/>) the terminal provider asks twice and re-asks on a
/// mismatch before returning.
/// </summary>
public delegate byte[] Fido2Pin(Fido2PinRequest request);

/// <summary>A PIN request: which key (its display name), the tries left when known, and whether it is a new PIN.</summary>
public sealed record Fido2PinRequest(string KeyName, int? RetriesLeft, bool NewPin);

/// <summary>The slot that answered and its 32-byte <c>hmac-secret</c> output (the caller zeroes it).</summary>
public sealed record Fido2Opened(Fido2SlotBlob Blob, byte[] Output);

/// <summary>Where a FIDO2 slot's key is (<see cref="IFido2Service.Locate"/>).</summary>
public abstract record Fido2Locate
{
    private Fido2Locate()
    {
    }

    /// <summary>This plugged-in key holds the slot's credential.</summary>
    public sealed record Found(Fido2KeyInfo Key) : Fido2Locate;

    /// <summary>
    /// No plugged-in key holds the credential, but <paramref name="PluggedKey"/> plausibly is the slot's key: its serial
    /// equals the blob's (<paramref name="SerialMatched"/>: a FIDO2 reset deleted the credential), or, when the blob
    /// has no serial, its AAGUID equals the blob's (another key of the same model, or a reset).
    /// </summary>
    public sealed record ResetOrOtherKey(Fido2KeyInfo PluggedKey, bool SerialMatched) : Fido2Locate;

    /// <summary>No plugged-in key holds the credential or looks like the slot's key.</summary>
    public sealed record NotPluggedIn(string KeyName) : Fido2Locate;

    /// <summary>Keys can't be listed here (Windows): only the dialog can tell.</summary>
    public sealed record Unknown : Fido2Locate;
}
