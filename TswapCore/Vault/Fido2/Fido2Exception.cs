namespace TswapCore.Vault.Fido2;

/// <summary>What went wrong with a FIDO2 key, at the device seam and in the service.</summary>
public enum Fido2Failure
{
    /// <summary>The key isn't plugged in (or was unplugged during the operation).</summary>
    NotPluggedIn,
    /// <summary>The key is not a YubiKey (its AAGUID is not in <see cref="Keyring.YubicoAaguids"/>), or didn't say which it is.</summary>
    NotAYubiKey,
    /// <summary>The key has no FIDO2 PIN set.</summary>
    NoPin,
    /// <summary>The PIN was wrong; the exception carries the tries left when the key reported them.</summary>
    PinWrong,
    /// <summary>The PIN is blocked (8 wrong in all): only a FIDO2 reset helps, and it deletes every credential.</summary>
    PinBlocked,
    /// <summary>Three wrong PINs in a row: the key takes no more until it is unplugged and plugged in again.</summary>
    PinNeedsReinsert,
    /// <summary>The key holds none of the credentials asked for.</summary>
    NoCredential,
    /// <summary>The person cancelled (at the PIN prompt, in the dialog, or by refusing the touch).</summary>
    Cancelled,
    /// <summary>No PIN or touch in time.</summary>
    TimedOut,
    /// <summary>Another program is using the key.</summary>
    Busy,
    /// <summary>No person at a terminal: FIDO2 needs one to type the PIN and touch the key.</summary>
    NoTerminal,
    /// <summary>Anything else (an answer tswap refuses, or a device status without its own kind).</summary>
    Other,
    /// <summary>The platform can't do FIDO2 slots (Windows' WebAuthn API below version 4).</summary>
    Unsupported,
    /// <summary>The key refused make-credential: it holds a credential from the exclude list (a slot in this vault).</summary>
    CredentialExcluded,
}

/// <summary>
/// A FIDO2 operation failed, with a text for the person (<see cref="Fido2Texts"/>, composed by
/// <see cref="Fido2Service"/>) and the kind beside it, so callers react to <see cref="Kind"/>, never the wording.
/// </summary>
public sealed class Fido2Exception(Fido2Failure kind, int? serial, int? retriesLeft, string message, Exception? inner = null)
    : TswapException(message, inner: inner)
{
    public Fido2Failure Kind { get; } = kind;

    /// <summary>The key's serial, when the failure concerns a key whose serial is known.</summary>
    public int? Serial { get; } = serial;

    /// <summary>PIN tries left, when the key reported them.</summary>
    public int? RetriesLeft { get; } = retriesLeft;
}

/// <summary>
/// A failure at the device seam (<see cref="IFido2Keys"/>), with no user text: the kind, the PIN tries left when the
/// key reported them, and <see cref="Detail"/>, a status name (never the SDK's prose).
/// </summary>
public sealed class Fido2DeviceException(Fido2Failure kind, int? retriesLeft, string? detail)
    : Exception(detail ?? kind.ToString())
{
    public Fido2Failure Kind { get; } = kind;
    public int? RetriesLeft { get; } = retriesLeft;
    public string? Detail { get; } = detail;

    /// <summary>
    /// The failed HRESULT <c>webauthn.dll</c> returned (Windows only; null elsewhere), printed under <c>-v</c> by
    /// <see cref="Fido2Service"/>. <see cref="Detail"/> stays its winerror.h name.
    /// </summary>
    public int? WindowsHResult { get; init; }
}
