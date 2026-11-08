namespace TswapCore.Vault;

/// <summary>
/// A YubiKey operation failed, with the failure's kind beside its text (task 4 review fix round): callers that react
/// to the kind (<c>tswap yubikey setup --replace</c> telling a busy key from one that didn't answer) match on
/// <see cref="Kind"/>, never on the wording. Thrown by <see cref="SdkYubiKeyService"/> (and the test doubles that stand
/// in for it); the message is the same text the service always gave.
/// </summary>
public class YubiKeyDeviceException(OtpFailure kind, int? serial, string message) : TswapException(message)
{
    public OtpFailure Kind { get; } = kind;

    /// <summary>The key's serial, when the failure concerns one known key.</summary>
    public int? Serial { get; } = serial;
}
