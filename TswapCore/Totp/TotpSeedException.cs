namespace TswapCore.Totp;

/// <summary>
/// Brief T58: a value that can't be used as a TOTP seed. <see cref="Exception.Message"/> is exactly the reason, one of
/// the fixed texts in <see cref="TotpSeed"/>; it never holds any part of the value.
/// </summary>
public sealed class TotpSeedException(string reason) : Exception(reason)
{
    public string Reason => Message;
}
