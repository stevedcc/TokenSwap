namespace TswapCore.Vault;

/// <summary>
/// <see cref="IYubiKeyService.ProgramSlot2"/> failed after it started writing: <see cref="Kind"/> is
/// <see cref="OtpFailure.ProgramFailed"/>, <see cref="OtpFailure.VerifyWrong"/> or
/// <see cref="OtpFailure.VerifyNoAnswer"/>, and <c>tswap yubikey setup</c> words its message from it.
/// </summary>
public sealed class YubiKeyProgramException(OtpFailure kind, int serial, string? detail = null)
    : TswapException(DefaultMessage(kind, serial, detail))
{
    public OtpFailure Kind { get; } = kind;
    public int Serial { get; } = serial;

    private static string DefaultMessage(OtpFailure kind, int serial, string? detail)
    {
        var what = kind switch
        {
            OtpFailure.ProgramFailed => $"Programming slot 2 of YubiKey {serial} failed; the slot may be empty or half-written",
            OtpFailure.VerifyWrong => $"Slot 2 of YubiKey {serial} was programmed, but it doesn't answer as programmed",
            OtpFailure.VerifyNoAnswer => $"Slot 2 of YubiKey {serial} was programmed, but it didn't answer the check",
            _ => $"Programming slot 2 of YubiKey {serial} failed",
        };
        return string.IsNullOrEmpty(detail) ? $"{what}." : $"{what} ({detail}).";
    }
}
