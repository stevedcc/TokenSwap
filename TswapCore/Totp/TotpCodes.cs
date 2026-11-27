using OtpNet;
using OtpTotp = OtpNet.Totp;

namespace TswapCore.Totp;

/// <summary>
/// Brief T58: codes from a parsed seed (Otp.NET, RFC 6238) and the classification of a stored value. The clock is always
/// the caller's: Otp.NET's parameterless overloads read <c>DateTime.UtcNow</c> and are never called.
/// </summary>
public static class TotpCodes
{
    /// <summary>The code of <paramref name="seed"/> at <paramref name="now"/>, and how long it stays valid.</summary>
    public static TotpCode Compute(TotpSeed seed, DateTimeOffset now)
    {
        var mode = seed.Algorithm switch
        {
            TotpAlgorithm.Sha1 => OtpHashMode.Sha1,
            TotpAlgorithm.Sha256 => OtpHashMode.Sha256,
            TotpAlgorithm.Sha512 => OtpHashMode.Sha512,
            _ => throw new ArgumentOutOfRangeException(nameof(seed)),
        };
        // Otp.NET's constructor order: (secretKey, step, mode, totpSize), the period before the algorithm before the digits.
        var totp = new OtpTotp(seed.KeyBytes, seed.Period, mode, seed.Digits);
        // Otp.NET reads only the DateTime's Ticks, so the UTC instant is passed.
        var at = now.UtcDateTime;
        return new TotpCode(totp.ComputeTotp(at), totp.RemainingSeconds(at), seed.Period);
    }

    /// <summary>
    /// <see cref="ValueKind.None"/> unless the value is an otpauth record (<see cref="OtpAuthUri.IsOtpAuth"/>);
    /// <see cref="ValueKind.Totp"/> when it parses (<see cref="TotpSeed.FromUri"/>); otherwise
    /// <see cref="ValueKind.OtpAuthUnusable"/>.
    /// </summary>
    public static ValueKind Classify(string value)
    {
        if (!OtpAuthUri.IsOtpAuth(value)) return ValueKind.None;
        try
        {
            using var _ = TotpSeed.FromUri(value);
            return ValueKind.Totp;
        }
        catch (TotpSeedException)
        {
            return ValueKind.OtpAuthUnusable;
        }
    }
}
