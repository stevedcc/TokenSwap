namespace TswapCore.Totp;

/// <summary>Brief T58, decision D1: recognition of otpauth records is generous, the parse (<see cref="TotpSeed.FromUri"/>) strict.</summary>
public static class OtpAuthUri
{
    /// <summary>True when <paramref name="value"/> contains <c>otpauth:</c> anywhere, case ignored.</summary>
    public static bool IsOtpAuth(string value) => value.Contains("otpauth:", StringComparison.OrdinalIgnoreCase);
}
