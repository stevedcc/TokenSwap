namespace TswapCore.Totp;

/// <summary>
/// Brief T58 (#374): what kind of value a secret holds, as far as TOTP is concerned. The byte values are the kind bytes
/// of the <c>ValueKinds</c> record extension (<c>0x0101</c>); <see cref="None"/> is never written.
/// </summary>
public enum ValueKind : byte
{
    /// <summary>An ordinary value (a bare Base32 seed is one too: it is never recognised).</summary>
    None = 0,

    /// <summary>An otpauth record that parses as a usable TOTP URI.</summary>
    Totp = 1,

    /// <summary>An otpauth record (the value contains <c>otpauth:</c>) that isn't a clean, usable TOTP URI.</summary>
    OtpAuthUnusable = 2,
}
