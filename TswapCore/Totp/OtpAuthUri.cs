namespace TswapCore.Totp;

/// <summary>Brief T58, decision D1: recognition of otpauth records is generous, the parse (<see cref="TotpSeed.FromUri"/>) strict.</summary>
public static class OtpAuthUri
{
    /// <summary>True when <paramref name="value"/> contains <c>otpauth:</c> anywhere, case ignored.</summary>
    public static bool IsOtpAuth(string value) => value.Contains("otpauth:", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// <see cref="IsOtpAuth(string)"/> on a value's UTF-8 bytes, without making a string of it (the broker zeroes the
    /// bytes it refuses). The marker is ASCII, and no byte of a multi-byte UTF-8 sequence is ASCII.
    /// </summary>
    public static bool IsOtpAuth(ReadOnlySpan<byte> utf8)
    {
        ReadOnlySpan<byte> marker = "otpauth:"u8;
        for (var start = 0; start + marker.Length <= utf8.Length; start++)
        {
            var i = 0;
            while (i < marker.Length && (utf8[start + i] | (marker[i] == (byte)':' ? 0 : 0x20)) == marker[i])
                i++;
            if (i == marker.Length)
                return true;
        }
        return false;
    }

    /// <summary>The broker's refusal of an otpauth record (decision D8).</summary>
    public static string BrokerRefusal(string name) =>
        $"secret '{name}' is a TOTP seed (an otpauth:// URI); the broker doesn't hand out TOTP seeds";
}
