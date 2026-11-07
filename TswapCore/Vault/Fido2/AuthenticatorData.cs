using System.Buffers.Binary;

namespace TswapCore.Vault.Fido2;

/// <summary>
/// The parts of WebAuthn authenticator data tswap reads from webauthn.dll (FIDO2 plan, task 5; from the Windows gate
/// spike): rpIdHash (32) | flags (1) | signCount (4, big-endian),
/// then, when the AT flag (0x40) is set, the attested credential data: AAGUID (16) | credentialIdLength (2, big-endian)
/// | credentialId | COSE public key (not parsed).
/// </summary>
internal sealed record AuthenticatorData(byte Flags, uint SignCount, byte[]? Aaguid, byte[]? CredentialId)
{
    private const int HeaderLength = 32 + 1 + 4;
    private const byte FlagUserPresent = 0x01;
    private const byte FlagUserVerified = 0x04;
    private const byte FlagAttestedCredentialData = 0x40;

    public bool UserPresent => (Flags & FlagUserPresent) != 0;
    public bool UserVerified => (Flags & FlagUserVerified) != 0;
    public bool AttestedCredentialData => (Flags & FlagAttestedCredentialData) != 0;
    public bool AaguidIsZero => Aaguid is { } a && !a.AsSpan().ContainsAnyExcept((byte)0);

    public static AuthenticatorData Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderLength)
            throw new FormatException($"authenticator data is {data.Length} bytes, shorter than its {HeaderLength}-byte header");
        var flags = data[32];
        var signCount = BinaryPrimitives.ReadUInt32BigEndian(data[33..]);
        if ((flags & FlagAttestedCredentialData) == 0)
            return new AuthenticatorData(flags, signCount, null, null);
        var rest = data[HeaderLength..];
        if (rest.Length < 16 + 2)
            throw new FormatException("the AT flag is set but the attested credential data is truncated");
        var aaguid = rest[..16].ToArray();
        int idLength = BinaryPrimitives.ReadUInt16BigEndian(rest[16..]);
        if (rest.Length < 18 + idLength)
            throw new FormatException("the credential id runs past the end of the authenticator data");
        return new AuthenticatorData(flags, signCount, aaguid, rest.Slice(18, idLength).ToArray());
    }

    /// <summary>The AAGUID in wire byte order as 8-4-4-4-12 hex, as Yubico and the FIDO metadata service write it.</summary>
    public static string FormatAaguid(ReadOnlySpan<byte> aaguid)
    {
        var hex = Convert.ToHexStringLower(aaguid);
        return $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
    }
}
