using TswapCore.Vault.Fido2;
using Xunit;

namespace TswapTests;

public class AuthenticatorDataTests
{
    // YubiKey 5 (USB-A, firmware 5.4) AAGUID as Yubico publishes it.
    private static readonly byte[] Aaguid = Convert.FromHexString("cb69481e8ff7403993ec0a2729a154a8");

    /// <summary>rpIdHash (32) | flags (1) | signCount (4, big-endian) [| AAGUID (16) | credIdLen (2, BE) | credId | key].</summary>
    private static byte[] Build(byte flags, byte[]? aaguid = null, byte[]? credentialId = null)
    {
        var data = new List<byte>(Enumerable.Repeat((byte)0xAB, 32)) { flags, 0, 0, 0, 7 };
        if (aaguid is not null)
        {
            data.AddRange(aaguid);
            var id = credentialId ?? [];
            data.Add((byte)(id.Length >> 8));
            data.Add((byte)id.Length);
            data.AddRange(id);
            data.AddRange([0xA5, 0x01, 0x02]); // the start of a COSE key; not parsed
        }
        return [.. data];
    }

    [Fact]
    public void WithAttestedCredentialData_ReadsAaguidAndCredentialId()
    {
        byte[] id = [1, 2, 3, 4, 5];
        var parsed = AuthenticatorData.Parse(Build(0x45, Aaguid, id)); // UP | UV | AT

        Assert.True(parsed.UserPresent);
        Assert.True(parsed.UserVerified);
        Assert.True(parsed.AttestedCredentialData);
        Assert.Equal(7u, parsed.SignCount);
        Assert.Equal(Aaguid, parsed.Aaguid);
        Assert.Equal(id, parsed.CredentialId);
        Assert.False(parsed.AaguidIsZero);
    }

    [Fact]
    public void WithoutAtFlag_HasNoAaguid()
    {
        var parsed = AuthenticatorData.Parse(Build(0x01)); // UP only, as in an assertion

        Assert.True(parsed.UserPresent);
        Assert.False(parsed.UserVerified);
        Assert.False(parsed.AttestedCredentialData);
        Assert.Null(parsed.Aaguid);
        Assert.Null(parsed.CredentialId);
        Assert.False(parsed.AaguidIsZero);
    }

    [Fact]
    public void ZeroAaguid_IsReported()
    {
        var parsed = AuthenticatorData.Parse(Build(0x45, new byte[16], [9]));

        Assert.True(parsed.AaguidIsZero);
        Assert.Equal("00000000-0000-0000-0000-000000000000", AuthenticatorData.FormatAaguid(parsed.Aaguid!));
    }

    [Fact]
    public void FormatAaguid_KeepsByteOrder()
    {
        // Not System.Guid's mixed-endian text: the bytes in wire order, as Yubico and the FIDO MDS write them.
        Assert.Equal("cb69481e-8ff7-4039-93ec-0a2729a154a8", AuthenticatorData.FormatAaguid(Aaguid));
    }

    [Fact]
    public void AtFlagButTruncated_Throws()
    {
        var data = Build(0x41, Aaguid, [1, 2, 3])[..45]; // cut inside the AAGUID
        Assert.Throws<FormatException>(() => AuthenticatorData.Parse(data));
    }

    [Fact]
    public void ShorterThanHeader_Throws() =>
        Assert.Throws<FormatException>(() => AuthenticatorData.Parse(new byte[36]));
}
