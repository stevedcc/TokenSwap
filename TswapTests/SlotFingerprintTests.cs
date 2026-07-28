using System.Security.Cryptography;
using System.Text.RegularExpressions;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Tests for the fingerprint display (issue #122): a short, deterministic, human-comparable
/// digest of an X25519 public key shown on both machines during hand-carried enrollment.
/// </summary>
public class SlotFingerprintTests
{
    [Fact]
    public void Compute_IsDeterministic()
    {
        var publicKey = SlotKeyPair.Generate().PublicKey;

        Assert.Equal(SlotFingerprint.Compute(publicKey), SlotFingerprint.Compute(publicKey));
    }

    [Fact]
    public void Compute_DifferentKeysProduceDifferentFingerprints()
    {
        var key1 = SlotKeyPair.Generate().PublicKey;
        var key2 = SlotKeyPair.Generate().PublicKey;

        Assert.NotEqual(SlotFingerprint.Compute(key1), SlotFingerprint.Compute(key2));
    }

    [Fact]
    public void Compute_MatchesExpectedFormat()
    {
        var publicKey = SlotKeyPair.Generate().PublicKey;

        var fingerprint = SlotFingerprint.Compute(publicKey);

        Assert.Matches(new Regex("^[0-9A-F]{4}(-[0-9A-F]{4}){3}$"), fingerprint);
    }

    [Fact]
    public void Compute_KnownAnswer_MatchesFirst8BytesOfSha256()
    {
        // Pins the exact construction (SHA-256, first 8 bytes, uppercase hex, dash-grouped every
        // 4 chars) so a future accidental change is caught rather than silently shipped.
        var publicKey = new byte[32];
        for (var i = 0; i < 32; i++) publicKey[i] = (byte)i;

        var expectedHash = SHA256.HashData(publicKey);
        var expectedHex = Convert.ToHexString(expectedHash, 0, 8);
        var expected = string.Join('-', new[] { expectedHex[..4], expectedHex[4..8], expectedHex[8..12], expectedHex[12..16] });

        Assert.Equal(expected, SlotFingerprint.Compute(publicKey));
    }
}
