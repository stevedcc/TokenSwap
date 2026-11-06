using System.Security.Cryptography;
using Xunit;

namespace TswapTests;

/// <summary>The leak checks catch what they look for, and let ordinary output through (final review item 8, round 2).</summary>
public sealed class KeyMaterialTests
{
    public static TheoryData<string, string> Leaks => new()
    {
        { "hex", Convert.ToHexString(RandomNumberGenerator.GetBytes(20)) },
        { "base64", Convert.ToBase64String(RandomNumberGenerator.GetBytes(20)) },
        { "dashed hex", BitConverter.ToString(RandomNumberGenerator.GetBytes(20)) },
        { "colon hex", BitConverter.ToString(RandomNumberGenerator.GetBytes(20)).Replace('-', ':') },
        { "spaced hex", BitConverter.ToString(RandomNumberGenerator.GetBytes(20)).Replace('-', ' ') },
        { "grouped base64", "q83v-EjRW-eJCr-ze8S-NFZ4-kKvN-7xI=" },
        { "grouped base64 with /", "q83v-EjRW/eJCr-ze8S-NFZ4-kKvN-7xI=" },
        { "grouped base64, no digit", "abcd-EFGH-ijkl-MNOP-qrst-UVWX-yzab" },
        { "grouped base64, no capital", "abcd-1234-ijkl-5678-qrst-9012-yzab" },
        { "base64 in a path", "/tmp/" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(20)).Replace('/', '+') + "/x.json" },
    };

    [Theory]
    [MemberData(nameof(Leaks))]
    public void AssertNone_CatchesKeyMaterial(string form, string leak) =>
        Assert.Throws<Xunit.Sdk.TrueException>(() => KeyMaterial.AssertNone($"{form}: key {leak} printed"));

    [Theory]
    [InlineData("(fingerprint ABCD-EF01-2345-6789) slot add --yubikey --recovery-key-stdin")]
    [InlineData("Previous config backed up to: /tmp/tswap-fleet-reenrol-d0ae5afb/config.json.bak-20261106T085949024Z")]
    [InlineData("no vault in /tmp/tswap-setup-1gZce3/pair-d49ddcb5")]
    [InlineData(@"C:\Users\someone\AppData\tswap-fleet-reenrol-d0ae5afb\config.json")]
    [InlineData("~/.config/tswap-fleet-reenrol-d0ae5afb/yubikey-slots.json")]
    public void AssertNone_LetsOrdinaryOutputThrough(string output) => KeyMaterial.AssertNone(output);

    [Fact]
    public void AssertNotEchoed_CatchesTheTypedValue() =>
        Assert.Throws<Xunit.Sdk.FalseException>(() => KeyMaterial.AssertNotEchoed("the key was correct horse battery staple", "correct horse battery staple"));
}
