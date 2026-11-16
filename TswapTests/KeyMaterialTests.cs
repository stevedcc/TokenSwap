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
        // #258: next to punctuation.
        { "hex ending a sentence", Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + "." },
        { "base64 in parentheses", "(" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(20)) + ")" },
        { "grouped base64 in parentheses", "(q83v-EjRW-eJCr-ze8S-NFZ4-kKvN-7xI=)" },
        { "grouped base64 with / ending a sentence", "q83v-EjRW/eJCr-ze8S-NFZ4-kKvN-7xI=." },
        { "hex in parentheses in a path", "/tmp/(" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + ")/x.json" },
        { "hex after a name and a /", "secret_name/" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + "." },
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
    // A bare hyphenated identifier that degroups to under 24 characters. (A bare tswap-fleet-reenrol-d0ae5afb outside a
    // path degroups to 25 base64-alphabet characters: it is flagged today and stays flagged.)
    [InlineData("wrote record-name-hash for the slot")]
    [InlineData("no vault in /tmp/tswap-setup-1gZce3/pair-d49ddcb5.")]
    public void AssertNone_LetsOrdinaryOutputThrough(string output) => KeyMaterial.AssertNone(output);

    // #345: a macOS runner's per-user temp folder is a random 30-character name; this one has no '_' and reads as base64.
    private const string MacTemp = "/var/folders/q2/p1t6rgxj5fj32g1dc7dmd49r0000gn/T/";

    [Theory]
    [InlineData(MacTemp + "tswap-setup-vMFq0C/pair-81f89a5f")]
    [InlineData("/private" + MacTemp + "tswap-move-53ebcfad/sync/tswap-vault")]
    [InlineData("/var/folders/q2/p1t6rgxj5fj32g1dc7dmd49r0000gn/T")]
    public void AssertNone_TheTestsOwnTempFolder_IsNotAKey(string path) =>
        KeyMaterial.AssertNone($"no vault in {path}", tempRoot: MacTemp);

    [Fact]
    public void AssertNone_TheSameFolder_IsFlaggedWhenItIsNotTheTempFolder() =>
        Assert.Throws<Xunit.Sdk.TrueException>(() =>
            KeyMaterial.AssertNone($"no vault in {MacTemp}tswap-setup-vMFq0C/pair-81f89a5f", tempRoot: "/tmp/"));

    [Fact]
    public void AssertNone_AKeyUnderTheTempFolder_IsStillCaught() =>
        Assert.Throws<Xunit.Sdk.TrueException>(() => KeyMaterial.AssertNone(
            $"wrote {MacTemp}{Convert.ToHexString(RandomNumberGenerator.GetBytes(16))}/x.json", tempRoot: MacTemp));

    [Fact]
    public void AssertNotEchoed_CatchesTheTypedValue() =>
        Assert.Throws<Xunit.Sdk.FalseException>(() => KeyMaterial.AssertNotEchoed("the key was correct horse battery staple", "correct horse battery staple"));
}
