using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// A version 3 <b>legacy pair-keyring</b> vault ('tswap init --keyring' with two YubiKeys, an XOR
/// share and a recovery slot, one secret added), captured byte for byte from the code at commit
/// 7e5c89b, before brief T4 made a YubiKey keyring slot one key. Pair keyring vaults made since
/// brief T2 are version 3 and may be in use, so this fixture must keep decoding and unlocking
/// through the unchanged pair path (brief T4 decision 7). Never regenerate it from newer code.
///
/// <para>Unlike <see cref="KeyringV2FixtureTests"/> (test mode, where the YubiKey backend returns
/// the test key without any derivation), this one was made outside test mode against
/// <see cref="SimulatedYubiKeyService.WithKeys"/> with serials 11111111 and 22222222, so its
/// <c>KEK_slot</c> really comes from the HMAC responses, the XOR share and PBKDF2. Made with
/// both keys plugged in for <c>init --keyring</c> (key 1, then key 2, system RNG), then
/// <c>add v3-pair-fixture-secret</c> with only key 1 plugged in. The recovery private key is the
/// one init printed.</para>
/// </summary>
public class KeyringV3PairFixtureTests : IDisposable
{
    internal const int SerialA = 11111111;
    internal const int SerialB = 22222222;
    internal const string FixtureRecoveryPrivateKey = "2Nqnp3wT8yJBLXF6t4S0ClTgSZUJXzjTXbJ284FG6XE=";
    internal const string FixtureSecretName = "v3-pair-fixture-secret";
    internal const string FixtureSecretValue = "v3-pair-fixture-value";

    /// <summary>config.json, verbatim.</summary>
    internal const string FixtureConfigJson = """
{
  "YubiKeySerials": [
    11111111,
    22222222
  ],
  "RedundancyXor": "E3A43527FB39B5835B4396813943131B7ECCFD59",
  "Created": "2026-10-30T07:08:50.5933418Z",
  "RequiresTouch": true,
  "RngMode": "system",
  "UnlockChallenge": "507865DABF1ED487A9376A38D764F6BD243B17F09C68BAC9C32F6FCAD624D02D",
  "MasterKeySalt": "bD27OMcXG+TL1dGpTG5K/qByk/dNJ9U6+gTNIFbJh5g=",
  "Keyring": "AyvcoDJSQv39lzTeGz0fwScBAgAAAA4t8btnED/RBPD8rQvuW2+0WP9/vu87V6+5SU7zS6/RPu/0v9uHEC3BCi5PafzPblwAAAAMUFsUE1za8cb4iY7gNNRlCDHFiM4F9QZZyUgM2K/slr1Qj5vQThly78Vo07vduIZAUbB9sbPcAHJG9ybeDLN9CLUz/14C6hoQJIkIsrzu2Er3xLXvi1LiWaPZIAAAAAAA8VFE5YX4w6amSB1tR0/RopBIZ5tMl/MElP30pBgfx8M7XR7DJL/HoKo8nDKJQZFfPAAAAKmmIdE/V3l5U50OSbukk0H9tX/0l7mz38/cQEjECrnCxPm2mLaSvpfsXmKcGiwecPR/n7lUwNBOSw8SaAEAAAAA",
  "KeyringSlotId": "Di3xu2cQP9EE8PytC+5bbw=="
}
""";

    /// <summary>secrets.json.enc, base64 of the raw file bytes.</summary>
    internal const string FixtureSecretsFileBase64 =
        "0Aslu9pXXDsHh2wmo1r2J171lnZ7S/xyPJt7hh1zDUMrRZmXPgx43BWmu/KiItmr58SL7T3d39C+DP2S0/QxhCPjU8S6faeN0hJr/E5tbQtwAju0l6xELP6XTUWfdpV1jiuBPggN6cSqwElF2jwmEX+IGkp4IfG0IgV5fnj0Q6ca0mms7ZZilxIlNDYXiEocqI2qW3fp6zQ19t5Z7bWosndNH7WsOC+xLISU6DTrGUAn77qEMVG2QZtxlj/f/elDrU1hhKbWFDt8ASCGd5Un82PkoZJQOwhsMjXLLIs4lf7t6gMdXMGiWHiTySxaNR3/VdtrP/vPXEjuGbZE+hgJYALnnMDDKVAV8N4C+R/t2sPCZ78D";

    private readonly string _dir;

    public KeyringV3PairFixtureTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "tswap-v3-pair-fixture-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "config.json"), FixtureConfigJson);
        File.WriteAllBytes(Path.Combine(_dir, "secrets.json.enc"), Convert.FromBase64String(FixtureSecretsFileBase64));
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
    }

    internal static Config FixtureConfig() =>
        JsonSerializer.Deserialize(FixtureConfigJson, TswapJsonContext.Default.Config)!;

    private static SimulatedYubiKeyService Keys(params int[] pluggedIn)
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        keys.PluggedIn = [.. pluggedIn];
        return keys;
    }

    private CommandContext Context(SimulatedYubiKeyService keys, FakeConsole console, string[] args)
    {
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = args };
        return new CommandContext(console, env, new Storage(_dir), keys, new VaultUnlocker(keys), TestKey: null, SudoBypass: true);
    }

    [Fact]
    public void Fixture_IsAVersion3PairKeyringWithAYubiKeyMachineSlotAndARecoverySlot()
    {
        var config = FixtureConfig();
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));

        Assert.Equal(3, keyring.FormatVersion);
        Assert.Equal(1, keyring.K);
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery], keyring.Slots.Select(s => s.Kind));
        Assert.All(keyring.Slots, s => Assert.Null(s.HwBlob));
        Assert.Null(config.Backend);
        Assert.Equal([SerialA, SerialB], config.YubiKeySerials);
        Assert.Equal(40, config.RedundancyXor!.Length);
    }

    [Theory]
    [InlineData(SerialA)]
    [InlineData(SerialB)]
    public void Fixture_EitherKeyAloneUnlocksAndGetReturnsTheSecret(int pluggedIn)
    {
        var keys = Keys(pluggedIn);
        var console = new FakeConsole();
        string[] args = ["get", FixtureSecretName];

        var exit = CliRunner.Run(Context(keys, console, args), args);

        Assert.True(exit == 0, console.ErrorText);
        Assert.Equal(FixtureSecretValue, console.OutText.Trim());
        // The pair path: one challenge, to the plugged-in key, with the vault's own challenge.
        Assert.Equal([(pluggedIn, FixtureConfig().UnlockChallenge!)], keys.Challenges);
    }

    [Fact]
    public void Fixture_RecoveryKeyRecoversTheSameVaultKey()
    {
        var config = FixtureConfig();
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        var recovery = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery);

        var viaRecovery = RecoverySlotWrap.Unwrap(recovery.Wrapped, recovery.PublicKey,
            Convert.FromBase64String(FixtureRecoveryPrivateKey),
            keyring.FormatVersion, keyring.VaultId, keyring.K, recovery.SlotId);
        var viaMachine = Context(Keys(SerialA), new FakeConsole(), []).Unlock(config);

        Assert.Equal(viaMachine, viaRecovery);
    }

    [Fact]
    public void Fixture_AnUnenrolledKeyDoesNotUnlock()
    {
        var keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB, 33333333);
        keys.PluggedIn = [33333333];
        var console = new FakeConsole();
        string[] args = ["get", FixtureSecretName];

        var exit = CliRunner.Run(Context(keys, console, args), args);

        Assert.NotEqual(0, exit);
        Assert.DoesNotContain(FixtureSecretValue, console.OutText);
        Assert.Contains("33333333 not authorized", console.ErrorText);
    }
}
