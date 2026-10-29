using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// A version 2 keyring vault (Phase 6, 'tswap init --keyring' with a recovery slot, one secret
/// added) captured byte for byte from the code at commit 1289c37, before brief T2 item 5 bumped
/// <see cref="KeyringFormat.KeyringFormatVersion"/> to 3. YubiKey keyring vaults made since Phase 6
/// are version 2 and may be in use, so this fixture must keep decoding and unlocking (brief T2
/// decision 3). Never regenerate it from newer code.
///
/// <para>How it was made (test mode, Debug build of 1289c37):
/// <c>TSWAP_TEST_KEY=&lt;FixtureTestKeyHex&gt; TSWAP_CONFIG_DIR=&lt;dir&gt; tswap init --keyring</c>, then
/// <c>tswap add v2-fixture-secret</c> with the value <c>v2-fixture-value</c>. In test mode the
/// YubiKey backend's <c>KEK_slot</c> is the test key itself. The recovery private key is the one
/// that init printed.</para>
/// </summary>
public class KeyringV2FixtureTests : IDisposable
{
    internal const string FixtureTestKeyHex = "1F2E3D4C5B6A79880102030405060708A1B2C3D4E5F60718293A4B5C6D7E8F90";
    internal const string FixtureRecoveryPrivateKey = "QKHIDgb7kkWQy3jfny3wg2xd413TMc2K4c/49YsRukk=";
    internal const string FixtureSecretName = "v2-fixture-secret";
    internal const string FixtureSecretValue = "v2-fixture-value";

    /// <summary>config.json, verbatim.</summary>
    internal const string FixtureConfigJson = """
{
  "YubiKeySerials": [
    99999999,
    99999998
  ],
  "RedundancyXor": "0000000000000000000000000000000000000000",
  "Created": "2026-10-29T18:52:19.2866027Z",
  "RequiresTouch": null,
  "RngMode": "system",
  "UnlockChallenge": "64110F2024AC2329A1CFC9CCB6FFC2E95BF2C3A6EA1DDEC0E6A006CE1CC22F51",
  "MasterKeySalt": "OewPp2/CPRsaoHhc1brhCJAPlX8TjuiMJbUOJaKpSfQ=",
  "Keyring": "AkpH\u002BboJx7MS3\u002BldoMSfLx0BAgAAALP8w/SYF6YY8L2SJwI1JpnlzweMq3FcXm3pjJORw4DayUbQ3hkmk6wWIN/yJ6QaLlwAAACT4cgV97BkTvWwkdDxMioFEkMMLwMpu9OYE1VlxJnioZLY3rIuan1WTsvUZxrnqb1BC2Jk/3hElNJGk6FyVNf9/N3Rm8xmA9NuufeFrAzR7KO9O18PzT8lCG4OhwBWG9LlaHVKspvxxpsN0VidYbRxRYuA5hDAPL860Tek55\u002Bp6vIpioE6TEymJFmi1j88AAAAZg6Z9jLok2fwVDQef4ncvXmlbOT9i3qQTj2cUc94olP\u002BS\u002BK0LFhjA6dE\u002BPFzvcxcY7sJgmzrBDQ9oE\u002BIAQ==",
  "KeyringSlotId": "s/zD9JgXphjwvZInAjUmmQ=="
}
""";

    /// <summary>secrets.json.enc, base64 of the raw file bytes.</summary>
    internal const string FixtureSecretsFileBase64 =
        "MPld0Drwme7IX7yPeux2GLRTEmEtn+KP9ThWrNgRVoTAx64akKSPt9c1lKCtuaVHRDo2II+ctf2K5iRSnWErar5q1eKUuvmivwkurE3lZe5QjZSDJMMHNnJ/2bEjMkyvNejyOhtf9psJz6ni+m7qoJUq7SbfAxTFaPAJaAHY9HO7fZRKVN/oCHx232t7u3/KLR/fu0C5MjgH76OUX7tuFoX8FAuqdk8DmdlKrFENXPHxgQTXrEmbDxmF46KNciqxdiffC8EwiuQADwf0GTHswBLAKBqB+Kn7LzLgTkA7o/FUoiU71HvYSLFeSONMOrVv3y8KdJ+zkuXZj63xHtALGMaj7ufJHAWa3XI=";

    private readonly string _dir;
    private readonly byte[] _testKey = Convert.FromHexString(FixtureTestKeyHex);

    public KeyringV2FixtureTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "tswap-v2-fixture-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "config.json"), FixtureConfigJson);
        File.WriteAllBytes(Path.Combine(_dir, "secrets.json.enc"), Convert.FromBase64String(FixtureSecretsFileBase64));
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
    }

    private static Config FixtureConfig() =>
        JsonSerializer.Deserialize(FixtureConfigJson, TswapJsonContext.Default.Config)!;

    private CommandContext Context(FakeConsole console, string[] args)
    {
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _dir, Verbose = false, CommandArgs = args };
        var yubiKeys = new TestKeyYubiKeyService(_testKey);
        var unlocker = new VaultUnlocker(yubiKeys, overrideKey: _testKey);
        return new CommandContext(console, env, new Storage(_dir), yubiKeys, unlocker, _testKey, SudoBypass: true);
    }

    [Fact]
    public void Fixture_IsAVersion2KeyringWithAYubiKeyMachineSlotAndARecoverySlot()
    {
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(FixtureConfig().Keyring!));

        Assert.Equal(2, keyring.FormatVersion);
        Assert.Equal(1, keyring.K);
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery], keyring.Slots.Select(s => s.Kind));
        Assert.Null(FixtureConfig().Backend);
    }

    [Fact]
    public void Fixture_UnlocksAndGetReturnsTheSecret()
    {
        var console = new FakeConsole();
        string[] args = ["get", FixtureSecretName];

        var exit = CliRunner.Run(Context(console, args), args);

        Assert.True(exit == 0, console.ErrorText);
        Assert.Equal(FixtureSecretValue, console.OutText.Trim());
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
        var viaMachine = Context(new FakeConsole(), []).Unlock(config);

        Assert.Equal(viaMachine, viaRecovery);
    }
}
