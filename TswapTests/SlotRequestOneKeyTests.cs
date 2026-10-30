using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T4 item 5 (decision 6): <c>slot request</c> enrolls <b>one</b> YubiKey; the request file
/// carries the slot's <see cref="YubiKeySlotBlob"/>, <c>slot approve</c> puts it into the approve
/// file, and <c>slot accept</c> writes it into the new machine slot. Two "machines" with separate
/// config dirs: a router with a simulated TPM, and a desktop with simulated YubiKeys.
/// </summary>
public class SlotRequestOneKeyTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;

    private static readonly byte[] RouterTpm = RandomNumberGenerator.GetBytes(32);

    private readonly string _routerDir = NewDir();
    private readonly string _desktopDir = NewDir();
    private readonly SimulatedYubiKeyService _desktopKeys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly SimulatedYubiKeyService _routerKeys = SimulatedYubiKeyService.WithKeys();

    private static string NewDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tswap-slot-req-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        return dir;
    }

    public void Dispose()
    {
        foreach (var dir in new[] { _routerDir, _desktopDir })
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
    }

    private string RequestFile => Path.Combine(_desktopDir, "request.json");
    private string ApproveFile => Path.Combine(_desktopDir, "approve.json");

    private (int Exit, string Out, string Err) OnRouter(string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _routerDir, Verbose = false, CommandArgs = args };
        var unlocker = new VaultUnlocker(_routerKeys, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, RouterTpm)]);
        var exit = CliRunner.Run(new CommandContext(console, env, new Storage(_routerDir), _routerKeys, unlocker, TestKey: RouterTpm, SudoBypass: true), args);
        return (exit, console.OutText, console.ErrorText);
    }

    private (int Exit, string Out, string Err) OnDesktop(string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _desktopDir, Verbose = false, CommandArgs = args };
        var exit = CliRunner.Run(new CommandContext(console, env, new Storage(_desktopDir), _desktopKeys, new VaultUnlocker(_desktopKeys), TestKey: null, SudoBypass: true), args);
        return (exit, console.OutText, console.ErrorText);
    }

    private static Config LoadConfig(string dir) =>
        JsonSerializer.Deserialize(File.ReadAllText(Path.Combine(dir, "config.json")), TswapJsonContext.Default.Config)!;

    private static Keyring DecodeKeyring(Config config) => KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));

    private void RouterVaultWithASecret()
    {
        Assert.Equal(0, OnRouter("", "init", "--tpm").Exit);
        Assert.Equal(0, OnRouter("router-pw\nrouter-pw\n", "add", "router").Exit);
    }

    private void Request(int serial)
    {
        _desktopKeys.PluggedIn = [serial];
        var (exit, _, err) = OnDesktop("", "slot", "request", RequestFile);
        Assert.True(exit == 0, err);
    }

    private void Approve()
    {
        var (exit, _, err) = OnRouter("", "slot", "approve", RequestFile, ApproveFile);
        Assert.True(exit == 0, err);
    }

    [Fact]
    public void RequestWithKeyA_ApproveOnTpmVault_Accept_KeyAUnlocksTheAcceptedVault()
    {
        RouterVaultWithASecret();

        Request(SerialA);
        var request = SlotEnrollmentFileCodec.DeserializeRequest(File.ReadAllText(RequestFile));
        Assert.Equal(2, request.FormatVersion);
        var requestBlob = Convert.FromBase64String(request.HwBlob!);
        Assert.Equal(SerialA, YubiKeySlotBlob.Decode(requestBlob).Serial);

        var (approveExit, approveOut, approveErr) = OnRouter("", "slot", "approve", RequestFile, ApproveFile);
        Assert.True(approveExit == 0, approveErr);
        Assert.Contains($"YubiKey {SerialA}", approveOut);
        Assert.Contains("unchanged", approveOut); // the approver's own keyring is not touched (v0)
        Assert.Equal(request.HwBlob, SlotEnrollmentFileCodec.DeserializeApprove(File.ReadAllText(ApproveFile)).NewSlotHwBlob);

        var (acceptExit, _, acceptErr) = OnDesktop("", "slot", "accept", ApproveFile);
        Assert.True(acceptExit == 0, acceptErr);

        var desktop = LoadConfig(_desktopDir);
        Assert.Null(desktop.Backend);
        Assert.Empty(desktop.YubiKeySerials);
        Assert.Null(desktop.PendingSlotId);
        Assert.Null(desktop.PendingSlotHwBlob);
        var keyring = DecodeKeyring(desktop);
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery, SlotKind.Machine], keyring.Slots.Select(s => s.Kind));
        Assert.Equal(requestBlob, keyring.Slots[2].HwBlob);
        Assert.Equal(desktop.KeyringSlotId, Convert.ToBase64String(keyring.Slots[2].SlotId));

        // Key A opens the accepted vault on the desktop; key B does not. (v0 carries no secrets:
        // accept makes an empty secrets file, so copy the router's across, as sharing would.)
        File.Copy(Path.Combine(_routerDir, "secrets.json.enc"), Path.Combine(_desktopDir, "secrets.json.enc"), overwrite: true);
        _desktopKeys.PluggedIn = [SerialA];
        var (getExit, getOut, getErr) = OnDesktop("", "get", "router");
        Assert.True(getExit == 0, getErr);
        Assert.Equal("router-pw", getOut.Trim());
        _desktopKeys.PluggedIn = [SerialB];
        var (otherExit, otherOut, otherErr) = OnDesktop("", "get", "router");
        Assert.NotEqual(0, otherExit);
        Assert.DoesNotContain("router-pw", otherOut);
        Assert.Contains("No plugged-in YubiKey matches a slot of this vault", otherErr);

        // The router's own keyring is unchanged by approve (v0, no sync).
        Assert.Equal(2, DecodeKeyring(LoadConfig(_routerDir)).Slots.Count);
    }

    [Fact]
    public void Request_EnrollsOneKey_NoPairFieldsInThePendingConfig()
    {
        _desktopKeys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = OnDesktop("2\n", "slot", "request", RequestFile);

        Assert.True(exit == 0, stderr);
        // Owner decision 2026-10-30 (T7 fix round 1): the enrolment prompt moved to stderr.
        Assert.Contains("Multiple YubiKeys detected", stderr);
        var pending = LoadConfig(_desktopDir);
        Assert.Empty(pending.YubiKeySerials);
        Assert.Equal("", pending.RedundancyXor);
        Assert.Null(pending.UnlockChallenge);
        Assert.Null(pending.MasterKeySalt);
        Assert.Null(pending.Keyring);
        Assert.NotNull(pending.PendingSlotId);
        Assert.Equal(SerialB, YubiKeySlotBlob.Decode(Convert.FromBase64String(pending.PendingSlotHwBlob!)).Serial);
        Assert.Equal([SerialB, SerialB], _desktopKeys.Challenges.Select(c => c.Serial)); // enrollment asks twice
    }

    [Fact]
    public void Request_NoKeyPluggedIn_FailsAndWritesNothing()
    {
        _desktopKeys.PluggedIn = [];

        var (exit, _, stderr) = OnDesktop("", "slot", "request", RequestFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("No YubiKey detected", stderr);
        Assert.False(File.Exists(RequestFile));
        Assert.False(File.Exists(Path.Combine(_desktopDir, "config.json")));
    }

    [Fact]
    public void OldFormatRequestWithoutABlob_IsRefusedWithAnActionableMessage()
    {
        RouterVaultWithASecret();
        var keyPair = SlotKeyPair.Generate();
        File.WriteAllText(RequestFile, $$"""
            { "FormatVersion": 1, "SlotId": "{{Convert.ToBase64String(new byte[16])}}", "PublicKey": "{{Convert.ToBase64String(keyPair.PublicKey)}}" }
            """);

        var (exit, _, stderr) = OnRouter("", "slot", "approve", RequestFile, ApproveFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("older tswap", stderr);
        Assert.Contains("slot request", stderr); // what to do: request again with this version
        Assert.False(File.Exists(ApproveFile));
    }

    [Fact]
    public void CurrentFormatRequestWithoutABlob_IsRefused()
    {
        RouterVaultWithASecret();
        Request(SerialA);
        var node = JsonNode.Parse(File.ReadAllText(RequestFile))!.AsObject();
        node.Remove("HwBlob");
        File.WriteAllText(RequestFile, node.ToJsonString());

        var (exit, _, stderr) = OnRouter("", "slot", "approve", RequestFile, ApproveFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("no YubiKey slot blob", stderr);
        Assert.False(File.Exists(ApproveFile));
    }

    [Fact]
    public void RequestWithAMalformedBlob_IsRefusedByApprove()
    {
        RouterVaultWithASecret();
        Request(SerialA);
        var node = JsonNode.Parse(File.ReadAllText(RequestFile))!.AsObject();
        var blob = Convert.FromBase64String(node["HwBlob"]!.GetValue<string>());
        node["HwBlob"] = Convert.ToBase64String([.. blob, 0]);
        File.WriteAllText(RequestFile, node.ToJsonString());

        var (exit, _, stderr) = OnRouter("", "slot", "approve", RequestFile, ApproveFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("Malformed YubiKey slot blob", stderr);
        Assert.False(File.Exists(ApproveFile));
    }

    [Fact]
    public void ApproveFileWithoutTheBlob_AcceptFailsAndWritesNothing()
    {
        RouterVaultWithASecret();
        Request(SerialA);
        Approve();
        var node = JsonNode.Parse(File.ReadAllText(ApproveFile))!.AsObject();
        node.Remove("NewSlotHwBlob");
        File.WriteAllText(ApproveFile, node.ToJsonString());
        var pending = File.ReadAllText(Path.Combine(_desktopDir, "config.json"));

        var (exit, _, stderr) = OnDesktop("", "slot", "accept", ApproveFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("no YubiKey slot blob", stderr);
        Assert.Equal(pending, File.ReadAllText(Path.Combine(_desktopDir, "config.json")));
        Assert.False(File.Exists(Path.Combine(_desktopDir, "secrets.json.enc")));
    }

    [Fact]
    public void ApproveFileWithAnotherSlotsBlob_AcceptFails()
    {
        RouterVaultWithASecret();
        Request(SerialA);
        Approve();
        var approve = SlotEnrollmentFileCodec.DeserializeApprove(File.ReadAllText(ApproveFile));
        var other = YubiKeySlotBlob.Create(SerialA, requiresTouch: true).Encode();
        File.WriteAllText(ApproveFile, SlotEnrollmentFileCodec.SerializeApprove(approve with { NewSlotHwBlob = Convert.ToBase64String(other) }));

        var (exit, _, stderr) = OnDesktop("", "slot", "accept", ApproveFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("does not match this machine's pending request", stderr);
    }

    [Fact]
    public void Accept_WithTheEnrolledKeyUnplugged_SaysWhichKeyToPlugIn()
    {
        RouterVaultWithASecret();
        Request(SerialA);
        Approve();
        _desktopKeys.PluggedIn = [SerialB];

        var (exit, _, stderr) = OnDesktop("", "slot", "accept", ApproveFile);

        Assert.NotEqual(0, exit);
        Assert.Contains($"Plug in YubiKey {SerialA}", stderr);
    }

    [Fact]
    public void ApproveOnAVersion2Vault_IsRefused()
    {
        File.WriteAllText(Path.Combine(_routerDir, "config.json"), KeyringV2FixtureTests.FixtureConfigJson);
        File.WriteAllBytes(Path.Combine(_routerDir, "secrets.json.enc"), Convert.FromBase64String(KeyringV2FixtureTests.FixtureSecretsFileBase64));
        Request(SerialA);
        var testKey = Convert.FromHexString(KeyringV2FixtureTests.FixtureTestKeyHex);
        var yubiKeys = new TestKeyYubiKeyService(testKey);
        var console = new FakeConsole();
        string[] args = ["slot", "approve", RequestFile, ApproveFile];
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _routerDir, Verbose = false, CommandArgs = args };

        var exit = CliRunner.Run(new CommandContext(console, env, new Storage(_routerDir), yubiKeys,
            new VaultUnlocker(yubiKeys, overrideKey: testKey), testKey, SudoBypass: true), args);

        Assert.NotEqual(0, exit);
        Assert.Contains("format version 2", console.ErrorText);
        Assert.False(File.Exists(ApproveFile));
    }
}
