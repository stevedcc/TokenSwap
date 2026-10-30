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
/// Brief T5 item 1 (decision 1): <c>slot accept</c> writes a receipt holding the finished slot,
/// and <c>slot approve</c> records what it approved in <see cref="Config.ApprovedSlots"/>. Two
/// "machines" with separate config dirs: a router with a simulated TPM (the vault's home) and a
/// desktop with simulated YubiKeys (the joiner).
/// </summary>
public class SlotReceiptTests : IDisposable
{
    private const int SerialA = 11111111;

    private static readonly byte[] RouterTpm = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] OtherTpm = RandomNumberGenerator.GetBytes(32);

    private readonly string _routerDir = NewDir();
    private readonly string _desktopDir = NewDir();
    private readonly SimulatedYubiKeyService _desktopKeys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly SimulatedYubiKeyService _routerKeys = SimulatedYubiKeyService.WithKeys();

    private static string NewDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tswap-receipt-" + Guid.NewGuid().ToString("N")[..8]);
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
    private string RouterConfigPath => Path.Combine(_routerDir, "config.json");

    private (int Exit, string Out, string Err) OnRouter(string stdin, byte[] tpm, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _routerDir, Verbose = false, CommandArgs = args };
        var unlocker = new VaultUnlocker(_routerKeys, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, tpm)]);
        var exit = CliRunner.Run(new CommandContext(console, env, new Storage(_routerDir), _routerKeys, unlocker, TestKey: tpm, SudoBypass: true), args);
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

    private void RouterVaultAndDesktopRequest()
    {
        Assert.Equal(0, OnRouter("", RouterTpm, "init", "--tpm").Exit);
        var (exit, _, err) = OnDesktop("", "slot", "request", RequestFile);
        Assert.True(exit == 0, err);
    }

    private void Approve()
    {
        var (exit, _, err) = OnRouter("", RouterTpm, "slot", "approve", RequestFile, ApproveFile);
        Assert.True(exit == 0, err);
    }

    // --- the codec ---

    private static SlotReceipt SampleReceipt(byte[]? hwBlob = null) => new(
        KeyringFormat.KeyringFormatVersion,
        RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize),
        1,
        new Slot(
            RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize),
            RandomNumberGenerator.GetBytes(SlotKeyPair.KeySize),
            RandomNumberGenerator.GetBytes(92),
            SlotKind.Machine,
            hwBlob ?? YubiKeySlotBlob.Create(SerialA, requiresTouch: true).Encode()));

    private static JsonObject SampleJson() => JsonNode.Parse(SlotReceiptCodec.Serialize(SampleReceipt()))!.AsObject();

    [Fact]
    public void Codec_RoundTrip_KeepsEveryField()
    {
        var receipt = SampleReceipt();

        var json = SlotReceiptCodec.Serialize(receipt);
        var back = SlotReceiptCodec.Deserialize(json);

        Assert.Equal(SlotReceiptCodec.CurrentFormatVersion, JsonNode.Parse(json)!["ReceiptFormatVersion"]!.GetValue<int>());
        Assert.Equal(1, SlotReceiptCodec.CurrentFormatVersion);
        Assert.Equal(receipt.KeyringFormatVersion, back.KeyringFormatVersion);
        Assert.Equal(receipt.VaultId, back.VaultId);
        Assert.Equal(receipt.K, back.K);
        Assert.Equal(receipt.Slot.SlotId, back.Slot.SlotId);
        Assert.Equal(receipt.Slot.PublicKey, back.Slot.PublicKey);
        Assert.Equal(receipt.Slot.Wrapped, back.Slot.Wrapped);
        Assert.Equal(SlotKind.Machine, back.Slot.Kind);
        Assert.Equal(receipt.Slot.HwBlob, back.Slot.HwBlob);
    }

    [Fact]
    public void Codec_OpaqueTpmBlob_RoundTrips()
    {
        var tpmBlob = RandomNumberGenerator.GetBytes(60);

        var back = SlotReceiptCodec.Deserialize(SlotReceiptCodec.Serialize(SampleReceipt(tpmBlob)));

        Assert.Equal(tpmBlob, back.Slot.HwBlob);
    }

    public static TheoryData<string, string, string> Rejections() => new()
    {
        // case, JSON mutation, expected message fragment
        { "bad receipt version", "version:2", "receipt format version 2" },
        { "keyring version 2", "keyring:2", "keyring format version 2" },
        { "vault id too short", "vaultid:short", "vault id must be 16 bytes" },
        { "vault id not base64", "vaultid:notb64", "vault id is not valid base64" },
        { "oversize blob", "hwblob:oversize", $"{KeyringFormat.MaxHwBlobSize}-byte limit" },
        { "no blob", "hwblob:none", "no hardware blob" },
        { "malformed YubiKey blob", "hwblob:badyk", "Malformed YubiKey slot blob" },
        { "recovery kind", "kind:recovery", "machine slot" },
        { "unknown field", "extra", "not valid JSON" },
        { "missing slot id", "slotid:none", "slot id" },
    };

    [Theory]
    [MemberData(nameof(Rejections))]
    public void Codec_StrictRejection(string name, string mutation, string expected)
    {
        _ = name;
        var node = SampleJson();
        switch (mutation)
        {
            case "version:2": node["ReceiptFormatVersion"] = 2; break;
            case "keyring:2": node["KeyringFormatVersion"] = 2; break;
            case "vaultid:short": node["VaultId"] = Convert.ToBase64String(new byte[15]); break;
            case "vaultid:notb64": node["VaultId"] = "not base64!!"; break;
            case "hwblob:oversize": node["HwBlob"] = Convert.ToBase64String(new byte[KeyringFormat.MaxHwBlobSize + 1]); break;
            case "hwblob:none": node.Remove("HwBlob"); break;
            case "hwblob:badyk":
                node["HwBlob"] = Convert.ToBase64String([.. YubiKeySlotBlob.Create(SerialA, true).Encode(), 0]);
                break;
            case "kind:recovery": node["Kind"] = (int)SlotKind.Recovery; break;
            case "extra": node["Smuggled"] = "x"; break;
            case "slotid:none": node.Remove("SlotId"); break;
        }

        var ex = Assert.Throws<TswapException>(() => SlotReceiptCodec.Deserialize(node.ToJsonString()));
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void Codec_TrailingData_IsRejected()
    {
        var json = SlotReceiptCodec.Serialize(SampleReceipt()) + "{}";

        var ex = Assert.Throws<TswapException>(() => SlotReceiptCodec.Deserialize(json));
        Assert.Contains("not valid JSON", ex.Message);
    }

    [Fact]
    public void Codec_OversizeFile_IsRejectedBeforeParsing()
    {
        var json = SlotReceiptCodec.Serialize(SampleReceipt()) + new string(' ', SlotReceiptCodec.MaxFileSize);

        var ex = Assert.Throws<TswapException>(() => SlotReceiptCodec.Deserialize(json));
        Assert.Contains("too large", ex.Message);
    }

    // --- accept writes the receipt ---

    [Fact]
    public void Accept_WritesAReceiptNextToTheApproveFile_ThatRoundTripsToTheNewSlot()
    {
        RouterVaultAndDesktopRequest();
        Approve();

        var (exit, stdout, err) = OnDesktop("", "slot", "accept", ApproveFile);
        Assert.True(exit == 0, err);

        var receiptPath = ApproveFile + ".receipt.json";
        Assert.True(File.Exists(receiptPath), "accept wrote no receipt");
        Assert.Contains(receiptPath, stdout);
        var receipt = SlotReceiptCodec.Deserialize(File.ReadAllText(receiptPath));
        var desktop = LoadConfig(_desktopDir);
        var keyring = DecodeKeyring(desktop);
        var ownSlot = keyring.Slots.Single(s => Convert.ToBase64String(s.SlotId) == desktop.KeyringSlotId);
        Assert.Equal(keyring.FormatVersion, receipt.KeyringFormatVersion);
        Assert.Equal(keyring.VaultId, receipt.VaultId);
        Assert.Equal(keyring.K, receipt.K);
        Assert.Equal(ownSlot.SlotId, receipt.Slot.SlotId);
        Assert.Equal(ownSlot.PublicKey, receipt.Slot.PublicKey);
        Assert.Equal(ownSlot.Wrapped, receipt.Slot.Wrapped);
        Assert.Equal(ownSlot.HwBlob, receipt.Slot.HwBlob);
        // It is the router's vault: the same vault id as the router's keyring.
        Assert.Equal(DecodeKeyring(LoadConfig(_routerDir)).VaultId, receipt.VaultId);
    }

    [Fact]
    public void Accept_WithReceiptOption_WritesTheReceiptThere()
    {
        RouterVaultAndDesktopRequest();
        Approve();
        var receiptPath = Path.Combine(_desktopDir, "elsewhere.json");

        var (exit, _, err) = OnDesktop("", "slot", "accept", ApproveFile, "--receipt", receiptPath);

        Assert.True(exit == 0, err);
        Assert.True(File.Exists(receiptPath));
        Assert.False(File.Exists(ApproveFile + ".receipt.json"));
        Assert.Equal(LoadConfig(_desktopDir).KeyringSlotId,
            Convert.ToBase64String(SlotReceiptCodec.Deserialize(File.ReadAllText(receiptPath)).Slot.SlotId));
    }

    [Fact]
    public void FailedAccept_WritesNoReceipt()
    {
        RouterVaultAndDesktopRequest();
        Approve();
        _desktopKeys.PluggedIn = [];

        var (exit, _, _) = OnDesktop("", "slot", "accept", ApproveFile);

        Assert.NotEqual(0, exit);
        Assert.False(File.Exists(ApproveFile + ".receipt.json"));
    }

    // --- approve records ApprovedSlots ---

    [Fact]
    public void Approve_AddsExactlyOneApprovedSlotsEntry_AndLeavesTheKeyringAlone()
    {
        RouterVaultAndDesktopRequest();
        var keyringBefore = LoadConfig(_routerDir).Keyring;
        Assert.Null(LoadConfig(_routerDir).ApprovedSlots);
        var request = SlotEnrollmentFileCodec.DeserializeRequest(File.ReadAllText(RequestFile));
        var before = DateTime.UtcNow;

        Approve();

        var router = LoadConfig(_routerDir);
        var entry = Assert.Single(router.ApprovedSlots!);
        Assert.Equal(request.SlotId, entry.SlotId);
        Assert.Equal(request.PublicKey, entry.PublicKey);
        Assert.InRange(entry.Approved, before.AddSeconds(-1), DateTime.UtcNow.AddSeconds(1));
        Assert.Equal(keyringBefore, router.Keyring);
    }

    [Fact]
    public void ApprovingTheSameRequestTwice_KeepsOneEntry()
    {
        RouterVaultAndDesktopRequest();

        Approve();
        Approve();

        Assert.Single(LoadConfig(_routerDir).ApprovedSlots!);
    }

    [Fact]
    public void FailedApprove_AddsNoEntry_AndLeavesConfigUntouched()
    {
        RouterVaultAndDesktopRequest();
        var before = File.ReadAllText(RouterConfigPath);

        // The router's TPM is not this one: the unlock fails.
        var (exit, _, _) = OnRouter("", OtherTpm, "slot", "approve", RequestFile, ApproveFile);

        Assert.NotEqual(0, exit);
        Assert.Equal(before, File.ReadAllText(RouterConfigPath));
        Assert.False(File.Exists(ApproveFile));
    }

    [Fact]
    public void ApproveWithAnUnwritableApproveFile_AddsNoEntry()
    {
        RouterVaultAndDesktopRequest();
        var before = File.ReadAllText(RouterConfigPath);
        var unwritable = Path.Combine(_desktopDir, "no-such-dir", "approve.json");

        var (exit, _, _) = OnRouter("", RouterTpm, "slot", "approve", RequestFile, unwritable);

        Assert.NotEqual(0, exit);
        Assert.Equal(before, File.ReadAllText(RouterConfigPath));
    }
}
