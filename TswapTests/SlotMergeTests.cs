using System.Security.Cryptography;
using System.Text.Json.Nodes;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T5 item 2 (decision 1, issue #190): <c>slot merge &lt;file&gt;</c> adds the slots of a
/// receipt or of another copy's <c>config.json</c> to this machine's keyring. The owner's setup,
/// simulated: a router whose vault is unlocked by its TPM (machine A), a desktop with YubiKeys
/// (machine B, the joiner), each its own config dir.
/// </summary>
public class SlotMergeTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly FleetMachine _router;
    private readonly FleetMachine _desktop;
    private readonly List<FleetMachine> _others = [];

    public SlotMergeTests()
    {
        _router = new FleetMachine("router", _keys) { Tpm = RandomNumberGenerator.GetBytes(32) };
        _desktop = new FleetMachine("desktop", _keys);
        _keys.PluggedIn = [];
    }

    public void Dispose()
    {
        _router.Dispose();
        _desktop.Dispose();
        foreach (var m in _others) m.Dispose();
    }

    private FleetMachine Another(string name, byte[]? tpm = null)
    {
        var m = new FleetMachine(name, _keys) { Tpm = tpm };
        _others.Add(m);
        return m;
    }

    private void RouterVault()
    {
        _router.Ok("", "init", "--tpm");
        _router.Ok("router-pw\nrouter-pw\n", "add", "router");
    }

    /// <summary>
    /// request (joiner) → approve (approver) → accept (joiner). Returns the receipt path. The
    /// joiner's key <paramref name="serial"/> is plugged in for request and accept only.
    /// </summary>
    private string Join(FleetMachine joiner, FleetMachine approver, int serial)
    {
        var request = joiner.PathOf("request.json");
        var approve = joiner.PathOf("approve.json");
        _keys.PluggedIn = [serial];
        joiner.Ok("", "slot", "request", request);
        _keys.PluggedIn = [];
        approver.Ok("", "slot", "approve", request, approve);
        _keys.PluggedIn = [serial];
        joiner.Ok("", "slot", "accept", approve);
        _keys.PluggedIn = [];
        return approve + ".receipt.json";
    }

    /// <summary>Reads 'router' on <paramref name="machine"/> with only these keys plugged in.</summary>
    private string GetWith(FleetMachine machine, params int[] pluggedIn)
    {
        _keys.PluggedIn = [.. pluggedIn];
        try
        {
            return machine.Get("router");
        }
        finally
        {
            _keys.PluggedIn = [];
        }
    }

    [Fact]
    public void OwnersFlow_RouterOpensWithTheDesktopKey_WithTheTpmUnavailable_AndStillWithTheTpm()
    {
        RouterVault();
        var receipt = Join(_desktop, _router, SerialA);
        var newSlotId = _desktop.Config.KeyringSlotId;
        Assert.Single(_router.Config.ApprovedSlots!);

        // No --yes and no terminal: the slot was approved here, so it is added without asking.
        var stdout = _router.Ok("", "slot", "merge", receipt);

        Assert.Contains("1 slot", stdout);
        var keyring = _router.Keyring;
        Assert.Equal(3, keyring.Slots.Count);
        Assert.Equal(newSlotId, Convert.ToBase64String(keyring.Slots[2].SlotId));
        Assert.Null(_router.Config.ApprovedSlots); // the entry is removed once merged

        var tpm = _router.Tpm;
        _router.Tpm = null; // the router's TPM is unavailable
        Assert.Equal("router-pw", GetWith(_router, SerialA));
        _router.Tpm = RandomNumberGenerator.GetBytes(32); // or cleared
        Assert.Equal("router-pw", GetWith(_router, SerialA));
        _router.Tpm = tpm;
        Assert.Equal("router-pw", GetWith(_router)); // and still the TPM alone
    }

    [Fact]
    public void ReceiptForASlotThisMachineDidNotApprove_IsRefusedWithoutATerminalOrYes()
    {
        RouterVault();
        var copy = Another("copy", _router.Tpm);
        _router.CopyVaultTo(copy); // a copy taken before the approval: it approved nothing
        var receipt = Join(_desktop, _router, SerialA);
        var before = copy.ConfigText;

        var (exit, _, stderr) = copy.Run("", "slot", "merge", receipt);

        Assert.NotEqual(0, exit);
        Assert.Contains("--yes", stderr);
        Assert.Contains(SlotFingerprint.Compute(_desktop.Keyring.Slots[^1].PublicKey), stderr);
        Assert.Equal(before, copy.ConfigText);
        Assert.Empty(copy.Backups);
    }

    [Fact]
    public void UnapprovedSlot_WithYes_IsAdded()
    {
        RouterVault();
        var copy = Another("copy", _router.Tpm);
        _router.CopyVaultTo(copy);
        var receipt = Join(_desktop, _router, SerialA);

        var stdout = copy.Ok("", "slot", "merge", receipt, "--yes");

        Assert.Contains(SlotFingerprint.Compute(_desktop.Keyring.Slots[^1].PublicKey), stdout);
        Assert.Equal(3, copy.Keyring.Slots.Count);
        Assert.Equal("router-pw", GetWith(copy, SerialA));
    }

    [Fact]
    public void UnapprovedSlot_OnATerminal_AskedByFingerprint_YesAdds_NoSkips()
    {
        RouterVault();
        var copy = Another("copy", _router.Tpm);
        _router.CopyVaultTo(copy);
        var receipt = Join(_desktop, _router, SerialA);
        var fingerprint = SlotFingerprint.Compute(_desktop.Keyring.Slots[^1].PublicKey);
        var before = copy.ConfigText;

        var (noExit, noOut, noErr) = copy.RunOnTerminal("no\n", "slot", "merge", receipt);
        Assert.True(noExit == 0, noErr);
        Assert.Contains(fingerprint, noOut);
        Assert.Equal(before, copy.ConfigText);

        var (yesExit, yesOut, yesErr) = copy.RunOnTerminal("yes\n", "slot", "merge", receipt);
        Assert.True(yesExit == 0, yesErr);
        Assert.Contains(fingerprint, yesOut);
        Assert.Equal(3, copy.Keyring.Slots.Count);
    }

    [Fact]
    public void ApprovalWithTheSameSlotIdButAnotherPublicKey_DoesNotCount()
    {
        RouterVault();
        var receipt = Join(_desktop, _router, SerialA);
        var config = _router.Config;
        var forged = config.ApprovedSlots!.Select(a => a with { PublicKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }).ToList();
        File.WriteAllText(_router.ConfigPath, System.Text.Json.JsonSerializer.Serialize(
            config with { ApprovedSlots = forged }, TswapCore.TswapJsonContext.Default.Config));
        var before = _router.ConfigText;

        var (exit, _, stderr) = _router.Run("", "slot", "merge", receipt);

        Assert.NotEqual(0, exit);
        Assert.Contains("--yes", stderr);
        Assert.Equal(before, _router.ConfigText);
    }

    [Fact]
    public void ReceiptFromAnotherVault_IsRefused()
    {
        RouterVault();
        var receipt = Join(_desktop, _router, SerialA);
        var node = JsonNode.Parse(File.ReadAllText(receipt))!.AsObject();
        node["VaultId"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        File.WriteAllText(receipt, node.ToJsonString());
        var before = _router.ConfigText;

        var (exit, _, stderr) = _router.Run("", "slot", "merge", receipt, "--yes");

        Assert.NotEqual(0, exit);
        Assert.Contains("another vault", stderr);
        Assert.Equal(before, _router.ConfigText);
        Assert.Empty(_router.Backups);
    }

    [Fact]
    public void ConfigOfAnotherVault_IsRefused()
    {
        RouterVault();
        var other = Another("other", RandomNumberGenerator.GetBytes(32));
        other.Ok("", "init", "--tpm");
        var before = _router.ConfigText;

        var (exit, _, stderr) = _router.Run("", "slot", "merge", other.ConfigPath, "--yes");

        Assert.NotEqual(0, exit);
        Assert.Contains("another vault", stderr);
        Assert.Equal(before, _router.ConfigText);
    }

    [Fact]
    public void Version2Keyring_IsRefusedWithTheExistingMessage()
    {
        RouterVault();
        var receipt = Join(_desktop, _router, SerialA);
        var v2 = Another("v2");
        File.WriteAllText(v2.ConfigPath, KeyringV2FixtureTests.FixtureConfigJson);

        var (exit, _, stderr) = v2.Run("", "slot", "merge", receipt, "--yes");

        Assert.NotEqual(0, exit);
        Assert.Contains("format version 2", stderr);
        Assert.Contains("create a new vault", stderr);
        Assert.Equal(KeyringV2FixtureTests.FixtureConfigJson, v2.ConfigText);
    }

    [Fact]
    public void MergingTwice_TheSecondIsANoOp()
    {
        RouterVault();
        var receipt = Join(_desktop, _router, SerialA);
        _router.Ok("", "slot", "merge", receipt);
        var after = _router.ConfigText;
        var backups = _router.Backups;

        var stdout = _router.Ok("", "slot", "merge", receipt);

        Assert.Contains("Nothing to merge", stdout);
        Assert.Equal(after, _router.ConfigText);
        Assert.Equal(backups, _router.Backups);

        // The joiner's whole config.json is a no-op too now: every slot in it is here already.
        Assert.Contains("Nothing to merge", _router.Ok("", "slot", "merge", _desktop.ConfigPath));
        Assert.Equal(after, _router.ConfigText);
    }

    [Fact]
    public void TheJoinersConfigJson_MergesLikeItsReceipt()
    {
        RouterVault();
        Join(_desktop, _router, SerialA);

        _router.Ok("", "slot", "merge", _desktop.ConfigPath);

        Assert.Equal(3, _router.Keyring.Slots.Count);
        Assert.Null(_router.Config.ApprovedSlots);
        _router.Tpm = null;
        Assert.Equal("router-pw", GetWith(_router, SerialA));
    }

    [Fact]
    public void DriftedCopies_EachApprovedADifferentJoiner_MergeIntoOneThatOpensWithAll()
    {
        RouterVault();
        var copy = Another("router-copy", _router.Tpm);
        _router.CopyVaultTo(copy);
        var laptop = Another("laptop");

        _router.Ok("", "slot", "merge", Join(_desktop, _router, SerialA));
        copy.Ok("", "slot", "merge", Join(laptop, copy, SerialB));
        Assert.Equal(3, _router.Keyring.Slots.Count);
        Assert.Equal(3, copy.Keyring.Slots.Count);

        // The copy's config.json: its own approval (the laptop) is not the router's, so --yes.
        var stdout = _router.Ok("", "slot", "merge", copy.ConfigPath, "--yes");
        Assert.Contains("1 slot", stdout);

        Assert.Equal(4, _router.Keyring.Slots.Count);
        Assert.Equal("router-pw", GetWith(_router)); // the TPM
        var tpm = _router.Tpm;
        _router.Tpm = null;
        Assert.Equal("router-pw", GetWith(_router, SerialA)); // the desktop's key alone
        Assert.Equal("router-pw", GetWith(_router, SerialB)); // the laptop's key alone
        _router.Tpm = tpm;

        // And back the other way: the copy gets the desktop's slot, so both are the union.
        copy.Ok("", "slot", "merge", _router.ConfigPath, "--yes");
        Assert.Equal(
            _router.Keyring.Slots.Select(s => Convert.ToBase64String(s.SlotId)).Order(),
            copy.Keyring.Slots.Select(s => Convert.ToBase64String(s.SlotId)).Order());
    }

    [Fact]
    public void ConfigJsonIsBackedUpBeforeTheWrite()
    {
        RouterVault();
        var receipt = Join(_desktop, _router, SerialA);
        var before = _router.ConfigText;

        var stdout = _router.Ok("", "slot", "merge", receipt);

        var backup = Assert.Single(_router.Backups);
        Assert.Equal(before, File.ReadAllText(backup));
        Assert.NotEqual(before, _router.ConfigText);
        Assert.Contains(backup, stdout);
    }

    [Fact]
    public void TwoBackupsInTheSameMillisecond_BothKeepTheirContent()
    {
        // Found by the full suite: two config writes within one millisecond gave the same backup
        // name, and File.Copy refused the second (the merge failed after unlocking).
        var now = DateTime.UtcNow;
        File.WriteAllText(_router.ConfigPath, "first");
        var first = TswapCli.Commands.SlotCommand.BackupConfigFile(_router.ConfigPath, now);
        File.WriteAllText(_router.ConfigPath, "second");
        var second = TswapCli.Commands.SlotCommand.BackupConfigFile(_router.ConfigPath, now);

        Assert.NotEqual(first, second);
        Assert.Equal("first", File.ReadAllText(first));
        Assert.Equal("second", File.ReadAllText(second));
        Assert.StartsWith(_router.ConfigPath + ".bak-", second);
    }

    [Fact]
    public void WithoutSudo_IsRefusedBeforeReadingTheFileOrUnlocking()
    {
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged (see SlotCommandTests)

        RouterVault();
        var receipt = Join(_desktop, _router, SerialA);
        var before = _router.ConfigText;
        _router.Sudo = false;

        var (exit, _, stderr) = _router.Run("", "slot", "merge", receipt);

        Assert.NotEqual(0, exit);
        Assert.Contains("slot merge", stderr);
        Assert.Contains("requires", stderr);
        Assert.Equal(before, _router.ConfigText);
    }

    [Fact]
    public void ASlotThatDiffersFromTheOneHereWithTheSameId_IsRefused()
    {
        RouterVault();
        var copy = Another("copy", _router.Tpm);
        _router.CopyVaultTo(copy);
        var keyring = copy.Keyring;
        var tampered = keyring with { Slots = [keyring.Slots[0] with { Wrapped = RandomNumberGenerator.GetBytes(92) }, .. keyring.Slots.Skip(1)] };
        File.WriteAllText(copy.ConfigPath, System.Text.Json.JsonSerializer.Serialize(
            copy.Config with { Keyring = Convert.ToBase64String(KeyringCodec.Encode(tampered)) }, TswapCore.TswapJsonContext.Default.Config));
        var before = _router.ConfigText;

        var (exit, _, stderr) = _router.Run("", "slot", "merge", copy.ConfigPath, "--yes");

        Assert.NotEqual(0, exit);
        Assert.Contains("differs", stderr);
        Assert.Equal(before, _router.ConfigText);
    }

    [Fact]
    public void AFileThatIsNeitherAReceiptNorAConfig_IsRefused()
    {
        RouterVault();
        var path = _router.PathOf("junk.json");
        File.WriteAllText(path, "{\"Hello\": 1}");

        var (exit, _, stderr) = _router.Run("", "slot", "merge", path, "--yes");

        Assert.NotEqual(0, exit);
        Assert.Contains("is neither a slot receipt", stderr);
    }

    [Theory]
    [InlineData("slot", "merge")]
    [InlineData("slot", "merge", "a.json", "b.json")]
    [InlineData("slot", "merge", "a.json", "--force")]
    public void WrongArguments_AreAUsageError(params string[] args)
    {
        var (exit, _, stderr) = _router.Run("", args);

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage:", stderr);
        Assert.Contains("slot merge", stderr);
    }
}
