using System.Security.Cryptography;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T24 task 3 (issue #309 comment 3): <c>slot accept</c>'s receipt text is keyed on where the keyring was written.
/// Into a vault folder (<c>--vault-dir</c>, or a record-store machine's own folder) the new slot is already in that
/// folder's keyring, so the text says so and the receipt is only for a copy of its own; a machine without a vault keeps
/// today's text. The receipt is written in all three.
/// </summary>
public sealed class SlotAcceptReceiptTextTests : IDisposable
{
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly FleetMachine _router;
    private readonly FleetMachine _desktop;

    public SlotAcceptReceiptTextTests()
    {
        _router = new FleetMachine("receipt-router", _keys) { Tpm = RandomNumberGenerator.GetBytes(32) };
        _desktop = new FleetMachine("receipt-desktop", _keys);
        _keys.PluggedIn = [];
        _router.Ok("", "init", "--tpm", "--no-password");
    }

    public void Dispose()
    {
        _router.Dispose();
        _desktop.Dispose();
    }

    private string Request => _desktop.PathOf("request.json");
    private string Approve => _desktop.PathOf("approve.json");
    private string Receipt => Approve + ".receipt.json";

    /// <summary>A key A request on the desktop, approved on the router.</summary>
    private void RequestAndApprove()
    {
        _keys.PluggedIn = [SerialA];
        _desktop.Ok("yes\n", "slot", "request", Request);
        _router.Ok("", "slot", "approve", Request, Approve);
    }

    // The code writes a literal "\n" before these lines (inside the message) and Environment.NewLine after each
    // (WriteLine), so the expected text does the same and holds on Windows too.
    private static string FolderLines(string folder, string receipt) =>
        $"\nThe new slot is in the keyring of the vault folder {folder}: every machine that shares that folder has it, with no merge.{Environment.NewLine}" +
        $"Receipt written to: {receipt} (only for a machine with its own copy of the vault, not this folder: there, run sudo tswap slot merge <receipt-file>).{Environment.NewLine}";

    private const string TodaysLastLine = "Until then, only this machine's copy of the vault has the new slot.";

    [Fact]
    public void AcceptWithVaultDir_SaysTheSlotIsInTheFoldersKeyring()
    {
        RequestAndApprove();

        var stdout = _desktop.Ok("", "slot", "accept", Approve, "--vault-dir", _router.VaultDir!);

        Assert.EndsWith(FolderLines(_router.VaultDir!, Receipt), stdout);
        Assert.DoesNotContain(TodaysLastLine, stdout);
        Assert.True(File.Exists(Receipt));
        Assert.Equal(3, _router.Keyring.Slots.Count); // the shared keyring has the new slot, as today
    }

    [Fact]
    public void AcceptOnARecordStoreMachine_SaysTheSlotIsInItsFoldersKeyring()
    {
        _desktop.Ok("", "init", "--vault-dir", _router.VaultDir!);
        Assert.Equal(_router.VaultDir, _desktop.VaultDir);
        RequestAndApprove();

        var stdout = _desktop.Ok("", "slot", "accept", Approve);

        Assert.EndsWith(FolderLines(_router.VaultDir!, Receipt), stdout);
        Assert.DoesNotContain(TodaysLastLine, stdout);
        Assert.True(File.Exists(Receipt));
        Assert.Equal(3, _router.Keyring.Slots.Count);
    }

    [Fact]
    public void AcceptOnAMachineWithoutAVault_KeepsTodaysText()
    {
        RequestAndApprove();

        var stdout = _desktop.Ok("", "slot", "accept", Approve);

        Assert.EndsWith(
            $"\nReceipt written to: {Receipt}{Environment.NewLine}" +
            $"Carry it back to the approving machine yourself (scp/USB/paste) and run there:{Environment.NewLine}" +
            $"  sudo tswap slot merge <receipt-file>{Environment.NewLine}" +
            $"{TodaysLastLine}{Environment.NewLine}",
            stdout);
        Assert.True(File.Exists(Receipt));
        Assert.Equal(2, _router.Keyring.Slots.Count); // the router's copy gets it only by the merge
        Assert.Equal(3, _desktop.Keyring.Slots.Count);
    }
}
