using TswapCli;
using Xunit;

namespace TswapTests;

public class OtherMachinesGuideTests
{
    private const string Prefix = "tswap";
    private const string ConfigDir = "/home/u/.config/tswap";
    private const string VaultDir = "/home/u/Sync/vault";

    private static string Render(bool folder)
    {
        var o = new StringWriter();
        OtherMachinesGuide.Print(o, Prefix, ConfigDir, VaultDir, folder);
        return o.ToString();
    }

    private static void AssertInOrder(string text, params string[] parts)
    {
        var from = 0;
        foreach (var part in parts)
        {
            var at = text.IndexOf(part, from, StringComparison.Ordinal);
            Assert.True(at >= 0, $"missing or out of order: {part}\n---\n{text}");
            from = at + part.Length;
        }
    }

    [Fact]
    public void TpmMachine_ListsRequestApproveAcceptMergeInOrder()
    {
        AssertInOrder(Render(false),
            "Adding other machines (carry each file between the machines yourself: scp, USB, or a paste):",
            "tswap slot request --tpm request.json",
            "sudo tswap slot approve request.json approve.json",
            "tswap slot accept approve.json --receipt receipt.json",
            "sudo tswap slot merge receipt.json");
    }

    [Fact]
    public void SecureEnclaveMachine_UsesWithTouchAndMentionsTouchId()
    {
        var text = Render(false);
        AssertInOrder(text,
            "tswap slot request --secure-enclave --with-touch request.json",
            "sudo tswap slot approve request.json approve.json",
            "tswap slot accept approve.json --receipt receipt.json",
            "sudo tswap slot merge receipt.json");
        Assert.Contains(text.Split('\n'), l => l.Contains("Touch ID") && l.Contains("at that Mac"));
    }

    [Fact]
    public void YubiKeyForAnotherMachine_OffersRequestThereOrSlotAddHere()
    {
        AssertInOrder(Render(false),
            "tswap slot request request.json",
            "sudo tswap slot add --yubikey");
    }

    [Fact]
    public void NonFolderVariants_NameConfigDirAsWhereTheReceiptIsMerged()
    {
        Assert.Contains($"merged into the config in {ConfigDir}", Render(false));
    }

    [Fact]
    public void WindowsLine_ExplainsTheSudoSteps()
    {
        Assert.Contains("On Windows, run the `sudo` steps from an administrator prompt, without `sudo`.", Render(false));
    }

    [Fact]
    public void FolderVariant_JoinsWithInitVaultDirAndHasNoMergeStep()
    {
        var text = Render(true);
        AssertInOrder(text,
            $"tswap init --vault-dir <its copy of {VaultDir}>",
            "tswap slot request --tpm request.json",
            "sudo tswap slot approve request.json approve.json",
            "tswap slot accept approve.json");
        Assert.DoesNotContain("slot merge", text);
        Assert.DoesNotContain("--receipt", text);
        Assert.Contains(ConfigDir, text);
    }
}
