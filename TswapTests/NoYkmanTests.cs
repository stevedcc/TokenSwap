using TswapCli;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// YubiKey SDK stage 1, task 3: nothing in the shipped code tells anyone to run the ykman tool, or says it is
/// needed. The one mention left is the migration note saying it is no longer needed.
/// </summary>
public class NoYkmanTests
{
    private static string HelpText()
    {
        var console = new FakeConsole("");
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = Path.GetTempPath(), Verbose = false, CommandArgs = [] };
        var yubiKeys = new TestKeyYubiKeyService(new byte[32]);
        var storage = VaultStores.Open(Path.Combine(Path.GetTempPath(), "tswap-noykman-" + Guid.NewGuid().ToString("N")[..8]));
        var ctx = new CommandContext(console, env, storage, yubiKeys, new VaultUnlocker(yubiKeys, overrideKey: new byte[32]), new byte[32], SudoBypass: true);
        Assert.Equal(0, CliRunner.Run(ctx, ["--help"]));
        return console.OutText;
    }

    [Fact]
    public void Help_MentionsNoYkman()
    {
        var help = HelpText();

        Assert.DoesNotContain("ykman", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("tswap yubikey setup", help);
    }

    [Fact]
    public void Help_BannerIsHardwareBacked()
    {
        var first = HelpText().Split('\n')[0].TrimEnd('\r');

        Assert.Equal("tswap - hardware-backed secret manager", first);
    }

    [Fact]
    public void Source_NoYkmanOutsideMigrationNote()
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !File.Exists(Path.Combine(root, "TokenSwap.slnx")))
            root = Path.GetDirectoryName(root);
        Assert.NotNull(root);

        var offenders = new[] { "TswapCli", "TswapCore" }
            .SelectMany(d => Directory.EnumerateFiles(Path.Combine(root, d), "*.cs", SearchOption.AllDirectories))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                        && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (File: f, Line: i + 1, Text: line)))
            .Where(l => l.Text.Contains("ykman", StringComparison.OrdinalIgnoreCase))
            .Where(l => !(Path.GetFileName(l.File) == "MigrateCommand.cs"
                          && l.Text.Contains("ykman is no longer needed", StringComparison.Ordinal)))
            .Select(l => $"{Path.GetRelativePath(root, l.File)}:{l.Line}: {l.Text.Trim()}")
            .ToList();

        Assert.True(offenders.Count == 0, "ykman is named in:\n" + string.Join("\n", offenders));
    }

    private static string TouchWarning(bool? requiresTouch)
    {
        var console = new FakeConsole("");
        SecurityWarnings.ExplainTouch(console, "YubiKey 12", requiresTouch);
        return console.ErrorText;
    }

    [Fact]
    public void TouchWarning_NoTouch_SuggestsSetupReplace()
    {
        var text = TouchWarning(false);

        Assert.Contains("tswap yubikey setup --replace --touch", text);
        Assert.DoesNotContain("ykman", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TouchWarning_Unknown_NamesNoYkman()
    {
        var text = TouchWarning(null);

        Assert.Contains("Couldn't check", text);
        Assert.DoesNotContain("ykman", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("yubikey-manager", text, StringComparison.OrdinalIgnoreCase);
    }
}
