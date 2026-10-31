using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T14 item 6: the argument errors of every command whose checks became list patterns, pinned
/// before the refactor: the exact message on stderr, nothing on stdout, exit code 1, and the order
/// of the checks (the usage error comes before the sudo check where it did, after it where it did).
/// Runs in process on a <see cref="FleetMachine"/> with no vault: every case fails before one is read.
/// </summary>
public sealed class CommandArgumentErrorTests : IDisposable
{
    private readonly FleetMachine _m = new("args") { Sudo = false };

    public void Dispose() => _m.Dispose();

    private static string ErrorLine(string message) => $"\n❌ Error: {message}{Environment.NewLine}";

    [Theory]
    [InlineData("Usage: tswap add <name>", "add")]
    [InlineData("Usage: tswap apply <file>", "apply")]
    [InlineData("Usage: tswap burn <name> [reason]", "burn")]
    [InlineData("Usage: tswap check <path> [--json]", "check")]
    [InlineData("Usage: tswap completion <bash|zsh|fish|powershell>", "completion")]
    [InlineData("Usage: tswap create <name> [length]", "create")]
    [InlineData("Usage: tswap delete <name>", "delete")]
    [InlineData("Usage: sudo tswap export <file>", "export")]
    [InlineData("Usage: tswap get <name>", "get")]
    [InlineData("Usage: tswap redact <file>", "redact")]
    [InlineData("Usage: tswap run <command> [args...]", "run")]
    [InlineData("Usage: tswap tocomment <file> [--dry-run]", "tocomment")]
    [InlineData("Usage: <source> | tswap ingest [--rotate] <name>", "ingest")]
    [InlineData("Usage: <source> | tswap ingest [--rotate] <name>", "ingest", "--rotate")]
    [InlineData("Usage: <source> | tswap ingest [--rotate] <name>", "ingest", "a", "b")]
    [InlineData("Usage: <source> | tswap ingest [--rotate] <name>", "ingest", "--rotate", "a", "b")]
    [InlineData("Usage: <source> | tswap ingest [--rotate] <name>", "ingest", "--name")]
    [InlineData("Usage: sudo tswap restore <name>", "restore")]
    [InlineData("Usage: sudo tswap restore <name>", "restore", "a", "b")]
    [InlineData("Usage: sudo tswap restore <name>", "restore", "--name")]
    public void AMissingOrExtraArgument_GivesTheCommandsUsage_BeforeAnyOtherCheck(string usage, params string[] args)
    {
        var (exit, stdout, stderr) = _m.Run("", args);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Equal(ErrorLine(usage), stderr);
    }

    [Theory]
    [InlineData("migrate", "--vault-dir")]
    [InlineData("migrate", "--to-records", "--vault-dir")]
    [InlineData("migrate", "--to-records", "--vault-dir", "--dir")]
    [InlineData("migrate", "--vault-dir", "--dir", "--to-records")]
    [InlineData("migrate", "--to-records", "extra")]
    [InlineData("migrate", "--vault-dir", "dir")]
    public void MigrateToRecords_AnyOtherArgumentShape_GivesItsUsage_BeforeTheSudoCheck(params string[] args)
    {
        var (exit, stdout, stderr) = _m.Run("", args);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Equal(ErrorLine("Usage: sudo tswap migrate --to-records [--vault-dir <dir>]"), stderr);
    }

    [Theory]
    [InlineData("migrate", "--to-records")]
    [InlineData("migrate", "--to-records", "--vault-dir", "dir")]
    [InlineData("migrate", "--vault-dir", "dir", "--to-records")]
    public void MigrateToRecords_TheThreeAcceptedShapes_GetPastTheUsageCheck_ToTheSudoCheck(params string[] args)
    {
        if (Environment.IsPrivilegedProcess)
            return; // no refusal is possible when already privileged

        var (exit, stdout, stderr) = _m.Run("", args);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Contains("requires", stderr);
        Assert.DoesNotContain("Usage", stderr);
    }

    [Fact]
    public void Slot_WithNoSubcommand_GivesItsUsage()
    {
        var (exit, stdout, stderr) = _m.Run("", "slot");

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.StartsWith(ErrorLine("Usage: tswap slot request [--tpm|").TrimEnd(), stderr);
        Assert.EndsWith($"| tswap slot add --yubikey{Environment.NewLine}", stderr);
    }

    [Theory]
    [InlineData]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("help")]
    [InlineData("help", "init")]
    public void NoCommandOrAHelpFlagFirst_PrintsTheHelpScreen(params string[] args)
    {
        var (exit, stdout, stderr) = _m.Run("", args);

        Assert.Equal(0, exit);
        Assert.Equal("", stderr);
        Assert.Equal(_m.Run("").Out, stdout);
        Assert.Contains("Usage", stdout);
    }

    [Fact]
    public void AnUnknownFirstWord_IsAnUnknownCommand_NotTheHelpScreen()
    {
        var (exit, stdout, stderr) = _m.Run("", "--helpme");

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Equal(ErrorLine("Unknown command: --helpme"), stderr);
    }

    [Theory]
    [InlineData("broker")]
    [InlineData("broker", "serve", "extra")]
    [InlineData("broker", "route")]
    [InlineData("broker", "route", "bogus")]
    [InlineData("broker", "socket")]
    [InlineData("broker", "template", "list")]
    [InlineData("broker", "nonsense")]
    [InlineData("broker", "route", "remove")]
    [InlineData("broker", "route", "remove", "a", "b")]
    [InlineData("broker", "socket", "remove")]
    [InlineData("broker", "template", "remove", "a", "b")]
    [InlineData("broker", "template", "add")]
    public void Broker_AMissingOrUnknownSubcommandOrArgument_GivesTheBrokerUsage(params string[] args)
    {
        if (OperatingSystem.IsWindows())
            return; // 'tswap broker' refuses Windows before it reads any argument
        _m.Sudo = true; // route|socket|template add|remove check sudo first (see the next test)

        var (exit, stdout, stderr) = _m.Run("", args);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.StartsWith("\n❌ Error: Usage:\n  tswap broker serve\n", stderr);
    }

    [Fact]
    public void BrokerRouteRemove_ChecksSudo_BeforeItsArguments()
    {
        if (OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess)
            return; // no refusal is possible when already privileged

        var (exit, stdout, stderr) = _m.Run("", "broker", "route", "remove");

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Contains("requires", stderr);
        Assert.DoesNotContain("Usage", stderr);
    }
}
