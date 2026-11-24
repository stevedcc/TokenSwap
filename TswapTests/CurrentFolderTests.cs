using TswapCli;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T56 task 3 (#382): when a command fails and the current folder no longer exists, the error is followed by
/// <see cref="CurrentFolder.GoneText"/>. Nothing new is printed on success or when the folder exists. The real deleted
/// folder (a dead <c>getcwd</c>) is in <see cref="EndToEndTests"/>; here the seam
/// <see cref="CliEnvironment.CurrentDirectory"/> plays it.
/// </summary>
public sealed class CurrentFolderTests : IDisposable
{
    private readonly FleetMachine _m = new("current-folder", SimulatedYubiKeyService.WithKeys(SerialA));

    public void Dispose() => _m.Dispose();

    private static Func<string> Throws(Exception ex) => () => throw ex;

    public static TheoryData<string, bool> IsGoneRows => new()
    {
        { "returns", false },
        { "FileNotFoundException", true },
        { "DirectoryNotFoundException", true },
        { "UnauthorizedAccessException", false },
        { "IOException", false },
    };

    [Theory]
    [MemberData(nameof(IsGoneRows))]
    public void IsGone_OnlyForAFolderThatIsNotFound(string outcome, bool gone)
    {
        Func<string> currentDirectory = outcome switch
        {
            "returns" => () => "/some/folder",
            "FileNotFoundException" => Throws(new FileNotFoundException()),
            "DirectoryNotFoundException" => Throws(new DirectoryNotFoundException()),
            "UnauthorizedAccessException" => Throws(new UnauthorizedAccessException()),
            "IOException" => Throws(new IOException()),
            _ => throw new ArgumentOutOfRangeException(nameof(outcome)),
        };

        Assert.Equal(gone, CurrentFolder.IsGone(currentDirectory));
    }

    [Fact]
    public void AFailedCommand_InADeletedFolder_SaysSoAfterTheError()
    {
        _m.CurrentDirectory = Throws(new FileNotFoundException());

        var (exit, _, stderr) = _m.Run("", "redact", "missing.txt");

        Assert.Equal(1, exit);
        var lines = stderr.Replace("\r\n", "\n").Split('\n');
        var error = Array.FindIndex(lines, l => l.StartsWith("❌ Error: File not found", StringComparison.Ordinal));
        Assert.True(error >= 0, stderr);
        Assert.Equal(CurrentFolder.GoneText, lines[error + 1]);
    }

    [Fact]
    public void AFailedCommand_InAFolderThatExists_HasNoHint()
    {
        var (exit, _, stderr) = _m.Run("", "redact", "missing.txt");

        Assert.Equal(1, exit);
        Assert.Contains("File not found", stderr);
        Assert.DoesNotContain(CurrentFolder.GoneText, stderr);
    }

    [Fact]
    public void ACommandThatSucceeds_InADeletedFolder_PrintsNothingNew()
    {
        InitRecordVault(_m);
        _m.Ok("v", "ingest", "s");
        _m.CurrentDirectory = Throws(new FileNotFoundException());

        var (exit, stdout, stderr) = _m.Run("", "names");

        Assert.Equal(0, exit);
        Assert.StartsWith("s ", stdout);
        Assert.DoesNotContain(CurrentFolder.GoneText, stdout + stderr);
    }
}
