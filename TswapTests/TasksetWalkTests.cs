using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T64 code review round 1 (C1): the shared walk (<see cref="Validation.ProgramPositions"/>) finds taskset's
/// command where <c>CheckWrapper</c> does: a CPU list attached to its option (<c>-c0-3</c>, <c>--cpu-list=0-3</c>) is the
/// mask, so the next word is the command; a separate list (<c>-c 0-3</c>) is the leading positional.
/// </summary>
public class TasksetWalkTests
{
    [Theory]
    [InlineData(new[] { "taskset", "-c0-3", "tool", "a" }, new[] { 0, 2 })]
    [InlineData(new[] { "taskset", "--cpu-list=0-3", "tool", "a" }, new[] { 0, 2 })]
    [InlineData(new[] { "taskset", "-c", "0-3", "tool", "a" }, new[] { 0, 3 })]
    [InlineData(new[] { "taskset", "0x3", "tool", "a" }, new[] { 0, 2 })]
    public void ProgramPositions_FindTasksetsCommand(string[] argv, int[] expected) =>
        Assert.Equal(expected, Validation.ProgramPositions(argv));

    [Theory]
    [InlineData("-c0-3")]
    [InlineData("--cpu-list=0-3")]
    public void GetFileTokenRefusal_InstallBehindTasksetWithAnAttachedList_IsRefused(string list)
    {
        var refusal = Validation.GetFileTokenRefusal(["taskset", list, "install", "{{@f}}", "/tmp/x"]);

        Assert.NotNull(refusal);
        Assert.Equal("install", refusal.Program);
        Assert.StartsWith("'install' copies files", refusal.Reason);
    }

    // taskset's options end at its first other word (util-linux getopt "+..."): a '-c...' word after the mask belongs
    // to the command and doesn't make the mask the command.
    [Fact]
    public void ACommandsDashCCluster_DoesNotHideTheCommand_FromTheInlineCodeCheck()
    {
        var blocked = Validation.GetBlockedInvocation(["taskset", "0x3", "python3", "-cprint('{{x}}')"]);

        Assert.NotNull(blocked);
        Assert.Equal("python3", blocked.Program);
        Assert.StartsWith("'taskset' runs 'python3': ", blocked.Reason);
    }

    [Fact]
    public void ACommandsDashCCluster_DoesNotHideTheCommand_FromTheBashLauncherCheck()
    {
        Assert.Equal([0, 2], Validation.ProgramPositions(["taskset", "0x3", "bash.exe", "./x.sh", "-cX"]));
        var refusal = Validation.BashLauncherRefusal(["taskset", "0x3", "bash.exe", "./x.sh", "-cX", "{{x}}"], windows: false, probe: null);

        Assert.NotNull(refusal);
        Assert.Equal("bash.exe", refusal.Program);
    }
}
