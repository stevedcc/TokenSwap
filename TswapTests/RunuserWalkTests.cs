using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T64 Task 2a (round 4 I-1): <c>runuser</c> is a wrapper for the shared program-position walk
/// (<see cref="Validation.ProgramPositions"/>), with util-linux's valued options (<c>-w</c>/<c>--whitelist-environment</c>
/// added), and its <c>-c</c>/<c>--command</c> refusal in <see cref="Validation.GetBlockedInvocation"/> still runs first.
/// </summary>
public class RunuserWalkTests
{
    [Fact]
    public void ProgramPositions_WalkThroughRunuserDashU() =>
        Assert.Equal([0, 3], Validation.ProgramPositions(["runuser", "-u", "app", "install", "a", "b"]));

    [Fact]
    public void ProgramPositions_SkipWhitelistEnvironmentsValue() =>
        Assert.Equal([0, 6], Validation.ProgramPositions(["runuser", "-w", "PATH", "-u", "app", "--", "tool"]));

    [Theory]
    [InlineData("-c", "runuser", "-c", "echo {{x}}")]
    [InlineData("--command=echo {{x}}", "runuser", "root", "--command=echo {{x}}")]
    [InlineData("-lc", "runuser", "-lc", "echo {{x}}")]
    public void GetBlockedInvocation_RunuserWithInlineCode_StillRefusedAsInlineCode(string flag, params string[] argv)
    {
        var blocked = Validation.GetBlockedInvocation(argv);

        Assert.NotNull(blocked);
        Assert.Equal("runuser", blocked.Program);
        Assert.Equal($"'runuser {flag}' runs inline code, which can transform and print secrets past redaction. {Validation.WayOutFor(false)}",
            blocked.Reason);
    }

    [Fact]
    public void GetFileTokenRefusal_InstallBehindRunuser_IsRefused()
    {
        var refusal = Validation.GetFileTokenRefusal(["runuser", "-u", "app", "install", "{{@f}}", "/tmp/x"]);

        Assert.NotNull(refusal);
        Assert.Equal("install", refusal.Program);
        Assert.StartsWith("'install' copies files", refusal.Reason);
    }

    // Known miss (round 6 M-1): in a '-lu USER' cluster the walk can't see that 'u' takes the next word, so it takes
    // 'app' for the command and stops. Unknown and clustered wrapper options are tracked in #438.
    [Fact]
    public void GetFileTokenRefusal_InstallBehindRunuserLuCluster_IsAKnownMiss() =>
        Assert.Null(Validation.GetFileTokenRefusal(["runuser", "-lu", "app", "install", "{{@f}}", "/tmp/x"]));
}
