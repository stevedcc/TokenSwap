using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T64 code review rounds 1 and 2 (C1, C-F1): taskset as util-linux parses it (e57914591653,
/// <c>schedutils/taskset.c</c>: <c>getopt_long(argc, argv, "+apchV", longopts, NULL)</c>, <c>:183</c>; the long options
/// <c>all-tasks</c>, <c>pid</c>, <c>cpu-list</c>, <c>help</c>, <c>version</c>, none taking a value, <c>:167-173</c>).
/// Its options end at the first other word or <c>--</c>; <c>-c</c>/<c>--cpu-list</c> take no value; the first positional
/// is the mask and the word after it the command. An option word it wouldn't accept as written (<c>-c0-3</c>,
/// <c>--cpu-list=0-3</c>, <c>-ca0</c>, <c>-x</c>) means the command can't be located, so every later word is a program
/// position for every guard (<see cref="Validation.ProgramPositions"/>, <see cref="Validation.GetBlockedInvocation"/>,
/// <see cref="Validation.BashLauncherRefusal"/>).
/// </summary>
public class TasksetWalkTests
{
    [Theory]
    [InlineData(new[] { "taskset", "-c", "0-3", "tool", "a" }, new[] { 0, 3 })]
    [InlineData(new[] { "taskset", "-ca", "0-3", "tool", "a" }, new[] { 0, 3 })]
    [InlineData(new[] { "taskset", "--cpu-list", "0-3", "tool", "a" }, new[] { 0, 3 })]
    [InlineData(new[] { "taskset", "0x3", "tool", "a" }, new[] { 0, 2 })]
    [InlineData(new[] { "taskset", "--", "0x3", "tool", "a" }, new[] { 0, 3 })]
    // Unclean option words: every later word is a position, the option word itself included.
    [InlineData(new[] { "taskset", "-c0-3", "tool", "a" }, new[] { 0, 1, 2, 3 })]
    [InlineData(new[] { "taskset", "--cpu-list=0-3", "tool", "a" }, new[] { 0, 1, 2, 3 })]
    [InlineData(new[] { "taskset", "-x", "0x3", "tool" }, new[] { 0, 1, 2, 3 })]
    public void ProgramPositions_FollowTasksetsGrammar(string[] argv, int[] expected) =>
        Assert.Equal(expected, Validation.ProgramPositions(argv));

    [Theory]
    [InlineData("-ca", "0-3")] // clean: the mask, then install
    [InlineData("-c0-3")] // unclean: every later word
    [InlineData("--cpu-list=0-3")]
    public void GetFileTokenRefusal_InstallBehindTaskset_IsRefused(params string[] taskset)
    {
        var refusal = Validation.GetFileTokenRefusal(["taskset", .. taskset, "install", "{{@f}}", "/tmp/x"]);

        Assert.NotNull(refusal);
        Assert.Equal("install", refusal.Program);
        Assert.StartsWith("'install' copies files", refusal.Reason);
    }

    [Theory]
    [InlineData("-ca", "0-3", "python3", "-cprint('{{x}}')")]
    [InlineData("-c0-3", "python", "-c", "print('{{x}}')")]
    [InlineData("-ca0", "python3", "-c", "print('{{x}}')")]
    [InlineData("-x", "python3", "-c", "print('{{x}}')")]
    // taskset's options end at its first other word: a '-c...' word after the mask is the command's.
    [InlineData("0x3", "python3", "-cprint('{{x}}')")]
    public void GetBlockedInvocation_InlineCodeBehindTaskset_IsRefused(params string[] rest)
    {
        var blocked = Validation.GetBlockedInvocation(["taskset", .. rest]);

        Assert.NotNull(blocked);
        Assert.StartsWith("'taskset' runs 'python", blocked.Reason);
    }

    [Theory]
    [InlineData("-c", "0-3", "./tool", "{{x}}")]
    [InlineData("-ac", "0-3", "./tool", "{{x}}")]
    [InlineData("-pc", "0,3", "700")]
    [InlineData("-c0-3", "./tool", "{{x}}")] // unclean, but no checked program after it
    public void GetBlockedInvocation_OrdinaryCommandBehindTaskset_IsAllowed(params string[] rest) =>
        Assert.Null(Validation.GetBlockedInvocation(["taskset", .. rest]));

    [Theory]
    [InlineData(false, "-ca", "0-3")]
    [InlineData(true, "-ca", "0-3")]
    [InlineData(false, "0x3")] // the '-cX' below is the script's
    public void BashLauncherRefusal_BashExeBehindTaskset_IsRefused(bool windows, params string[] taskset)
    {
        var refusal = Validation.BashLauncherRefusal(["taskset", .. taskset, "bash.exe", "./x.sh", "-cX", "{{x}}"], windows,
            windows ? MsysTargetTests.FakeProbe([@"C:\Windows\System32\bash.exe"]) : null);

        Assert.NotNull(refusal);
        Assert.Equal(windows ? "bash" : "bash.exe", refusal.Program);
    }

    [Fact]
    public void BashLauncherRefusal_UncleanTasksetWithNoBash_IsAllowed() =>
        Assert.Null(Validation.BashLauncherRefusal(["taskset", "-c0-3", "./tool", "{{x}}"], windows: false, probe: null));
}
