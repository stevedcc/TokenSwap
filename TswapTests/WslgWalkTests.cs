using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T65 (#448): <c>wslg</c> (wslg.exe, WSL's second launcher) is checked as <c>wsl</c> is, by wslg.exe's own
/// parser (microsoft/WSL f753835d5464, <c>WslgMain</c>): no <c>-e</c>, exec mode only after <c>--shell-type none</c>,
/// every other <c>-</c> word an error; at every program position and in every padded spelling. And, for <c>wsl</c> and
/// <c>wslg</c> alike, a valued option's value that is empty or holds white space or a <c>"</c> is refused: wsl.exe
/// reads such a value only up to the first space or tab and takes what follows as its command line, so <c>run</c>
/// can't tell which words wsl runs. In process on every OS: the OS is the <c>windows</c> argument.
/// </summary>
public class WslgWalkTests
{
    private static readonly string Unix = Validation.WayOutFor(false);

    internal static readonly string WslgShell =
        "'wslg' without --shell-type none runs its command line through the Linux shell (the user's login shell by default), " +
        "which parses a substituted value again and can transform and print secrets past redaction. Give the command after " +
        "--shell-type none: 'wslg --shell-type none ./deploy.sh {{secret}}'. " + Unix;

    internal static readonly string WslgUnknown =
        "'wslg': an option or a value this check doesn't know (wslg.exe takes only -d, --distribution, -u, --user, --cd, " +
        "--shell-type (login, standard or none) and --, matched exactly, and has no -e), so it can't tell what wslg runs. " +
        "Give the command after --shell-type none: 'wslg --shell-type none ./deploy.sh {{secret}}'. " + Unix;

    internal const string PaddedWslg =
        @"'wslg' written with quote characters, surrounding white space, or a trailing dot, '\' or '/' can't be checked: " +
        @"run reads it as another program, but Windows starts wslg.exe, which runs its command line through the Linux " +
        @"shell. Write it plainly: 'wslg --shell-type none ./deploy.sh {{secret}}'.";

    internal static string QuotedValue(string name) =>
        $"'{name}': an option's value is empty or holds white space or a double quote, which run's command line quotes, " +
        $"but {name}.exe reads an option's value up to the first space or tab and keeps the quotes, so it can't be told " +
        $"where {name}'s command begins (the rest would run through the Linux shell). Give the value without them (cd in " +
        "a script instead of --cd). " + Unix;

    private static string NoCommand(string p) =>
        $"'{p}' with no command starts a shell reading stdin, which can transform and print secrets past redaction. {Unix}";

    // As InlineCodeBlockTests.WslShellReason writes it (that constant is private).
    private static readonly string WslShell =
        "'wsl' without -e (or --shell-type none) runs its command line through the Linux shell ($SHELL -c), which " +
        "parses a substituted value again and can transform and print secrets past redaction. Give the command after " +
        "-e: 'wsl -e ./deploy.sh {{secret}}'. " + Unix;

    private static string Runs(string p, string[] inner)
    {
        var i = Validation.GetBlockedInvocation(inner);
        Assert.NotNull(i);
        return $"'{p}' runs '{i.Program}': {i.Reason}";
    }

    private static readonly string Off = BashLauncherRefusalTests.OffWindowsReason;

    public static TheoryData<string[], string, string> Refused() => new()
    {
        { ["wslg", "./deploy.sh", "{{x}}"], "wslg", WslgShell },
        { ["wslg.exe", "./deploy.sh", "{{x}}"], "wslg", WslgShell },
        { [@"C:\Program Files\WSL\wslg.exe", "./deploy.sh", "{{x}}"], "wslg", WslgShell },
        { ["WSLG.EXE", "./deploy.sh", "{{x}}"], "WSLG", WslgShell },
        { ["wslg.exe.", "./deploy.sh", "{{x}}"], "wslg", WslgShell },
        { ["wslg", "-d", "Ubuntu", "-u", "app", "--cd", "/srv", "./deploy.sh", "{{x}}"], "wslg", WslgShell },
        { ["wslg", "--shell-type", "login", "./x.sh", "{{x}}"], "wslg", WslgShell },
        { ["wslg", "--shell-type", "standard", "./x.sh", "{{x}}"], "wslg", WslgShell },
        { ["wslg", "--shell-type", "none", "--shell-type", "login", "./x.sh", "{{x}}"], "wslg", WslgShell },
        { ["wslg", "--", "./x.sh", "{{x}}"], "wslg", WslgShell },
        { ["wslg", "~", "--shell-type", "none", "./x.sh", "{{x}}"], "wslg", WslgShell },
        { ["wslg", "{00000000-0000-0000-0000-000000000000}", "--shell-type", "none", "./x.sh", "{{x}}"], "wslg", WslgShell },
        { ["wslg", "-e", "./deploy.sh", "{{x}}"], "wslg", WslgUnknown },
        { ["wslg", "--exec", "./deploy.sh", "{{x}}"], "wslg", WslgUnknown },
        { ["wslg", "--system", "--shell-type", "none", "./x.sh", "{{x}}"], "wslg", WslgUnknown },
        { ["wslg", "--distribution-id", "1", "--shell-type", "none", "./x.sh", "{{x}}"], "wslg", WslgUnknown },
        { ["wslg", "--parent-console", "1", "--shell-type", "none", "./x.sh", "{{x}}"], "wslg", WslgUnknown },
        { ["wslg", "--list"], "wslg", WslgUnknown },
        { ["wslg", "--debug-shell"], "wslg", WslgUnknown },
        { ["wslg", "--install"], "wslg", WslgUnknown },
        { ["wslg", "--shell-type", "bogus", "./x.sh", "{{x}}"], "wslg", WslgUnknown },
        { ["wslg", "--shell-type", "None", "./x.sh", "{{x}}"], "wslg", WslgUnknown },
        { ["wslg", "--Shell-Type", "none", "./x.sh", "{{x}}"], "wslg", WslgUnknown },
        { ["wslg", "--shell-type=none", "./x.sh", "{{x}}"], "wslg", WslgUnknown },
        { ["wslg", "-D", "Ubuntu", "--shell-type", "none", "./x.sh", "{{x}}"], "wslg", WslgUnknown },
        { ["wslg", "-"], "wslg", WslgUnknown },
        { ["wslg"], "wslg", NoCommand("wslg") },
        { ["wslg", "-d", "Ubuntu"], "wslg", NoCommand("wslg") },
        { ["wslg", "--"], "wslg", NoCommand("wslg") },
        { ["wslg", "-d"], "wslg", NoCommand("wslg") },
        { ["wslg", "-d", "My Distro", "--shell-type", "none", "./deploy.sh", "{{x}}"], "wslg", QuotedValue("wslg") },
        { ["wslg", "--cd", @"C:\My Dir", "--shell-type", "none", "./deploy.sh", "{{x}}"], "wslg", QuotedValue("wslg") },
        { ["wslg", "--shell-type", "none", "python3", "/dev/stdin"], "python3", Runs("wslg", ["python3", "/dev/stdin"]) },
        { ["wslg", "--shell-type", "none", "bash", "-c", "echo {{x}}"], "bash", Runs("wslg", ["bash", "-c", "echo {{x}}"]) },
        { ["wslg", "-d", "Ubuntu", "--shell-type", "none", "--", "sh", "-c", "x"], "sh", Runs("wslg", ["sh", "-c", "x"]) },
        { ["wslg", "--shell-type", "none", "wsl", "./x.sh", "{{x}}"], "wsl", "'wslg' runs 'wsl': " + WslShell },
        { ["wsl", "-e", "wslg", "./x.sh", "{{x}}"], "wslg", "'wsl' runs 'wslg': " + WslgShell },
        { ["timeout", "5", "wslg", "./x.sh", "{{x}}"], "wslg", "'timeout' runs 'wslg': " + WslgShell },
        { ["sudo", "-u", "app", "wslg", "./x.sh", "{{x}}"], "wslg", "'sudo' runs 'wslg': " + WslgShell },
        { ["taskset", "-c", "0", "wslg", "./x.sh", "{{x}}"], "wslg", "'taskset' runs 'wslg': " + WslgShell },
        { ["runuser", "-u", "app", "wslg", "./x.sh", "{{x}}"], "wslg", "'runuser' runs 'wslg': " + WslgShell },
        { ["nice", "-n", "5", "wslg.exe", "./x.sh", "{{x}}"], "wslg", "'nice' runs 'wslg': " + WslgShell },
        { ["find", ".", "-exec", "wslg", "./x.sh", "{}", ";"], "wslg", "'find -exec' runs 'wslg': " + WslgShell },
        { ["npx", "wslg", "./x.sh", "{{x}}"], "wslg", "'npx' runs 'wslg': " + WslgShell },
        { ["uv", "run", "wslg", "./x.sh", "{{x}}"], "wslg", "'uv' runs 'wslg': " + WslgShell },
        { ["wsl", "-d", "My Distro", "-e", "./deploy.sh", "{{x}}"], "wsl", QuotedValue("wsl") },
        { ["wsl", "-u", "a b", "-e", "./deploy.sh", "{{x}}"], "wsl", QuotedValue("wsl") },
        { ["wsl", "--cd", @"C:\My Dir", "-e", "./deploy.sh", "{{x}}"], "wsl", QuotedValue("wsl") },
        { ["wsl", "-d", "a\tb", "-e", "./x.sh", "{{x}}"], "wsl", QuotedValue("wsl") },
        { ["wsl", "-d", "a\"b", "-e", "./x.sh", "{{x}}"], "wsl", QuotedValue("wsl") },
        { ["wsl", "-d", "", "-e", "./x.sh", "{{x}}"], "wsl", QuotedValue("wsl") },
        { ["wsl", "--distribution-id", "x y", "-e", "./x.sh", "{{x}}"], "wsl", QuotedValue("wsl") },
        { ["sudo", "wsl", "-d", "My Distro", "-e", "./x.sh", "{{x}}"], "wsl", "'sudo' runs 'wsl': " + QuotedValue("wsl") },
    };

    [Theory, MemberData(nameof(Refused))]
    public void GetBlockedInvocation_IsRefused(string[] argv, string program, string reason) =>
        Assert.Equal(new Validation.BlockedInvocation(program, reason), Validation.GetBlockedInvocation(argv));

    public static TheoryData<string[]> Allowed() => new()
    {
        { ["wslg", "--shell-type", "none", "./deploy.sh", "{{x}}"] },
        { ["wslg.exe", "-d", "Ubuntu", "-u", "app", "--cd", "/srv", "--shell-type", "none", "./deploy.sh", "{{x}}"] },
        { ["wslg", "--distribution", "Ubuntu", "--user", "app", "--shell-type", "none", "--", "./deploy.sh", "{{x}}"] },
        { ["wslg", "--shell-type", "login", "--shell-type", "none", "./deploy.sh", "{{x}}"] },
        { ["wslg", "--shell-type", "none"] },
        { ["wslg", "--shell-type", "none", "bash", "./x.sh", "{{x}}"] },
        { ["wslg", "--shell-type", "none", "./x.sh", "a b", "{{x}}"] },
        { ["timeout", "5", "wslg", "--shell-type", "none", "./deploy.sh", "{{x}}"] },
        { ["wsl", "-d", "Ubuntu-22.04", "-e", "./deploy.sh", "{{x}}"] },
        { ["wsl", "--cd", @"C:\work", "-e", "./deploy.sh", "{{x}}"] },
        { ["wsl", "-e", "./x.sh", "a b", "{{x}}"] },
        { ["wslgx", "./deploy.sh", "{{x}}"] },
        { ["wslconfig", "/l"] },
        { ["tool", "wslg", "./x.sh", "{{x}}"] },
    };

    [Theory, MemberData(nameof(Allowed))]
    public void GetBlockedInvocation_IsAllowed(string[] argv) => Assert.Null(Validation.GetBlockedInvocation(argv));

    public static TheoryData<string[], bool, string?, string?> Launcher() => new()
    {
        { ["\"wslg.exe\"", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["\"w\"slg", "--shell-type", "none", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { [" wslg", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["wslg.exe.", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["wslg/", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["wslg::$DATA", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["wslg.exe:x", "--shell-type", "none", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["\"C:\\Program Files\\WSL\\wslg.exe\"", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["wslg::$DATA", "./deploy.sh", "{{x}}"], false, "wslg", PaddedWslg },
        { ["sudo", "\"wslg\"", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["timeout", "5", "wslg.", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["find", ".", "-exec", "\"wslg\"", "./x.sh", ";"], true, "wslg", PaddedWslg },
        { ["uv", "run", "\"wslg\"", "./x.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["wsl", "-e", "\"wslg.exe\"", "./x.sh", "{{x}}"], true, "wslg", "'wsl' runs 'wslg': " + PaddedWslg },
        { ["wslg ", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["wslg.exe ", "--shell-type", "none", "./deploy.sh", "{{x}}"], true, "wslg", PaddedWslg },
        { ["wslg", "--shell-type", "none", "bash.exe", "./x.sh", "{{x}}"], true, "bash.exe", "'wslg' runs 'bash.exe': " + Off },
        { ["wslg", "-d", "Ubuntu", "-u", "app", "--cd", "/srv", "--shell-type", "none", "/mnt/c/Windows/System32/bash.exe", "./x.sh", "{{x}}"],
            true, "bash.exe", "'wslg' runs 'bash.exe': " + Off },
        { ["wslg", "--shell-type", "none", "--", "BASH.EXE", "./x.sh", "{{x}}"], true, "bash.exe", "'wslg' runs 'bash.exe': " + Off },
        { ["sudo", "wslg", "--shell-type", "none", "bash.exe", "./x.sh", "{{x}}"], true, "bash.exe", "'wslg' runs 'bash.exe': " + Off },
        { ["wslg.exe", "--shell-type", "none", "bash.exe", "./x.sh", "{{x}}"], false, "bash.exe", "'wslg' runs 'bash.exe': " + Off },
        { ["wsl", "-e", "wslg.exe", "--shell-type", "none", "bash.exe", "./x.sh", "{{x}}"], true, "bash.exe",
            "'wsl' runs 'bash.exe': 'wslg' runs 'bash.exe': " + Off },
        { ["wslg", "--shell-type", "none", "wsl.exe", "-e", "bash.exe", "./x.sh", "{{x}}"], true, "bash.exe",
            "'wslg' runs 'bash.exe': 'wsl' runs 'bash.exe': " + Off },
        { ["wslg", "--shell-type", "none", "bash", "./x.sh", "{{x}}"], true, null, null },
        { ["wslg", "--shell-type", "none", "./deploy.sh", "{{x}}"], true, null, null },
        { ["wslg", "bash.exe", "./x.sh", "{{x}}"], true, null, null },
        { ["wslg", "-e", "bash.exe", "./x.sh", "{{x}}"], true, null, null },
        { ["wslgx", "./x.sh", "{{x}}"], true, null, null },
        { ["tool", "wslg.exe", "./x.sh"], true, null, null },
    };

    [Theory, MemberData(nameof(Launcher))]
    public void BashLauncherRefusal_KnowsWslg(string[] argv, bool windows, string? program, string? reason)
    {
        var probe = windows ? MsysTargetTests.FakeProbe([@"C:\Windows\System32\bash.exe"]) : null;

        var refusal = Validation.BashLauncherRefusal(argv, windows, probe);

        Assert.Equal(program is null ? null : new Validation.BlockedInvocation(program, reason!), refusal);
    }

    [Fact]
    public void ProgramWords_WalkIntoWslgsCommand() =>
        Assert.Equal(["wslg", "timeout", "x"], Validation.ProgramWords(["wslg", "-u", "app", "--shell-type", "none", "timeout", "5", "x"]));

    [Fact]
    public void GetFileTokenRefusal_InstallBehindWslg_IsRefused()
    {
        var refusal = Validation.GetFileTokenRefusal(["wslg", "-u", "app", "--shell-type", "none", "install", "{{@f}}", "/tmp/x"]);

        Assert.NotNull(refusal);
        Assert.Equal("install", refusal.Program);
        Assert.StartsWith("'install' copies files", refusal.Reason);
    }

    [Fact]
    public void TheNewReasons_HaveTheExactText()
    {
        Assert.Equal(new Validation.BlockedInvocation("wslg",
                "'wslg' without --shell-type none runs its command line through the Linux shell (the user's login shell by default), which parses a substituted value again and can transform and print secrets past redaction. Give the command after --shell-type none: 'wslg --shell-type none ./deploy.sh {{secret}}'. Put the commands in a script file and run that instead, e.g. 'run ./script.sh {{secret}}' (the script reads the value as $1)."),
            Validation.GetBlockedInvocation(["wslg", "./deploy.sh", "{{x}}"]));
        Assert.Equal(new Validation.BlockedInvocation("wslg",
                "'wslg': an option or a value this check doesn't know (wslg.exe takes only -d, --distribution, -u, --user, --cd, --shell-type (login, standard or none) and --, matched exactly, and has no -e), so it can't tell what wslg runs. Give the command after --shell-type none: 'wslg --shell-type none ./deploy.sh {{secret}}'. Put the commands in a script file and run that instead, e.g. 'run ./script.sh {{secret}}' (the script reads the value as $1)."),
            Validation.GetBlockedInvocation(["wslg", "-e", "./deploy.sh", "{{x}}"]));
        Assert.Equal(new Validation.BlockedInvocation("wslg",
                "'wslg': an option's value is empty or holds white space or a double quote, which run's command line quotes, but wslg.exe reads an option's value up to the first space or tab and keeps the quotes, so it can't be told where wslg's command begins (the rest would run through the Linux shell). Give the value without them (cd in a script instead of --cd). Put the commands in a script file and run that instead, e.g. 'run ./script.sh {{secret}}' (the script reads the value as $1)."),
            Validation.GetBlockedInvocation(["wslg", "-d", "My Distro", "--shell-type", "none", "./deploy.sh", "{{x}}"]));
        Assert.Equal(new Validation.BlockedInvocation("wslg",
                @"'wslg' written with quote characters, surrounding white space, or a trailing dot, '\' or '/' can't be checked: run reads it as another program, but Windows starts wslg.exe, which runs its command line through the Linux shell. Write it plainly: 'wslg --shell-type none ./deploy.sh {{secret}}'."),
            Validation.BashLauncherRefusal(["\"wslg.exe\"", "./deploy.sh", "{{x}}"], windows: true, MsysTargetTests.FakeProbe([@"C:\Windows\System32\bash.exe"])));
    }
}
