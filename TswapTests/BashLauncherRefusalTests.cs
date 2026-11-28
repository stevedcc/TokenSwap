using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T64 Task 2 (#411): <see cref="Validation.BashLauncherRefusal"/> refuses a bash at a program position that may
/// be WSL's <c>bash.exe</c> launcher, which runs its whole command line through <c>/bin/bash -c</c>. In process on every
/// OS: the OS is the <c>windows</c> argument, the machine a fake <see cref="MsysTarget.Probe"/>
/// (<see cref="MsysTargetTests.FakeProbe"/>, Git's and MSYS2's files).
/// </summary>
public class BashLauncherRefusalTests
{
    internal const string WindowsReason =
        @"'bash' here is not a bash.exe that 'run' recognises as Git Bash or MSYS2 (msys-2.0.dll beside it, or Git's bin\bash.exe launcher). It may be WSL's launcher (System32's bash.exe, or the WSL app's bash.exe alias), which runs its whole command line through the Linux shell (/bin/bash -c), so a substituted value is parsed again and can transform and print secrets past redaction. A bash at a program position (run's own program, or the command of a wrapper or runner such as sudo or uv run) is refused unless it is Git Bash or MSYS2's bash; behind a wrapper or runner it must be given by its full path. For WSL give the command after -e: 'wsl -e ./deploy.sh {{secret}}'; for Git Bash name it by its path: 'run ""C:\Program Files\Git\bin\bash.exe"" ./deploy.sh {{secret}}'.";

    internal const string OffWindowsReason =
        @"'bash.exe' is a Windows program: under WSL it is System32's bash.exe, WSL's launcher, reached through Windows interop, which runs its whole command line through the Linux shell (/bin/bash -c), so a substituted value is parsed again and can transform and print secrets past redaction. Run the Linux shell instead: 'run bash ./deploy.sh {{secret}}'.";

    internal const string PaddedWslReason =
        @"'wsl' written with quote characters, surrounding white space or a trailing dot can't be checked: run reads it as another program, but Windows starts wsl.exe, which runs its command line through the Linux shell. Write it plainly: 'wsl -e ./deploy.sh {{secret}}'.";

    private const string WslRuns = "'wsl' runs 'bash.exe': ";

    // Code review round 1 (I1): a padded word naming a wrapper or runner.
    internal static string PaddedWrapperReason(string wrapper) =>
        $"'{wrapper}' written with quote characters, surrounding white space, a trailing dot or a stream suffix can't be checked: " +
        $"run reads it as another program, but Windows starts {wrapper}, and the command it runs (a bash that may be WSL's launcher, " +
        "which parses its command line again) is then not checked. Write the name plainly.";

    private static MsysTarget.Probe? ProbeFor(string probe) => probe switch
    {
        "WSL" => MsysTargetTests.FakeProbe([@"C:\Windows\System32\bash.exe"]),
        "Git" => MsysTargetTests.FakeProbe([]),
        "Win32" => Win32Probe(),
        "Sysnative" => MsysTargetTests.FakeProbe([@"C:\Windows\System32\bash.exe", @"C:\Windows\Sysnative\bash.exe"]),
        "Alias" => MsysTargetTests.FakeProbe([@"C:\Users\u\AppData\Local\Microsoft\WindowsApps\bash.exe"]),
        "Work" => MsysTargetTests.FakeProbe([@"C:\work\bash.exe"]),
        "Tools" => MsysTargetTests.FakeProbe([@"C:\tools\bash.exe"]),
        "SubMsys" => MsysTargetTests.FakeProbe([@"C:\work\sub\bash.exe", @"C:\work\sub\msys-2.0.dll"]),
        "Empty" => new MsysTarget.Probe(@"C:\tools", @"C:\work", @"C:\Windows\System32", @"C:\Windows", _ => null, _ => false),
        "null" => null,
        _ => throw new ArgumentOutOfRangeException(nameof(probe), probe, null),
    };

    // The Git probe with FileExists normalising as Win32 does: trailing dots and spaces of the path dropped (round 4 I-3).
    private static MsysTarget.Probe Win32Probe()
    {
        var git = MsysTargetTests.FakeProbe([]);
        return git with { FileExists = path => git.FileExists(path.TrimEnd('.', ' ')) };
    }

    private static string[] Script(string program) => [program, "./x.sh", "{{x}}"];

    /// <summary>
    /// argv, windows, probe, the refusal's Program (null: allowed), and how many wsl exec walks its reason went through
    /// (each prefixes 'wsl' runs 'bash.exe': ).
    /// </summary>
    public static TheoryData<string[], bool, string, string?, int> Rows()
    {
        TheoryData<string[], bool, string, string?, int> rows = new();
        void Add(string[] argv, bool windows, string probe, string? program, int walks = 0) =>
            rows.Add(argv, windows, probe, program, walks);

        // System32 comes before PATH.
        foreach (var name in new[] { "bash", "BASH.EXE", "Bash", "bash.exe" })
            Add(Script(name), true, "WSL", "bash");
        Add(["bash"], true, "WSL", "bash");
        Add([], true, "WSL", null);
        Add(Script(@"C:\Windows\System32\bash.exe"), true, "WSL", "bash");
        Add(Script("c:/windows/system32/BASH"), true, "WSL", "bash");
        Add(Script(@"C:\Windows\Sysnative\bash.exe"), true, "Sysnative", "bash");
        Add(Script(@"C:\Windows\Sysnative\bash.exe"), true, "Git", "bash");
        Add(Script(@"C:\Windows\SysWOW64\bash.exe"), true, "Git", "bash");
        Add(Script(@"C:\Users\u\AppData\Local\Microsoft\WindowsApps\bash.exe"), true, "Alias", "bash");
        Add(Script("bash"), true, "Git", null);
        Add(Script(@"C:\Program Files\Git\bin\bash.exe"), true, "WSL", null);
        Add(Script("C:/msys64/usr/bin/bash"), true, "WSL", null);
        Add(Script("bash"), true, "Work", "bash");
        Add(Script("bash"), true, "Tools", "bash");
        Add(Script("bash"), true, "Empty", "bash");
        // Padded: refused outright.
        foreach (var name in new[] { "bash.exe.", "bash.exe ", " bash", @"bash\.", @"bash\", "bash/" })
            Add(Script(name), true, "Git", "bash");
        Add(Script(@"C:\msys64\usr\bin\bash.exe"), true, "Win32", null);
        Add(Script(@"C:\msys64\usr\bin\bash.exe."), true, "Win32", "bash");
        Add(Script(@"C:\msys64\usr\bin\bash.exe "), true, "Win32", "bash");
        // Quotes in the word.
        Add(Script("\"C:\\Windows\\System32\\bash.exe\""), true, "WSL", "bash");
        Add(Script("\"ba\"sh"), true, "WSL", "bash");
        Add(Script("\"C:\\Program Files\\Git\\bin\\bash.exe\""), true, "WSL", "bash");
        // The stream cut (round 6 I-1).
        foreach (var name in new[] { "bash::$DATA", "bash:x", "bash.exe:x", "bash.exe::$DATA", "bash.exe:stream", @"C:\Windows\System32\bash.exe::$DATA" })
            Add(Script(name), true, "Git", "bash");
        Add(["wsl::$DATA", "./deploy.sh", "{{x}}"], true, "WSL", "wsl");
        Add(["wsl.exe:x", "-e", "./deploy.sh", "{{x}}"], true, "WSL", "wsl");
        Add(Script("bash.exe:x"), false, "null", "bash.exe");
        Add(["wsl::$DATA", "./deploy.sh", "{{x}}"], false, "null", "wsl");
        Add(Script(@"C:\Program Files\Git\bin\bash.exe"), true, "Git", null);
        // Dotted folders, \\?\ and 8.3 folder names: not found by the exact fake probe.
        foreach (var name in new[] { @"C:\Windows\System32\.\bash.exe", @"\\?\C:\Windows\System32\bash.exe", @"C:\WINDOW~1\System32\bash.exe" })
            Add(Script(name), true, "WSL", "bash");
        // Extra text in one word doesn't start bash.
        Add(["bash ./x.sh", "{{x}}"], true, "WSL", null);
        Add(["bash;x", "{{x}}"], true, "WSL", null);
        // Behind a wrapper.
        Add(["sudo", "bash", "./x.sh", "{{x}}"], true, "Git", "bash");
        Add(["timeout", "5", "bash", "./x.sh", "{{x}}"], true, "Git", "bash");
        Add(["npx", "bash", "./x.sh", "{{x}}"], true, "Git", "bash");
        Add(["sudo", @"C:\Program Files\Git\bin\bash.exe", "./x.sh", "{{x}}"], true, "Git", null);
        Add(["sudo", @".\bash", "./x.sh", "{{x}}"], true, "Git", "bash");
        Add(["sudo", @"sub\bash.exe", "./x.sh", "{{x}}"], true, "SubMsys", "bash");
        Add(["sudo", @"\Program Files\Git\bin\bash.exe", "./x.sh", "{{x}}"], true, "Git", "bash");
        Add(["timeout", "5", @"C:\Windows\System32\bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["bwrap", "--tmpfs", "/x", "bash", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["runuser", "-u", "x", "bash", "./x.sh", "{{x}}"], true, "Git", "bash");
        // Code review round 1 C1: taskset's attached CPU list is the mask, so the next word is the command.
        Add(["taskset", "-c0-3", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["taskset", "--cpu-list=0-3", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["taskset", "-c0-3", "bash.exe", "./x.sh", "{{x}}"], false, "null", "bash.exe");
        Add(["taskset", "--cpu-list=0-3", "bash.exe", "./x.sh", "{{x}}"], false, "null", "bash.exe");
        Add(["taskset", "-c", "0-3", "bash.exe", "./x.sh", "{{x}}"], false, "null", "bash.exe");
        Add(["runuser", "-w", "PATH", "-u", "x", "bash", "./x.sh", "{{x}}"], true, "Git", "bash");
        Add(["command", "bash", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["command", "-v", "bash"], true, "WSL", null);
        Add(["command", "-V", "bash"], true, "WSL", null);
        Add(["npx", "wsl", "-e", "bash", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["npx", "wsl", "-e", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash.exe", walks: 1);
        Add(["find", ".", "-exec", "bwrap", "--tmpfs", "/x", "bash", "./x.sh", "{{x}}", ";"], true, "WSL", "bash");
        // Runners.
        Add(["uv", "run", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["poetry", "run", "bash", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["conda", "run", "-n", "x", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["npm", "exec", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["uv", "run", "\"ba\"sh", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["uv", "run", @"C:\Program Files\Git\bin\bash.exe", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["uv", "pip", "install", "bash"], true, "WSL", null);
        Add(["uv", "pip", "install", "requests"], true, "WSL", null);
        // An option before the subcommand: every later word scanned (round 5 I1).
        Add(["uv", "--directory", "/x", "run", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["pnpm", "--dir", "/x", "exec", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["poetry", "-C", "/x", "run", "bash", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["npm", "--prefix", "/x", "exec", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash");
        Add(["uv", "--x", "y", "pip", "install", "bash"], true, "WSL", "bash"); // declared over-refusal
        // Padded wrapper and runner words (code review round 1 I1): refused outright, at any program position.
        Add(["\"uv\"", "run", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "uv");
        Add(["\"sudo\"", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "sudo");
        Add(["\"npx\"", "bash", "./x.sh", "{{x}}"], true, "WSL", "npx");
        Add(["sudo.", "bash", "./x.sh", "{{x}}"], true, "Git", "sudo");
        Add([" timeout", "5", "tool", "{{x}}"], true, "Git", "timeout");
        Add(["docker:x", "run", "img", "tool", "{{x}}"], true, "Git", "docker");
        Add(["sudo", "\"uv\"", "run", "tool", "{{x}}"], true, "Git", "uv");
        Add(["\"sudo\"", "bash.exe", "./x.sh", "{{x}}"], false, "null", "sudo");
        Add(["uv", "run", "./x", "{{x}}"], true, "WSL", null);
        Add(["sudo", "tool", "{{x}}"], true, "WSL", null);
        // Padded wsl (round 5 I2).
        Add(["\"wsl.exe\"", "./deploy.sh", "{{x}}"], true, "WSL", "wsl");
        Add(["\"w\"sl", "-e", "./deploy.sh", "{{x}}"], true, "WSL", "wsl");
        Add([" wsl", "./deploy.sh", "{{x}}"], true, "WSL", "wsl");
        Add(["wsl.exe.", "./deploy.sh", "{{x}}"], true, "WSL", "wsl");
        // Shell-mode wsl: GetBlockedInvocation's business (npx), or a declared residual (uv --directory).
        Add(["npx", "wsl", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["uv", "--directory", "/x", "run", "wsl", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", null);
        // Container tools: Linux bash in the container; bash.exe by the off-Windows rule.
        Add(["docker", "run", "img", "bash", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["kubectl", "exec", "pod", "--", "bash", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["docker", "run", "img", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash.exe");
        // Code review round 1 M3: behind npx (rule 2) every later word is scanned by the Windows rule, a container
        // tool's words included, so this is refused with the Windows reason (a declared over-refusal).
        Add(["npx", "docker", "run", "img", "bash", "./x.sh", "{{x}}"], true, "WSL", "bash");
        // Not a wrapper or runner the guards know (residual), runner pass-through (residual), arguments.
        Add(["pipx", "run", "bash", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["dotnet", "tool", "run", "bash", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["npm", "exec", "x&bash ./x.sh", "{{x}}"], true, "WSL", null);
        Add(["npm", "exec", "bash;x", "{{x}}"], true, "WSL", null);
        Add(["git", "commit", "-m", "bash", "{{x}}"], true, "WSL", null);
        Add(["git", "commit", "-m", "fix the bash script", "{{x}}"], true, "WSL", null);
        Add(["tool", "bash", "./x.sh"], true, "WSL", null);
        Add(["tool", "correct horse bash staple"], true, "WSL", null);
        // wsl's exec mode: its command by the off-Windows rule.
        Add(["wsl", "-e", "bash", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["wsl", "-d", "Ubuntu", "--exec", "bash", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["wsl", "-e", "./deploy.sh", "{{x}}"], true, "WSL", null);
        Add(["wsl", "--shell-type", "none", "bash", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["wsl", "-e", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash.exe", walks: 1);
        Add(["wsl", "--exec", "BASH.EXE", "./x.sh", "{{x}}"], true, "WSL", "bash.exe", walks: 1);
        Add(["wsl", "--shell-type", "none", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash.exe", walks: 1);
        Add(["wsl", "-d", "Ubuntu", "-e", "/mnt/c/Windows/System32/bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash.exe", walks: 1);
        Add(["wsl", "-e", "sudo", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash.exe", walks: 1);
        Add(["wsl", "-e", "wsl.exe", "-e", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", "bash.exe", walks: 2);
        Add(["wsl", "-e", "wsl.exe", "-e", "bash", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["wsl", "bash.exe", "./x.sh", "{{x}}"], true, "WSL", null);
        Add(["wsl", "--list"], true, "WSL", null);
        Add(["wsl", "--bogus", "bash.exe"], true, "WSL", null);
        Add(["bashful", "./x.sh"], true, "WSL", null);
        Add([@"C:\tools\bash-5.exe", "./x.sh"], true, "WSL", null);
        Add(["tool", "./bashrc.d", "{{x}}"], true, "WSL", null);
        // No probe on Windows: run can't tell which file starts.
        Add(Script("bash"), true, "null", "bash");
        Add(Script(@"C:\Program Files\Git\bin\bash.exe"), true, "null", "bash");
        // Off Windows: any bash.exe at a program position is WSL's launcher through interop.
        foreach (var name in new[] { "bash.exe", "BASH.EXE", "bash.exe.", "/mnt/c/Windows/System32/bash.exe",
                     "/mnt/c/Program Files/Git/bin/bash.exe", "\"bash.exe\"", " bash.exe", "\"ba\"sh.exe" })
            Add(Script(name), false, "null", "bash.exe");
        Add(["runuser", "-u", "x", "bash.exe", "./x.sh", "{{x}}"], false, "null", "bash.exe");
        Add(["runuser", "-u", "x", "--", "bash.exe", "./x.sh", "{{x}}"], false, "null", "bash.exe");
        Add(["sudo", "bash.exe", "./x.sh", "{{x}}"], false, "null", "bash.exe");
        Add(["uv", "run", "bash.exe", "./x.sh", "{{x}}"], false, "null", "bash.exe");
        Add(["wsl.exe", "-e", "bash.exe", "./x.sh", "{{x}}"], false, "null", "bash.exe", walks: 1);
        Add(["wsl.exe", "-e", "/mnt/c/Windows/System32/bash.exe", "./x.sh", "{{x}}"], false, "null", "bash.exe", walks: 1);
        Add(["wsl.exe", "-e", "wsl.exe", "-e", "bash.exe", "./x.sh", "{{x}}"], false, "null", "bash.exe", walks: 2);
        foreach (var argv in new[] { ["bash"], ["/bin/bash"], ["/usr/bin/bash"], ["sudo", "bash", "./x.sh", "{{x}}"],
                     ["uv", "run", "bash", "./x.sh", "{{x}}"], new[] { "wsl.exe", "-e", "bash", "./x.sh", "{{x}}" } })
            Add(argv, false, "null", null);
        Add(["tool", "bash.exe"], false, "null", null);
        Add(["bash.exe ./x.sh"], false, "null", null);
        return rows;
    }

    [Theory]
    [MemberData(nameof(Rows))]
    public void BashLauncherRefusal_RefusesALauncherAtAProgramPosition(string[] argv, bool windows, string probe, string? program, int walks)
    {
        var refusal = Validation.BashLauncherRefusal(argv, windows, ProbeFor(probe));

        if (program is null)
        {
            Assert.Null(refusal);
            return;
        }
        Assert.NotNull(refusal);
        Assert.Equal(program, refusal.Program);
        var reason = program switch
        {
            "bash" => WindowsReason,
            "bash.exe" => OffWindowsReason,
            "wsl" => PaddedWslReason,
            _ => PaddedWrapperReason(program),
        };
        Assert.Equal(string.Concat(Enumerable.Repeat(WslRuns, walks)) + reason, refusal.Reason);
    }

    [Fact]
    public void TheWindowsRefusal_IsTheExactText()
    {
        var refusal = Validation.BashLauncherRefusal(Script("bash"), windows: true, ProbeFor("WSL"));

        Assert.Equal(new Validation.BlockedInvocation("bash", WindowsReason), refusal);
    }

    [Fact]
    public void TheOffWindowsRefusal_IsTheExactText()
    {
        var refusal = Validation.BashLauncherRefusal(Script("bash.exe"), windows: false, probe: null);

        Assert.Equal(new Validation.BlockedInvocation("bash.exe", OffWindowsReason), refusal);
    }

    [Fact]
    public void ThePaddedWslRefusal_IsTheExactText()
    {
        var refusal = Validation.BashLauncherRefusal(["\"wsl.exe\"", "./deploy.sh", "{{x}}"], windows: true, ProbeFor("WSL"));

        Assert.Equal(new Validation.BlockedInvocation("wsl", PaddedWslReason), refusal);
    }

    [Fact]
    public void TheNestedWslRefusal_NamesBothWalks()
    {
        var refusal = Validation.BashLauncherRefusal(["wsl", "-e", "wsl.exe", "-e", "bash.exe", "./x.sh", "{{x}}"], windows: true, ProbeFor("WSL"));

        Assert.Equal(new Validation.BlockedInvocation("bash.exe", WslRuns + WslRuns + OffWindowsReason), refusal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TheRefusal_NeverHoldsAWordOfTheCommand(bool windows)
    {
        string[] argv = [windows ? "bash" : "bash.exe", "./x.sh", "v$(id)k7Qz"];

        var refusal = Validation.BashLauncherRefusal(argv, windows, windows ? ProbeFor("WSL") : null);

        Assert.NotNull(refusal);
        Assert.DoesNotContain("k7Qz", refusal.Reason);
        Assert.DoesNotContain("k7Qz", refusal.Program);
    }
}
