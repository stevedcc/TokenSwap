using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T55 Task 2 (#402): which file <c>run</c>'s child starts as on Windows (<see cref="MsysTarget.Resolve"/>), and
/// whether that file is an MSYS2 program (<see cref="MsysTarget.IsMsys2"/>), over a fake file set that ignores case.
/// </summary>
public class MsysTargetTests
{
    private static readonly string[] GitAndMsys64Files =
    [
        @"C:\Program Files\Git\bin\bash.exe",
        @"C:\Program Files\Git\bin\sh.exe",
        @"C:\Program Files\Git\usr\bin\bash.exe",
        @"C:\Program Files\Git\usr\bin\msys-2.0.dll",
        @"C:\msys64\usr\bin\bash.exe",
        @"C:\msys64\usr\bin\msys-2.0.dll",
    ];

    internal static MsysTarget.Probe FakeProbe(IEnumerable<string> extraFiles, IReadOnlyDictionary<string, string>? variables = null)
    {
        HashSet<string> files = new(GitAndMsys64Files.Concat(extraFiles), StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string> vars = new(StringComparer.OrdinalIgnoreCase)
        {
            ["PATH"] = @"C:\Program Files\Git\bin;C:\Program Files\Git\usr\bin",
        };
        foreach (var (name, value) in variables ?? new Dictionary<string, string>())
            vars[name] = value;
        return new MsysTarget.Probe(@"C:\tools", @"C:\work", @"C:\Windows\System32", @"C:\Windows",
            name => vars.GetValueOrDefault(name), files.Contains);
    }

    public static TheoryData<string, string[], string?, string?, bool> Rows => new()
    {
        // Program, extra files, NoDefaultCurrentDirectoryInExePath, expected Resolve, expected IsMsys2.
        { "bash", [@"C:\Windows\System32\bash.exe"], null, @"C:\Windows\System32\bash.exe", false },
        { "bash", [], null, @"C:\Program Files\Git\bin\bash.exe", true },
        { "sh.exe", [], null, @"C:\Program Files\Git\bin\sh.exe", true },
        { @"C:\Program Files\Git\usr\bin\bash.exe", [], null, @"C:\Program Files\Git\usr\bin\bash.exe", true },
        // Spike round 2 (t55probe2): Windows appends .exe to a name holding a path too.
        { "C:/msys64/usr/bin/bash", [], null, @"C:\msys64\usr\bin\bash.exe", true },
        { "C:/msys64/usr/bin/bash.exe", [], null, @"C:\msys64\usr\bin\bash.exe", true },
        { "bash", [@"C:\work\bash.exe"], null, @"C:\work\bash.exe", false },
        { "bash", [@"C:\work\bash.exe"], "1", @"C:\Program Files\Git\bin\bash.exe", true },
        { "bash", [@"C:\tools\bash.exe"], null, @"C:\tools\bash.exe", false },
        { @".\x\bash.exe", [@"C:\work\.\x\bash.exe"], null, @"C:\work\.\x\bash.exe", false },
        { @"C:\Program Files\Git\mingw64\bin\git.exe", [@"C:\Program Files\Git\mingw64\bin\git.exe"], null,
            @"C:\Program Files\Git\mingw64\bin\git.exe", false },
        { @"C:\Windows\System32\bin\bash.exe", [@"C:\Windows\System32\bin\bash.exe"], null, @"C:\Windows\System32\bin\bash.exe", false },
        { "nosuch", [], null, null, false },
    };

    [Theory]
    [MemberData(nameof(Rows))]
    public void Resolve_And_IsMsys2_FollowCreateProcessAndTheTwoShapes(string program, string[] extraFiles, string? noDefaultCurrentDirectory,
        string? expectedPath, bool expectedMsys2)
    {
        var probe = FakeProbe(extraFiles,
            noDefaultCurrentDirectory is null ? null : new Dictionary<string, string> { ["NoDefaultCurrentDirectoryInExePath"] = noDefaultCurrentDirectory });

        var path = MsysTarget.Resolve(program, probe);

        Assert.Equal(expectedPath, path);
        Assert.Equal(expectedMsys2, path is not null && MsysTarget.IsMsys2(path, probe.FileExists));
    }

    [Fact]
    public void Resolve_SearchesPathEntriesInOrder_SkippingEmptyOnes_AndRemovingQuotes()
    {
        var probe = FakeProbe([@"C:\b\tool.exe", @"C:\c\tool.exe"],
            new Dictionary<string, string> { ["PATH"] = @";C:\a;""C:\b\"";C:\c" });

        Assert.Equal(@"C:\b\tool.exe", MsysTarget.Resolve("tool", probe));
    }

    [Fact]
    public void Resolve_SearchesTheWindowsSystemFolder_BeforeTheWindowsFolder()
    {
        var probe = FakeProbe([@"C:\Windows\System\tool.exe", @"C:\Windows\tool.exe"]);

        Assert.Equal(@"C:\Windows\System\tool.exe", MsysTarget.Resolve("tool", probe));
    }

    [Fact]
    public void Resolve_KeepsAGivenExtension_AndAppendsOnlyExe()
    {
        var probe = FakeProbe([@"C:\tools\tool.com"]);

        Assert.Equal(@"C:\tools\tool.com", MsysTarget.Resolve("tool.com", probe));
        Assert.Null(MsysTarget.Resolve("tool", probe));
    }

    [UnixFact("the real machine's probe exists on Windows only")]
    public void ForThisProcess_IsNullOffWindows() => Assert.Null(MsysTarget.Probe.ForThisProcess());

    [WindowsFact("needs Git for Windows on PATH (every GitHub Windows runner has it)")]
    public void IsMsys2_OnTheRealMachine_GitBashAndItsMsys2Bash_NotSystem32Bash()
    {
        var bash = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Where(dir => dir.Contains(@"\Git\", StringComparison.OrdinalIgnoreCase) || dir.EndsWith(@"\Git", StringComparison.OrdinalIgnoreCase))
            .Select(dir => Path.Combine(dir, "bash.exe"))
            .FirstOrDefault(File.Exists);
        Assert.True(bash is not null, "no Git Bash (a bash.exe under a \\Git\\ folder) on PATH");

        Assert.True(MsysTarget.IsMsys2(bash, File.Exists), $"{bash} not recognised as Git's launcher");
        var usrBash = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(bash)!, "..", "usr", "bin", "bash.exe"));
        Assert.True(MsysTarget.IsMsys2(usrBash, File.Exists), $"{usrBash} not recognised as an MSYS2 program");
        Assert.False(MsysTarget.IsMsys2(Path.Combine(Environment.SystemDirectory, "bash.exe"), File.Exists));
        Assert.NotNull(MsysTarget.Probe.ForThisProcess());
    }
}
