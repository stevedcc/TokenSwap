using System.Diagnostics;
using TswapCore.Agent;
using Xunit;

namespace TswapTests;

/// <summary>
/// #297: the CLI holds a FIDO2 PIN, the vault key and secret values in memory, so it must not leave a core dump. Ctrl+\
/// at the PIN prompt dumped one, and systemd-coredump kept it. <see cref="ProcessHardening.HardenCli"/> runs first thing
/// in the binary (Program.cs, never in <see cref="TswapCli.CliHost"/>, which tests run in-process).
/// </summary>
public class CliCoreDumpTests
{
    [Theory]
    [InlineData(ProcessHardening.Platform.Linux, true)]
    [InlineData(ProcessHardening.Platform.MacOs, true)]
    [InlineData(ProcessHardening.Platform.Windows, false)]
    public void HardenCli_ZeroesTheSoftCoreLimitOnUnix(ProcessHardening.Platform platform, bool zeroed)
    {
        var calls = 0;

        ProcessHardening.HardenCli(() => { calls++; return true; }, platform);

        Assert.Equal(zeroed ? 1 : 0, calls);
    }

    [Fact]
    public void HardenCli_AFailedStep_DoesNotStopTheCommand()
    {
        // Best effort: a command that can't switch dumps off still runs (the agent, which holds the password for
        // hours, is the one that refuses).
        var ex = Record.Exception(() => ProcessHardening.HardenCli(() => false, ProcessHardening.Platform.Linux));

        Assert.Null(ex);
    }
}

/// <summary>
/// #297 against the real binary: a running tswap has a soft core limit of 0 (Linux), and stays dumpable, so the agent
/// and the broker can still check it through <c>/proc</c> (their peer checks read a client's user-namespace link).
/// </summary>
[Trait("Category", "E2E")]
public sealed class CliCoreDumpEndToEndTests(TswapBinaryFixture binary) : IClassFixture<TswapBinaryFixture>, IDisposable
{
    private readonly string _configDir = Path.Combine(Path.GetTempPath(), "tswap-core-" + Guid.NewGuid().ToString("N")[..8]);

    public void Dispose()
    {
        if (Directory.Exists(_configDir))
            Directory.Delete(_configDir, true);
    }

    [Fact]
    public void RunningTswap_HasASoftCoreLimitOfZero_AndStaysReadableForPeerChecks()
    {
        if (!OperatingSystem.IsLinux())
            return; // /proc; macOS's part (the core limit) is the same setrlimit call, covered by the unit test
        Directory.CreateDirectory(_configDir);
        Assert.Equal(0, Run("init", "--yubikey", "--no-recovery").Exit);
        Assert.Equal(0, Run("create", "probe", "16").Exit); // run needs a token; the script ignores its $1

        // The child of `run` reports on its parent, the running tswap: its limits show the soft core limit, and its
        // /proc/<pid> links stay readable to the same user (ptrace read access), as the agent's peer check needs.
        var script = Path.Combine(_configDir, "probe.sh");
        File.WriteAllText(script, "#!/bin/sh\nif cat /proc/$PPID/environ >/dev/null 2>&1; then echo parent=open; else echo parent=closed; fi\n" +
            "grep 'Max core file size' /proc/$PPID/limits\n");
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var (exit, output) = Run("run", script, "{{probe}}");

        Assert.True(exit == 0, output);
        Assert.Contains("parent=open", output);
        Assert.Matches(@"Max core file size\s+0\s", output);
    }

    private (int Exit, string Output) Run(params string[] args)
    {
        var psi = new ProcessStartInfo(binary.BinaryPath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["TSWAP_TEST_KEY"] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        psi.Environment["TSWAP_CONFIG_DIR"] = _configDir;
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdout.Result + stderr);
    }
}
