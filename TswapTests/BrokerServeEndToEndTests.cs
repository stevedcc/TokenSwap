using System.Diagnostics;
using System.Net;
using System.Threading.Channels;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T8: <c>tswap broker serve</c> and <c>broker forward</c> as processes of the built binary
/// (simulated TPM via TSWAP_TEST_KEY, sudo bypass for the config commands): serve makes itself
/// non-dumpable, listens, unlocks per request, keeps its config on a SIGHUP with an invalid file,
/// and removes its socket on SIGTERM; forward relays without a vault.
/// </summary>
[Trait("Category", "E2E")]
public class BrokerServeEndToEndTests : IClassFixture<TswapBinaryFixture>, IDisposable
{
    private const string TestKeyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    private readonly string _binary;
    private readonly string _root = Path.Combine(Path.GetTempPath(), "tswap-bke-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly List<Process> _processes = [];

    public BrokerServeEndToEndTests(TswapBinaryFixture binary)
    {
        _binary = binary.BinaryPath;
        Directory.CreateDirectory(ConfigDir);
        Directory.CreateDirectory(SocketDir);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(SocketDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private string ConfigDir => Path.Combine(_root, "c");
    private string SocketDir => Path.Combine(_root, "s");
    private string SocketPath => Path.Combine(SocketDir, "lane1.sock");

    public void Dispose()
    {
        foreach (var p in _processes)
        {
            if (!p.HasExited)
                p.Kill();
            p.Dispose();
        }
        if (Directory.Exists(_root))
            Directory.Delete(_root, true);
    }

    private string RunDir => Path.Combine(_root, "run");

    private ProcessStartInfo Psi(bool withVault, params string[] args) => Psi(withVault, terminal: false, args);

    private ProcessStartInfo Psi(bool withVault, bool terminal, params string[] args)
    {
        var psi = new ProcessStartInfo(_binary)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        if (withVault)
        {
            psi.Environment["TSWAP_TEST_KEY"] = TestKeyHex;
            psi.Environment["TSWAP_TEST_SUDO_BYPASS"] = "1";
            psi.Environment["TSWAP_CONFIG_DIR"] = ConfigDir;
            // Brief T17: the control socket's run folder in this test's temp folder (Debug, test key only).
            psi.Environment["TSWAP_TEST_BROKER_RUN_DIR"] = RunDir;
            if (terminal)
                psi.Environment["TSWAP_TEST_TERMINAL"] = "1";
            else
                psi.Environment.Remove("TSWAP_TEST_TERMINAL");
        }
        else
        {
            // forward: no vault, no config folder, a home that doesn't exist.
            psi.Environment.Remove("TSWAP_CONFIG_DIR");
            psi.Environment.Remove("TSWAP_TEST_KEY");
            psi.Environment["HOME"] = Path.Combine(_root, "no-such-home");
            psi.Environment.Remove("XDG_CONFIG_HOME");
        }
        return psi;
    }

    private (int Exit, string Out, string Err) Run(string stdin, params string[] args) => Run(stdin, terminal: false, args);

    /// <summary>With <c>TSWAP_TEST_TERMINAL</c>: stdin plays a terminal, so the vault password can be typed.</summary>
    private (int Exit, string Out, string Err) RunOnTerminal(string stdin, params string[] args) => Run(stdin, terminal: true, args);

    private (int Exit, string Out, string Err) Run(string stdin, bool terminal, params string[] args)
    {
        using var p = Process.Start(Psi(true, terminal, args))!;
        p.StandardInput.Write(stdin);
        p.StandardInput.Close();
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        return (p.ExitCode, stdout.Result, stderr.Result);
    }

    private void Ok(string stdin, params string[] args)
    {
        var (exit, stdout, stderr) = Run(stdin, args);
        Assert.True(exit == 0, $"{string.Join(' ', args)}: {stderr}\n{stdout}");
    }

    /// <summary>Starts a long-running process; its stderr lines go into the returned channel.</summary>
    private (Process Process, Channel<string> Lines) Start(bool withVault, params string[] args)
    {
        var lines = Channel.CreateUnbounded<string>();
        var p = new Process { StartInfo = Psi(withVault, args) };
        p.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
                lines.Writer.TryWrite(e.Data);
        };
        p.Start();
        p.BeginErrorReadLine();
        _processes.Add(p);
        return (p, lines);
    }

    /// <summary>Waits for a stderr line containing <paramref name="text"/> (a hang fails after 60 s).</summary>
    private static async Task<string> WaitForLineAsync(Channel<string> lines, string text)
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        while (true)
        {
            var line = await lines.Reader.ReadAsync(guard.Token);
            if (line.Contains(text, StringComparison.Ordinal))
                return line;
        }
    }

    private static void Signal(Process p, string signal)
    {
        using var kill = Process.Start("kill", [signal, p.Id.ToString()])!;
        kill.WaitForExit();
        Assert.Equal(0, kill.ExitCode);
    }

    private static async Task<int> StatusOverSocketAsync(string socketPath, string target)
    {
        using var client = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.Unix, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Unspecified);
        await client.ConnectAsync(new System.Net.Sockets.UnixDomainSocketEndPoint(socketPath));
        await client.SendAsync(System.Text.Encoding.ASCII.GetBytes($"GET {target} HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n"));
        var ms = new MemoryStream();
        var buffer = new byte[4096];
        int n;
        while ((n = await client.ReceiveAsync(buffer)) > 0)
            ms.Write(buffer, 0, n);
        return BrokerHarness.StatusOf(System.Text.Encoding.ASCII.GetString(ms.ToArray()));
    }

    [Fact]
    public async Task Serve_IsNonDumpable_UnlocksPerRequest_KeepsItsConfigOnABadSighup_AndCleansUpOnSigterm()
    {
        if (!OperatingSystem.IsLinux())
            return; // prctl and /proc are Linux; serve on macOS is covered by the in-process tests
        Ok("", "init", "--tpm", "--no-recovery");
        Ok("tok-value\ntok-value\n", "add", "tok");
        // An upstream nothing listens on: the request unlocks, then fails upstream (502).
        Ok("", "broker", "route", "add", "api", "--upstream", "https://127.0.0.1:1/v1", "--auth", "bearer", "--secret", "tok", "--path", "");
        Ok("", "broker", "socket", "add", "lane1", "--uids", BrokerHarness.MyUid.ToString(), "--routes", "api", "--socket-dir", SocketDir, "--uid-only");

        var (serve, serveLines) = Start(true, "broker", "serve");
        await WaitForLineAsync(serveLines, "event started");

        // Decision 1: PR_SET_DUMPABLE 0 makes /proc/<pid> root's.
        Assert.Equal(0u, BrokerNative.LStat($"/proc/{serve.Id}/environ")!.Value.Uid);
        Assert.Equal((UnixFileMode)0b110_110_110, BrokerNative.LStat(SocketPath)!.Value.Mode);

        Assert.Equal(404, await StatusOverSocketAsync(SocketPath, "/nope/x"));
        Assert.Equal(502, await StatusOverSocketAsync(SocketPath, "/api/x"));
        var line = await WaitForLineAsync(serveLines, "route=api");
        Assert.Contains("unlocks=1", line);
        Assert.Contains("reason=upstream-error", line);

        // A hand-edited invalid broker.json and SIGHUP: refused, the old config keeps serving.
        var brokerJson = Path.Combine(ConfigDir, "broker.json");
        var good = File.ReadAllText(brokerJson);
        File.WriteAllText(brokerJson, good.Replace("https://127.0.0.1:1/v1", "http://127.0.0.1:1/v1"));
        Signal(serve, "-HUP");
        await WaitForLineAsync(serveLines, "config reload refused");
        Assert.False(serve.HasExited);
        Assert.Equal(404, await StatusOverSocketAsync(SocketPath, "/nope/x"));

        // forward relays to it with no vault and no home folder; and it is dumpable (no prctl).
        var (forward, forwardLines) = Start(false, "broker", "forward", "--listen", "127.0.0.1:0", "--socket", SocketPath);
        var listening = await WaitForLineAsync(forwardLines, " -> ");
        var port = int.Parse(listening.Split("127.0.0.1:")[1].Split(' ')[0]);
        using (var http = new HttpClient())
        {
            var response = await http.GetAsync($"http://127.0.0.1:{port}/nope/x");
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
        Assert.Equal(BrokerHarness.MyUid, BrokerNative.LStat($"/proc/{forward.Id}/environ")!.Value.Uid);
        Signal(forward, "-TERM");
        await forward.WaitForExitAsync(new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);
        Assert.Equal(0, forward.ExitCode);

        Signal(serve, "-TERM");
        await serve.WaitForExitAsync(new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);
        Assert.Equal(0, serve.ExitCode);
        Assert.Equal(BrokerNative.EntryType.Missing, BrokerNative.LStat(SocketPath)!.Value.Type);
        var log = Path.Combine(ConfigDir, BrokerLog.FileName);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(log));
        var logText = File.ReadAllText(log);
        Assert.Contains("route=api", logText);
        Assert.Contains("event stopped", logText);
        Assert.DoesNotContain("tok-value", logText);
    }

    /// <summary>The owner of <c>/proc/&lt;pid&gt;/environ</c>: the process's uid while it is dumpable, root while it isn't.</summary>
    private static uint ProcOwner(Process p) => BrokerNative.LStat($"/proc/{p.Id}/environ")!.Value.Uid;

    /// <summary>
    /// Brief T17 task 12, the real binary and the real <c>/proc</c> (which the seams can't stand in for): a
    /// broker whose TPM slot has the vault password starts locked and dumpable, refuses requests as busy,
    /// is unlocked by 'broker unlock' (non-dumpable from then on, so a second unlock can't read its link),
    /// serves, and after 'broker lock' is locked and dumpable again.
    /// </summary>
    [Fact]
    public async Task Unlock_ThenLock_ThenLockedAgain()
    {
        if (!OperatingSystem.IsLinux())
            return; // prctl and /proc are Linux; the macOS side is covered in process
        const string password = "correct horse battery staple";
        Ok(password + "\n" + password + "\n", "init", "--tpm", "--password", "--no-recovery");
        var (added, _, addErr) = RunOnTerminal("tok-value\ntok-value\n" + password + "\n", "add", "tok");
        Assert.True(added == 0, addErr);
        Ok("", "broker", "route", "add", "api", "--upstream", "https://127.0.0.1:1/v1", "--auth", "bearer", "--secret", "tok", "--path", "");
        Ok("", "broker", "socket", "add", "lane1", "--uids", BrokerHarness.MyUid.ToString(), "--routes", "api", "--socket-dir", SocketDir, "--uid-only");

        var (serve, serveLines) = Start(true, "broker", "serve");
        await WaitForLineAsync(serveLines, "locked: this broker's slot has the vault password");

        // Locked: dumpable (nothing held), and a request gets the busy refusal, logged as locked.
        Assert.Equal(BrokerHarness.MyUid, ProcOwner(serve));
        Assert.Equal(503, await StatusOverSocketAsync(SocketPath, "/api/x"));
        Assert.Contains("reason=locked", await WaitForLineAsync(serveLines, "route=api"));
        var control = Directory.GetFiles(RunDir, "control.sock", SearchOption.AllDirectories).Single();
        Assert.Equal((UnixFileMode)0b111_000_000, BrokerNative.LStat(Path.GetDirectoryName(control)!)!.Value.Mode & (UnixFileMode)0b111_111_111);
        Assert.Contains("The broker is locked.", Run("", "broker", "status").Out);

        // A wrong password: refused at the TPM, still locked and dumpable.
        var wrong = RunOnTerminal("not the password\n", "broker", "unlock");
        Assert.NotEqual(0, wrong.Exit);
        Assert.Contains(TswapCore.VaultPassword.VaultPasswordMessages.WrongPasswordKdf, wrong.Err);
        Assert.Equal(BrokerHarness.MyUid, ProcOwner(serve));

        // The right one: unlocked, non-dumpable, and the request now unlocks (and fails upstream: 502).
        var unlock = RunOnTerminal(password + "\n", "broker", "unlock", "--timeout", "8h");
        Assert.True(unlock.Exit == 0, unlock.Err);
        Assert.Contains("The broker is unlocked", unlock.Out);
        Assert.Contains("The broker keeps your stretched vault password in memory", unlock.Err);
        Assert.Equal(0u, ProcOwner(serve));
        Assert.Equal(502, await StatusOverSocketAsync(SocketPath, "/api/x"));
        var served = await WaitForLineAsync(serveLines, "reason=upstream-error");
        Assert.Contains("unlocks=1", served);
        Assert.Contains("The broker is unlocked until", Run("", "broker", "status").Out);

        // Unlocked, it is non-dumpable: a second 'broker unlock' can't read its namespace link and sends nothing.
        var again = RunOnTerminal(password + "\n", "broker", "unlock");
        Assert.NotEqual(0, again.Exit);
        Assert.Contains(BrokerControlClient.UnreadableServerLinkText, again.Err);

        // Locked again: dumpable, and the next request is refused as locked.
        var locked = Run("", "broker", "lock");
        Assert.True(locked.Exit == 0, locked.Err);
        Assert.Contains("The broker is locked.", locked.Out);
        Assert.Equal(BrokerHarness.MyUid, ProcOwner(serve));
        Assert.Equal(503, await StatusOverSocketAsync(SocketPath, "/api/x"));
        Assert.Contains("reason=locked", await WaitForLineAsync(serveLines, "route=api"));
        Assert.Contains("The broker is locked.", Run("", "broker", "status").Out);

        Signal(serve, "-TERM");
        await serve.WaitForExitAsync(new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token);
        Assert.Equal(0, serve.ExitCode);
        Assert.Equal(BrokerNative.EntryType.Missing, BrokerNative.LStat(control)!.Value.Type);
        Assert.DoesNotContain("tok-value", File.ReadAllText(Path.Combine(ConfigDir, BrokerLog.FileName)));
    }

    [Fact]
    public async Task Forward_RefusesANonLoopbackListenAddress()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var p = Process.Start(Psi(false, "broker", "forward", "--listen", "0.0.0.0:18080"))!;
        p.StandardInput.Close();
        var stderr = await p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();

        Assert.NotEqual(0, p.ExitCode);
        Assert.Contains("loopback", stderr);
    }
}
