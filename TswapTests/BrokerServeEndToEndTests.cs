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

    private ProcessStartInfo Psi(bool withVault, params string[] args)
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
        psi.Environment["DOTNET_EnableWriteXorExecute"] = "0";
        if (withVault)
        {
            psi.Environment["TSWAP_TEST_KEY"] = TestKeyHex;
            psi.Environment["TSWAP_TEST_SUDO_BYPASS"] = "1";
            psi.Environment["TSWAP_CONFIG_DIR"] = ConfigDir;
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

    private (int Exit, string Out, string Err) Run(string stdin, params string[] args)
    {
        using var p = Process.Start(Psi(true, args))!;
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
        Ok("", "migrate", "--to-records"); // serve needs a record-store vault
        // An upstream nothing listens on: the request unlocks, then fails upstream (502).
        Ok("", "broker", "route", "add", "api", "--upstream", "https://127.0.0.1:1/v1", "--auth", "bearer", "--secret", "tok", "--path", "");
        Ok("", "broker", "socket", "add", "lane1", "--uids", BrokerHarness.MyUid.ToString(), "--routes", "api", "--socket-dir", SocketDir);

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
