using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Channels;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T10 item 3, the interop gate: the system's own <c>sshd</c>, unprivileged on a loopback port in
/// a temp folder, and the system's own <c>ssh</c> with <c>IdentityAgent</c> pointing at the broker's
/// agent socket (through a recording relay). For each vault key type and an Ed25519 or ECDSA host
/// key: login succeeds when the host key is allowed and fails when it isn't. Linux only (sshd must
/// run unprivileged); without <c>sshd</c>/<c>ssh</c> the recorded frames
/// (<see cref="SshAgentRecordedFrames"/>) carry the protocol checks; CI_REQUIRE_SSHD=1 makes a missing
/// tool a failure. Set TSWAP_SSH_FIXTURE_OUT to a file path to write those frames afresh from a real run.
/// </summary>
[Trait("Category", "E2E")]
public class SshAgentSshdTests(ITestOutputHelper output) : IAsyncLifetime
{
    private readonly SshAgentHarness _h = new();
    private readonly SshTestKeys _keys = new();
    private readonly List<Process> _processes = [];

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        foreach (var p in _processes)
        {
            if (!p.HasExited)
                p.Kill();
            p.Dispose();
        }
        await _h.DisposeAsync();
        _keys.Dispose();
    }

    /// <summary>Why the live sshd run can't happen here, or null when it can.</summary>
    private static string? SshdProblem() =>
        !OperatingSystem.IsLinux() ? "the sshd interop run is Linux-only (sshd must run unprivileged)"
        : !SshTestKeys.HaveTools ? "ssh-keygen or openssl is not installed"
        : SshTestKeys.Which("sshd") is null ? "sshd is not installed"
        : SshTestKeys.Which("ssh") is null ? "ssh is not installed"
        : null;

    /// <summary>
    /// Whether the live run can happen. Otherwise the test writes why to its output and returns (the
    /// recorded frames carry the protocol checks), except when CI_REQUIRE_SSHD=1: then it fails, so a
    /// CI job that sets it can't skip the interop gate silently (fix round 1, MiMo M7).
    /// </summary>
    private bool CanRun()
    {
        if (SshdProblem() is not { } problem)
            return true;
        if (Environment.GetEnvironmentVariable("CI_REQUIRE_SSHD") == "1")
            Assert.Fail($"CI_REQUIRE_SSHD=1 but the sshd interop run can't happen: {problem}");
        output.WriteLine($"SKIPPED: {problem}; the recorded frames (SshAgentRecordedFramesTests) carry the protocol checks.");
        return false;
    }

    public static TheoryData<string, int?, string> Cases => new()
    {
        { "ed25519", null, "ed25519" },
        { "ed25519", null, "ecdsa" },
        { "ecdsa", 256, "ed25519" },
        { "ecdsa", 384, "ecdsa" },
        { "rsa", 3072, "ed25519" },
        { "rsa", 3072, "ecdsa" },
    };

    [Fact]
    public void TheOpenSshClient_Is89OrNewer()
    {
        if (!CanRun())
            return;
        var version = SshTestKeys.Run("ssh", "-V").Err.Trim();
        output.WriteLine(version);
        var match = System.Text.RegularExpressions.Regex.Match(version, @"OpenSSH_(\d+)\.(\d+)");
        Assert.True(match.Success, version);
        var (major, minor) = (int.Parse(match.Groups[1].Value), int.Parse(match.Groups[2].Value));
        Assert.True(major > 8 || (major == 8 && minor >= 9), $"{version}: session-bind needs OpenSSH 8.9 or newer");
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task RealSsh_LogsIn_OnlyWhenTheHostKeyIsAllowed(string clientType, int? clientBits, string hostType)
    {
        if (!CanRun())
            return;
        var allowed = await RunAsync(clientType, clientBits, hostType, allowHost: true);
        Assert.True(allowed.Exit == 0, $"ssh failed with the host allowed:\n{allowed.Err}\n--- broker log:\n{_h.Broker.LogText}");
        Assert.Equal("tswap-ssh-ok", allowed.Out.Trim());
        Assert.Contains($"ssh-sign socket=lane1.ssh uid={BrokerHarness.MyUid}", _h.Broker.LogText.ToString());
        Assert.Contains($"key=deploy host={allowed.HostFingerprint} result=ok", _h.Broker.LogText.ToString());
        Assert.Contains($"ssh-bind socket=lane1.ssh uid={BrokerHarness.MyUid}", _h.Broker.LogText.ToString());
        Assert.Equal(1, allowed.SignUnlocks);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task RealSsh_IsRefused_WhenTheHostKeyIsNotAllowed(string clientType, int? clientBits, string hostType)
    {
        if (!CanRun())
            return;
        var refused = await RunAsync(clientType, clientBits, hostType, allowHost: false);

        Assert.NotEqual(0, refused.Exit);
        Assert.DoesNotContain("tswap-ssh-ok", refused.Out);
        Assert.Contains($"host={refused.HostFingerprint} result=refused reason=host-not-allowed", _h.Broker.LogText.ToString());
        Assert.DoesNotContain(_h.Broker.LogText.ToString().Split('\n'), l => l.Contains("ssh-sign") && l.Contains("result=ok"));
        Assert.Equal(0, refused.SignUnlocks);
    }

    /// <summary>
    /// Captures the frames a real <c>ssh</c> sends (identities, session-bind, sign request) for one
    /// client key of each type and writes them as C# to TSWAP_SSH_FIXTURE_OUT (a no-op without it).
    /// </summary>
    [Fact]
    public async Task CaptureFixtures_WhenAsked()
    {
        var target = Environment.GetEnvironmentVariable("TSWAP_SSH_FIXTURE_OUT");
        if (target is null || !CanRun())
            return;
        var sb = new StringBuilder();
        sb.AppendLine("// Generated by SshAgentSshdTests.CaptureFixtures_WhenAsked (TSWAP_SSH_FIXTURE_OUT) from a real run of");
        sb.AppendLine($"// {SshTestKeys.Run("ssh", "-V").Err.Trim()} against an unprivileged sshd. Test-only keys made for this");
        sb.AppendLine("// capture; they open nothing. The user name inside each signed userauth request is replaced with");
        sb.AppendLine($"// '{NeutralUserName}' (the agent never checks it; the server does), so no local name is recorded.");
        sb.AppendLine("// Regenerate rather than edit.");
        sb.AppendLine("namespace TswapTests;");
        sb.AppendLine();
        sb.AppendLine("public static partial class SshAgentRecordedFrames");
        sb.AppendLine("{");
        sb.AppendLine("    public static readonly RecordedSshSession[] Sessions =");
        sb.AppendLine("    [");
        foreach (var (clientType, bits, hostType) in new[] { ("ed25519", (int?)null, "ed25519"), ("ecdsa", 256, "ecdsa"), ("rsa", 3072, "ed25519") })
        {
            await using var h = new SshAgentHarness();
            var run = await RunAsync(clientType, bits, hostType, allowHost: true, record: true, harness: h);
            Assert.True(run.Exit == 0, run.Err);
            sb.AppendLine("        new(");
            sb.AppendLine($"            Name: \"{clientType}-client-{hostType}-host\",");
            // A test-only key generated for this capture, inert: annotated on its header line for secret scanners.
            var pemLines = File.ReadAllText(run.ClientKeyFile).TrimEnd().Split('\n');
            sb.AppendLine("            ClientKeyPem:");
            for (var i = 0; i < pemLines.Length; i++)
                sb.AppendLine($"                \"{pemLines[i]}\\n\"{(i < pemLines.Length - 1 ? " +" : ",")}"
                    + (i == 0 ? " // gitleaks:allow test-only key generated for this fixture; it opens nothing" : ""));
            sb.AppendLine($"            HostKeyBlob: \"{Convert.ToBase64String(SshTestKeys.BlobOf(run.HostKeyFile + ".pub"))}\",");
            sb.AppendLine("            ClientFrames:");
            sb.AppendLine("            [");
            foreach (var frame in run.ClientFrames!)
                sb.AppendLine($"                \"{Convert.ToBase64String(NeutralUser(frame))}\",");
            sb.AppendLine("            ]),");
        }
        sb.AppendLine("    ];");
        sb.AppendLine("}");
        File.WriteAllText(target, sb.ToString());
    }

    private const string NeutralUserName = "tswap-test";

    /// <summary>
    /// A recorded sign request with the userauth user name replaced by <see cref="NeutralUserName"/>
    /// (fix round 1, MiMo M8); every other byte is as ssh sent it. Other frames are returned unchanged.
    /// </summary>
    private static byte[] NeutralUser(byte[] frame)
    {
        if (frame[0] != SshAgentProtocol.SignRequest)
            return frame;
        var request = new SshReader(frame.AsSpan(1));
        var keyBlob = request.ReadString().ToArray();
        var data = request.ReadString().ToArray();
        var flags = request.ReadUInt32();
        request.EnsureEnd();
        var userauth = new SshReader(data);
        var sessionId = userauth.ReadString().ToArray();
        var type = userauth.ReadByte();
        var user = userauth.ReadString();
        var tail = data.AsSpan(data.Length - userauth.Remaining).ToArray();
        Assert.Equal(Environment.UserName, System.Text.Encoding.UTF8.GetString(user));
        var neutral = new SshWriter().String(sessionId).Byte(type).String(NeutralUserName).Raw(tail).ToArray();
        return new SshWriter().Byte(SshAgentProtocol.SignRequest).String(keyBlob).String(neutral).UInt32(flags).ToArray();
    }

    private sealed record RunResult(int Exit, string Out, string Err, string HostFingerprint, int SignUnlocks,
        string ClientKeyFile, string HostKeyFile, List<byte[]>? ClientFrames);

    private async Task<RunResult> RunAsync(string clientType, int? clientBits, string hostType, bool allowHost,
        bool record = false, SshAgentHarness? harness = null)
    {
        var h = harness ?? _h;
        var dir = Path.Combine(_keys.Dir, Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(dir);
        var client = Path.Combine(dir, "client");
        SshTestKeys.Ok("ssh-keygen", ["-q", "-t", clientType, .. clientBits is { } b ? new[] { "-b", b.ToString() } : [], "-N", "", "-C", "", "-f", client]);
        var host = Path.Combine(dir, "host");
        SshTestKeys.Ok("ssh-keygen", ["-q", "-t", hostType, "-N", "", "-C", "", "-f", host]);
        var hostFingerprint = SshTestKeys.Fingerprint(host + ".pub");

        // The broker's agent, with the client key as the vault secret.
        var source = new FakeSshKeySource(_ => File.ReadAllBytes(client));
        var loadReads = 0;
        var config = h.Config(keys: [("deploy", "client-key", [allowHost ? hostFingerprint : SshAgentHarness.SomeHostFingerprint])], lane1Keys: ["deploy"], otherKeys: []);
        await h.StartAsync(config, policy =>
        {
            var loaded = SshAgentKeyLoader.Load(policy, source);
            loadReads = source.Reads;
            return new SshAgentOptions { Keys = loaded, KeySource = source };
        });

        // sshd: unprivileged, loopback, this temp folder only.
        var port = FreePort();
        File.Copy(client + ".pub", Path.Combine(dir, "authorized_keys"));
        File.WriteAllText(Path.Combine(dir, "sshd_config"), $"""
            ListenAddress 127.0.0.1
            Port {port}
            HostKey {host}
            AuthorizedKeysFile {Path.Combine(dir, "authorized_keys")}
            StrictModes no
            PidFile none
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            PubkeyAuthentication yes
            """);
        var sshd = Start(SshTestKeys.Which("sshd")!, "-D", "-e", "-f", Path.Combine(dir, "sshd_config"));
        await WaitForLineAsync(sshd.Lines, "Server listening on");

        File.WriteAllText(Path.Combine(dir, "known_hosts"), $"[127.0.0.1]:{port} {File.ReadAllText(host + ".pub").Trim()}\n");
        var agentSocket = h.AgentSocket("lane1");
        Recorder? recorder = null;
        if (record)
        {
            recorder = new Recorder(Path.Combine(dir, "rec.sock"), agentSocket);
            agentSocket = recorder.Path;
        }
        var ssh = new ProcessStartInfo(SshTestKeys.Which("ssh")!)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        foreach (var arg in new[]
                 {
                     "-F", "/dev/null", "-p", port.ToString(),
                     "-o", $"IdentityAgent={agentSocket}",
                     "-o", $"IdentityFile={Path.Combine(dir, "no-such-identity")}",
                     "-o", $"UserKnownHostsFile={Path.Combine(dir, "known_hosts")}",
                     "-o", "GlobalKnownHostsFile=/dev/null",
                     "-o", "StrictHostKeyChecking=yes", "-o", "CheckHostIP=no", "-o", "UpdateHostKeys=no",
                     "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
                     "-o", "HostbasedAuthentication=no", "-o", "PubkeyAuthentication=yes",
                     "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=20", "-o", "LogLevel=ERROR",
                     $"{Environment.UserName}@127.0.0.1", "echo", "tswap-ssh-ok",
                 })
            ssh.ArgumentList.Add(arg);
        ssh.Environment.Remove("SSH_AUTH_SOCK"); // never the user's agent
        ssh.Environment["HOME"] = dir;
        using var process = Process.Start(ssh)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using (var guard = new CancellationTokenSource(TimeSpan.FromSeconds(60)))
            await process.WaitForExitAsync(guard.Token);
        var frames = recorder is null ? null : await recorder.StopAsync();
        sshd.Process.Kill();
        return new RunResult(process.ExitCode, await stdout, await stderr, hostFingerprint, source.Reads - loadReads, client, host, frames);
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private (Process Process, Channel<string> Lines) Start(string file, params string[] args)
    {
        var lines = Channel.CreateUnbounded<string>();
        var psi = new ProcessStartInfo(file) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false };
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        var p = new Process { StartInfo = psi };
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

    private static async Task WaitForLineAsync(Channel<string> lines, string text)
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        while (!(await lines.Reader.ReadAsync(guard.Token)).Contains(text, StringComparison.Ordinal)) { }
    }

    /// <summary>A Unix-socket relay to the agent that records the client's frames (one connection).</summary>
    private sealed class Recorder
    {
        private readonly Socket _listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        private readonly Task<List<byte[]>> _run;

        public Recorder(string path, string agentSocket)
        {
            Path = path;
            _listener.Bind(new UnixDomainSocketEndPoint(path));
            _listener.Listen(4);
            _run = RunAsync(agentSocket);
        }

        public string Path { get; }

        private async Task<List<byte[]>> RunAsync(string agentSocket)
        {
            using var client = await _listener.AcceptAsync();
            using var agent = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await agent.ConnectAsync(new UnixDomainSocketEndPoint(agentSocket));
            var fromClient = new MemoryStream();
            var up = Pump(client, agent, fromClient);
            var down = Pump(agent, client, null);
            await Task.WhenAny(up, down);
            agent.Shutdown(SocketShutdown.Both);
            client.Shutdown(SocketShutdown.Both);
            var bytes = fromClient.ToArray();
            var frames = new List<byte[]>();
            for (var pos = 0; pos + 4 <= bytes.Length;)
            {
                var length = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(pos));
                frames.Add(bytes[(pos + 4)..(pos + 4 + length)]);
                pos += 4 + length;
            }
            return frames;
        }

        private static async Task Pump(Socket from, Socket to, MemoryStream? copy)
        {
            var buffer = new byte[64 * 1024];
            try
            {
                int n;
                while ((n = await from.ReceiveAsync(buffer)) > 0)
                {
                    copy?.Write(buffer, 0, n);
                    await to.SendAsync(buffer.AsMemory(0, n));
                }
            }
            catch (SocketException)
            {
                // either side gone: the session is over
            }
        }

        public async Task<List<byte[]>> StopAsync()
        {
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var frames = await _run.WaitAsync(guard.Token);
            _listener.Dispose();
            return frames;
        }
    }
}
