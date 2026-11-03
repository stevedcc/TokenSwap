using System.Diagnostics;
using System.Net.Sockets;
using TswapCore.Broker;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 11, end to end through the built binary: <c>init --tpm --password</c> (test key), then
/// <c>agent start</c> with the password on stdin (the Debug-only <c>TSWAP_TEST_TERMINAL</c> console seam plays
/// the terminal), which starts <c>agent serve</c> as a real background child. <c>TSWAP_AGENT_SOCK</c> points
/// into this test's folder, so the user's own agent is never met. Unix only (the socket and <c>/proc</c>).
/// </summary>
[Trait("Category", "E2E")]
public sealed class AgentEndToEndTests(TswapBinaryFixture binary) : IClassFixture<TswapBinaryFixture>, IDisposable
{
    private const string Password = "correct horse battery staple";
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(60);
    private readonly string _dir = Directory.CreateTempSubdirectory("tswap-e2e-agent-").FullName;

    private string Socket => Path.Combine(_dir, "run", "agent.sock");

    public void Dispose()
    {
        // The agent of this test stops even when an assertion failed; a stopped one answers "not running".
        if (File.Exists(Socket))
            Run("", terminal: false, "agent", "stop");
        Directory.Delete(_dir, true);
    }

    private (int Exit, string Out, string Err) Run(string stdin, bool terminal, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = binary.BinaryPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["TSWAP_TEST_KEY"] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        psi.Environment["TSWAP_TEST_SUDO_BYPASS"] = "1";
        psi.Environment["TSWAP_CONFIG_DIR"] = _dir;
        psi.Environment["TSWAP_AGENT_SOCK"] = Socket;
        if (terminal)
            psi.Environment["TSWAP_TEST_TERMINAL"] = "1";
        else
            psi.Environment.Remove("TSWAP_TEST_TERMINAL");

        using var process = Process.Start(psi)!;
        process.StandardInput.Write(stdin);
        process.StandardInput.Close();
        // Both streams to their end: for 'agent start' that end comes only once its background child has
        // reopened its stdio on /dev/null (ruling 10), so a child that kept them would fail this bound.
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(Task.WhenAll(stdout, stderr).Wait(Bound), $"tswap {string.Join(' ', args)} kept its output open");
        Assert.True(process.WaitForExit(Bound), $"tswap {string.Join(' ', args)} did not exit");
        return (process.ExitCode, stdout.Result, stderr.Result);
    }

    private void InitAndCreate()
    {
        var init = Run(Password + "\n" + Password + "\n", terminal: false, "init", "--tpm", "--password", "--no-recovery");
        Assert.True(init.Exit == 0, init.Err);
        var create = Run(Password + "\n", terminal: true, "create", "db");
        Assert.True(create.Exit == 0, create.Err);
    }

    /// <summary>The pid serving <see cref="Socket"/>, from the kernel's view of a connection to it.</summary>
    private int AgentPid()
    {
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        socket.Connect(new UnixDomainSocketEndPoint(Socket));
        var credentials = BrokerNative.TryGetPeerCredentials(socket);
        Assert.NotNull(credentials);
        return credentials.Value.Pid;
    }

    [Fact]
    public void Start_Get_Get_Stop()
    {
        if (OperatingSystem.IsWindows())
            return;
        InitAndCreate();

        var start = Run(Password + "\n", terminal: true, "agent", "start");
        Assert.True(start.Exit == 0, start.Err);
        Assert.Contains(Socket, start.Out);

        // Two gets without a terminal: no prompt, the agent unlocks (the held password survives an unlock).
        var first = Run("", terminal: false, "get", "db");
        var second = Run("", terminal: false, "get", "db");
        Assert.True(first.Exit == 0, first.Err);
        Assert.True(second.Exit == 0, second.Err);
        Assert.False(string.IsNullOrWhiteSpace(first.Out));
        Assert.Equal(first.Out, second.Out);
        Assert.DoesNotContain("Vault password", first.Err);

        var status = Run("", terminal: false, "agent", "status");
        Assert.True(status.Exit == 0, status.Err);
        var stop = Run("", terminal: false, "agent", "stop");
        Assert.True(stop.Exit == 0, stop.Err);

        var after = Run("", terminal: false, "get", "db");
        Assert.NotEqual(0, after.Exit);
        Assert.Contains(VaultPasswordMessages.NoTerminal, after.Err);
    }

    [Fact]
    public void Start_ParentGone_AgentStillAnswers()
    {
        if (OperatingSystem.IsWindows())
            return;
        InitAndCreate();

        // Run returns only after 'agent start' exited and both its pipes reached their end: the child holds
        // none of them any more. The agent still answers.
        var start = Run(Password + "\n", terminal: true, "agent", "start");
        Assert.True(start.Exit == 0, start.Err);

        var status = Run("", terminal: false, "agent", "status");
        Assert.True(status.Exit == 0, status.Err);
        Assert.Contains("refused peers: 0", status.Out);
    }

    [Fact]
    public void AgentServe_IsNotDumpable()
    {
        if (!OperatingSystem.IsLinux())
            return;
        InitAndCreate();
        var start = Run(Password + "\n", terminal: true, "agent", "start");
        Assert.True(start.Exit == 0, start.Err);

        var pid = AgentPid();

        // A same-uid process may read a dumpable process's environ; a non-dumpable one's is refused.
        Assert.NotEqual(Environment.ProcessId, pid);
        Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllBytes($"/proc/{pid}/environ"));
        // The agent left the starting terminal's session (setsid): it leads a session of its own.
        var stat = File.ReadAllText($"/proc/{pid}/stat");
        var fields = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
        Assert.Equal(pid.ToString(), fields[3]); // field 6, session id
    }

    [Fact]
    public void Start_WrongPassword_ExitsOne_NoAgentLeft()
    {
        if (OperatingSystem.IsWindows())
            return;
        InitAndCreate();

        var start = Run("not the password\n", terminal: true, "agent", "start");

        Assert.Equal(1, start.Exit);
        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, start.Err);
        Assert.False(File.Exists(Socket));
    }
}
