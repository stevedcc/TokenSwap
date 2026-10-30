using System.Diagnostics;
using System.Text.Json;
using System.Threading.Channels;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T10 item 2, through the built binary (simulated TPM via TSWAP_TEST_KEY): serve loads each ssh
/// key once at start, refuses to start on a key it can't use (naming it), and its agent socket lists
/// the key so OpenSSH's own <c>ssh-add -L</c> prints the original public key.
/// </summary>
[Trait("Category", "E2E")]
public class SshAgentServeEndToEndTests : IClassFixture<TswapBinaryFixture>, IDisposable
{
    private const string TestKeyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    private readonly string _binary;
    private readonly string _root = Path.Combine(Path.GetTempPath(), "tswap-ske-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly List<Process> _processes = [];
    private readonly SshTestKeys _keys = new();

    public SshAgentServeEndToEndTests(TswapBinaryFixture binary)
    {
        _binary = binary.BinaryPath;
        Directory.CreateDirectory(ConfigDir);
        Directory.CreateDirectory(SocketDir);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(SocketDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private string ConfigDir => Path.Combine(_root, "c");
    private string SocketDir => Path.Combine(_root, "s");

    public void Dispose()
    {
        foreach (var p in _processes)
        {
            if (!p.HasExited)
                p.Kill();
            p.Dispose();
        }
        _keys.Dispose();
        if (Directory.Exists(_root))
            Directory.Delete(_root, true);
    }

    private ProcessStartInfo Psi(params string[] args)
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
        psi.Environment["TSWAP_TEST_KEY"] = TestKeyHex;
        psi.Environment["TSWAP_TEST_SUDO_BYPASS"] = "1";
        psi.Environment["TSWAP_CONFIG_DIR"] = ConfigDir;
        psi.Environment.Remove("SSH_AUTH_SOCK");
        return psi;
    }

    private (int Exit, string Out, string Err) Run(string stdin, params string[] args)
    {
        using var p = Process.Start(Psi(args))!;
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

    /// <summary>A record-store TPM vault holding the key file as secret <c>deploy-key</c>, and broker.json with key <c>deploy</c> on socket <c>lane1</c>.</summary>
    private void Setup(string keyFile)
    {
        Ok("", "init", "--tpm", "--no-recovery");
        Ok(File.ReadAllText(keyFile), "ingest", "deploy-key");
        Ok("", "migrate", "--to-records");
        var config = new BrokerConfig
        {
            Version = 1,
            SocketDir = SocketDir,
            Sockets = [new BrokerSocketConfig { Name = "lane1", Uids = [BrokerHarness.MyUid.ToString()], Routes = [], SshKeys = ["deploy"] }],
            SshKeys = [new BrokerSshKeyConfig { Name = "deploy", Secret = "deploy-key", AllowedHostKeys = [SshAgentHarness.SomeHostFingerprint] }],
        };
        var path = Path.Combine(ConfigDir, "broker.json");
        File.WriteAllText(path, JsonSerializer.Serialize(config, BrokerJsonContext.Default.BrokerConfig));
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [Fact]
    public async Task Serve_ListsTheKeyOnItsAgentSocket_AsSshAddPrintsIt()
    {
        if (!OperatingSystem.IsLinux() || !SshTestKeys.HaveTools || SshTestKeys.Which("ssh-add") is null)
            return;
        var key = _keys.Generate("id", "ed25519");
        Setup(key);

        var lines = Channel.CreateUnbounded<string>();
        var serve = new Process { StartInfo = Psi("broker", "serve") };
        serve.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
                lines.Writer.TryWrite(e.Data);
        };
        serve.Start();
        serve.BeginErrorReadLine();
        _processes.Add(serve);
        using (var guard = new CancellationTokenSource(TimeSpan.FromSeconds(60)))
            while (!(await lines.Reader.ReadAsync(guard.Token)).Contains("event started", StringComparison.Ordinal)) { }

        var agentSocket = SshAgentListener.SocketPath(SocketDir, "lane1");
        var psi = new ProcessStartInfo(SshTestKeys.Which("ssh-add")!, ["-L"]) { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.Environment["SSH_AUTH_SOCK"] = agentSocket; // the broker's agent socket, never the user's agent
        using var sshAdd = Process.Start(psi)!;
        var listed = await sshAdd.StandardOutput.ReadToEndAsync();
        await sshAdd.WaitForExitAsync();

        Assert.Equal(0, sshAdd.ExitCode);
        var original = File.ReadAllText(key + ".pub").Split(' ');
        Assert.Equal($"{original[0]} {original[1]} deploy", listed.Trim()); // the comment is the key's name
        var listedFile = Path.Combine(_keys.Dir, "listed.pub");
        File.WriteAllText(listedFile, listed);
        Assert.Equal(SshTestKeys.Fingerprint(key + ".pub"), SshTestKeys.Fingerprint(listedFile));
    }

    [Theory]
    [InlineData("encrypted")]
    [InlineData("rsa-2048")]
    public void Serve_WithAKeyItCantUse_RefusesToStart_NamingTheKey(string problem)
    {
        if (!OperatingSystem.IsLinux() || !SshTestKeys.HaveTools)
            return;
        var key = problem == "encrypted"
            ? _keys.Generate("id", "ed25519", passphrase: "pw")
            : _keys.Generate("id", "rsa", 2048);
        Setup(key);

        var (exit, _, stderr) = Run("", "broker", "serve");

        Assert.NotEqual(0, exit);
        Assert.Contains("Ssh key 'deploy'", stderr);
        Assert.Contains(problem == "encrypted" ? "encrypted" : "3072", stderr);
        Assert.False(File.Exists(SshAgentListener.SocketPath(SocketDir, "lane1")));
    }
}
