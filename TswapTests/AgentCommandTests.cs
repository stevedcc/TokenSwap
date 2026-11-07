using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 11: <c>tswap agent start|serve|stop|status</c> and the CLI asking a running agent before it
/// prompts (ruling 13's pass 2), in process. <c>agent start</c>'s child (<c>agent serve</c>) runs in this
/// process through <see cref="AgentCommand.LaunchChild"/>, with its stdin and stdout on pipes;
/// <see cref="AgentEndToEndTests"/> runs the real binary. Unix sockets only (the agent's Windows pipe is
/// task 10's and Windows CI's).
/// </summary>
[Collection(StaticSeamCollection.Name)]
public sealed class AgentCommandTests : IDisposable
{
    private const string Password = "correct horse battery staple";

    private const string RamDisclosure =
        "The agent keeps your stretched vault password in memory until you stop it or it times out. Root, or anything that can read this process's memory, can take it while it runs; it still needs this machine's TPM/YubiKey/Secure Enclave to open the vault.";

    private const string AskingLine = "Asking the tswap agent to unlock...";

    private readonly List<FleetMachine> _machines = [];
    private readonly List<string> _shortFolders = [];
    private readonly List<AgentServer> _fakeAgents = [];
    private readonly InProcessChildren _children = new();

    public AgentCommandTests()
    {
        AgentCommand.LaunchChild = _children.Launch;
    }

    public void Dispose()
    {
        // Every agent this test started stops (zeroing its password) before its folders go.
        _children.Dispose();
        foreach (var agent in _fakeAgents)
            agent.DisposeAsync().AsTask().GetAwaiter().GetResult();
        AgentCommand.LaunchChild = null;
        AgentUnlock.AskedObserver = null;
        AgentUnlock.PathInputs = null;
        CommandContext.AgentKeyZeroedObserver = null;
        AgentClient.ResetSeamsForTests();
        foreach (var m in _machines)
            m.Dispose();
        foreach (var dir in _shortFolders.Where(Directory.Exists))
            Directory.Delete(dir, recursive: true);
    }

    // ------------------------------------------------------------------ helpers

    private FleetMachine Machine(string name, bool tpm = true, params int[] serials)
    {
        var m = new FleetMachine(name, SimulatedYubiKeyService.WithKeys(serials)) { Tpm = tpm ? RandomNumberGenerator.GetBytes(32) : null };
        _machines.Add(m);
        _children.Machine = m;
        return m;
    }

    /// <summary>A record vault whose own slot is a simulated TPM password slot, with one secret; returns <c>K_v</c>.</summary>
    private (FleetMachine Machine, byte[] VaultKey) TpmPasswordVault(string name, params int[] serials)
    {
        var m = Machine(name, tpm: true, serials);
        var vaultKey = PasswordVaultTestSupport.InitTpmPasswordVault(m, Password);
        var (exit, _, err) = m.RunOnTerminal(Password + "\n", "create", "db");
        Assert.True(exit == 0, err);
        return (m, vaultKey);
    }

    private static byte[] VaultId(FleetMachine m) => m.Keyring.VaultId;

    private static VaultPasswordFile PasswordFile(FleetMachine m) =>
        VaultPasswordFile.Decode(File.ReadAllBytes(PasswordVaultTestSupport.VaultPasswordPath(m)), VaultId(m));

    private static StretchedPassword Stretched(FleetMachine m, string password)
    {
        var file = PasswordFile(m);
        return VaultPasswordKdf.Stretch(password, file.Salt, file.Params);
    }

    /// <summary><c>agent start</c> on a terminal with <paramref name="password"/> typed.</summary>
    private static (int Exit, string Out, string Err) Start(FleetMachine m, string password = Password, params string[] extra) =>
        m.RunOnTerminal(password + "\n", ["agent", "start", .. extra]);

    /// <summary>
    /// Where this machine's agent listens, as the CLI names it. On Unix the socket <see cref="FleetMachine.AgentSocket"/>
    /// (<c>TSWAP_AGENT_SOCK</c>). On Windows that variable is ignored (it is Unix only, ruling 6): the agent is the named
    /// pipe of this user and this vault, unique per test because every test's vault id is random (CI run 41619549912
    /// failed these tests on Windows by expecting the socket path there).
    /// </summary>
    private static string Address(FleetMachine m) =>
        OperatingSystem.IsWindows() ? AgentSocketPath.For(0, VaultId(m), _ => null) : m.AgentSocket!;

    /// <summary>
    /// A new empty folder under <c>/tmp</c> (removed after the test) for a home that holds a socket: under the temp
    /// folder, a long one (macOS's <c>/var/folders/…/T</c>, CI run 41619549912) pushes the socket path past 103 bytes.
    /// </summary>
    private string ShortFolder(string name)
    {
        var dir = Path.Combine("/tmp", $"tswap-{name}-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4)));
        Directory.CreateDirectory(dir);
        _shortFolders.Add(dir);
        return dir;
    }

    /// <summary>An agent server that answers this vault with what <paramref name="unlock"/> returns, at the machine's socket.</summary>
    private AgentServer FakeAgent(FleetMachine m, Func<byte[]> unlock)
    {
        var options = new AgentServerOptions(Address(m), VaultId(m), unlock, null, TimeProvider.System, AgentHarness.MyUid);
        var server = AgentServer.StartAsync(options).GetAwaiter().GetResult();
        _fakeAgents.Add(server);
        return server;
    }

    /// <summary>Records each connect of <see cref="AgentClient"/> and then connects.</summary>
    private static List<string> RecordConnects()
    {
        var connects = new List<string>();
        AgentClient.Connect = async (socket, endpoint, ct) =>
        {
            lock (connects)
                connects.Add(endpoint.ToString()!);
            await socket.ConnectAsync(endpoint, ct);
        };
        return connects;
    }

    private static void AssertHoldsNoSecret(string text, params byte[][] secrets)
    {
        foreach (var secret in secrets)
        {
            Assert.DoesNotContain(Convert.ToHexString(secret), text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(Convert.ToBase64String(secret), text);
            Assert.DoesNotContain(Convert.ToBase64String(secret).TrimEnd('='), text);
            Assert.DoesNotContain(Encoding.Latin1.GetString(secret), text);
        }
    }

    // ------------------------------------------------------------------ agent start

    [Fact]
    public void Start_ThenGetWithoutTerminal_UsesTheAgent_ThenStop()
    {
        var (m, _) = TpmPasswordVault("start-get");

        var (exit, stdout, stderr) = Start(m);
        Assert.True(exit == 0, stderr);
        Assert.Contains(Address(m), stdout);

        // No terminal: the agent answers, twice (the held password survives an unlock, ruling 4).
        var first = m.Run("", "get", "db");
        var second = m.Run("", "get", "db");
        Assert.True(first.Exit == 0, first.Err);
        Assert.True(second.Exit == 0, second.Err);
        Assert.False(string.IsNullOrWhiteSpace(first.Out));
        Assert.Equal(first.Out, second.Out);
        Assert.Equal(0, m.LastConsole!.Reads);

        var (stopExit, _, stopErr) = m.Run("", "agent", "stop");
        Assert.True(stopExit == 0, stopErr);
        var after = m.Run("", "get", "db");
        Assert.NotEqual(0, after.Exit);
        Assert.Contains(VaultPasswordMessages.NoTerminal, after.Err);
    }

    [Fact]
    public void Start_PrintsTheRamDisclosureVerbatim()
    {
        var (m, _) = TpmPasswordVault("disclosure");

        var (exit, stdout, stderr) = Start(m);

        Assert.True(exit == 0, stderr);
        Assert.Contains(RamDisclosure + Environment.NewLine, stdout + stderr);
        Assert.DoesNotContain("Secure Enclave library", stdout + stderr); // the macOS line is for Secure Enclave slots only
    }

    [Fact]
    public void Start_RamDisclosureOnStderr_OnceBeforeThePrompt()
    {
        // Review T17 p3 GLM M3: on stderr, next to the prompt, as 'broker unlock' does.
        var (m, _) = TpmPasswordVault("disclosure-stderr");

        var (exit, stdout, stderr) = Start(m);

        Assert.True(exit == 0, stderr);
        Assert.DoesNotContain(RamDisclosure, stdout);
        var at = stderr.IndexOf(RamDisclosure + Environment.NewLine, StringComparison.Ordinal);
        Assert.True(at >= 0, stderr);
        Assert.Equal(at, stderr.LastIndexOf(RamDisclosure, StringComparison.Ordinal));
        Assert.True(at < stderr.IndexOf(TerminalPasswordProvider.PromptText, StringComparison.Ordinal), stderr);
    }

    [Fact]
    public void Start_WrongPassword_ExitsOne_NoAgentLeft()
    {
        var (m, _) = TpmPasswordVault("start-wrong");

        var (exit, _, stderr) = Start(m, "not the password");

        Assert.Equal(1, exit);
        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, stderr);
        Assert.False(File.Exists(m.AgentSocket!));
        Assert.False(Directory.Exists(Path.GetDirectoryName(m.AgentSocket!))); // nothing was made for it
        Assert.Equal(0, _children.Running);
    }

    [Fact]
    public void Start_NoPasswordSlotHere_Refuses()
    {
        var m = Machine("start-free");
        m.Ok("", "init", "--tpm", "--no-password", "--no-recovery");

        var (exit, _, stderr) = Start(m);

        Assert.Equal(1, exit);
        Assert.Contains("No slot of this vault on this machine needs the vault password; the agent has nothing to hold.", stderr);
        Assert.Equal(0, m.LastConsole!.Reads);
        Assert.Empty(_children.Started);
    }

    [Fact]
    public void Start_PasswordYubiKeyNotPluggedIn_SaysPlugIn()
    {
        var m = Machine("start-unplugged", tpm: false, RecordVaultTestSupport.SerialA);
        m.Ok(Password + "\n" + Password + "\n", "init", "--yubikey", "--password", "--no-recovery");
        m.Keys = SimulatedYubiKeyService.WithKeys();

        var (exit, _, stderr) = Start(m);

        Assert.Equal(1, exit);
        Assert.Contains($"No password slot is usable right now (plug in YubiKey {RecordVaultTestSupport.SerialA}) and try again.", stderr);
        Assert.Equal(0, m.LastConsole!.Reads);
        Assert.Empty(_children.Started);
    }

    [Fact]
    public void Start_AsRoot_Refuses_LeavesNothing()
    {
        // Root and sudo are Unix's: on Windows the agent has no root refusal and no "(as root, …)" suffix by design
        // (AgentCommand checks !OperatingSystem.IsWindows()); CI run 41619549912 ran this on Windows.
        if (OperatingSystem.IsWindows())
            return;
        var (m, _) = TpmPasswordVault("start-root");
        var before = Directory.EnumerateFileSystemEntries(m.Dir, "*", SearchOption.AllDirectories).Order().ToList();
        m.Ownership = new DirectoryOwnerMatcher(new FakeRoot());

        var (exit, _, stderr) = Start(m);

        Assert.Equal(1, exit);
        var name = BrokerNativeName();
        Assert.Contains($"Don't run the agent as root: run 'tswap agent start' as the vault user ({name}), without sudo.", stderr);
        Assert.Equal(0, m.LastConsole!.Reads);
        Assert.Empty(_children.Started);
        Assert.Equal(before, Directory.EnumerateFileSystemEntries(m.Dir, "*", SearchOption.AllDirectories).Order().ToList());
    }

    [Fact]
    public void Start_NoTerminal_Refuses_WithoutReadingStdin()
    {
        var (m, _) = TpmPasswordVault("start-piped");

        var (exit, _, stderr) = m.Run(Password + "\n", "agent", "start");

        Assert.Equal(1, exit);
        Assert.Contains("agent start reads the vault password from a terminal; there is none.", stderr);
        Assert.Equal(0, m.LastConsole!.Reads);
    }

    [Fact]
    public void Start_AlreadyRunning_RefusesBeforeAsking()
    {
        var (m, _) = TpmPasswordVault("start-twice");
        Assert.Equal(0, Start(m).Exit);

        var (exit, _, stderr) = Start(m);

        Assert.Equal(1, exit);
        Assert.Contains($"An agent for this vault is already running ({Address(m)}).", stderr);
        Assert.Equal(0, m.LastConsole!.Reads);
    }

    [Fact]
    public void Start_ReadyLinePath_NotParsed()
    {
        var (m, _) = TpmPasswordVault("ready-line");
        // A child whose ready line names another path, with a space and a newline in it.
        _children.Script = "ready /tmp/not the\nagent path.sock 2030-01-02T03:04:05Z\n";

        var (exit, stdout, stderr) = Start(m);

        Assert.True(exit == 0, stderr);
        Assert.Contains(Address(m), stdout);
        Assert.DoesNotContain("/tmp/not the", stdout + stderr);
        Assert.DoesNotContain("agent path.sock", stdout + stderr);
        Assert.Contains("2030-01-02T03:04:05Z", stdout); // the expiry is relayed
    }

    [Fact]
    public void Start_ReadyReply_ReadsAtMostSixteenLines()
    {
        // Review T17 p3 GLM M2: a ready reply whose path never ends in an expiry is not read without bound.
        var (m, _) = TpmPasswordVault("ready-bounded");
        _children.Script = "ready /tmp/x\n" + string.Concat(Enumerable.Repeat("more of the path\n", 20)) +
                           "tail 2030-01-02T03:04:05Z\n";

        var (exit, stdout, stderr) = Start(m);

        Assert.True(exit == 0, stderr);
        Assert.Contains("It holds the vault password until it times out or 'tswap agent stop'.", stdout);
        Assert.DoesNotContain("2030-01-02T03:04:05Z", stdout); // past the bound: never read
    }

    [Fact]
    public void Start_ZeroesItsCopy_BeforeWaitingForTheChild()
    {
        // Ruling 10: the parent writes the 32 bytes to the child's stdin and zeroes its own copy; it doesn't keep
        // it while the child proves the password (which may wait for a touch).
        var (m, _) = TpmPasswordVault("parent-zeroes");
        using var freed = new ManualResetEventSlim();
        var frees = new List<byte[]>();
        StretchedPassword.BeforeFreeObserver = memory =>
        {
            lock (frees)
                frees.Add(memory.ToArray());
            freed.Set();
        };
        _children.Script = "ready /x 2030-01-02T03:04:05Z\n";
        _children.BeforeReply = () => Assert.True(freed.Wait(TimeSpan.FromSeconds(30)), "the parent still holds the password");
        try
        {
            var (exit, _, stderr) = Start(m);

            Assert.True(exit == 0, stderr);
            var copy = Assert.Single(frees);
            Assert.All(copy, b => Assert.Equal(0, b));
            // The child got exactly the stretched password (review T17 p5 MiMo M1: not only its length).
            using var stretched = Stretched(m, Password);
            var expected = new byte[StretchedPassword.Size];
            stretched.CopyTo(expected);
            Assert.Equal(expected, _children.ChildInputs.Single());
        }
        finally
        {
            StretchedPassword.BeforeFreeObserver = null;
        }
    }

    [Fact]
    public void Start_ProvesWithTheVerifier()
    {
        var (m, vaultKey) = TpmPasswordVault("verifier");
        // A planted file: same salt and parameters (so the TPM opens with the right password), but its verifier
        // is for another password.
        var file = PasswordFile(m);
        using (var other = VaultPasswordKdf.Stretch("another password", file.Salt, file.Params))
            File.WriteAllBytes(PasswordVaultTestSupport.VaultPasswordPath(m),
                VaultPasswordFile.Create(vaultKey, file.VaultId, other, file.Salt, file.Params).Encode());

        var (exit, _, stderr) = Start(m);

        Assert.Equal(1, exit);
        // Review T17 p5 MiMo I2: the shared text of fix round 3's ruling, the one broker unlock gives too.
        Assert.Contains(VaultPasswordMessages.VerifierMismatch, stderr);
        Assert.False(File.Exists(m.AgentSocket!));
        // The hardware unlock itself succeeded: the refusal came from the verifier.
        Assert.DoesNotContain(VaultPasswordMessages.WrongPasswordKdf, stderr);
    }

    /// <summary>
    /// A mixed vault: this machine's TPM slot has the password, and a plugged-in YubiKey slot has none.
    /// Returns the machine with the YubiKey's challenge log cleared.
    /// </summary>
    private FleetMachine MixedVault(string name)
    {
        var (m, _) = TpmPasswordVault(name, RecordVaultTestSupport.SerialA);
        var (addExit, _, addErr) = m.RunOnTerminal(Password + "\n", "slot", "add", "--yubikey", "--no-password");
        Assert.True(addExit == 0, addErr);
        m.Keys.Challenges.Clear();
        return m;
    }

    [Fact]
    public void Start_MixedVault_ProvesThroughThePasswordSlot()
    {
        // Ruling 10 (fix after the merge): the proof exercises a password slot of this machine, even when a
        // password-free slot here would open the vault without the password.
        var m = MixedVault("mixed-proof");
        var tpmUnlocks = 0;

        (int Exit, string Out, string Err) started;
        using (SimulatedHardwareService.ObserveCalls((backend, call) =>
               {
                   if (backend == HardwareBackend.Tpm && call == "Unlock")
                       Interlocked.Increment(ref tpmUnlocks);
               }))
            started = Start(m);

        Assert.True(started.Exit == 0, started.Err);
        Assert.Equal(1, tpmUnlocks);
        Assert.Empty(m.Keys.Challenges); // the password-free YubiKey slot was not what proved it
    }

    [Fact]
    public void Start_MixedVault_WrongPassword_RefusedByThePasswordSlot()
    {
        // The password-free YubiKey slot would open the vault; the wrong password is still refused, by the
        // password slot's hardware (ruling 18's text), not only by the verifier.
        var m = MixedVault("mixed-wrong");

        var (exit, _, stderr) = Start(m, "not the password");

        Assert.Equal(1, exit);
        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, stderr);
        Assert.DoesNotContain(VaultPasswordMessages.VerifierMismatch, stderr);
        Assert.Empty(m.Keys.Challenges);
        Assert.False(File.Exists(m.AgentSocket!));
    }

    [Fact]
    public void ChildErrorLine_AndVerifierMismatchText_HoldNoSecret()
    {
        var (m, vaultKey) = TpmPasswordVault("no-secret");
        var file = PasswordFile(m);
        using (var other = VaultPasswordKdf.Stretch("another password", file.Salt, file.Params))
            File.WriteAllBytes(PasswordVaultTestSupport.VaultPasswordPath(m),
                VaultPasswordFile.Create(vaultKey, file.VaultId, other, file.Salt, file.Params).Encode());
        using var stretched = Stretched(m, Password);
        var stretchedBytes = new byte[32];
        stretched.CopyTo(stretchedBytes);

        var (exit, stdout, stderr) = Start(m);

        Assert.Equal(1, exit);
        var childLine = Assert.Single(_children.ChildOutputs);
        Assert.StartsWith("error ", childLine);
        AssertHoldsNoSecret(childLine, stretchedBytes, vaultKey);
        AssertHoldsNoSecret(stdout + stderr, stretchedBytes, vaultKey);
        AssertHoldsNoSecret(VaultPasswordMessages.VerifierMismatch, stretchedBytes, vaultKey);
    }

    [Fact]
    public void Stretched_NotInArgvOrEnvironment_OfTheChild()
    {
        var (m, _) = TpmPasswordVault("argv");
        using var stretched = Stretched(m, Password);
        var bytes = new byte[32];
        stretched.CopyTo(bytes);

        Assert.Equal(0, Start(m).Exit);

        var psi = Assert.Single(_children.Started);
        Assert.Equal(["agent", "serve"], psi.ArgumentList);
        var everything = string.Join("\n", psi.ArgumentList) + "\n" +
                         string.Join("\n", psi.Environment.Select(e => e.Key + "=" + e.Value));
        AssertHoldsNoSecret(everything, bytes);
        Assert.False(psi.Environment.ContainsKey("TSWAP_TEST_TERMINAL")); // the child never plays a terminal
        // What the child got on stdin is the stretched password, 32 bytes, nothing else.
        Assert.Equal(bytes, _children.ChildInputs.Single());
    }

    [Fact]
    public void Timeout_ParsedAndReportedByStatus()
    {
        var (m, _) = TpmPasswordVault("timeout");
        var before = DateTimeOffset.UtcNow;

        var (exit, stdout, stderr) = Start(m, Password, "--timeout", "90m");

        Assert.True(exit == 0, stderr);
        Assert.Equal(["agent", "serve", "--timeout", "90m"], _children.Started.Single().ArgumentList);
        var (statusExit, status, statusErr) = m.Run("", "agent", "status");
        Assert.True(statusExit == 0, statusErr);
        var expires = DateTimeOffset.Parse(status.Split("expires: ")[1].Split('\n')[0].Trim(), System.Globalization.CultureInfo.InvariantCulture);
        Assert.InRange(expires, before.AddMinutes(90).AddSeconds(-1), DateTimeOffset.UtcNow.AddMinutes(90).AddSeconds(1));
        Assert.Contains(expires.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"), stdout);
        Assert.Contains("refused peers: 0", status);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("59")]
    [InlineData("31d")]
    [InlineData("5m5m")]
    public void Timeout_OutOfRange_IsUsageError_BeforeAsking(string value)
    {
        var (m, _) = TpmPasswordVault("timeout-bad");

        var (exit, _, stderr) = Start(m, Password, "--timeout", value);

        Assert.Equal(1, exit);
        Assert.Contains("Usage: --timeout", stderr);
        Assert.Equal(0, m.LastConsole!.Reads);
        Assert.Empty(_children.Started);
    }

    private const string NoPasswordEnteredText = "No vault password was entered, so nothing was unlocked.";

    [Fact]
    public void AgentStart_EmptyPassword_Cancels_NoChild()
    {
        var (m, _) = TpmPasswordVault("empty");

        var (exit, _, stderr) = Start(m, password: "");

        Assert.Equal(1, exit);
        Assert.Contains(NoPasswordEnteredText, stderr);
        Assert.DoesNotContain("Argon2", stderr);
        Assert.Empty(_children.Started);
    }

    /// <summary>Through <see cref="AgentCommand.Serve"/> with a host that only records, so the test process isn't hardened.</summary>
    [Fact]
    public void AgentServeForeground_EmptyPassword_Cancels()
    {
        var (m, _) = TpmPasswordVault("fg-empty");
        var console = new FakeConsole("\n") { IsInputRedirected = false };
        var ctx = m.Context(console, ["agent", "serve", "--foreground"]);
        var listening = false;
        var host = new AgentServeHost(Stream.Null, TextWriter.Null, Detach: () => { }, Harden: _ => { },
            HandleSignals: _ => { listening = true; return new EmptyDisposable(); });

        var ex = Assert.ThrowsAny<TswapException>(() => AgentCommand.Serve(ctx, ["--foreground"], host));

        Assert.Equal(NoPasswordEnteredText, ex.Message);
        Assert.Equal(1, console.Reads);
        Assert.False(listening);
        var (statusExit, _, statusErr) = m.Run("", "agent", "status");
        Assert.Equal(1, statusExit);
        Assert.Contains("No tswap agent is running for this vault", statusErr);
    }

    private sealed class EmptyDisposable : IDisposable
    {
        public void Dispose() { }
    }

    // ------------------------------------------------------------------ agent serve, stop, status

    [Fact]
    public void Foreground_NoTerminal_Refuses()
    {
        var (m, _) = TpmPasswordVault("foreground");

        var (exit, _, stderr) = m.Run(Password + "\n", "agent", "serve", "--foreground");

        Assert.Equal(1, exit);
        Assert.Contains(
            "agent serve --foreground reads the password from a terminal; there is none. Run 'tswap agent start' from your session.",
            stderr);
        Assert.Equal(0, m.LastConsole!.Reads);
    }

    [Fact]
    public void Status_And_Stop_WhenNoAgentRuns()
    {
        var (m, _) = TpmPasswordVault("none");

        var (statusExit, _, statusErr) = m.Run("", "agent", "status");
        var (stopExit, _, stopErr) = m.Run("", "agent", "stop");

        Assert.Equal(1, statusExit);
        Assert.Equal(1, stopExit);
        Assert.Contains($"No tswap agent is running for this vault ({Address(m)}).", statusErr);
        Assert.Contains($"No tswap agent is running for this vault ({Address(m)}).", stopErr);
    }

    [Fact]
    public void StopAndStatus_UnderSudo_SayForWhom()
    {
        // Root and sudo are Unix's: on Windows the agent has no root refusal and no "(as root, …)" suffix by design
        // (AgentCommand checks !OperatingSystem.IsWindows()); CI run 41619549912 ran this on Windows.
        if (OperatingSystem.IsWindows())
            return;
        var (m, _) = TpmPasswordVault("sudo-status");
        Assert.Equal(0, Start(m).Exit);
        m.Ownership = new DirectoryOwnerMatcher(new FakeRoot());
        var suffix = $"(as root, for {BrokerNativeName()}'s agent)";

        var (statusExit, status, statusErr) = m.Run("", "agent", "status");
        var (stopExit, stop, stopErr) = m.Run("", "agent", "stop");

        Assert.True(statusExit == 0, statusErr);
        Assert.True(stopExit == 0, stopErr);
        Assert.Contains(suffix, status);
        Assert.Contains(suffix, stop);
        _children.WaitForAllToStop();
    }

    [Fact]
    public void AgentServe_OwnUnlock_NeverAsksAnAgent()
    {
        var (m, _) = TpmPasswordVault("serve-own");
        var asked = 0;
        AgentUnlock.AskedObserver = () => Interlocked.Increment(ref asked);

        Assert.Equal(0, Start(m).Exit);
        Assert.Equal(0, asked); // the proving unlock never asked an agent (itself)

        var (exit, _, err) = m.Run("", "get", "db");

        Assert.True(exit == 0, err);
        Assert.Equal(1, asked); // the client asked once; the agent's own unlock did not
    }

    [Fact]
    public void Serve_HardensBeforeReadingThePassword_ThenDetaches()
    {
        var (m, _) = TpmPasswordVault("harden");

        Assert.Equal(0, Start(m).Exit);

        Assert.Equal(["harden", "read", "ready", "detach"], _children.Events);
    }

    // ------------------------------------------------------------------ the CLI asking the agent

    [Fact]
    public void Client_KeyCheckMismatch_Refuses()
    {
        var (m, _) = TpmPasswordVault("mismatch");
        FakeAgent(m, () => RandomNumberGenerator.GetBytes(32));

        var (exit, stdout, stderr) = m.Run("", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Equal("", stdout);
        Assert.Contains($"The tswap agent at {Address(m)} returned a key that doesn't open this vault; not using it.", stderr);
    }

    [Fact]
    public void Agent_AnswerWithNoVaultPasswordFile_Refused()
    {
        var (m, vaultKey) = TpmPasswordVault("no-file");
        var calls = 0;
        FakeAgent(m, () =>
        {
            Interlocked.Increment(ref calls);
            return vaultKey.ToArray(); // the genuine key
        });
        File.Delete(PasswordVaultTestSupport.VaultPasswordPath(m));

        var (exit, stdout, stderr) = m.Run("", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Equal("", stdout);
        Assert.Equal(1, calls); // the agent answered; the answer was not used
        Assert.Contains(VaultPasswordMessages.MissingFile, stderr);
    }

    [Fact]
    public void Agent_HardwareFailed_ThenNoTerminal_NamesBoth()
    {
        // Lane A's note: when the prompt refuses after an agent failure, the agent's failure is added (ruling 13).
        var (m, _) = TpmPasswordVault("agent-failed");
        FakeAgent(m, () => throw new TswapException("The simulated TPM is unplugged."));

        var (exit, _, stderr) = m.Run("", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Contains(VaultPasswordMessages.NoTerminal + " " +
                        VaultPasswordMessages.AgentAlsoFailed("The simulated TPM is unplugged."), stderr);
    }

    // Review T17 p1 MiMo I2 / p3 GLM I2 (controller: pin the typed-exception semantics at the CLI boundary).

    [Fact]
    public void Agent_HardwareFailed_ThenTerminal_ThePromptStillOpensTheVault()
    {
        // AgentUnlockFailedException is pass 2 failing, not the unlock: the prompt follows (ruling 13).
        var (m, _) = TpmPasswordVault("agent-failed-prompt");
        var (gotBefore, value, errBefore) = m.RunOnTerminal(Password + "\n", "get", "db");
        Assert.True(gotBefore == 0 && value.Length > 0, errBefore);
        FakeAgent(m, () => throw new TswapException("The simulated TPM is unplugged."));

        var (exit, stdout, stderr) = m.RunOnTerminal(Password + "\n", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.Equal(value, stdout);
        Assert.Contains(TerminalPasswordProvider.PromptText, stderr);
    }

    [Fact]
    public void Agent_HardwareFailed_ThenWrongPassword_ExactTextsOfBoth_ExitOne()
    {
        var (m, _) = TpmPasswordVault("agent-failed-wrong");
        FakeAgent(m, () => throw new TswapException("The simulated TPM is unplugged."));

        var (exit, stdout, stderr) = m.RunOnTerminal("not the password\n", "get", "db");

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf + " " +
                        VaultPasswordMessages.AgentAlsoFailed("The simulated TPM is unplugged."), stderr);
    }

    [Fact]
    public void WrongPasswordAtThePrompt_NoAgent_ExactRefusedText_ExitOne()
    {
        var (m, _) = TpmPasswordVault("wrong-no-agent");

        var (exit, stdout, stderr) = m.RunOnTerminal("not the password\n", "get", "db");

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, stderr);
        Assert.DoesNotContain("another machine", stderr); // never relabelled as a foreign slot
    }

    [Fact]
    public void Client_KeyCheckMismatch_OnATerminal_RefusesWithoutPrompting()
    {
        // Ruling 9: a key that fails keyCheck refuses; it is not a pass-2 failure that falls back to the prompt.
        var (m, _) = TpmPasswordVault("mismatch-terminal");
        FakeAgent(m, () => RandomNumberGenerator.GetBytes(32));

        var (exit, _, stderr) = m.RunOnTerminal(Password + "\n", "get", "db");

        Assert.Equal(1, exit);
        Assert.Contains($"The tswap agent at {Address(m)} returned a key that doesn't open this vault; not using it.", stderr);
        Assert.DoesNotContain(TerminalPasswordProvider.PromptText, stderr);
    }

    [Fact]
    public void PasswordFreeVault_NeverConnects()
    {
        var m = Machine("free-vault");
        m.Ok("", "init", "--tpm", "--no-password", "--no-recovery");
        m.Ok("", "create", "db");
        var asked = 0;
        AgentUnlock.AskedObserver = () => Interlocked.Increment(ref asked);
        FakeAgent(m, () => throw new InvalidOperationException("must not be asked"));
        var connects = RecordConnects();

        var (exit, _, stderr) = m.Run("", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.Empty(connects);
        Assert.Equal(0, asked);
        Assert.DoesNotContain(AskingLine, stderr);
    }

    [Fact]
    public void MixedVault_AgentRunning_NeverContacted()
    {
        // Review focus 2: a TPM password slot beside a plugged-in YubiKey slot without the password.
        var (m, _) = TpmPasswordVault("mixed", RecordVaultTestSupport.SerialA);
        var (addExit, _, addErr) = m.RunOnTerminal(Password + "\n", "slot", "add", "--yubikey", "--no-password");
        Assert.True(addExit == 0, addErr);
        FakeAgent(m, () => throw new InvalidOperationException("must not be asked"));
        var connects = RecordConnects();

        var (exit, stdout, stderr) = m.Run("", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.False(string.IsNullOrWhiteSpace(stdout));
        Assert.Empty(connects);
        Assert.DoesNotContain(AskingLine, stderr);
    }

    [Fact]
    public void AskingLine_PrintedOnlyWhenTheAgentIsAsked()
    {
        var (m, vaultKey) = TpmPasswordVault("asking");

        // No agent running: nothing is asked, no line.
        var none = m.Run("", "get", "db");
        Assert.DoesNotContain(AskingLine, none.Err);

        FakeAgent(m, () => vaultKey.ToArray());
        var asked = m.Run("", "get", "db");
        Assert.True(asked.Exit == 0, asked.Err);
        // A TPM slot: no suffix.
        Assert.Contains(AskingLine + Environment.NewLine, asked.Err);
    }

    [Fact]
    public void AskingLine_PasswordYubiKeySlot_SaysTouch()
    {
        var m = Machine("asking-yk", tpm: false, RecordVaultTestSupport.SerialA);
        m.Ok(Password + "\n" + Password + "\n", "init", "--yubikey", "--password", "--no-recovery");
        FakeAgent(m, () => RandomNumberGenerator.GetBytes(32));

        var (_, _, stderr) = m.Run("", "names");

        Assert.Contains(AskingLine + " (touch your YubiKey if it flashes)" + Environment.NewLine, stderr);
    }

    [Fact]
    public void AskingLine_SecureEnclavePresenceSlot_SaysTouchId()
    {
        var m = new FleetMachine("asking-se") { SecureEnclave = RandomNumberGenerator.GetBytes(32) };
        _machines.Add(m);
        _children.Machine = m;
        m.Ok(Password + "\n" + Password + "\n", "init", "--secure-enclave", "--with-touch", "--password", "--no-recovery");
        FakeAgent(m, () => RandomNumberGenerator.GetBytes(32));

        var (_, _, stderr) = m.Run("", "names");

        Assert.Contains(AskingLine + " (Touch ID may ask)" + Environment.NewLine, stderr);
    }

    [Fact]
    public void SudoRoot_FindsOwnersAgent()
    {
        // Review focus 5: under sudo the environment is gone (no TSWAP_AGENT_SOCK); the client finds the
        // agent through the vault owner's uid. The run folder's root is a temp folder here (seam).
        // Root and sudo are Unix's: on Windows the agent has no root refusal and no "(as root, …)" suffix by design
        // (AgentCommand checks !OperatingSystem.IsWindows()); CI run 41619549912 ran this on Windows.
        if (OperatingSystem.IsWindows())
            return;
        var (m, _) = TpmPasswordVault("sudo-get");
        var home = ShortFolder("home");
        AgentUnlock.PathInputs = new AgentSocketPath.Inputs(Path.Combine(m.Dir, "no-run-user"), _ => home, new UnixOwnership(), MacOs: false);
        m.AgentSocket = null;
        Assert.Equal(0, Start(m).Exit);
        Assert.True(File.Exists(Path.Combine(home, ".cache", "tswap", "run", AgentSocketPath.SocketName(VaultId(m)))));

        m.Ownership = new DirectoryOwnerMatcher(new FakeRoot());
        var (exit, stdout, stderr) = m.Run("", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.False(string.IsNullOrWhiteSpace(stdout));
        Assert.Contains(AskingLine, stderr);
    }

    [Fact]
    public void Client_TooLongAgentSockVariable_SaysSo_ThenPrompts()
    {
        // Review T17 p3 MiMo M-11: a TSWAP_AGENT_SOCK the client can't use is reported, not silently skipped.
        if (OperatingSystem.IsWindows())
            return; // the variable is Unix only
        var (m, _) = TpmPasswordVault("long-sock");
        m.AgentSocket = "/" + new string('a', 120) + "/agent.sock";

        var (exit, stdout, stderr) = m.RunOnTerminal(Password + "\n", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.False(string.IsNullOrWhiteSpace(stdout));
        Assert.Contains($"The agent socket path {m.AgentSocket} is 132 bytes, over the 103-byte limit for a socket; set TSWAP_AGENT_SOCK to a shorter path.", stderr);
        Assert.True(stderr.IndexOf("103-byte", StringComparison.Ordinal) < stderr.IndexOf(TerminalPasswordProvider.PromptText, StringComparison.Ordinal), stderr);
    }

    [Fact]
    public void Client_NoAgentSockVariable_NoHomeFolder_StaysSilent()
    {
        // ...while an unset variable with no owner home folder to find an agent by stays silent (none can be asked).
        if (OperatingSystem.IsWindows())
            return;
        var (m, _) = TpmPasswordVault("no-home");
        m.AgentSocket = null;
        AgentUnlock.PathInputs = new AgentSocketPath.Inputs(Path.Combine(m.Dir, "no-run-user"), _ => null, new UnixOwnership(), MacOs: false);

        var (exit, _, stderr) = m.RunOnTerminal(Password + "\n", "get", "db");

        Assert.True(exit == 0, stderr);
        Assert.DoesNotContain("home folder", stderr);
        Assert.DoesNotContain(AskingLine, stderr);
    }

    [Fact]
    public void Client_ZeroesTheKeyAfterUse()
    {
        var (m, vaultKey) = TpmPasswordVault("zeroes");
        FakeAgent(m, () => vaultKey.ToArray());
        var seen = new List<byte[]>();
        CommandContext.AgentKeyZeroedObserver = key => seen.Add(key.ToArray());

        var (exit, _, stderr) = m.Run("", "get", "db");

        Assert.True(exit == 0, stderr);
        var zeroed = Assert.Single(seen);
        Assert.Equal(32, zeroed.Length);
        Assert.All(zeroed, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task Client_OtherVaultsAgent_SaysSo_AndFallsBack()
    {
        var (m, _) = TpmPasswordVault("other-vault");
        var options = new AgentServerOptions(Address(m), RandomNumberGenerator.GetBytes(16),
            () => throw new InvalidOperationException("never"), null, TimeProvider.System, AgentHarness.MyUid);
        _fakeAgents.Add(await AgentServer.StartAsync(options));

        var (exit, _, stderr) = m.Run("", "get", "db");

        Assert.NotEqual(0, exit);
        Assert.Contains(AgentSocketPath.OtherVaultMessage(Address(m)), stderr);
        Assert.Contains(VaultPasswordMessages.NoTerminal, stderr);
    }

    [Fact]
    public void Signals_Windows_NoPosixRegistration_CtrlCStillStops()
    {
        // Review T17 p3 GLM B1: the detached Windows agent must not die after 'ready' on a signal
        // registration; on Windows serve registers no POSIX signal, only a Ctrl+C hook (foreground).
        var registered = new List<PosixSignal>();
        Action? ctrlC = null;
        var unhooked = false;
        var stops = 0;

        using (AgentServeHost.StopOnSignals(() => stops++, isWindows: true,
                   register: (signal, _) => { registered.Add(signal); return new Released(() => { }); },
                   hookCtrlC: handler => { ctrlC = handler; return new Released(() => unhooked = true); }))
        {
            Assert.Empty(registered);
            Assert.NotNull(ctrlC);
            ctrlC!();
            Assert.Equal(1, stops);
        }
        Assert.True(unhooked);
    }

    [Fact]
    public void Signals_Windows_CtrlCHookFails_ServeKeepsRunning()
    {
        // No console after the detach can make the Ctrl+C hook throw; that must never stop serve.
        using var signals = AgentServeHost.StopOnSignals(() => { }, isWindows: true,
            register: (_, _) => throw new PlatformNotSupportedException(),
            hookCtrlC: _ => throw new System.ComponentModel.Win32Exception(6));
        Assert.NotNull(signals);
    }

    [Fact]
    public void Signals_Unix_SigtermAndSigintStop()
    {
        var handlers = new Dictionary<PosixSignal, Action<PosixSignalContext>>();
        var released = 0;
        var stops = 0;

        using (AgentServeHost.StopOnSignals(() => stops++, isWindows: false,
                   register: (signal, handler) => { handlers.Add(signal, handler); return new Released(() => released++); },
                   hookCtrlC: _ => throw new InvalidOperationException("not on Unix")))
        {
            Assert.Equal(new HashSet<PosixSignal> { PosixSignal.SIGINT, PosixSignal.SIGTERM }, handlers.Keys.ToHashSet());
            var term = new PosixSignalContext(PosixSignal.SIGTERM);
            handlers[PosixSignal.SIGTERM](term);
            Assert.True(term.Cancel);
            Assert.Equal(1, stops);
        }
        Assert.Equal(2, released);
    }

    private sealed class Released(Action onDispose) : IDisposable
    {
        public void Dispose() => onDispose();
    }

    // ------------------------------------------------------------------ support

    private static string BrokerNativeName() =>
        TswapCore.Broker.BrokerNative.NameOf(AgentHarness.MyUid) ?? $"uid {AgentHarness.MyUid}";

    /// <summary>Root (the euid seam): privileged, euid 0; files are owned as they really are; no switch happens.</summary>
    private sealed class FakeRoot : IUnixOwnership
    {
        private readonly UnixOwnership _real = new();
        public bool IsPrivileged => true;
        public uint EffectiveUid => 0;
        public (uint Uid, uint Gid)? GetOwner(string path) => _real.GetOwner(path);
        public IDisposable ActAs(uint uid, uint gid, string path) => new Nothing();

        private sealed class Nothing : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }

    /// <summary>
    /// <see cref="AgentCommand.LaunchChild"/> in process: records the start info, then runs <c>agent serve</c>
    /// on a thread of this process with its stdin and stdout on anonymous pipes, through the same
    /// <see cref="AgentCommand.Serve"/> the binary runs. Or, with <see cref="Script"/>, a child that only prints that.
    /// </summary>
    private sealed class InProcessChildren : IDisposable
    {
        private readonly List<Task> _running = [];

        public FleetMachine? Machine { get; set; }
        public string? Script { get; set; }

        /// <summary>With <see cref="Script"/>: runs after the child read its 32 bytes, before it replies.</summary>
        public Action? BeforeReply { get; set; }
        public List<ProcessStartInfo> Started { get; } = [];
        public List<byte[]> ChildInputs { get; } = [];
        /// <summary>
        /// What each child wrote to its parent, in launch order. Recorded as it is written, before the bytes reach the
        /// pipe (<see cref="TeeWriter"/>), so a line the parent has read is already here: a test may read this as soon
        /// as the parent returns, without waiting for the child's task to finish.
        /// </summary>
        public List<string> ChildOutputs
        {
            get
            {
                lock (_recordings)
                    return [.. _recordings.Select(recording => { lock (recording) return recording.ToString().TrimEnd('\n'); })];
            }
        }

        private readonly List<StringBuilder> _recordings = [];
        public List<string> Events { get; } = [];
        private readonly List<(FleetMachine Machine, CommandContext Context)> _agents = [];


        /// <summary>
        /// How many in-process agents are still running, after giving each up to 10 s to finish: a child that has
        /// written its last line (an error the parent has already read) may still be in its task's clean-up when the
        /// parent returns, which is not "still running". One that serves on never finishes, so it is counted.
        /// </summary>
        public int Running
        {
            get
            {
                Task.WhenAll(_running).Wait(TimeSpan.FromSeconds(10));
                return _running.Count(t => !t.IsCompleted);
            }
        }

        public IAgentChild Launch(ProcessStartInfo psi)
        {
            Started.Add(psi);
            var toChild = new AnonymousPipeServerStream(PipeDirection.Out);
            var childIn = new AnonymousPipeClientStream(PipeDirection.In, toChild.ClientSafePipeHandle);
            var fromChild = new AnonymousPipeServerStream(PipeDirection.In);
            var childOut = new AnonymousPipeClientStream(PipeDirection.Out, fromChild.ClientSafePipeHandle);
            var output = new StreamReader(fromChild);
            var args = psi.ArgumentList.ToArray();
            var machine = Machine!;
            var recorded = new StringBuilder();
            lock (_recordings)
                _recordings.Add(recorded);

            var task = Task.Run(() =>
            {
                var readyOut = new StreamWriter(childOut) { AutoFlush = true };
                var tee = new TeeWriter(readyOut, recorded, text =>
                {
                    if (text.StartsWith("ready", StringComparison.Ordinal))
                        Events.Add("ready");
                });
                try
                {
                    if (Script is { } script)
                    {
                        // Everything up to end of file (the parent closes its end after writing), so a parent that
                        // wrote too few or too many bytes shows in ChildInputs instead of hanging a fixed-size read.
                        using var input = new MemoryStream();
                        childIn.CopyTo(input);
                        ChildInputs.Add(input.ToArray());
                        BeforeReply?.Invoke();
                        tee.Write(script);
                        return 0;
                    }
                    var console = new FakeConsole("");
                    var ctx = machine.Context(console, args);
                    lock (_agents)
                        _agents.Add((machine, ctx));
                    var host = new AgentServeHost(
                        new RecordingStream(childIn, this),
                        tee,
                        Detach: () =>
                        {
                            Events.Add("detach");
                            readyOut.Dispose(); // the parent sees end of file, as after the real child's reopen
                        },
                        Harden: _ => Events.Add("harden"),
                        HandleSignals: _ => new NoSignals());
                    return AgentCommand.Serve(ctx, args[2..], host);
                }
                finally
                {
                    try { readyOut.Dispose(); } catch (ObjectDisposedException) { }
                    childIn.Dispose();
                }
            });
            _running.Add(task);
            return new Child(toChild, output, fromChild);
        }

        /// <summary>Waits until every in-process agent has returned (each test stops its own).</summary>
        public void WaitForAllToStop()
        {
            Assert.True(Task.WhenAll(_running).Wait(TimeSpan.FromSeconds(30)), "an in-process agent did not stop");
        }

        public void Dispose()
        {
            // Each in-process agent is stopped the way a user would; the test's own seams still apply.
            List<FleetMachine> machines;
            lock (_agents)
                machines = _agents.Select(a => a.Machine).Distinct().ToList();
            foreach (var machine in machines)
                machine.Run("", "agent", "stop");
            WaitForAllToStop();
        }

        private sealed class Child(Stream input, TextReader output, Stream outputPipe) : IAgentChild
        {
            public Stream Input => input;
            public TextReader Output => output;
            public TextReader? Errors => null;

            public void Dispose()
            {
                input.Dispose();
                output.Dispose();
                outputPipe.Dispose();
            }
        }

        private sealed class RecordingStream(Stream inner, InProcessChildren owner) : Stream
        {
            public override int Read(byte[] buffer, int offset, int count)
            {
                var n = inner.Read(buffer, offset, count);
                lock (owner.ChildInputs)
                {
                    if (owner.Events.LastOrDefault() != "read")
                        owner.Events.Add("read");
                    if (owner.ChildInputs.Count == 0)
                        owner.ChildInputs.Add([]);
                    owner.ChildInputs[^1] = [.. owner.ChildInputs[^1], .. buffer.AsSpan(offset, n).ToArray()];
                }
                return n;
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private sealed class TeeWriter(TextWriter inner, StringBuilder copy, Action<string> onText) : TextWriter
        {
            public override Encoding Encoding => inner.Encoding;

            public override void Write(char value) => Write(value.ToString());

            public override void Write(string? value)
            {
                // Recorded before the parent can read it (ChildOutputs).
                lock (copy)
                    copy.Append(value);
                onText(value ?? "");
                inner.Write(value);
            }

            public override void WriteLine(string? value) => Write(value + "\n");

            public override void Flush() => inner.Flush();
        }

        private sealed class NoSignals : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }
}
