using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;

namespace TswapCli.Commands;

/// <summary>
/// <c>tswap agent</c> (brief T17 task 11, rulings 4, 10, 11, 12, 13 and 21): holds the stretched vault password in
/// memory, like <c>ssh-agent</c>, and unlocks this vault for the vault user's commands, which ask it before they
/// prompt (<see cref="AgentUnlock"/>).
/// <list type="bullet">
/// <item><b><c>start [--timeout &lt;d&gt;]</c></b>: refuses root; asks for the password on the terminal and
/// stretches it; starts <c>agent serve</c> as a background child and hands it the 32 stretched bytes on its stdin
/// (never argv or the environment); relays the child's <c>ready</c> or <c>error</c> line, printing its own socket
/// path.</item>
/// <item><b><c>serve</c></b> (the child): hardens the process, reads the 32 bytes, proves them with one real unlock
/// checked against the <c>vault-password</c> file's verifier, listens (<see cref="AgentServer"/>), prints
/// <c>ready &lt;path&gt; &lt;expiry&gt;</c>, then reopens its stdio on <c>/dev/null</c> and leaves the session.
/// <c>serve --foreground</c> reads the password from its own terminal instead.</item>
/// <item><b><c>stop</c>, <c>status</c></b>: ask the vault owner's agent; allowed under sudo (the agent accepts
/// root), and they say so.</item>
/// </list>
/// The agent's own unlocks pass no agent source (ruling 13), so it never asks itself.
/// </summary>
public sealed class AgentCommand : ICliCommand
{
    public string Name => "agent";
    public string HelpUsage => "agent <start [--timeout <d>]|serve [--foreground]|stop|status>";
    public string Description =>
        "Hold the vault password in memory so commands need no prompt, like ssh-agent (run as the vault user, never with sudo)";
    public bool RequiresSudo => false;

    private const string Usage =
        "tswap agent start [--timeout <d>] | tswap agent serve [--foreground] [--timeout <d>] | tswap agent stop | tswap agent status\n" +
        "  " + AgentDuration.Usage;

    /// <summary>The RAM disclosure (Global constraints), verbatim from the spec, once per start.</summary>
    public const string RamDisclosure =
        "The agent keeps your stretched vault password in memory until you stop it or it times out. Root, or anything that can read this process's memory, can take it while it runs; it still needs this machine's TPM/YubiKey/Secure Enclave to open the vault.";

    /// <summary>Ruling 19: the macOS line after the disclosure when a password Secure Enclave slot is held.</summary>
    public const string SecureEnclaveRamLine =
        "On this Mac the Secure Enclave library also holds a copy during each unlock, which tswap can't wipe.";

    /// <summary>Ruling 10.</summary>
    public const string NothingToHoldText =
        "No slot of this vault on this machine needs the vault password; the agent has nothing to hold.";

    /// <summary>Ruling 10.</summary>
    public static string PlugInText(IEnumerable<int> serials) =>
        $"No password slot is usable right now (plug in YubiKey {string.Join(", ", serials)}) and try again.";

    /// <summary>Ruling 10.</summary>
    public const string ForegroundNoTerminalText =
        "agent serve --foreground reads the password from a terminal; there is none. Run 'tswap agent start' from your session.";

    public const string StartNoTerminalText =
        "agent start reads the vault password from a terminal; there is none. Run 'tswap agent start' from your session.";

    public const string ServeNoInputText =
        "agent serve reads the stretched password from 'tswap agent start'; run that instead (or 'tswap agent serve --foreground' in a terminal).";

    /// <summary>Ruling 10: the proving unlock opened the vault, but the password fails the verifier.</summary>
    public const string VerifierMismatchText =
        "That password doesn't match this vault's vault-password file; the agent won't hold it.";

    public const string ExitedWithoutStartingText = "The agent exited without starting.";

    /// <summary>
    /// Test seam: starts the <c>agent serve</c> child (null: a real process). Tests run the child in process,
    /// through <see cref="Serve"/>.
    /// </summary>
    internal static Func<ProcessStartInfo, IAgentChild>? LaunchChild;

    public int Execute(CommandContext ctx, string[] args) => args switch
    {
        ["start", .. var rest] => Start(ctx, rest),
        ["serve", .. var rest] => ServeThisProcess(ctx, rest),
        ["stop"] => Stop(ctx),
        ["status"] => Status(ctx),
        _ => throw new UsageException(Usage),
    };

    // ------------------------------------------------------------------ start

    private static int Start(CommandContext ctx, string[] args)
    {
        var (_, _, timeoutText) = ParseOptions(args, allowForeground: false);
        var ownership = AgentUnlock.Ownership(ctx);
        RefuseRoot(ctx, ownership);
        var (config, vaultId) = LoadVault(ctx);
        RequireSomethingToHold(ctx, config);
        var file = RequireFile(ctx, config);
        var location = AgentUnlock.Resolve(ctx, vaultId);
        RefuseIfRunning(location, vaultId);

        var c = ctx.Console;
        if (c.IsInputRedirected)
            throw new TswapException(StartNoTerminalText);
        PrintDisclosure(c, config);
        c.Error.Write(TerminalPasswordProvider.PromptText);
        var password = c.ReadPassword(c.Error);

        var psi = ChildStartInfo(ctx, timeoutText);
        var stretched = VaultPasswordKdf.Stretch(password, file.Salt, file.Params, c.Error);
        string reply;
        using (var child = Launch(psi, stretched))
        {
            // The child's stderr (a touch prompt, a warning) reaches the user until the child is ready. Not
            // awaited: the agent's own copy of that pipe outlives this process, which closes its end on exit.
            if (child.Errors is { } errors)
                _ = Task.Run(() => RelayErrors(errors, c.Error));
            // No time bound (ruling 10): the proving unlock may wait for a touch; Ctrl+C ends both.
            reply = ReadReply(child.Output);
        }
        return Relay(c, reply, location.Path);
    }

    /// <summary>
    /// The child's <c>ready &lt;path&gt; &lt;expiry&gt;</c> or <c>error &lt;message&gt;</c>, without waiting for the end of
    /// its output. A path may hold a newline, so a <c>ready</c> reply is read until a line ends in an expiry.
    /// </summary>
    private static string ReadReply(TextReader output)
    {
        var line = output.ReadLine();
        if (line is null || !line.StartsWith("ready ", StringComparison.Ordinal))
            return line ?? "";
        var text = line;
        while (!IsExpiry(line.Split(' ')[^1]) && output.ReadLine() is { } next)
        {
            line = next;
            text += "\n" + next;
        }
        return text;
    }

    private static bool IsExpiry(string word) =>
        word == "no-expiry" || DateTimeOffset.TryParseExact(word, ExpiryFormat, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out _);

    private static void RelayErrors(TextReader errors, TextWriter to)
    {
        var buffer = new char[256];
        try
        {
            int n;
            while ((n = errors.Read(buffer, 0, buffer.Length)) > 0)
            {
                to.Write(buffer, 0, n);
                to.Flush();
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            // This process is done with the child.
        }
    }

    /// <summary>
    /// The child's reply. The path printed is the parent's own (ruling 10): the reply is read for its status
    /// and its last word, the expiry, only.
    /// </summary>
    private static int Relay(IConsole c, string reply, string path)
    {
        if (reply.StartsWith("ready ", StringComparison.Ordinal))
        {
            var expiry = reply.TrimEnd('\r', '\n').Split(' ')[^1];
            c.Out.WriteLine($"The tswap agent is running for this vault at {path}.");
            if (expiry == "no-expiry")
                c.Out.WriteLine("It holds the vault password until 'tswap agent stop'.");
            else if (IsExpiry(expiry))
                c.Out.WriteLine($"It holds the vault password until {expiry} (or until 'tswap agent stop').");
            else
                c.Out.WriteLine("It holds the vault password until it times out or 'tswap agent stop'.");
            return 0;
        }
        if (reply.StartsWith("error ", StringComparison.Ordinal))
            throw new TswapException(reply["error ".Length..].Split('\n')[0].TrimEnd('\r'));
        throw new TswapException(ExitedWithoutStartingText);
    }

    private const string ExpiryFormat = "yyyy-MM-ddTHH:mm:ssZ";

    private static string FormatExpiry(DateTimeOffset? expiresAt) =>
        expiresAt is { } at ? at.UtcDateTime.ToString(ExpiryFormat, CultureInfo.InvariantCulture) : "no-expiry";

    /// <summary>
    /// <c>agent serve</c> as a child of this binary, with only non-secret arguments; the config folder and the
    /// socket variable are pinned to the parent's, and the Debug-only terminal seam is dropped (the child's stdin
    /// is the pipe the password comes on).
    /// </summary>
    private static ProcessStartInfo ChildStartInfo(CommandContext ctx, string? timeoutText)
    {
        var processPath = Environment.ProcessPath ?? throw new TswapException("Can't tell which tswap binary is running, to start the agent.");
        var psi = new ProcessStartInfo
        {
            FileName = processPath,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true, // relayed until ready, so the child never holds this process's stderr
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("agent");
        psi.ArgumentList.Add("serve");
        if (timeoutText is not null)
        {
            psi.ArgumentList.Add("--timeout");
            psi.ArgumentList.Add(timeoutText);
        }
        psi.Environment["TSWAP_CONFIG_DIR"] = ctx.Env.ConfigDir;
        if (ctx.Env.AgentSocketVariable is { Length: > 0 } socket)
            psi.Environment[AgentSocketPath.Variable] = socket;
        else
            psi.Environment.Remove(AgentSocketPath.Variable);
        psi.Environment.Remove("TSWAP_TEST_TERMINAL");
        return psi;
    }

    private static IAgentChild StartProcess(ProcessStartInfo psi)
    {
        var process = Process.Start(psi) ?? throw new TswapException(ExitedWithoutStartingText);
        return new ProcessChild(process);
    }

    /// <summary>
    /// Starts the child and hands it <paramref name="stretched"/> on its stdin, then end of file; this process's
    /// copies (the held one and the write buffer) are zeroed before the child's reply is waited for.
    /// </summary>
    private static IAgentChild Launch(ProcessStartInfo psi, StretchedPassword stretched)
    {
        var bytes = new byte[StretchedPassword.Size];
        IAgentChild? child = null;
        try
        {
            child = (LaunchChild ?? StartProcess)(psi);
            stretched.CopyTo(bytes);
            try
            {
                child.Input.Write(bytes);
                child.Input.Flush();
                child.Input.Dispose(); // end of file: the child reads exactly 32 bytes
            }
            catch (IOException)
            {
                // The child is gone already; its error line (or none) says why.
            }
            return child;
        }
        catch
        {
            child?.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            stretched.Dispose();
        }
    }

    private sealed class ProcessChild(Process process) : IAgentChild
    {
        public Stream Input => process.StandardInput.BaseStream;
        public TextReader Output => process.StandardOutput;
        public TextReader Errors => process.StandardError;

        // Never kills: a started agent outlives this process.
        public void Dispose() => process.Dispose();
    }

    // ------------------------------------------------------------------ serve

    private static int ServeThisProcess(CommandContext ctx, string[] args)
    {
        // Ruling 10: the child ignores SIGHUP (a closing terminal); SIGINT still ends it until it is ready.
        using var hangup = OperatingSystem.IsWindows() ? null : PosixSignalRegistration.Create(PosixSignal.SIGHUP, s => s.Cancel = true);
        return Serve(ctx, args, AgentServeHost.ForThisProcess());
    }

    /// <summary>
    /// <c>agent serve [--foreground] [--timeout &lt;d&gt;]</c> with <paramref name="host"/>'s stdin, stdout and
    /// process steps (the real process's, or a test's).
    /// </summary>
    internal static int Serve(CommandContext ctx, string[] args, AgentServeHost host)
    {
        var (foreground, timeout, _) = ParseOptions(args, allowForeground: true);
        if (foreground)
            return Foreground(ctx, timeout, host);

        AgentServer server;
        DateTimeOffset? expiresAt;
        try
        {
            server = StartChildAgent(ctx, timeout, host, out expiresAt);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            host.ReadyOut.WriteLine("error " + AgentServer.SafeMessage(ex));
            host.ReadyOut.Flush();
            return 1;
        }
        try
        {
            host.ReadyOut.WriteLine($"ready {server.SocketPath} {FormatExpiry(expiresAt)}");
            host.ReadyOut.Flush();
        }
        catch (IOException)
        {
            // 'agent start' is gone (Ctrl+C): nobody was told this agent runs, so it doesn't.
            server.StopAsync().GetAwaiter().GetResult();
            return 1;
        }
        host.Detach();
        return Run(server, host);
    }

    /// <summary>Everything before the child's <c>ready</c> line; throws for its <c>error</c> line.</summary>
    private static AgentServer StartChildAgent(CommandContext ctx, TimeSpan? timeout, AgentServeHost host, out DateTimeOffset? expiresAt)
    {
        var ownership = AgentUnlock.Ownership(ctx);
        RefuseRoot(ctx, ownership);
        if (!ctx.Console.IsInputRedirected)
            throw new TswapException(ServeNoInputText);
        var (config, vaultId) = LoadVault(ctx);
        RequireSomethingToHold(ctx, config);
        var file = RequireFile(ctx, config);
        var location = AgentUnlock.Resolve(ctx, vaultId);

        // Ruling 12: hardened before the password is in this process's memory.
        host.Harden(line => ctx.Console.Error.WriteLine(line));
        StretchedPassword held;
        using (host.Input)
            held = ReadHeld(host.Input, ctx.Console.Error);
        return Listen(ctx, ownership, config, vaultId, file, location, held, timeout, out expiresAt);
    }

    private static int Foreground(CommandContext ctx, TimeSpan? timeout, AgentServeHost host)
    {
        var ownership = AgentUnlock.Ownership(ctx);
        RefuseRoot(ctx, ownership);
        var c = ctx.Console;
        if (c.IsInputRedirected)
            throw new TswapException(ForegroundNoTerminalText);
        var (config, vaultId) = LoadVault(ctx);
        RequireSomethingToHold(ctx, config);
        var file = RequireFile(ctx, config);
        var location = AgentUnlock.Resolve(ctx, vaultId);
        RefuseIfRunning(location, vaultId);

        host.Harden(line => c.Error.WriteLine(line));
        PrintDisclosure(c, config);
        c.Error.Write(TerminalPasswordProvider.PromptText);
        var held = VaultPasswordKdf.Stretch(c.ReadPassword(c.Error), file.Salt, file.Params, c.Error);
        var server = Listen(ctx, ownership, config, vaultId, file, location, held, timeout, out var expiresAt);
        c.Out.WriteLine($"The tswap agent is running for this vault at {server.SocketPath} " +
                        (expiresAt is null ? "with no timeout" : $"until {FormatExpiry(expiresAt)}") + "; Ctrl+C stops it.");
        return Run(server, host);
    }

    /// <summary>Proves <paramref name="held"/> and starts the server holding it; disposes it on any failure.</summary>
    private static AgentServer Listen(CommandContext ctx, IUnixOwnership ownership, Config config, byte[] vaultId,
        VaultPasswordFile file, AgentUnlock.Location location, StretchedPassword held, TimeSpan? timeout, out DateTimeOffset? expiresAt)
    {
        try
        {
            Prove(ctx, config, file, held);
            expiresAt = timeout is { } t ? ctx.Time.GetUtcNow() + t : null;
            var options = new AgentServerOptions(location.Path, vaultId, () => UnlockWithHeld(ctx, held), expiresAt, ctx.Time,
                ownership.EffectiveUid)
            {
                Ownership = ownership,
                Held = held,
                Log = line => ctx.Console.Error.WriteLine(line),
                VaultUserName = VaultUserName(ctx, ownership),
            };
            return AgentServer.StartAsync(options).GetAwaiter().GetResult();
        }
        catch
        {
            held.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Ruling 10: one real unlock with the held password through a <b>password slot of this machine</b>
    /// (<see cref="VaultUnlocker.UnlockWithPasswordSlots"/>: no password-free slot, no agent, no prompt), and
    /// the unlocked <c>K_v</c> with the held bytes checked against the file's verifier. <c>K_v</c> is zeroed.
    /// </summary>
    private static void Prove(CommandContext ctx, Config config, VaultPasswordFile file, StretchedPassword held)
    {
        var vaultKey = ctx.Unlocker.UnlockWithPasswordSlots(config, ctx.UnlockSelection() with { Ask = null }, held);
        try
        {
            if (!file.Verifies(vaultKey, held))
                throw new TswapException(VerifierMismatchText);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }

    /// <summary>An agent request: the current config, unlocked with clones of the held password (ruling 4).</summary>
    private static byte[] UnlockWithHeld(CommandContext ctx, StretchedPassword held) => Unlock(ctx, ctx.Storage.LoadConfig(), held);

    /// <summary>Ruling 13: <c>UnlockSources(AskAgent: null, Prompt: held password)</c>, never through <see cref="CommandContext.Unlock"/>.</summary>
    private static byte[] Unlock(CommandContext ctx, Config config, StretchedPassword held) =>
        ctx.Unlocker.Unlock(config, ctx.UnlockSelection() with { Ask = null }, new UnlockSources(AskAgent: null, Prompt: held.Clone));

    private static StretchedPassword ReadHeld(Stream input, TextWriter warnings)
    {
        var buffer = new byte[StretchedPassword.Size];
        try
        {
            if (input.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false) < buffer.Length)
                throw new TswapException(ServeNoInputText);
            return StretchedPassword.FromBytes(buffer, warnings);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>Serves until the agent stops: <c>agent stop</c>, its deadline, or SIGTERM (and SIGINT).</summary>
    private static int Run(AgentServer server, AgentServeHost host)
    {
        using (host.HandleSignals(() => _ = server.StopAsync()))
            server.Stopped.GetAwaiter().GetResult();
        return 0;
    }

    // ------------------------------------------------------------------ stop, status

    private static int Stop(CommandContext ctx)
    {
        var (_, vaultId) = LoadVault(ctx);
        var location = AgentUnlock.Resolve(ctx, vaultId);
        switch (AgentClient.Stop(location.Path, vaultId, location.OwnerUid))
        {
            case AgentAnswer.Stopped:
                ctx.Console.Out.WriteLine($"Stopped the tswap agent at {location.Path}{ForWhom(location)}.");
                return 0;
            case AgentAnswer.OtherVault:
                throw new TswapException(AgentSocketPath.OtherVaultMessage(location.Path));
            default:
                ctx.Console.Error.WriteLine(NotRunning(location));
                return 1;
        }
    }

    private static int Status(CommandContext ctx)
    {
        var (_, vaultId) = LoadVault(ctx);
        var location = AgentUnlock.Resolve(ctx, vaultId);
        switch (AgentClient.Status(location.Path, vaultId, location.OwnerUid))
        {
            case AgentAnswer.Running running:
                var o = ctx.Console.Out;
                o.WriteLine($"The tswap agent for this vault is running at {location.Path}{ForWhom(location)}.");
                o.WriteLine(running.ExpiresAt is { } at ? $"expires: {FormatExpiry(at)}" : "expires: never (until 'tswap agent stop')");
                o.WriteLine($"refused peers: {running.RefusedPeers}");
                return 0;
            case AgentAnswer.OtherVault:
                throw new TswapException(AgentSocketPath.OtherVaultMessage(location.Path));
            default:
                ctx.Console.Error.WriteLine(NotRunning(location));
                return 1;
        }
    }

    private static string NotRunning(AgentUnlock.Location location) =>
        $"No tswap agent is running for this vault ({location.Path}){ForWhom(location)}.";

    /// <summary>Ruling 21: under sudo, <c>stop</c> and <c>status</c> say whose agent they reached.</summary>
    private static string ForWhom(AgentUnlock.Location location) =>
        !OperatingSystem.IsWindows() && location.Ownership.IsPrivileged
            ? $" (as root, for {BrokerNative.NameOf(location.OwnerUid) ?? $"uid {location.OwnerUid}"}'s agent)"
            : "";

    // ------------------------------------------------------------------ shared

    private static (bool Foreground, TimeSpan? Timeout, string? TimeoutText) ParseOptions(string[] args, bool allowForeground)
    {
        var foreground = false;
        string? text = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--foreground" when allowForeground && !foreground:
                    foreground = true;
                    break;
                case "--timeout" when text is null && i + 1 < args.Length:
                    text = args[++i];
                    break;
                default:
                    throw new UsageException(Usage);
            }
        }
        return (foreground, text is null ? null : AgentDuration.Parse(text), text);
    }

    /// <summary>Ruling 21: before anything is created or read from the terminal.</summary>
    private static void RefuseRoot(CommandContext ctx, IUnixOwnership ownership)
    {
        if (!OperatingSystem.IsWindows() && ownership.IsPrivileged)
            throw new TswapException(AgentServer.RootRefusal(VaultUserName(ctx, ownership)));
    }

    private static string VaultUserName(CommandContext ctx, IUnixOwnership ownership)
    {
        try
        {
            var uid = AgentUnlock.OwnerUid(ctx, ownership);
            return BrokerNative.NameOf(uid) ?? $"uid {uid}";
        }
        catch (Exception ex) when (ex is TswapException or IOException or InvalidOperationException)
        {
            return "the vault's owner";
        }
    }

    private static (Config Config, byte[] VaultId) LoadVault(CommandContext ctx)
    {
        var config = ctx.Storage.LoadConfig();
        if (config.Keyring is null)
            throw new TswapException("This vault has no keyring, so it has no vault password for an agent to hold.");
        return (config, KeyringCodec.Decode(Convert.FromBase64String(config.Keyring)).VaultId);
    }

    /// <summary>Ruling 10: a password slot this machine can use now (its own, or a password YubiKey slot plugged in).</summary>
    private static void RequireSomethingToHold(CommandContext ctx, Config config)
    {
        var own = VaultUnlocker.CouldNeedPassword(config, []);
        var serials = AgentUnlock.PasswordYubiKeySerials(config);
        if (!own && serials.Count == 0)
            throw new TswapException(NothingToHoldText);
        if (!own && !VaultUnlocker.CouldNeedPassword(config, AgentUnlock.PluggedIn(ctx)))
            throw new TswapException(PlugInText(serials));
    }

    private static VaultPasswordFile RequireFile(CommandContext ctx, Config config) =>
        TerminalPasswordProvider.ReadFile(ctx, config) ?? throw new TswapException(VaultPasswordMessages.MissingFile);

    /// <summary>A running agent for this vault: said before the password is asked for (the server's lock decides a race).</summary>
    private static void RefuseIfRunning(AgentUnlock.Location location, byte[] vaultId)
    {
        if (AgentClient.Status(location.Path, vaultId, location.OwnerUid) is AgentAnswer.Running)
            throw new TswapException(AgentServer.AlreadyRunning(location.Path));
    }

    private static void PrintDisclosure(IConsole c, Config config)
    {
        c.Out.WriteLine(RamDisclosure);
        if (OperatingSystem.IsMacOS() && config.Backend == HardwareBackend.SecureEnclave && VaultUnlocker.CouldNeedPassword(config, []))
            c.Out.WriteLine(SecureEnclaveRamLine);
    }
}

/// <summary>The <c>agent serve</c> child as <c>agent start</c> sees it (a process, or a test's stand-in).</summary>
internal interface IAgentChild : IDisposable
{
    /// <summary>The child's stdin: the 32 stretched bytes, then end of file.</summary>
    Stream Input { get; }

    /// <summary>The child's stdout: its one <c>ready</c> or <c>error</c> line.</summary>
    TextReader Output { get; }

    /// <summary>The child's stderr, relayed to the user until the child is ready (null: the child shares this process's).</summary>
    TextReader? Errors { get; }
}

/// <summary>
/// What <c>agent serve</c> takes from its process (brief T17 ruling 10): the stdin the stretched password comes
/// on, the stdout its <c>ready</c>/<c>error</c> line goes to, and the process steps: hardening (ruling 12),
/// detaching from the starting session after <c>ready</c>, and stopping on a signal.
/// </summary>
internal sealed record AgentServeHost(
    Stream Input,
    TextWriter ReadyOut,
    Action Detach,
    Action<Action<string>> Harden,
    Func<Action, IDisposable> HandleSignals)
{
    /// <summary>
    /// This process. On Unix stdin and stdout are fds 0 and 1 themselves, not .NET's console streams (which are
    /// <c>dup()</c>s): reopening fd 1 on <c>/dev/null</c> then really closes the parent's pipe.
    /// </summary>
    public static AgentServeHost ForThisProcess() => new(
        OperatingSystem.IsWindows() ? Console.OpenStandardInput() : new FileStream(new SafeFileHandle(0, ownsHandle: false), FileAccess.Read, 1),
        new StreamWriter(OperatingSystem.IsWindows()
            ? Console.OpenStandardOutput()
            : new FileStream(new SafeFileHandle(1, ownsHandle: false), FileAccess.Write, 1)) { AutoFlush = true },
        Detach: () => ProcessDetach.Detach(), // nowhere left to report a failed step: stdio is gone
        Harden: ProcessHardening.HardenHolder,
        HandleSignals: StopOnSignals);

    private static IDisposable StopOnSignals(Action stop)
    {
        var registrations = new List<PosixSignalRegistration>
        {
            PosixSignalRegistration.Create(PosixSignal.SIGTERM, s =>
            {
                s.Cancel = true;
                stop();
            }),
            PosixSignalRegistration.Create(PosixSignal.SIGINT, s =>
            {
                s.Cancel = true;
                stop();
            }),
        };
        return new Registrations(registrations);
    }

    private sealed class Registrations(List<PosixSignalRegistration> registrations) : IDisposable
    {
        public void Dispose()
        {
            foreach (var r in registrations)
                r.Dispose();
        }
    }
}
