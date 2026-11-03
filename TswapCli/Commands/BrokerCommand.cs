using System.Runtime.InteropServices;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using TswapCore.Broker.Templates;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;

namespace TswapCli.Commands;

/// <summary>
/// <c>tswap broker</c> (brief T8): a credential-adding HTTP proxy. <c>serve</c> runs as the vault's
/// user and listens on one Unix socket per client; <c>forward</c> runs inside a container and relays
/// a loopback TCP port to that socket. Changing <c>broker.json</c> (<c>route|socket add|remove</c>)
/// needs sudo. Unix only.
/// </summary>
public sealed class BrokerCommand : ICliCommand
{
    public string Name => "broker";
    public string HelpUsage => "broker <serve|unlock|lock|status|forward|call|route|socket|template> ...";
    public string Description =>
        "Credentials for containers that never hold them: HTTP routes, command templates and an ssh-agent (serve, and unlock|lock|status for a broker whose slot has the vault password, as the vault user; forward/call in the container; sudo for route|socket|template add|remove)";

    // serve, forward and call never need sudo (serve refuses root); only config changes do, checked inside.
    public bool RequiresSudo => false;

    private const string Usage =
        "Usage:\n" +
        "  tswap broker serve\n" +
        "  tswap broker unlock [--timeout <90m|8h|1d12h|seconds>]   (a broker whose slot has the vault password starts locked)\n" +
        "  tswap broker lock\n" +
        "  tswap broker status\n" +
        "  tswap broker forward --listen 127.0.0.1:<port> [--socket /run/tswap.sock]\n" +
        "  tswap broker call <template> [name=value ...] [--socket /run/tswap.sock]   (exit 125: the broker refused or failed)\n" +
        "  sudo tswap broker route add <name> --upstream https://host[/base] --auth bearer|basic|header --secret <secret-name>\n" +
        "        [--user <basic-user>] [--header <header-name>] --path <regex> [--methods GET,HEAD,POST] [--idle-timeout <sec>]\n" +
        "  sudo tswap broker route remove <name>\n" +
        "  sudo tswap broker socket add <name> --uids <uid|N-M>[,...] [--routes <route>[,...]] [--templates <template>[,...]] [--socket-dir <dir>]\n" +
        "  sudo tswap broker socket remove <name>\n" +
        "  sudo tswap broker template add <file.json|->\n" +
        "  sudo tswap broker template remove <name>";

    public int Execute(CommandContext ctx, string[] args)
    {
        if (OperatingSystem.IsWindows())
            throw new TswapException("'tswap broker' is not supported on Windows (it needs Unix sockets and peer credentials; Linux and macOS only).");
        return args switch
        {
            ["serve"] => Serve(ctx),
            ["unlock", ..] => Unlock(ctx, args[1..]),
            ["lock"] => Lock(ctx),
            ["status"] => Status(ctx),
            ["forward", ..] => Forward(ctx, args[1..]),
            ["call", ..] => Call(ctx, args[1..]),
            ["route", "add", ..] => RouteAdd(ctx, args[2..]),
            ["route", "remove", ..] => RouteRemove(ctx, args[2..]),
            ["socket", "add", ..] => SocketAdd(ctx, args[2..]),
            ["socket", "remove", ..] => SocketRemove(ctx, args[2..]),
            ["template", "add", ..] => TemplateAdd(ctx, args[2..]),
            ["template", "remove", ..] => TemplateRemove(ctx, args[2..]),
            _ => throw new TswapException(Usage),
        };
    }

    // ------------------------------------------------------------------ serve

    /// <summary>
    /// Runs the broker until SIGTERM/SIGINT; SIGHUP reloads broker.json (a valid file is swapped
    /// in, an invalid or missing one keeps the current config).
    /// </summary>
    private static int Serve(CommandContext ctx)
    {
        // Owner decision (fix round 1): one record is decrypted per request, never the whole vault.
        if (ctx.Storage is not RecordVaultStore records)
            throw new TswapException(
                "'tswap broker serve' needs a record-store vault, so each request decrypts only its route's secret " +
                "(a classic vault would be decrypted whole for every request). Convert it first: sudo tswap migrate --to-records");

        // Brief T17 (ruling 6): refused before anything is created, with BrokerServer's own words.
        if (Ownership.IsPrivileged)
            throw new TswapException("'tswap broker serve' must run as the vault's own user, never as root (run it from the vault user's systemd user unit).");

        // Brief T17 ruling 14: this machine's slot decides. A password slot starts locked; a slot this
        // build can't use (newer tswap, corrupt) refuses to start.
        var vaultConfig = records.LoadConfig();
        var own = VaultUnlocker.OwnSlotPassword(vaultConfig);
        if (own.Kind is SlotPasswordKind.NeedsNewerTswap or SlotPasswordKind.Corrupt)
            throw new TswapException($"Slot {own.SlotId8}: {own.Error}");
        var withPassword = own.Kind == SlotPasswordKind.Password;

        // Decision 1: no same-uid ptrace, no core dumps holding secrets. Brief T17 ruling 12: a password
        // broker is dumpable only while locked with nothing held (so 'broker unlock' can check it).
        BrokerPasswordState.HardenAtStart(BrokerHardening.Native, withPassword, ctx.Console.Error.WriteLine);

        var owner = Owner(ctx);
        var configDir = ctx.Env.ConfigDir;
        var host = Host(ctx);
        var holder = new BrokerPolicyHolder(BrokerConfigFile.Load(owner, configDir, host: host));
        using var log = new BrokerLog(ctx.Console.Error, Path.Combine(configDir, BrokerLog.FileName));
        using var forwarder = new HttpBrokerForwarder(TimeProvider.System);
        var fatalHardening = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var state = withPassword
            ? new BrokerPasswordState(BrokerHardening.Native, TimeProvider.System, log.Event, reason => fatalHardening.TrySetResult(reason))
            : null;
        var deferredKeys = state is null ? null : new DeferredSshKeys();
        var sshAgent = SshAgentFor(ctx, records, holder.Current, state, deferredKeys);
        var options = new BrokerServerOptions
        {
            SshAgent = sshAgent,
            Policy = holder,
            Secrets = new VaultBrokerSecretSource(records, ctx.Unlocker, state?.Provider),
            Forwarder = forwarder,
            Log = log,
            Password = state,
        };
#if DEBUG
        // The end-to-end tests connect as their own uid, which serve otherwise refuses, on the HTTP
        // and the ssh-agent sockets alike (one switch). Compiled into Debug builds only (fix round 1);
        // there, only with TSWAP_TEST_KEY set (a test key).
        options = options with { AllowOwnUidForTests = ctx.TestKey is not null };
#endif

        var stop = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        BrokerServer? server = null;
        void Stop(PosixSignalContext signal)
        {
            signal.Cancel = true;
            stop.TrySetResult();
        }
        using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, Stop);
        using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, Stop);
        using var hangup = PosixSignalRegistration.Create(PosixSignal.SIGHUP, signal =>
        {
            signal.Cancel = true;
            server?.Reload(() => BrokerConfigFile.Load(owner, configDir, host: host));
        });

        server = BrokerServer.StartAsync(options).GetAwaiter().GetResult();
        BrokerControlServer? control = null;
        Task finished;
        try
        {
            if (state is not null)
            {
                // Brief T17 ruling 14: the control socket, after BrokerServer took the socket folder's lock; the control
                // server takes control.lock beside its own socket.
                var vaultId = VaultIdOf(vaultConfig);
                var uid = Ownership.EffectiveUid;
                if (sshAgent is not null)
                    state.UnloadSshKeys = deferredKeys!.Unload;
                var keySource = sshAgent?.KeySource;
                control = BrokerControlServer.StartAsync(new BrokerControlOptions(ControlPath(ctx, uid, vaultId), vaultId, uid, state,
                    candidate => BrokerPasswordProof.Prove(records, ctx.Unlocker, candidate), server.UnlockGuard, TimeProvider.System)
                {
                    Ownership = Ownership,
                    Log = log.Event,
                    LoadSshKeys = keySource is null ? null : () => deferredKeys!.Load(holder.Current, keySource),
                }).GetAwaiter().GetResult();
                log.Event($"locked: this broker's slot has the vault password; run 'tswap broker unlock' as the vault user ({control.SocketPath})");
            }
            finished = Task.WhenAny(stop.Task, server.Fatal, fatalHardening.Task).GetAwaiter().GetResult();
        }
        finally
        {
            control?.StopAsync().GetAwaiter().GetResult();
            server.StopAsync().GetAwaiter().GetResult();
        }
        // Unlocks hanging again and again: exit non-zero so systemd (Restart=on-failure) restarts serve.
        if (finished == server.Fatal)
            throw new TswapException($"tswap broker serve stopped: {server.Fatal.Result}");
        if (finished == fatalHardening.Task)
            throw new TswapException($"tswap broker serve stopped: {fatalHardening.Task.Result}");
        return 0;
    }

    /// <summary>
    /// Brief T10: the ssh-agent endpoint, when broker.json has ssh keys. Each key is loaded once here
    /// (one unlock, one record) to derive its public key; a key that can't be loaded stops serve,
    /// naming it. New keys need a restart (a reload never unlocks).
    /// </summary>
    private static SshAgentOptions? SshAgentFor(CommandContext ctx, RecordVaultStore records, BrokerPolicy policy,
        BrokerPasswordState? state, DeferredSshKeys? deferred)
    {
        if (policy.SshKeys.Count == 0)
            return null;
        var source = new VaultSshKeySource(records, ctx.Unlocker, state?.Provider);
        if (state is null)
            return new SshAgentOptions
            {
                Keys = SshAgentKeyLoader.Load(policy, source),
                KeySource = source,
            };
        // Brief T17 ruling 14: a locked broker can't unlock, so the keys load after the first
        // 'broker unlock'; the checks that need no unlock still stop serve now.
        SshAgentKeyLoader.Validate(policy);
        return new SshAgentOptions
        {
            Keys = new Dictionary<string, SshAgentKey>(),
            CurrentKeys = () => deferred!.Current,
            KeySource = source,
        };
    }

    // ------------------------------------------------------------------ unlock, lock, status (brief T17 ruling 14)

    /// <summary>Ruling 14: <c>broker unlock|lock|status</c> on a vault whose slot here has no vault password.</summary>
    public const string NeverLockedText = "This broker's slot has no vault password; it is never locked.";

    /// <summary>The RAM disclosure (Global constraints), with "The broker keeps" for its first words.</summary>
    public const string RamDisclosure =
        "The broker keeps your stretched vault password in memory until you stop it or it times out. Root, or anything that can read this process's memory, can take it while it runs; it still needs this machine's TPM/YubiKey/Secure Enclave to open the vault.";

    /// <summary>Ruling 19's extra line on a Mac whose password slot is a Secure Enclave one.</summary>
    public const string SecureEnclaveCopyLine =
        "On this Mac the Secure Enclave library also holds a copy during each unlock, which tswap can't wipe.";

    /// <summary>Test seam: the euid (root refusals) and owner lookups.</summary>
    internal static IUnixOwnership Ownership = new UnixOwnership();

    /// <summary>Test seam: the control socket's path for (owner uid, vault id); null: <see cref="AgentSocketPath.BrokerControlFor(uint, byte[])"/>.</summary>
    internal static Func<uint, byte[], string>? ControlPathOverride;

    internal static void ResetSeamsForTests()
    {
        Ownership = new UnixOwnership();
        ControlPathOverride = null;
    }

    private static string ControlPath(CommandContext ctx, uint uid, byte[] vaultId)
    {
        if (ControlPathOverride is { } seam)
            return seam(uid, vaultId);
#if DEBUG
        // Debug builds with a test key only: the end-to-end tests keep the run folder in a temp folder.
        if (ctx.TestKey is not null && Environment.GetEnvironmentVariable("TSWAP_TEST_BROKER_RUN_DIR") is { Length: > 0 } runDir)
            return Path.Combine(Path.GetFullPath(runDir), $"broker-{AgentSocketPath.Prefix(vaultId)}", "control.sock");
#else
        _ = ctx;
#endif
        return AgentSocketPath.BrokerControlFor(uid, vaultId);
    }

    private static byte[] VaultIdOf(Config config) =>
        KeyringCodec.Decode(Convert.FromBase64String(config.Keyring
            ?? throw new TswapException("This vault has no keyring; only a keyring vault's slot can carry a vault password."))).VaultId;

    /// <summary>
    /// Everything <c>broker unlock|lock|status</c> check before connecting (ruling 14): not as root, a
    /// record vault, and this machine's slot has the vault password. Returns the vault's config, its id,
    /// the vault user's uid and the control socket's path.
    /// </summary>
    private static (Config Config, byte[] VaultId, uint Uid, string Path) ControlTarget(CommandContext ctx, string op)
    {
        if (Ownership.IsPrivileged)
        {
            var configOwner = Ownership.GetOwner(ctx.Env.ConfigDir)?.Uid;
            var name = configOwner is { } u ? BrokerNative.NameOf(u) ?? $"uid {u}" : "the vault's owner";
            throw new TswapException($"Run 'tswap broker {op}' as the vault user ({name}), without sudo.");
        }
        if (ctx.Storage is not RecordVaultStore records)
            throw new TswapException($"'tswap broker {op}' needs a record-store vault.");
        var config = records.LoadConfig();
        var own = VaultUnlocker.OwnSlotPassword(config);
        switch (own.Kind)
        {
            case SlotPasswordKind.None:
                throw new TswapException(NeverLockedText);
            case SlotPasswordKind.NeedsNewerTswap or SlotPasswordKind.Corrupt:
                throw new TswapException($"Slot {own.SlotId8}: {own.Error}");
        }
        var vaultId = VaultIdOf(config);
        var uid = Ownership.EffectiveUid;
        return (config, vaultId, uid, ControlPath(ctx, uid, vaultId));
    }

    /// <summary>
    /// <c>tswap broker unlock [--timeout d]</c>: reads the vault password at the terminal, stretches it with
    /// the vault's <c>vault-password</c> file, and hands the 32 bytes to the broker (ruling 14).
    /// </summary>
    private static int Unlock(CommandContext ctx, string[] args)
    {
        TimeSpan? timeout = args switch
        {
            [] => null,
            ["--timeout", var text] => AgentDuration.Parse(text),
            _ => throw new TswapException(Usage),
        };
        var (config, vaultId, uid, path) = ControlTarget(ctx, "unlock");
        // A broker that doesn't answer is said before the password is typed (the unlock itself still decides).
        if (BrokerControlClient.Status(path, vaultId, uid) is not BrokerControlAnswer.State and var absent)
            throw Failure(absent, path);
        // The disclosure comes before the password is read: it is what the user decides on. Without a
        // terminal the provider refuses next, so there is nothing to disclose.
        if (!ctx.Console.IsInputRedirected)
        {
            ctx.Console.Error.WriteLine(RamDisclosure);
            if (OperatingSystem.IsMacOS() && config.Backend == HardwareBackend.SecureEnclave)
                ctx.Console.Error.WriteLine(SecureEnclaveCopyLine);
        }
        using var password = TerminalPasswordProvider.For(ctx, config)();
        var expiresAt = timeout is { } t ? ctx.Time.GetUtcNow() + t : (DateTimeOffset?)null;
        switch (BrokerControlClient.Unlock(path, vaultId, uid, password, expiresAt))
        {
            case BrokerControlAnswer.Done:
                ctx.Console.Out.WriteLine(expiresAt is { } e
                    ? $"The broker is unlocked; it locks again at {e.UtcDateTime:yyyy-MM-dd HH:mm:ss}Z."
                    : "The broker is unlocked.");
                return 0;
            case var other:
                throw Failure(other, path);
        }
    }

    private static int Lock(CommandContext ctx)
    {
        var (_, vaultId, uid, path) = ControlTarget(ctx, "lock");
        switch (BrokerControlClient.Lock(path, vaultId, uid))
        {
            case BrokerControlAnswer.Done:
                ctx.Console.Out.WriteLine("The broker is locked.");
                return 0;
            case var other:
                throw Failure(other, path);
        }
    }

    private static int Status(CommandContext ctx)
    {
        var (_, vaultId, uid, path) = ControlTarget(ctx, "status");
        switch (BrokerControlClient.Status(path, vaultId, uid))
        {
            case BrokerControlAnswer.State { Unlocked: false } locked:
                ctx.Console.Out.WriteLine("The broker is locked.");
                ctx.Console.Out.WriteLine($"refused peers: {locked.RefusedPeers}");
                return 0;
            case BrokerControlAnswer.State unlocked:
                ctx.Console.Out.WriteLine(unlocked.ExpiresAt is { } e
                    ? $"The broker is unlocked until {e.UtcDateTime:yyyy-MM-dd HH:mm:ss}Z."
                    : "The broker is unlocked (no timeout).");
                ctx.Console.Out.WriteLine($"refused peers: {unlocked.RefusedPeers}");
                return 0;
            case var other:
                throw Failure(other, path);
        }
    }

    private static TswapException Failure(BrokerControlAnswer answer, string path) => answer switch
    {
        BrokerControlAnswer.Refused refused => new TswapException(refused.Message),
        BrokerControlAnswer.NotRunning => new TswapException($"No 'tswap broker serve' answers at {path}; is it running?"),
        BrokerControlAnswer.OtherVault => new TswapException($"Another vault's broker answers at {path}."),
        _ => new TswapException($"The broker at {path} gave an answer tswap can't read."),
    };

    // ------------------------------------------------------------------ forward

    /// <summary>Relays a loopback TCP port to the broker socket until SIGTERM/SIGINT. Needs no vault.</summary>
    private static int Forward(CommandContext ctx, string[] args)
    {
        var (positional, options) = ParseOptions(args, ["--listen", "--socket"]);
        if (positional.Count != 0)
            throw new TswapException(Usage);
        var listen = BrokerTcpRelay.ParseListen(Required(options, "--listen"));
        var socket = options.GetValueOrDefault("--socket") ?? "/run/tswap.sock";

        var stop = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Stop(PosixSignalContext signal)
        {
            signal.Cancel = true;
            stop.TrySetResult();
        }
        using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, Stop);
        using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, Stop);

        var relay = BrokerTcpRelay.Start(listen, socket, ctx.Console.Error);
        ctx.Console.Error.WriteLine($"tswap broker forward: {relay.LocalEndPoint} -> {socket}");
        try
        {
            stop.Task.GetAwaiter().GetResult();
        }
        finally
        {
            relay.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        return 0;
    }

    // ------------------------------------------------------------------ call

    /// <summary>
    /// Calls a template on the broker socket (brief T9 decision 5): prints its stdout and stderr and
    /// exits with its exit code; a broker-side error (refused, unreachable, sandbox unavailable)
    /// exits 125. Needs no vault.
    /// </summary>
    private static int Call(CommandContext ctx, string[] args)
    {
        string? socket = null;
        string? template = null;
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--socket" && i + 1 < args.Length && socket is null)
            {
                socket = args[++i];
                continue;
            }
            if (template is null)
            {
                template = args[i];
                continue;
            }
            var eq = args[i].IndexOf('=');
            if (eq <= 0 || !values.TryAdd(args[i][..eq], args[i][(eq + 1)..]))
            {
                ctx.Console.Error.WriteLine($"tswap broker call: '{BrokerPolicy.Printable(args[i])}' is not name=value (or is given twice).\n{Usage}");
                return BrokerTemplateClient.BrokerError;
            }
        }
        if (template is null)
        {
            ctx.Console.Error.WriteLine(Usage);
            return BrokerTemplateClient.BrokerError;
        }
        var real = ctx.Console is SystemConsole;
        using var stdout = real ? Console.OpenStandardOutput() : new TextWriterStream(ctx.Console.Out);
        using var stderr = real ? Console.OpenStandardError() : new TextWriterStream(ctx.Console.Error);
        return BrokerTemplateClient.CallAsync(socket ?? "/run/tswap.sock", template, values, stdout, stderr, ctx.Console.Error)
            .GetAwaiter().GetResult();
    }

    /// <summary>Bytes to a <see cref="TextWriter"/> as UTF-8 text (an in-process console; the real one gets raw bytes).</summary>
    private sealed class TextWriterStream(TextWriter writer) : Stream
    {
        private readonly System.Text.Decoder _decoder = new System.Text.UTF8Encoding(false).GetDecoder();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => writer.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            var chars = new char[_decoder.GetCharCount(buffer, offset, count)];
            _decoder.GetChars(buffer, offset, count, chars, 0);
            writer.Write(chars);
        }
    }

    // ------------------------------------------------------------------ config edits (sudo)

    private static DirectoryOwnerMatcher Owner(CommandContext ctx) =>
        (ctx.Storage as IFileVaultStore)?.Owner ?? DirectoryOwnerMatcher.Default;

    private static BrokerConfig ReadOrNew(CommandContext ctx) =>
        BrokerConfigFile.ReadRaw(Owner(ctx), ctx.Env.ConfigDir)
        ?? new BrokerConfig { Version = BrokerConfig.CurrentVersion };

    private static void Save(CommandContext ctx, BrokerConfig config) =>
        BrokerConfigFile.Save(Owner(ctx), ctx.Env.ConfigDir, config, Host(ctx));

    /// <summary>
    /// The host context templates are checked against (brief T9 decision 2): the vault user is the
    /// config folder's owner, and the config folder, the record store's vault folder and that user's
    /// home are protected. Null off Linux (no templates there).
    /// </summary>
    private static BrokerHostContext? Host(CommandContext ctx)
    {
        if (!OperatingSystem.IsLinux())
            return null;
        string? vaultDir = null;
        try
        {
            vaultDir = (ctx.Storage as RecordVaultStore)?.VaultDir;
        }
        catch (TswapException)
        {
            // No usable record-store config: only the config folder is known.
        }
        return BrokerHostContext.ForVault(ctx.Env.ConfigDir, vaultDir);
    }

    private static int RouteAdd(CommandContext ctx, string[] args)
    {
        ctx.RequireSudo("broker route add", "Changing broker.json needs sudo: it decides which credentials containers can use.");
        var (positional, options) = ParseOptions(args,
            ["--upstream", "--auth", "--secret", "--user", "--header", "--path", "--methods", "--idle-timeout"]);
        if (positional.Count != 1)
            throw new TswapException(Usage);
        var name = positional[0];
        var secret = Required(options, "--secret");
        if (!secret.StartsWith("{{", StringComparison.Ordinal))
            secret = "{{" + secret + "}}";
        int? idle = null;
        if (options.TryGetValue("--idle-timeout", out var idleText))
            idle = int.TryParse(idleText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var v)
                ? v
                : throw new TswapException("--idle-timeout must be a whole number of seconds.");
        var route = new BrokerRouteConfig
        {
            Name = name,
            Upstream = Required(options, "--upstream"),
            Auth = new BrokerAuthConfig
            {
                Type = Required(options, "--auth"),
                Secret = secret,
                User = options.GetValueOrDefault("--user"),
                Header = options.GetValueOrDefault("--header"),
            },
            Path = Required(options, "--path"),
            Methods = options.TryGetValue("--methods", out var m) ? SplitList(m) : null,
            IdleTimeoutSec = idle,
        };

        using var editLock = BrokerConfigFile.LockForEdit(Owner(ctx), ctx.Env.ConfigDir);
        var config = ReadOrNew(ctx);
        BrokerPolicy.ValidateName(name, "route");
        if (config.Routes.Any(r => r.Name == name))
            throw new TswapException($"Route '{name}' already exists. Remove it first: sudo {ctx.Prefix} broker route remove {name}");
        Save(ctx, config with { Routes = [.. config.Routes, route] });
        ctx.Console.Out.WriteLine($"Added route '{name}'. A running 'tswap broker serve' picks it up on SIGHUP (systemctl --user reload tswap-broker).");
        return 0;
    }

    private static int RouteRemove(CommandContext ctx, string[] args)
    {
        ctx.RequireSudo("broker route remove", "Changing broker.json needs sudo: it decides which credentials containers can use.");
        if (args is not [var name])
            throw new TswapException(Usage);
        using var editLock = BrokerConfigFile.LockForEdit(Owner(ctx), ctx.Env.ConfigDir);
        var config = ReadOrNew(ctx);
        if (config.Routes.All(r => r.Name != name))
            throw new TswapException($"No route named '{BrokerPolicy.Printable(name)}'.");
        var users = config.Sockets.Where(s => s.Routes.Contains(name)).Select(s => s.Name).ToList();
        if (users.Count > 0)
            throw new TswapException($"Route '{name}' is allowed on socket(s) {string.Join(", ", users)}; remove those sockets (or re-add them without it) first.");
        Save(ctx, config with { Routes = [.. config.Routes.Where(r => r.Name != name)] });
        ctx.Console.Out.WriteLine($"Removed route '{name}'.");
        return 0;
    }

    private static int SocketAdd(CommandContext ctx, string[] args)
    {
        ctx.RequireSudo("broker socket add", "Changing broker.json needs sudo: it decides which credentials containers can use.");
        var (positional, options) = ParseOptions(args, ["--uids", "--routes", "--templates", "--socket-dir"]);
        if (positional.Count != 1)
            throw new TswapException(Usage);
        var name = positional[0];
        var socket = new BrokerSocketConfig
        {
            Name = name,
            Uids = SplitList(Required(options, "--uids")),
            Routes = options.TryGetValue("--routes", out var r) ? SplitList(r) : [],
            Templates = options.TryGetValue("--templates", out var t) ? SplitList(t) : null,
        };
        using var editLock = BrokerConfigFile.LockForEdit(Owner(ctx), ctx.Env.ConfigDir);
        var config = ReadOrNew(ctx);
        BrokerPolicy.ValidateName(name, "socket");
        if (config.Sockets.Any(s => s.Name == name))
            throw new TswapException($"Socket '{name}' already exists. Remove it first: sudo {ctx.Prefix} broker socket remove {name}");
        var socketDir = options.GetValueOrDefault("--socket-dir") ?? config.SocketDir
            ?? throw new TswapException("No socket folder yet: pass --socket-dir <dir> (a folder owned by the vault user, mode 0711).");
        Save(ctx, config with { SocketDir = socketDir, Sockets = [.. config.Sockets, socket] });
        ctx.Console.Out.WriteLine($"Added socket '{name}' ({Path.Combine(socketDir, name + ".sock")}). Restart 'tswap broker serve' to listen on a new socket.");
        return 0;
    }

    private static int SocketRemove(CommandContext ctx, string[] args)
    {
        ctx.RequireSudo("broker socket remove", "Changing broker.json needs sudo: it decides which credentials containers can use.");
        if (args is not [var name])
            throw new TswapException(Usage);
        using var editLock = BrokerConfigFile.LockForEdit(Owner(ctx), ctx.Env.ConfigDir);
        var config = ReadOrNew(ctx);
        if (config.Sockets.All(s => s.Name != name))
            throw new TswapException($"No socket named '{BrokerPolicy.Printable(name)}'.");
        Save(ctx, config with { Sockets = [.. config.Sockets.Where(s => s.Name != name)] });
        ctx.Console.Out.WriteLine($"Removed socket '{name}'. A running 'tswap broker serve' refuses it after SIGHUP.");
        return 0;
    }

    /// <summary>
    /// <c>sudo tswap broker template add &lt;file.json|-&gt;</c> (brief T9 decision 9): one template as a
    /// JSON object, validated with the whole file (binds checked on this host) before anything is
    /// written.
    /// </summary>
    private static int TemplateAdd(CommandContext ctx, string[] args)
    {
        ctx.RequireSudo("broker template add", "Changing broker.json needs sudo: a template runs host-side commands with vault secrets.");
        if (args is not [var file])
            throw new TswapException(Usage);
        string json;
        try
        {
            json = file == "-" ? ctx.Console.In.ReadToEnd() : File.ReadAllText(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new TswapException($"Can't read the template file {file}: {ex.Message}");
        }
        BrokerTemplateConfig template;
        try
        {
            template = System.Text.Json.JsonSerializer.Deserialize(json, BrokerJsonContext.Default.BrokerTemplateConfig)
                ?? throw new TswapException("The template file holds null; it must be one JSON object.");
        }
        catch (System.Text.Json.JsonException ex)
        {
            throw new TswapException($"The template can't be read: {ex.Message}");
        }
        BrokerPolicy.ValidateName(template.Name, "template");
        using var editLock = BrokerConfigFile.LockForEdit(Owner(ctx), ctx.Env.ConfigDir);
        var config = ReadOrNew(ctx);
        if (config.Templates?.Any(x => x.Name == template.Name) == true)
            throw new TswapException($"Template '{template.Name}' already exists. Remove it first: sudo {ctx.Prefix} broker template remove {template.Name}");
        Save(ctx, config with { Templates = [.. config.Templates ?? [], template] });
        ctx.Console.Out.WriteLine($"Added template '{template.Name}'. Allow it on a socket ('socket add ... --templates {template.Name}'); a running 'tswap broker serve' picks it up on SIGHUP.");
        return 0;
    }

    private static int TemplateRemove(CommandContext ctx, string[] args)
    {
        ctx.RequireSudo("broker template remove", "Changing broker.json needs sudo: a template runs host-side commands with vault secrets.");
        if (args is not [var name])
            throw new TswapException(Usage);
        using var editLock = BrokerConfigFile.LockForEdit(Owner(ctx), ctx.Env.ConfigDir);
        var config = ReadOrNew(ctx);
        if (config.Templates?.Any(t => t.Name == name) != true)
            throw new TswapException($"No template named '{BrokerPolicy.Printable(name)}'.");
        var users = config.Sockets.Where(s => s.Templates?.Contains(name) == true).Select(s => s.Name).ToList();
        if (users.Count > 0)
            throw new TswapException($"Template '{name}' is allowed on socket(s) {string.Join(", ", users)}; remove those sockets (or re-add them without it) first.");
        var rest = config.Templates.Where(t => t.Name != name).ToList();
        Save(ctx, config with { Templates = rest.Count == 0 ? null : rest });
        ctx.Console.Out.WriteLine($"Removed template '{name}'.");
        return 0;
    }

    // ------------------------------------------------------------------ argument parsing

    private static (List<string> Positional, Dictionary<string, string> Options) ParseOptions(string[] args, string[] known)
    {
        List<string> positional = [];
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                if (!known.Contains(arg))
                    throw new TswapException($"Unknown option '{BrokerPolicy.Printable(arg)}'.\n{Usage}");
                if (i + 1 >= args.Length)
                    throw new TswapException($"{arg} needs a value.");
                if (!options.TryAdd(arg, args[++i]))
                    throw new TswapException($"{arg} given twice.");
            }
            else
            {
                positional.Add(arg);
            }
        }
        return (positional, options);
    }

    private static string Required(Dictionary<string, string> options, string name) =>
        options.TryGetValue(name, out var v) ? v : throw new TswapException($"{name} is required.\n{Usage}");

    private static List<string> SplitList(string value) =>
        [.. value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)];
}
