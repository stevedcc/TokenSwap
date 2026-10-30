using System.Runtime.InteropServices;
using TswapCore;
using TswapCore.Broker;

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
    public string HelpUsage => "broker <serve|forward|route|socket> ...";
    public string Description =>
        "Credential-adding HTTP proxy for containers (serve as the vault user; forward in the container; sudo for route|socket add|remove)";

    // serve and forward never need sudo (serve refuses root); only config changes do, checked inside.
    public bool RequiresSudo => false;

    private const string Usage =
        "Usage:\n" +
        "  tswap broker serve\n" +
        "  tswap broker forward --listen 127.0.0.1:<port> [--socket /run/tswap.sock]\n" +
        "  sudo tswap broker route add <name> --upstream https://host[/base] --auth bearer|basic|header --secret <secret-name>\n" +
        "        [--user <basic-user>] [--header <header-name>] --path <regex> [--methods GET,HEAD,POST] [--idle-timeout <sec>]\n" +
        "  sudo tswap broker route remove <name>\n" +
        "  sudo tswap broker socket add <name> --uids <uid|N-M>[,...] --routes <route>[,...] [--socket-dir <dir>]\n" +
        "  sudo tswap broker socket remove <name>";

    public int Execute(CommandContext ctx, string[] args)
    {
        if (OperatingSystem.IsWindows())
            throw new TswapException("'tswap broker' is not supported on Windows (it needs Unix sockets and peer credentials; Linux and macOS only).");
        if (args.Length == 0)
            throw new TswapException(Usage);

        return args[0] switch
        {
            "serve" when args.Length == 1 => Serve(ctx),
            "forward" => Forward(ctx, args[1..]),
            "route" when args.Length >= 2 && args[1] == "add" => RouteAdd(ctx, args[2..]),
            "route" when args.Length >= 2 && args[1] == "remove" => RouteRemove(ctx, args[2..]),
            "socket" when args.Length >= 2 && args[1] == "add" => SocketAdd(ctx, args[2..]),
            "socket" when args.Length >= 2 && args[1] == "remove" => SocketRemove(ctx, args[2..]),
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
        // Decision 1: no same-uid ptrace, no core dumps holding secrets.
        if (!BrokerNative.MakeNonDumpable())
            throw new TswapException($"Could not make this process non-dumpable (prctl PR_SET_DUMPABLE, errno {Marshal.GetLastPInvokeError()}); not serving.");

        var owner = Owner(ctx);
        var configDir = ctx.Env.ConfigDir;
        var holder = new BrokerPolicyHolder(BrokerConfigFile.Load(owner, configDir));
        using var log = new BrokerLog(ctx.Console.Error, Path.Combine(configDir, BrokerLog.FileName));
        using var forwarder = new HttpBrokerForwarder(TimeProvider.System);
        var options = new BrokerServerOptions
        {
            Policy = holder,
            Secrets = new VaultBrokerSecretSource(ctx.Storage, ctx.Unlocker),
            Forwarder = forwarder,
            Log = log,
        };

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
            server?.Reload(() => BrokerConfigFile.Load(owner, configDir));
        });

        server = BrokerServer.StartAsync(options).GetAwaiter().GetResult();
        try
        {
            stop.Task.GetAwaiter().GetResult();
        }
        finally
        {
            server.StopAsync().GetAwaiter().GetResult();
        }
        return 0;
    }

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

    // ------------------------------------------------------------------ config edits (sudo)

    private static DirectoryOwnerMatcher Owner(CommandContext ctx) =>
        (ctx.Storage as IFileVaultStore)?.Owner ?? DirectoryOwnerMatcher.Default;

    private static BrokerConfig ReadOrNew(CommandContext ctx) =>
        BrokerConfigFile.ReadRaw(Owner(ctx), ctx.Env.ConfigDir)
        ?? new BrokerConfig { Version = BrokerConfig.CurrentVersion };

    private static void Save(CommandContext ctx, BrokerConfig config) =>
        BrokerConfigFile.Save(Owner(ctx), ctx.Env.ConfigDir, config);

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
        if (args.Length != 1)
            throw new TswapException(Usage);
        var name = args[0];
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
        var (positional, options) = ParseOptions(args, ["--uids", "--routes", "--socket-dir"]);
        if (positional.Count != 1)
            throw new TswapException(Usage);
        var name = positional[0];
        var socket = new BrokerSocketConfig
        {
            Name = name,
            Uids = SplitList(Required(options, "--uids")),
            Routes = options.TryGetValue("--routes", out var r) ? SplitList(r) : [],
        };
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
        if (args.Length != 1)
            throw new TswapException(Usage);
        var name = args[0];
        var config = ReadOrNew(ctx);
        if (config.Sockets.All(s => s.Name != name))
            throw new TswapException($"No socket named '{BrokerPolicy.Printable(name)}'.");
        Save(ctx, config with { Sockets = [.. config.Sockets.Where(s => s.Name != name)] });
        ctx.Console.Out.WriteLine($"Removed socket '{name}'. A running 'tswap broker serve' refuses it after SIGHUP.");
        return 0;
    }

    // ------------------------------------------------------------------ argument parsing

    private static (List<string> Positional, Dictionary<string, string> Options) ParseOptions(string[] args, string[] known)
    {
        var positional = new List<string>();
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
