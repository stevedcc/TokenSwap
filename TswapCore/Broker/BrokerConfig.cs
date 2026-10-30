using System.Text.Json.Serialization;

namespace TswapCore.Broker;

/// <summary>
/// <c>broker.json</c> as stored (brief T8 decision 9): next to the vault's <c>config.json</c>,
/// mode 0600, changed only with <c>sudo tswap broker route|socket add|remove</c>. This is the raw
/// shape; <see cref="BrokerPolicy.Validate"/> turns it into the checked, compiled form that
/// <c>serve</c> uses, and runs on every load.
/// </summary>
public sealed record BrokerConfig
{
    /// <summary>The only version this build reads.</summary>
    public const int CurrentVersion = 1;

    public required int Version { get; init; }

    /// <summary>The folder <c>serve</c> creates one Unix socket per client in.</summary>
    public string? SocketDir { get; init; }

    public List<BrokerSocketConfig> Sockets { get; init; } = [];

    public List<BrokerRouteConfig> Routes { get; init; } = [];

    /// <summary>
    /// The <c>bwrap</c> binary every template runs under (brief T9 decision 1), at a fixed absolute
    /// path, never looked up on <c>PATH</c>; null means <c>/usr/bin/bwrap</c>.
    /// </summary>
    public string? BwrapPath { get; init; }

    /// <summary>Host-side commands a socket may run (brief T9); null or empty for none.</summary>
    public List<BrokerTemplateConfig>? Templates { get; init; }

    /// <summary>Private keys the ssh-agent endpoint signs with (brief T10 reads these); null or empty for none.</summary>
    public List<BrokerSshKeyConfig>? SshKeys { get; init; }
}

/// <summary>One client's socket: who may connect (peer uids) and which routes it may use.</summary>
public sealed record BrokerSocketConfig
{
    public required string Name { get; init; }

    /// <summary>Allowed peer uids: each entry <c>"N"</c> or an inclusive range <c>"N-M"</c>.</summary>
    public required List<string> Uids { get; init; }

    /// <summary>The routes this socket may use (allow-list of route names).</summary>
    public required List<string> Routes { get; init; }

    /// <summary>The templates this socket may call (allow-list; null or empty: none, brief T9 decision 4).</summary>
    public List<string>? Templates { get; init; }

    /// <summary>The ssh keys this socket's agent offers (allow-list; null or empty: none, brief T10).</summary>
    public List<string>? SshKeys { get; init; }
}

/// <summary>One upstream the broker adds a credential for.</summary>
public sealed record BrokerRouteConfig
{
    public required string Name { get; init; }

    /// <summary>An <c>https://</c> base URL, optionally with a base path.</summary>
    public required string Upstream { get; init; }

    public required BrokerAuthConfig Auth { get; init; }

    /// <summary>Allowed methods; null means GET, HEAD and POST.</summary>
    public List<string>? Methods { get; init; }

    /// <summary>The regex the decoded path after <c>/&lt;route&gt;/</c> must match (prefix match).</summary>
    public required string Path { get; init; }

    /// <summary>Seconds with no bytes moving before a stream is ended; null means 120.</summary>
    public int? IdleTimeoutSec { get; init; }
}

/// <summary>How the credential is added: <c>bearer</c>, <c>basic</c> (with <see cref="User"/>) or <c>header</c> (with <see cref="Header"/>).</summary>
public sealed record BrokerAuthConfig
{
    public required string Type { get; init; }

    /// <summary>The secret, named as <c>{{secret-name}}</c>.</summary>
    public required string Secret { get; init; }

    /// <summary>The fixed user name of a <c>basic</c> route.</summary>
    public string? User { get; init; }

    /// <summary>The header name of a <c>header</c> route.</summary>
    public string? Header { get; init; }
}

/// <summary>
/// A command template (brief T9 decision 4): a program run directly (never through a shell) under
/// <c>bwrap</c>, with declared arguments, secrets only in its environment or in read-only files.
/// </summary>
public sealed record BrokerTemplateConfig
{
    public required string Name { get; init; }

    /// <summary>The command: <c>argv[0]</c> a literal absolute path, <c>{arg}</c> placeholders in <c>argv[1..]</c> only.</summary>
    public required List<string> Argv { get; init; }

    /// <summary>The arguments a caller supplies, by name.</summary>
    public Dictionary<string, BrokerTemplateArgConfig>? Args { get; init; }

    /// <summary>The child's environment (besides the fixed baseline): each value a literal or exactly <c>{{secret}}</c>.</summary>
    public Dictionary<string, string>? Env { get; init; }

    /// <summary>Secrets the child reads as read-only files under <c>/run/secrets/</c>.</summary>
    public List<BrokerTemplateFileConfig>? Files { get; init; }

    /// <summary>Host paths the child may see (read-only unless <c>rw</c>).</summary>
    public List<BrokerTemplateBindConfig>? Binds { get; init; }

    /// <summary>The child's working folder, inside one of the binds; null means <c>/tmp</c> (private).</summary>
    public string? Cwd { get; init; }

    /// <summary><c>none</c> (the default: a network namespace of its own) or <c>host</c>.</summary>
    public string? Network { get; init; }

    public BrokerTemplateLimitsConfig? Limits { get; init; }

    /// <summary>Seconds before the child (and everything it started) is killed; null means 120.</summary>
    public int? TimeoutSec { get; init; }

    /// <summary>Output (stdout and stderr together) passed back; the rest is read and discarded. Null means 1 MiB.</summary>
    public long? MaxOutputBytes { get; init; }

    /// <summary>Calls a minute per socket; null means 6.</summary>
    public int? Rate { get; init; }
}

/// <summary>One declared template argument: the pattern its whole value must match, a length cap, and whether it may start with '-'.</summary>
public sealed record BrokerTemplateArgConfig
{
    public required string Pattern { get; init; }

    /// <summary>The longest value accepted, in characters; null means 256.</summary>
    public int? MaxLength { get; init; }

    /// <summary>Whether a value may start with '-' (false by default: a leading dash is flag injection).</summary>
    public bool? AllowLeadingDash { get; init; }
}

/// <summary>A secret handed to the child as a read-only file (<c>--ro-bind-data</c>).</summary>
public sealed record BrokerTemplateFileConfig
{
    /// <summary>Where the child sees it: under <c>/run/secrets/</c>.</summary>
    public required string Path { get; init; }

    /// <summary>The secret's name (plain, not <c>{{...}}</c>).</summary>
    public required string Secret { get; init; }
}

/// <summary>A host path the child may see, at the same (resolved) path.</summary>
public sealed record BrokerTemplateBindConfig
{
    public required string Path { get; init; }

    /// <summary>Writable inside the sandbox; null or false means read-only.</summary>
    public bool? Rw { get; init; }
}

/// <summary>Per-template resource limits, each at most the default (brief T9 decision 1).</summary>
public sealed record BrokerTemplateLimitsConfig
{
    /// <summary>RLIMIT_NPROC (processes in the sandbox): 1 to 64.</summary>
    public int? Nproc { get; init; }

    /// <summary>RLIMIT_AS in MiB: 1 to 2048.</summary>
    public int? AsMib { get; init; }

    /// <summary>RLIMIT_NOFILE: 1 to 256.</summary>
    public int? Nofile { get; init; }

    /// <summary>RLIMIT_FSIZE in MiB: 0 to 256.</summary>
    public int? FsizeMib { get; init; }
}

/// <summary>
/// A private key for the broker's ssh-agent endpoint (the shape brief T10 reads): the vault secret
/// that holds it and the <c>SHA256:</c> fingerprints of the server host keys it may sign in to.
/// </summary>
public sealed record BrokerSshKeyConfig
{
    public required string Name { get; init; }

    /// <summary>The secret's name (plain, not <c>{{...}}</c>).</summary>
    public required string Secret { get; init; }

    /// <summary><c>SHA256:</c> fingerprints (unpadded base64, as <c>ssh-keygen -lf</c> prints them); at least one.</summary>
    public required List<string> AllowedHostKeys { get; init; }
}

/// <summary>
/// Source-generated (NativeAOT) JSON for <c>broker.json</c>: snake_case names, unknown fields and
/// duplicate keys refused, nullability and <c>required</c> respected.
/// </summary>
[JsonSerializable(typeof(BrokerConfig))]
[JsonSerializable(typeof(BrokerTemplateConfig))]
[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    AllowDuplicateProperties = false,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
public partial class BrokerJsonContext : JsonSerializerContext;
