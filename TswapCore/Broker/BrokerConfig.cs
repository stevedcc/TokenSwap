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
}

/// <summary>One client's socket: who may connect (peer uids) and which routes it may use.</summary>
public sealed record BrokerSocketConfig
{
    public required string Name { get; init; }

    /// <summary>Allowed peer uids: each entry <c>"N"</c> or an inclusive range <c>"N-M"</c>.</summary>
    public required List<string> Uids { get; init; }

    /// <summary>The routes this socket may use (allow-list of route names).</summary>
    public required List<string> Routes { get; init; }
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
/// Source-generated (NativeAOT) JSON for <c>broker.json</c>: snake_case names, unknown fields and
/// duplicate keys refused, nullability and <c>required</c> respected.
/// </summary>
[JsonSerializable(typeof(BrokerConfig))]
[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    AllowDuplicateProperties = false,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
public partial class BrokerJsonContext : JsonSerializerContext;
