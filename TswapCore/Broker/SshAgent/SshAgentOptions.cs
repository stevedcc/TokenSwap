namespace TswapCore.Broker.SshAgent;

/// <summary>What <c>serve</c> needs to run the ssh-agent endpoint (brief T10).</summary>
public sealed record SshAgentOptions
{
    /// <summary>The keys loaded at start, by name (public parts only).</summary>
    public required IReadOnlyDictionary<string, SshAgentKey> Keys { get; init; }

    /// <summary>A connection idle this long between messages is closed.</summary>
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromSeconds(BrokerPolicy.DefaultIdleTimeoutSec);

    /// <summary>
    /// Test seam: accept a peer with the broker's own uid (refused otherwise, as brief T9 refuses it on
    /// the HTTP sockets). The in-process tests connect as their own uid.
    /// </summary>
    public bool AllowOwnUidForTests { get; init; }
}
