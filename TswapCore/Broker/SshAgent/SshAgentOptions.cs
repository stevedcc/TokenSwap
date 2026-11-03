namespace TswapCore.Broker.SshAgent;

/// <summary>What <c>serve</c> needs to run the ssh-agent endpoint (brief T10).</summary>
public sealed record SshAgentOptions
{
    /// <summary>The keys loaded at start, by name (public parts only).</summary>
    public required IReadOnlyDictionary<string, SshAgentKey> Keys { get; init; }

    /// <summary>
    /// Brief T17: a password broker's keys, which change at unlock and lock (<see cref="DeferredSshKeys.Current"/>);
    /// null: <see cref="Keys"/>, fixed at start.
    /// </summary>
    public Func<IReadOnlyDictionary<string, SshAgentKey>>? CurrentKeys { get; init; }

    /// <summary>Where each signature's private key comes from: a fresh unlock reading only that key's record.</summary>
    public required ISshKeySource KeySource { get; init; }

    /// <summary>
    /// Successful signatures per socket per minute (brief T10 decision 5, GLM I2: each one is a TPM
    /// unlock); beyond it a sign request gets <c>SSH_AGENT_FAILURE</c> and a log line, with no unlock.
    /// </summary>
    public int SignsPerMinute { get; init; } = 30;

    /// <summary>A connection idle this long between messages is closed.</summary>
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromSeconds(BrokerPolicy.DefaultIdleTimeoutSec);

}
