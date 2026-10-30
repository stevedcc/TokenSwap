namespace TswapCore.Broker.SshAgent;

/// <summary>Message numbers, flags and limits of <c>docs/ssh-agent-wire.md</c> (RFC 9987 §8; OpenSSH).</summary>
public static class SshAgentProtocol
{
    // Client to agent (RFC 9987 §8.1).
    public const byte RequestIdentities = 11;
    public const byte SignRequest = 13;
    public const byte AddIdentity = 17;
    public const byte RemoveIdentity = 18;
    public const byte RemoveAllIdentities = 19;
    public const byte AddSmartcardKey = 20;
    public const byte RemoveSmartcardKey = 21;
    public const byte Lock = 22;
    public const byte Unlock = 23;
    public const byte AddIdConstrained = 25;
    public const byte AddSmartcardKeyConstrained = 26;
    public const byte Extension = 27;

    // Agent to client.
    public const byte Failure = 5;
    public const byte Success = 6;
    public const byte IdentitiesAnswer = 12;
    public const byte SignResponse = 14;
    public const byte ExtensionFailure = 28;

    // Signature flags (RFC 9987 §8.3).
    public const uint RsaSha2_256 = 0x02;
    public const uint RsaSha2_512 = 0x04;

    /// <summary>The longest message (type and contents) accepted: OpenSSH's <c>AGENT_MAX_LEN</c>, 256 KiB.</summary>
    public const int MaxMessageLength = 256 * 1024;

    /// <summary>OpenSSH's <c>AGENT_MAX_SID_LEN</c>: the longest session identifier a bind may carry.</summary>
    public const int MaxSessionIdLength = 128;

    /// <summary>The most identities one answer lists.</summary>
    public const int MaxIdentities = 64;

    /// <summary>The largest key secret parsed (bytes).</summary>
    public const int MaxKeySecretLength = 16 * 1024;

    public const string SessionBindExtension = "session-bind@openssh.com";

    /// <summary>The one-byte <c>SSH_AGENT_FAILURE</c> reply.</summary>
    public static byte[] FailureReply => [Failure];

    public static byte[] ExtensionFailureReply => [ExtensionFailure];
}
