namespace TswapCore.Broker.SshAgent;

/// <summary>
/// One agent connection's requests, handled in order, one at a time (brief T10 decision 2). Every
/// refusal is <c>SSH_AGENT_FAILURE</c> and keeps the connection open.
/// </summary>
internal sealed class SshAgentSession(SshAgentListener agent, BrokerPeer peer)
{
    public BrokerPeer Peer => peer;

    public Task<SshAgentReply> HandleAsync(byte[] message, CancellationToken cancellationToken)
    {
        _ = cancellationToken;
        return Task.FromResult(message[0] switch
        {
            SshAgentProtocol.RequestIdentities => Identities(message),
            // Extensions: none supported yet; RFC 9987 §5.8, an unsupported type gets SSH_AGENT_FAILURE.
            _ => SshAgentReply.Failure, // add/remove/lock/unlock/smartcard and every unknown type
        });
    }

    /// <summary>Wire doc section 4: only the keys on this socket's allow-list, comment = name. No unlock.</summary>
    private SshAgentReply Identities(byte[] message)
    {
        if (message.Length != 1)
            return SshAgentReply.Failure;
        var policy = agent.Policy;
        if (!policy.Sockets.TryGetValue(peer.Socket, out var socket))
            return SshAgentReply.Failure;
        var keys = socket.SshKeys
            .Order(StringComparer.Ordinal)
            .Select(name => agent.Keys.GetValueOrDefault(name))
            .OfType<SshAgentKey>()
            .Take(SshAgentProtocol.MaxIdentities)
            .ToList();
        var writer = new SshWriter().Byte(SshAgentProtocol.IdentitiesAnswer).UInt32((uint)keys.Count);
        foreach (var key in keys)
            writer.String(key.PublicBlob).String(key.Name);
        return new SshAgentReply(writer.ToArray());
    }
}
