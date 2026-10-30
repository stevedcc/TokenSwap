using System.Globalization;
using System.Text;

namespace TswapCore.Broker.SshAgent;

/// <summary>
/// One agent connection's requests, handled in order, one at a time (brief T10 decision 2), and its
/// bind state, which belongs to this connection only. Every refusal of a request is
/// <c>SSH_AGENT_FAILURE</c> and keeps the connection open; a failed bind answers
/// <c>SSH_AGENT_EXTENSION_FAILURE</c> and closes it.
/// </summary>
internal sealed class SshAgentSession(SshAgentListener agent, BrokerPeer peer)
{
    private SshBinding? _binding;
    private bool _bindTried;

    public BrokerPeer Peer => peer;

    public async Task<SshAgentReply> HandleAsync(byte[] message, CancellationToken cancellationToken) => message[0] switch
    {
        SshAgentProtocol.RequestIdentities => Identities(message),
        SshAgentProtocol.SignRequest => await SignAsync(message, cancellationToken).ConfigureAwait(false),
        SshAgentProtocol.Extension => Extension(message),
        _ => SshAgentReply.Failure, // add/remove/lock/unlock/smartcard and every unknown type
    };

    /// <summary>Wire doc section 4: only the keys on this socket's allow-list, comment = name. No unlock.</summary>
    private SshAgentReply Identities(byte[] message)
    {
        if (message.Length != 1)
            return SshAgentReply.Failure;
        var keys = AllowedKeys().Take(SshAgentProtocol.MaxIdentities).ToList();
        var writer = new SshWriter().Byte(SshAgentProtocol.IdentitiesAnswer).UInt32((uint)keys.Count);
        foreach (var key in keys)
            writer.String(key.PublicBlob).String(key.Name);
        return new SshAgentReply(writer.ToArray());
    }

    /// <summary>The loaded keys on this socket's allow-list in the current config, by name (ordinal).</summary>
    private IEnumerable<SshAgentKey> AllowedKeys()
    {
        if (!agent.Policy.Sockets.TryGetValue(peer.Socket, out var socket))
            return [];
        return socket.SshKeys
            .Order(StringComparer.Ordinal)
            .Select(name => agent.Keys.GetValueOrDefault(name))
            .OfType<SshAgentKey>();
    }

    // ------------------------------------------------------------------ extensions

    private SshAgentReply Extension(byte[] message)
    {
        bool isBind;
        try
        {
            var reader = new SshReader(message.AsSpan(1));
            isBind = reader.ReadStringEquals(Encoding.ASCII.GetBytes(SshAgentProtocol.SessionBindExtension));
        }
        catch (SshWireException)
        {
            isBind = false;
        }
        // RFC 9987 §5.8: an extension type the agent doesn't support gets SSH_AGENT_FAILURE.
        return isBind ? Bind(message) : SshAgentReply.Failure;
    }

    /// <summary>Wire doc section 6: verify, check the host against this socket's keys, record for this connection.</summary>
    private SshAgentReply Bind(byte[] message)
    {
        var (binding, fingerprint, reason, detail) = CheckBind(message);
        var line = $"ssh-bind {PeerFields()} host={fingerprint ?? "-"} result={(reason is null ? "ok" : "refused")}";
        if (reason != null)
            line += $" reason={reason}" + (detail is null ? "" : $" detail={detail}");
        agent.Log.Event(line);
        if (reason != null)
            return new SshAgentReply(SshAgentProtocol.ExtensionFailureReply, Close: true);
        _binding = binding;
        return new SshAgentReply([SshAgentProtocol.Success]);
    }

    private (SshBinding? Binding, string? Fingerprint, string? Reason, string? Detail) CheckBind(byte[] message)
    {
        if (_bindTried)
            return (null, null, "second-bind", null); // OpenSSH's client binds each connection once
        _bindTried = true;
        byte[] hostKey, sessionId, signature;
        byte forwarding;
        try
        {
            var reader = new SshReader(message.AsSpan(1));
            reader.ReadString(); // the extension name, checked by the caller
            hostKey = reader.ReadString().ToArray();
            sessionId = reader.ReadString().ToArray();
            signature = reader.ReadString().ToArray();
            forwarding = reader.ReadByte();
            reader.EnsureEnd();
        }
        catch (SshWireException)
        {
            return (null, null, "malformed", null);
        }
        if (sessionId.Length == 0 || sessionId.Length > SshAgentProtocol.MaxSessionIdLength)
            return (null, null, "malformed", "session-id-length");
        var fingerprint = SshFingerprint.Of(hostKey);
        if (forwarding != 0)
            return (null, fingerprint, "forwarding", null);
        SshPublicKey host;
        try
        {
            host = SshPublicKey.Parse(hostKey);
        }
        catch (SshWireException)
        {
            return (null, fingerprint, "host-key-type", null);
        }
        if (host.VerifyRefusal(sessionId, signature) is { } bad)
            return (null, fingerprint, "bad-signature", bad);
        // No key of this socket may sign in to this host: nothing could ever be signed on this connection.
        var policy = agent.Policy;
        var allowed = AllowedKeys().Any(k => policy.SshKeys.TryGetValue(k.Name, out var p) && p.AllowedHostKeys.Contains(fingerprint, StringComparer.Ordinal));
        if (!allowed)
            return (null, fingerprint, "host-not-allowed", null);
        return (new SshBinding(hostKey, sessionId, fingerprint), fingerprint, null, null);
    }

    // ------------------------------------------------------------------ signing

    /// <summary>
    /// Wire doc section 5 and brief T10 decision 4: every check before any unlock, in this order:
    /// the key is on this socket's allow-list; the flags fit it; the connection is bound; the bound
    /// host is on this key's own <c>allowed_host_keys</c>; the data is this session's userauth request
    /// for this key. Then the sign-rate limit, then one fresh unlock (serialised with the broker's).
    /// </summary>
    private async Task<SshAgentReply> SignAsync(byte[] message, CancellationToken cancellationToken)
    {
        var started = agent.Time.GetTimestamp();
        byte[] keyBlob, data;
        uint flags;
        try
        {
            var reader = new SshReader(message.AsSpan(1));
            keyBlob = reader.ReadString().ToArray();
            data = reader.ReadString().ToArray();
            flags = reader.ReadUInt32();
            reader.EnsureEnd();
        }
        catch (SshWireException)
        {
            return Refused(null, "malformed", started);
        }

        // 1. This socket's allow-list, at sign time.
        var key = AllowedKeys().FirstOrDefault(k => k.PublicBlob.AsSpan().SequenceEqual(keyBlob));
        if (key is null || !agent.Policy.SshKeys.TryGetValue(key.Name, out var keyPolicy))
            return Refused(null, "key-not-allowed", started);
        if (keyPolicy.SecretName != key.SecretName)
            return Refused(key, "key-changed-restart", started); // a reload pointed the key at another secret
        // 2. The flags fit the key.
        if (SshKeySigner.FlagsRefusal(key.Type, flags) is { } flagRefusal)
            return Refused(key, flagRefusal, started);
        // 3. A verified bind on this connection.
        if (_binding is not { } binding)
            return Refused(key, "no-session-bind", started);
        // 4. The bound host is on THIS key's list (a bind allowed for key A never lets key B sign).
        if (!keyPolicy.AllowedHostKeys.Contains(binding.Fingerprint, StringComparer.Ordinal))
            return Refused(key, "host-not-allowed", started);
        // 5. Not an oracle: only this session's userauth request for this key.
        if (SshUserauth.Refusal(data, binding, key, flags) is { } notUserauth)
            return Refused(key, notUserauth, started);

        var (signature, reason, unlocked) = await agent.SignAsync(peer.Socket, key, data, flags, cancellationToken).ConfigureAwait(false);
        var line = $"ssh-sign {PeerFields()} key={key.Name} host={binding.Fingerprint} " +
                   (signature is null ? $"result={(unlocked ? "failed" : "refused")} reason={reason}" : "result=ok") +
                   $" unlocks={(unlocked ? 1 : 0)} ms={Ms(started)}";
        agent.Log.Event(line);
        return signature is null
            ? SshAgentReply.Failure
            : new SshAgentReply(new SshWriter().Byte(SshAgentProtocol.SignResponse).String(signature).ToArray());
    }

    private SshAgentReply Refused(SshAgentKey? key, string reason, long started)
    {
        agent.Log.Event($"ssh-sign {PeerFields()} key={key?.Name ?? "-"} host={_binding?.Fingerprint ?? "-"} result=refused reason={reason} unlocks=0 ms={Ms(started)}");
        return SshAgentReply.Failure;
    }

    private string PeerFields() =>
        $"socket={SshAgentListener.LogName(peer.Socket)} uid={peer.Uid.ToString(CultureInfo.InvariantCulture)} pid={peer.Pid.ToString(CultureInfo.InvariantCulture)}";

    private string Ms(long started) => ((long)agent.Time.GetElapsedTime(started).TotalMilliseconds).ToString(CultureInfo.InvariantCulture);
}
