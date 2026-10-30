namespace TswapCore.Broker.SshAgent;

/// <summary>A connection's verified <c>session-bind@openssh.com</c>: the host key, the session identifier and the host key's fingerprint.</summary>
internal sealed record SshBinding(byte[] HostKeyBlob, byte[] SessionId, string Fingerprint);

/// <summary>
/// The only data the agent signs (brief T10 decision 4, check 5; wire doc section 5.1): an SSH
/// publickey userauth request for this connection's bound session, for exactly the requested key and
/// algorithm, parsed completely with no trailing bytes. Anything else (SSHSIG documents, git commits,
/// arbitrary blobs) is refused, so the agent is not a signing oracle.
/// </summary>
internal static class SshUserauth
{
    private const byte UserauthRequest = 50; // SSH_MSG_USERAUTH_REQUEST (RFC 4252 §6)

    /// <summary>Why <paramref name="data"/> may not be signed for <paramref name="key"/> on this binding, or null when it may.</summary>
    public static string? Refusal(ReadOnlySpan<byte> data, SshBinding binding, SshAgentKey key, uint flags)
    {
        try
        {
            var reader = new SshReader(data);
            if (!reader.ReadString().SequenceEqual(binding.SessionId))
                return "session-id";
            if (reader.ReadByte() != UserauthRequest)
                return "not-userauth";
            reader.ReadString(); // the user name: the server decides who may log in
            if (!reader.ReadStringEquals("ssh-connection"u8))
                return "service";
            var method = reader.ReadString();
            var hostBound = method.SequenceEqual("publickey-hostbound-v00@openssh.com"u8);
            if (!hostBound && !method.SequenceEqual("publickey"u8))
                return "method";
            if (reader.ReadByte() != 1)
                return "not-userauth";
            if (!reader.ReadString().SequenceEqual(System.Text.Encoding.ASCII.GetBytes(SshKeySigner.AlgorithmName(key.Type, flags))))
                return "algorithm";
            if (!reader.ReadString().SequenceEqual(key.PublicBlob))
                return "key-blob";
            if (hostBound && !reader.ReadString().SequenceEqual(binding.HostKeyBlob))
                return "host-key";
            return reader.AtEnd ? null : "trailing-bytes";
        }
        catch (SshWireException)
        {
            return "not-userauth";
        }
    }
}

/// <summary>
/// Successful signatures per socket in the last minute (brief T10 decision 5): each one is a vault
/// unlock, so beyond <see cref="SshAgentOptions.SignsPerMinute"/> a socket is refused until the
/// window moves on. Times come from the injected clock.
/// </summary>
internal sealed class SshSignRateLimiter(int perMinute, TimeProvider time)
{
    private readonly Dictionary<string, Queue<DateTimeOffset>> _signs = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    public bool Allows(string socket)
    {
        var now = time.GetUtcNow();
        lock (_gate)
            return Window(socket, now).Count < perMinute;
    }

    public void Record(string socket)
    {
        var now = time.GetUtcNow();
        lock (_gate)
            Window(socket, now).Enqueue(now);
    }

    private Queue<DateTimeOffset> Window(string socket, DateTimeOffset now)
    {
        if (!_signs.TryGetValue(socket, out var queue))
            _signs[socket] = queue = new Queue<DateTimeOffset>();
        while (queue.Count > 0 && queue.Peek() <= now - TimeSpan.FromMinutes(1))
            queue.Dequeue();
        return queue;
    }
}
