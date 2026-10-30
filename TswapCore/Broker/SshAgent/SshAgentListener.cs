using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.IO.Pipelines;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace TswapCore.Broker.SshAgent;

/// <summary>
/// The broker's ssh-agent endpoint (brief T10 decisions 1 and 2): for each socket that lists ssh keys,
/// <c>serve</c> also listens on <c>&lt;name&gt;.ssh.sock</c> next to it, in the same folder, under the
/// same lock, with the same peer-uid check and connection limits as T8's sockets. Each connection
/// speaks the agent protocol (<c>docs/ssh-agent-wire.md</c>): frames of at most 256 KiB, handled one
/// at a time and in order; an oversize, empty or truncated frame, an idle connection or any
/// exception closes that connection only.
/// </summary>
public sealed class SshAgentListener
{
    public const string SocketSuffix = ".ssh.sock";

    private readonly SshAgentOptions _agent;
    private readonly BrokerServerOptions _server;
    private readonly BrokerConnectionCounter _connections;
    private readonly IReadOnlyList<(string Socket, string Path)> _sockets;
    private readonly BrokerRequestHandler _http;
    private readonly Action<string> _onFatal;

    internal SshAgentListener(SshAgentOptions agent, BrokerServerOptions server, string socketDir,
        BrokerConnectionCounter connections, BrokerRequestHandler http, Action<string> onFatal)
    {
        _http = http;
        _onFatal = onFatal;
        _agent = agent;
        _server = server;
        _connections = connections;
        _sockets = [.. server.Policy.Current.Sockets.Values
            .Where(s => s.SshKeys.Count > 0)
            .OrderBy(s => s.Name, StringComparer.Ordinal)
            .Select(s => (s.Name, SocketPath(socketDir, s.Name)))];
    }

    /// <summary>The agent socket of client socket <paramref name="socketName"/>: <c>&lt;name&gt;.ssh.sock</c> next to its HTTP socket.</summary>
    public static string SocketPath(string socketDir, string socketName) => Path.Combine(socketDir, socketName + SocketSuffix);

    /// <summary>True for an agent socket's path (HTTP socket names can't contain '.', so the two never collide).</summary>
    public static bool IsAgentSocketPath(string path) => path.EndsWith(SocketSuffix, StringComparison.Ordinal);

    /// <summary>The agent socket files this listener creates (serve removes stale ones, sets their mode and removes them at stop).</summary>
    public IEnumerable<string> SocketPaths => _sockets.Select(s => s.Path);

    /// <summary>Adds the agent sockets to Kestrel: raw connections, never parsed as HTTP.</summary>
    internal void Listen(KestrelServerOptions kestrel)
    {
        foreach (var (socket, path) in _sockets)
            kestrel.ListenUnixSocket(path, listen => listen.Use(_ => connection => HandleConnectionAsync(connection, socket)));
    }

    /// <summary>The name used for this socket's agent in logs and connection counts.</summary>
    internal static string LogName(string socket) => socket + ".ssh";

    private async Task HandleConnectionAsync(ConnectionContext connection, string socketName)
    {
        var logName = LogName(socketName);
        var log = _server.Log;
        if (!_connections.TryOpen(logName))
        {
            log.Connection(logName, null, null, "too-many-connections");
            return; // closed, unanswered
        }
        uint? uid = null;
        int? pid = null;
        try
        {
            var socket = connection.Features.Get<IConnectionSocketFeature>()?.Socket;
            var peer = socket is null ? null : BrokerNative.TryGetPeerCredentials(socket);
            if (peer is not { } creds)
            {
                log.Connection(logName, null, null, "no-peer-credentials");
                return;
            }
            (uid, pid) = (creds.Uid, creds.Pid);
            // As brief T9 decides for the HTTP sockets: no client shares the broker's (the vault user's) uid.
            if (creds.Uid == _server.Ownership.EffectiveUid && !_agent.AllowOwnUidForTests)
            {
                log.Connection(logName, creds.Uid, creds.Pid, "own-uid");
                return;
            }
            if (Refusal(socketName, creds.Uid) is { } refused)
            {
                log.Connection(logName, creds.Uid, creds.Pid, refused);
                return;
            }

            var session = new SshAgentSession(this, new BrokerPeer(socketName, creds.Uid, creds.Pid));
            var input = connection.Transport.Input;
            var output = connection.Transport.Output;
            while (true)
            {
                var (message, closeReason) = await ReadFrameAsync(input).ConfigureAwait(false);
                if (message is null)
                {
                    if (closeReason != null)
                        log.Event($"ssh-connection socket={logName} uid={Num(creds.Uid)} pid={Num(creds.Pid)} closed reason={closeReason}");
                    return;
                }
                // The config may have changed since the connection was accepted (SIGHUP): re-check per message.
                if (Refusal(socketName, creds.Uid) is { } now)
                {
                    log.Connection(logName, creds.Uid, creds.Pid, now);
                    return;
                }
                var reply = await session.HandleAsync(message, connection.ConnectionClosed).ConfigureAwait(false);
                if (reply.Body is { } body)
                {
                    var frame = new byte[4 + body.Length];
                    BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)body.Length);
                    body.CopyTo(frame, 4);
                    await output.WriteAsync(frame, connection.ConnectionClosed).ConfigureAwait(false);
                }
                if (reply.Close)
                    return;
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // One connection's failure closes that connection, never serve. The message is not logged
            // (it could quote bytes the client sent).
            log.Event($"ssh-connection socket={logName} uid={(uid is { } u ? Num(u) : "?")} pid={(pid is { } p ? Num(p) : "?")} closed reason=error ({ex.GetType().Name})");
        }
        finally
        {
            _connections.Close(logName);
        }
    }

    /// <summary>Why this uid may not use this socket's agent now (<c>socket-removed</c>, <c>uid-not-allowed</c>), or null.</summary>
    private string? Refusal(string socketName, uint uid)
    {
        var policy = _server.Policy.Current;
        if (!policy.Sockets.TryGetValue(socketName, out var socket))
            return "socket-removed";
        return socket.AllowsUid(uid) ? null : "uid-not-allowed";
    }

    /// <summary>
    /// One frame's body (type and contents), or null with the reason the connection ends: a clean end
    /// (null reason), <c>truncated</c>, <c>frame-length</c> (0 or over 256 KiB) or <c>idle</c>.
    /// </summary>
    private async Task<(byte[]? Message, string? CloseReason)> ReadFrameAsync(PipeReader input)
    {
        // Only the idle timer cancels a read: a peer that closes ends the read with what it sent.
        using var idle = new CancellationTokenSource(_agent.IdleTimeout, _server.Time);
        try
        {
            var header = new byte[4];
            var got = await ReadExactlyAsync(input, header, idle.Token).ConfigureAwait(false);
            if (got < header.Length)
                return (null, got == 0 ? null : "truncated");
            var length = BinaryPrimitives.ReadUInt32BigEndian(header);
            if (length == 0 || length > SshAgentProtocol.MaxMessageLength)
                return (null, "frame-length");
            var message = new byte[length];
            if (await ReadExactlyAsync(input, message, idle.Token).ConfigureAwait(false) < message.Length)
                return (null, "truncated");
            return (message, null);
        }
        catch (OperationCanceledException) when (idle.IsCancellationRequested)
        {
            return (null, "idle");
        }
    }

    /// <summary>
    /// Copies the next <c>target.Length</c> bytes into <paramref name="target"/> as they arrive (never
    /// waiting for the pipe to buffer a whole frame); returns fewer when the peer ends the stream.
    /// </summary>
    private static async Task<int> ReadExactlyAsync(PipeReader input, byte[] target, CancellationToken cancellationToken)
    {
        var filled = 0;
        while (filled < target.Length)
        {
            var result = await input.ReadAsync(cancellationToken).ConfigureAwait(false);
            var buffer = result.Buffer;
            var take = (int)Math.Min(buffer.Length, target.Length - filled);
            buffer.Slice(0, take).CopyTo(target.AsSpan(filled));
            filled += take;
            input.AdvanceTo(buffer.GetPosition(take));
            if (filled < target.Length && result.IsCompleted)
                break;
        }
        return filled;
    }

    // ------------------------------------------------------------------ what sessions use

    internal BrokerPolicy Policy => _server.Policy.Current;

    internal IReadOnlyDictionary<string, SshAgentKey> Keys => _agent.Keys;

    private static string Num(uint value) => value.ToString(CultureInfo.InvariantCulture);

    private static string Num(int value) => value.ToString(CultureInfo.InvariantCulture);
}

/// <summary>A reply to send (null for none) and whether to close the connection after it.</summary>
internal readonly record struct SshAgentReply(byte[]? Body, bool Close = false)
{
    public static SshAgentReply Failure => new(SshAgentProtocol.FailureReply);
}
