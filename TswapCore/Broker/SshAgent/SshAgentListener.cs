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
    private readonly SshSignRateLimiter _signRate;
    private int _timeoutsInARow;

    internal SshAgentListener(SshAgentOptions agent, BrokerServerOptions server, string socketDir,
        BrokerConnectionCounter connections, BrokerRequestHandler http, Action<string> onFatal)
    {
        _http = http;
        _onFatal = onFatal;
        _signRate = new SshSignRateLimiter(agent.SignsPerMinute, server.Time);
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

    private readonly HashSet<string> _removed = new(StringComparer.Ordinal);
    private readonly HashSet<string> _announcedBack = new(StringComparer.Ordinal);
    private readonly HashSet<string> _announcedOverCap = new(StringComparer.Ordinal);

    /// <summary>
    /// After a reload (fix round 1, MiMo M1, GLM 3): an agent socket whose client socket is gone from
    /// broker.json, or which lists no ssh key any more, has its file removed (its connections were
    /// already refused at their next message), so nothing is left listening for a removed client.
    /// Listening again needs a restart, which a later reload that lists a key again says.
    /// </summary>
    internal void Reloaded(BrokerPolicy policy)
    {
        lock (_removed)
        {
            foreach (var (socket, path) in _sockets)
            {
                var wanted = policy.Sockets.TryGetValue(socket, out var s) && s.SshKeys.Count > 0;
                if (!wanted && _removed.Add(socket))
                {
                    _announcedBack.Remove(socket);
                    _server.Log.Event($"agent socket '{LogName(socket)}' {RemoveSocketFile(path)}: its client socket or last ssh key is no longer in broker.json (restart serve to listen on it again)");
                }
                else if (wanted && _removed.Contains(socket) && _announcedBack.Add(socket))
                {
                    _server.Log.Event($"agent socket '{LogName(socket)}' has ssh keys again: restart serve to listen on it");
                }
                // Round 2 (MiMo N3, GLM 2): a reload can't be refused for this, so it is said once:
                // only the first 64 keys by name are listed and may sign.
                if (wanted && s!.SshKeys.Count > SshAgentProtocol.MaxIdentities && _announcedOverCap.Add(socket))
                    _server.Log.Event($"socket '{socket}' lists {s.SshKeys.Count} ssh keys after the reload; only the first {SshAgentProtocol.MaxIdentities} by name are offered (serve refuses more at start)");
                else if (wanted && s!.SshKeys.Count <= SshAgentProtocol.MaxIdentities)
                    _announcedOverCap.Remove(socket);
            }
        }
    }

    /// <summary>
    /// Removes an agent socket file, saying what happened for the log line (round 2, GLM 1/3, MiMo
    /// N1): <c>removed</c>, <c>was already gone</c>, or why it couldn't be removed (it is then removed
    /// under the lock at the next start; its connections are refused meanwhile).
    /// </summary>
    private static string RemoveSocketFile(string path)
    {
        if (BrokerNative.LStat(path) is not { Type: BrokerNative.EntryType.Socket })
            return "was already gone";
        try
        {
            File.Delete(path);
            return "removed";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"could not be removed ({ex.GetType().Name}; it goes at the next start)";
        }
    }

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
            // As brief T9 decides for the HTTP sockets, with the same switch: no client shares the
            // broker's (the vault user's) uid.
            if (creds.Uid == _server.Ownership.EffectiveUid && !_server.AllowOwnUidForTests)
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

    internal BrokerLog Log => _server.Log;

    internal TimeProvider Time => _server.Time;

    /// <summary>
    /// One signature with a fresh unlock (brief T10 decision 5), after every request check passed:
    /// the sign-rate limit, then T8's unlock-failure limits, the per-socket unlock budget (T13) and the global unlock limit
    /// (<see cref="BrokerUnlockGuard"/>, shared with the HTTP sockets and keyed by the client socket),
    /// then the broker's single unlock at a time (waiting at most <see cref="BrokerLimits.MaxQueueWait"/>),
    /// abandoning an unlock that hangs past <see cref="BrokerLimits.UnlockTimeout"/>. Returns the
    /// signature blob, or null with the reason and whether an unlock was made.
    /// </summary>
    internal async Task<(byte[]? Signature, string? Reason, bool Unlocked)> SignAsync(
        string socket, SshAgentKey key, byte[] data, uint flags, CancellationToken cancellationToken)
    {
        var guard = _http.UnlockGuard;
        if (!_signRate.Allows(socket))
            return (null, "sign-rate", false);
        if (guard.Refusal(socket) is { } refused)
            return (null, refused, false);
        using var queueWait = new CancellationTokenSource(_server.Limits.MaxQueueWait, _server.Time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(queueWait.Token, cancellationToken);
        try
        {
            await _http.UnlockGate.WaitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return (null, cancellationToken.IsCancellationRequested ? "client-closed" : "busy", false);
        }
        try
        {
            // Re-checked under the unlock lock: other connections may have used the window meanwhile.
            if (!_signRate.Allows(socket))
                return (null, "sign-rate", false);
            if (guard.Refusal(socket) is { } refusedNow)
                return (null, refusedNow, false);
            guard.RecordAttempt(socket);
            var sign = Task.Run(() => SshKeySigner.Sign(_agent.KeySource, key, data, flags));
            byte[] signature;
            try
            {
                signature = await sign.WaitAsync(_server.Limits.UnlockTimeout, _server.Time).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                _ = sign.ContinueWith(t => _ = t.Exception, TaskScheduler.Default); // abandoned; its result is never used
                if (Interlocked.Increment(ref _timeoutsInARow) >= _server.Limits.UnlockTimeoutsBeforeExit)
                {
                    var reason = $"{_server.Limits.UnlockTimeoutsBeforeExit} ssh-agent unlocks in a row took longer than {_server.Limits.UnlockTimeout.TotalSeconds:0} s; exiting so the service manager restarts serve";
                    _server.Log.Event(reason);
                    _onFatal(reason);
                }
                return (null, "unlock-timeout", true);
            }
            catch (BrokerUnlockException)
            {
                Interlocked.Exchange(ref _timeoutsInARow, 0);
                if (guard.RecordFailure(socket))
                    _server.Log.Event($"socket '{socket}' locked out after repeated unlock failures");
                return (null, "unlock-failed", true);
            }
            catch (BrokerSecretException)
            {
                Interlocked.Exchange(ref _timeoutsInARow, 0);
                return (null, "secret-unusable", true);
            }
            catch (SshSignRefusedException ex)
            {
                Interlocked.Exchange(ref _timeoutsInARow, 0);
                return (null, ex.Message, true); // key-changed, key-unusable: fixed words
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Interlocked.Exchange(ref _timeoutsInARow, 0);
                return (null, "signer-error", true);
            }
            Interlocked.Exchange(ref _timeoutsInARow, 0);
            guard.RecordSuccess(socket);
            _signRate.Record(socket);
            return (signature, null, true);
        }
        finally
        {
            _http.UnlockGate.Release();
        }
    }

    private static string Num(uint value) => value.ToString(CultureInfo.InvariantCulture);

    private static string Num(int value) => value.ToString(CultureInfo.InvariantCulture);
}

/// <summary>A reply to send (null for none) and whether to close the connection after it.</summary>
internal readonly record struct SshAgentReply(byte[]? Body, bool Close = false)
{
    public static SshAgentReply Failure => new(SshAgentProtocol.FailureReply);
}
