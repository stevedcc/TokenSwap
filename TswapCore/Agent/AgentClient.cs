using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TswapCore.Broker;

namespace TswapCore.Agent;

/// <summary>What the agent answered, or why there was no usable answer (brief T17 ruling 8).</summary>
public abstract record AgentAnswer
{
    private AgentAnswer()
    {
    }

    /// <summary>The vault key. The caller zeroes <see cref="VaultKey"/> when done with it (ruling 8).</summary>
    public sealed record Unlocked(byte[] VaultKey) : AgentAnswer
    {
        public override string ToString() => "Unlocked { VaultKey = (32 bytes, not shown) }";
    }

    /// <summary>The agent runs; <see cref="ExpiresAt"/> is null without a timeout.</summary>
    public sealed record Running(DateTimeOffset? ExpiresAt, uint RefusedPeers) : AgentAnswer;

    /// <summary>The agent accepted <c>stop</c>.</summary>
    public sealed record Stopped : AgentAnswer;

    /// <summary>The agent holds another vault's password (two vaults sharing a socket name).</summary>
    public sealed record OtherVault : AgentAnswer;

    /// <summary>The password expired, or the agent was stopped while this request waited.</summary>
    public sealed record Expired : AgentAnswer;

    /// <summary>The agent's own hardware unlock failed; <see cref="Message"/> is safe to show.</summary>
    public sealed record HardwareFailed(string Message) : AgentAnswer;

    /// <summary>No agent: no socket, nothing listening, no answer in time, or the connection closed unanswered.</summary>
    public sealed record NotRunning : AgentAnswer;

    /// <summary>An answer that breaks the protocol.</summary>
    public sealed record Malformed : AgentAnswer;
}

/// <summary>
/// Asks a running agent (brief T17 rulings 7 and 8). It never creates a file or folder: a missing
/// folder or socket is <see cref="AgentAnswer.NotRunning"/>. Before it sends anything it checks the
/// <b>server's</b> uid (<c>SO_PEERCRED</c>/<c>getpeereid</c> on the connected socket), which must be the
/// vault owner's, whatever path <c>TSWAP_AGENT_SOCK</c> chose; on Windows, the server's SID must be
/// this user's. A server that fails the check is refused with a <see cref="TswapException"/>. There is
/// no namespace or label check on the agent: the request carries nothing secret, and the caller checks
/// the answer against the vault's <c>keyCheck</c> (ruling 9).
/// </summary>
public static class AgentClient
{
    public static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(2);

    /// <summary>An unlock may wait for a touch or Touch ID.</summary>
    public static readonly TimeSpan DefaultResponseTimeout = TimeSpan.FromSeconds(120);

    /// <summary><c>status</c> and <c>stop</c> answer at once (they bypass the unlock gate); this bounds a server that doesn't.</summary>
    public static readonly TimeSpan ControlResponseTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Test seam: the clock of the deadlines.</summary>
    internal static TimeProvider Time = TimeProvider.System;

    /// <summary>Test seam: the connect (a listener that never accepts).</summary>
    internal static Func<Socket, EndPoint, CancellationToken, ValueTask>? Connect;

    /// <summary>Test seam: called once the request has been sent.</summary>
    internal static Action? RequestSentObserver;

    internal static void ResetSeamsForTests()
    {
        Time = TimeProvider.System;
        Connect = null;
        RequestSentObserver = null;
    }

    public static AgentAnswer Unlock(string socketPath, byte[] vaultId, uint expectedServerUid) =>
        Unlock(socketPath, vaultId, expectedServerUid, DefaultConnectTimeout, DefaultResponseTimeout);

    /// <summary>Asks for the vault key.</summary>
    public static AgentAnswer Unlock(string socketPath, byte[] vaultId, uint expectedServerUid, TimeSpan connectTimeout,
        TimeSpan responseTimeout) =>
        Send(AgentOp.Unlock, socketPath, vaultId, expectedServerUid, connectTimeout, responseTimeout);

    /// <summary>Asks whether the agent runs, its expiry and how many peers it refused.</summary>
    public static AgentAnswer Status(string socketPath, byte[] vaultId, uint expectedServerUid, TimeSpan? connectTimeout = null) =>
        Send(AgentOp.Status, socketPath, vaultId, expectedServerUid, connectTimeout ?? DefaultConnectTimeout, ControlResponseTimeout);

    /// <summary>Asks the agent to zero the password and exit.</summary>
    public static AgentAnswer Stop(string socketPath, byte[] vaultId, uint expectedServerUid, TimeSpan? connectTimeout = null) =>
        Send(AgentOp.Stop, socketPath, vaultId, expectedServerUid, connectTimeout ?? DefaultConnectTimeout, ControlResponseTimeout);

    private static AgentAnswer Send(AgentOp op, string socketPath, byte[] vaultId, uint expectedServerUid,
        TimeSpan connectTimeout, TimeSpan responseTimeout) =>
        // The CLI is synchronous; run the socket work off any caller's synchronization context.
        Task.Run(() => SendAsync(op, socketPath, vaultId, expectedServerUid, connectTimeout, responseTimeout))
            .GetAwaiter().GetResult();

    private static async Task<AgentAnswer> SendAsync(AgentOp op, string path, byte[] vaultId, uint expectedServerUid,
        TimeSpan connectTimeout, TimeSpan responseTimeout)
    {
        if (OperatingSystem.IsWindows())
            return await SendOverPipeAsync(op, path, vaultId, connectTimeout, responseTimeout).ConfigureAwait(false);

        if (BrokerNative.LStat(path) is not { Type: not BrokerNative.EntryType.Missing })
            return new AgentAnswer.NotRunning();
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        using (var connectDeadline = new CancellationTokenSource(connectTimeout, Time))
        {
            try
            {
                var endpoint = new UnixDomainSocketEndPoint(path);
                if (Connect is { } connect)
                    await connect(socket, endpoint, connectDeadline.Token).ConfigureAwait(false);
                else
                    await socket.ConnectAsync(endpoint, connectDeadline.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException)
            {
                return new AgentAnswer.NotRunning(); // refused (a stale socket), missing, or no accept in time
            }
        }

        var verdict = PeerIdentity.Check(socket, PeerPolicy.AgentServer(expectedServerUid));
        if (!verdict.Allowed)
            throw new TswapException(verdict.Uid is { } uid
                ? $"The tswap agent socket {path} is served by uid {uid}, not the vault owner (uid {expectedServerUid}); not using it."
                : $"Can't tell who serves the tswap agent socket {path} ({verdict.Reason}); not using it.");

        await using var stream = new NetworkStream(socket, ownsSocket: false);
        return await ExchangeAsync(stream, op, vaultId, responseTimeout).ConfigureAwait(false);
    }

    private static async Task<AgentAnswer> SendOverPipeAsync(AgentOp op, string pipeName, byte[] vaultId,
        TimeSpan connectTimeout, TimeSpan responseTimeout)
    {
        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using (var connectDeadline = new CancellationTokenSource(connectTimeout, Time))
        {
            try
            {
                await pipe.ConnectAsync(connectDeadline.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or TimeoutException or IOException)
            {
                return new AgentAnswer.NotRunning();
            }
        }
        var own = WindowsPipeIdentity.ReadOwnSid();
        var server = WindowsPipeIdentity.ReadServerSid(pipe);
        if (own is null || server is null || !string.Equals(own, server, StringComparison.OrdinalIgnoreCase))
            throw new TswapException(
                $"The tswap agent pipe {pipeName} is served by {server ?? "an unknown user"}, not by this user ({own ?? "?"}); not using it.");
        return await ExchangeAsync(pipe, op, vaultId, responseTimeout).ConfigureAwait(false);
    }

    private static async Task<AgentAnswer> ExchangeAsync(Stream stream, AgentOp op, byte[] vaultId, TimeSpan responseTimeout)
    {
        byte[]? body = null;
        try
        {
            using var deadline = new CancellationTokenSource(responseTimeout, Time);
            try
            {
                await stream.WriteAsync(AgentProtocol.EncodeRequest((byte)op, vaultId), deadline.Token).ConfigureAwait(false);
                RequestSentObserver?.Invoke();
                var prefix = new byte[AgentProtocol.LengthPrefixSize];
                var read = await stream.ReadAtLeastAsync(prefix, prefix.Length, throwOnEndOfStream: false, deadline.Token)
                    .ConfigureAwait(false);
                if (read == 0)
                    return new AgentAnswer.NotRunning(); // closed unanswered (killed mid-request, or it refused us)
                if (read < prefix.Length)
                    return new AgentAnswer.Malformed();
                body = new byte[AgentProtocol.DecodeLength(prefix)];
                if (await stream.ReadAtLeastAsync(body, body.Length, throwOnEndOfStream: false, deadline.Token)
                        .ConfigureAwait(false) < body.Length)
                    return new AgentAnswer.Malformed();
            }
            catch (OperationCanceledException)
            {
                return new AgentAnswer.NotRunning(); // no answer in time
            }
            catch (IOException)
            {
                return new AgentAnswer.NotRunning();
            }
            catch (AgentProtocolException)
            {
                return new AgentAnswer.Malformed();
            }
            return Interpret(op, body);
        }
        finally
        {
            if (body is not null)
                CryptographicOperations.ZeroMemory(body);
        }
    }

    private static AgentAnswer Interpret(AgentOp op, byte[] body)
    {
        AgentResponse response;
        try
        {
            response = AgentProtocol.DecodeResponse(body);
        }
        catch (AgentProtocolException)
        {
            return new AgentAnswer.Malformed();
        }
        var payload = response.Payload;
        try
        {
            switch (response.Status)
            {
                case AgentStatus.Ok when op == AgentOp.Unlock:
                    return payload.Length == AgentProtocol.VaultKeySize
                        ? new AgentAnswer.Unlocked(payload.ToArray())
                        : new AgentAnswer.Malformed();
                case AgentStatus.Ok when op == AgentOp.Status:
                    try
                    {
                        var (expiresAt, refused) = AgentProtocol.DecodeStatusPayload(payload);
                        return new AgentAnswer.Running(expiresAt, refused);
                    }
                    catch (AgentProtocolException)
                    {
                        return new AgentAnswer.Malformed();
                    }
                case AgentStatus.Ok when op == AgentOp.Stop:
                    return payload.Length == 0 ? new AgentAnswer.Stopped() : new AgentAnswer.Malformed();
                case AgentStatus.OtherVault:
                    return new AgentAnswer.OtherVault();
                case AgentStatus.Expired:
                    return new AgentAnswer.Expired();
                case AgentStatus.HardwareFailed when payload.Length <= AgentProtocol.MaxMessageBytes:
                    try
                    {
                        return new AgentAnswer.HardwareFailed(new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(payload));
                    }
                    catch (DecoderFallbackException)
                    {
                        return new AgentAnswer.Malformed();
                    }
                default:
                    return new AgentAnswer.Malformed();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }
}
