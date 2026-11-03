using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TswapCore.Agent;
using TswapCore.VaultPassword;

namespace TswapCore.Broker;

/// <summary>What a password broker's control socket answered (brief T17 ruling 14).</summary>
public abstract record BrokerControlAnswer
{
    private BrokerControlAnswer()
    {
    }

    /// <summary><c>unlock</c> or <c>lock</c> done.</summary>
    public sealed record Done : BrokerControlAnswer;

    /// <summary><c>status</c>: locked or unlocked, the unlock's timeout, and how many peers the socket refused.</summary>
    public sealed record State(bool Unlocked, DateTimeOffset? ExpiresAt, uint RefusedPeers) : BrokerControlAnswer;

    /// <summary>The broker refused, with a text to show (a wrong password, already unlocked, ...).</summary>
    public sealed record Refused(string Message) : BrokerControlAnswer;

    /// <summary>No broker: no socket, nothing listening, or no answer in time.</summary>
    public sealed record NotRunning : BrokerControlAnswer;

    /// <summary>Another vault's broker answers there.</summary>
    public sealed record OtherVault : BrokerControlAnswer;

    /// <summary>An answer that breaks the protocol.</summary>
    public sealed record Malformed : BrokerControlAnswer;
}

/// <summary>
/// <c>tswap broker unlock|lock|status</c>'s side of the control socket (brief T17 ruling 14). It never
/// creates a file or folder. Before sending anything it checks the <b>server</b> on the connected socket:
/// its uid must be the vault user's, and on Linux its SELinux label must not be a container's. Before it
/// sends the stretched password (<c>unlock</c>) it also checks, on Linux, that the server is in this user
/// namespace: the genuine broker is dumpable while locked, so its link is readable, and an unreadable link
/// (an unlocked broker, or not the real one) is refused with nothing sent. On macOS the uid is all there is.
/// </summary>
public static class BrokerControlClient
{
    public const string UnreadableServerLinkText =
        "The broker is already unlocked or is not the real broker; run 'tswap broker status'.";

    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);

    /// <summary>An unlock may wait for the TPM; a lock waits for in-flight unlocks to finish.</summary>
    public static readonly TimeSpan SlowResponseTimeout = TimeSpan.FromSeconds(120);

    public static readonly TimeSpan StatusResponseTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Test seam: called with the path before every connect.</summary>
    internal static Action<string>? ConnectObserver;

    /// <summary>Test seam: the clock of the deadlines.</summary>
    internal static TimeProvider Time = TimeProvider.System;

    internal static void ResetSeamsForTests()
    {
        ConnectObserver = null;
        Time = TimeProvider.System;
    }

    /// <summary>Sends the stretched password (and the absolute timeout, if any) to the broker at <paramref name="path"/>.</summary>
    public static BrokerControlAnswer Unlock(string path, byte[] vaultId, uint ownerUid, StretchedPassword password, DateTimeOffset? expiresAt)
    {
        var payload = new byte[expiresAt is null ? BrokerControlProtocol.PasswordPayloadSize : BrokerControlProtocol.PasswordWithExpirySize];
        byte[]? frame = null;
        try
        {
            password.CopyTo(payload.AsSpan(0, StretchedPassword.Size));
            if (expiresAt is { } e)
                BinaryPrimitives.WriteInt64LittleEndian(payload.AsSpan(StretchedPassword.Size), e.ToUnixTimeSeconds());
            frame = AgentProtocol.EncodeRequest((byte)BrokerControlOp.Unlock, vaultId, payload);
            return Send(BrokerControlOp.Unlock, path, frame, PeerPolicy.BrokerServerForUnlock(ownerUid), SlowResponseTimeout);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            if (frame is not null)
                CryptographicOperations.ZeroMemory(frame);
        }
    }

    /// <summary>Asks the broker to zero the password and return to locked.</summary>
    public static BrokerControlAnswer Lock(string path, byte[] vaultId, uint ownerUid) =>
        Send(BrokerControlOp.Lock, path, AgentProtocol.EncodeRequest((byte)BrokerControlOp.Lock, vaultId),
            PeerPolicy.BrokerServerUidAndLabel(ownerUid), SlowResponseTimeout);

    /// <summary>Asks whether the broker is locked.</summary>
    public static BrokerControlAnswer Status(string path, byte[] vaultId, uint ownerUid) =>
        Send(BrokerControlOp.Status, path, AgentProtocol.EncodeRequest((byte)BrokerControlOp.Status, vaultId),
            PeerPolicy.BrokerServerUidAndLabel(ownerUid), StatusResponseTimeout);

    private static BrokerControlAnswer Send(BrokerControlOp op, string path, byte[] frame, PeerPolicy policy, TimeSpan responseTimeout) =>
        // The CLI is synchronous; run the socket work off any caller's synchronization context.
        Task.Run(() => SendAsync(op, path, frame, policy, responseTimeout)).GetAwaiter().GetResult();

    private static async Task<BrokerControlAnswer> SendAsync(BrokerControlOp op, string path, byte[] frame, PeerPolicy policy,
        TimeSpan responseTimeout)
    {
        if (OperatingSystem.IsWindows())
            throw new TswapException("'tswap broker' is not supported on Windows.");
        ConnectObserver?.Invoke(path);
        if (BrokerNative.LStat(path) is not { Type: not BrokerNative.EntryType.Missing })
            return new BrokerControlAnswer.NotRunning();
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        using (var connectDeadline = new CancellationTokenSource(ConnectTimeout, Time))
        {
            try
            {
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), connectDeadline.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException)
            {
                return new BrokerControlAnswer.NotRunning();
            }
        }

        var verdict = PeerIdentity.Check(socket, policy);
        if (!verdict.Allowed)
        {
            if (op == BrokerControlOp.Unlock && verdict.Reason is "peer's user namespace unreadable" or "peer's /proc entry unreadable")
                throw new TswapException(UnreadableServerLinkText);
            throw new TswapException(verdict.Uid is { } uid && uid != policy.Uid
                ? $"The broker control socket {path} is served by uid {uid}, not the vault user (uid {policy.Uid}); not using it."
                : $"The broker control socket {path} failed its check ({verdict.Reason}); not using it.");
        }

        await using var stream = new NetworkStream(socket, ownsSocket: false);
        byte[]? body = null;
        try
        {
            using var deadline = new CancellationTokenSource(responseTimeout, Time);
            try
            {
                await stream.WriteAsync(frame, deadline.Token).ConfigureAwait(false);
                var prefix = new byte[AgentProtocol.LengthPrefixSize];
                var read = await stream.ReadAtLeastAsync(prefix, prefix.Length, throwOnEndOfStream: false, deadline.Token).ConfigureAwait(false);
                if (read == 0)
                    return new BrokerControlAnswer.NotRunning();
                if (read < prefix.Length)
                    return new BrokerControlAnswer.Malformed();
                body = new byte[AgentProtocol.DecodeLength(prefix)];
                if (await stream.ReadAtLeastAsync(body, body.Length, throwOnEndOfStream: false, deadline.Token).ConfigureAwait(false) < body.Length)
                    return new BrokerControlAnswer.Malformed();
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException)
            {
                return new BrokerControlAnswer.NotRunning();
            }
            catch (AgentProtocolException)
            {
                return new BrokerControlAnswer.Malformed();
            }
            return Interpret(op, body);
        }
        finally
        {
            if (body is not null)
                CryptographicOperations.ZeroMemory(body);
        }
    }

    private static BrokerControlAnswer Interpret(BrokerControlOp op, byte[] body)
    {
        AgentResponse response;
        try
        {
            response = AgentProtocol.DecodeResponse(body);
        }
        catch (AgentProtocolException)
        {
            return new BrokerControlAnswer.Malformed();
        }
        var payload = response.Payload;
        switch (response.Status)
        {
            case AgentStatus.Ok when op == BrokerControlOp.Status:
                try
                {
                    var (unlocked, expiresAt, refused) = BrokerControlProtocol.DecodeStatus(payload);
                    return new BrokerControlAnswer.State(unlocked, expiresAt, refused);
                }
                catch (AgentProtocolException)
                {
                    return new BrokerControlAnswer.Malformed();
                }
            case AgentStatus.Ok:
                return payload.Length == 0 ? new BrokerControlAnswer.Done() : new BrokerControlAnswer.Malformed();
            case AgentStatus.OtherVault:
                return new BrokerControlAnswer.OtherVault();
            case AgentStatus.HardwareFailed when payload.Length <= AgentProtocol.MaxMessageBytes:
                try
                {
                    return new BrokerControlAnswer.Refused(new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(payload));
                }
                catch (DecoderFallbackException)
                {
                    return new BrokerControlAnswer.Malformed();
                }
            default:
                return new BrokerControlAnswer.Malformed();
        }
    }
}
