using System.Net.Sockets;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T37 (#332): <see cref="SshAgentTestClient.SendFrameUnlessClosedAsync"/>, the send for tests where the broker
/// may refuse the connection at accept. A send that meets the peer's close counts as closed; anything else still throws.
/// Against a plain listener on a Unix socket in a temp folder, no broker.
/// </summary>
public class SshAgentTestClientTests
{
    [UnixFact("Unix sockets")]
    public async Task SendFrameUnlessClosed_AfterThePeerClosed_ReturnsFalse_AndReadsAsClosed()
    {
        var dir = Directory.CreateTempSubdirectory("tswap-agentclient-").FullName;
        try
        {
            using var listener = Listen(dir);
            using var client = await ConnectAsync(dir);
            (await listener.AcceptAsync()).Dispose(); // the peer closes first: the send below fails with EPIPE every time

            Assert.False(await client.SendFrameUnlessClosedAsync([11]));
            Assert.True(await client.ClosedWithoutReplyAsync());
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [UnixFact("Unix sockets")]
    public async Task SendFrameUnlessClosed_ToAnOpenPeer_ReturnsTrue_AndThePeerGetsTheFrame()
    {
        var dir = Directory.CreateTempSubdirectory("tswap-agentclient-").FullName;
        try
        {
            using var listener = Listen(dir);
            using var client = await ConnectAsync(dir);
            using var accepted = await listener.AcceptAsync();

            Assert.True(await client.SendFrameUnlessClosedAsync([11]));
            client.Socket.Shutdown(SocketShutdown.Send);

            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30)); // a hang fails the test
            using var stream = new NetworkStream(accepted, ownsSocket: false);
            var frame = new byte[5];
            await stream.ReadExactlyAsync(frame, guard.Token);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x01, 0x0B }, frame);
            Assert.Equal(0, await stream.ReadAsync(new byte[1], guard.Token)); // nothing after the frame
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [UnixFact("Unix sockets")]
    public async Task SendFrameUnlessClosed_OnADisposedClient_StillThrows()
    {
        var dir = Directory.CreateTempSubdirectory("tswap-agentclient-").FullName;
        try
        {
            using var listener = Listen(dir);
            var client = await ConnectAsync(dir);
            using var accepted = await listener.AcceptAsync();
            client.Dispose();

            await Assert.ThrowsAsync<ObjectDisposedException>(() => client.SendFrameUnlessClosedAsync([11]));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static Socket Listen(string dir)
    {
        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(Path.Combine(dir, "s")));
        listener.Listen(1);
        return listener;
    }

    private static async Task<SshAgentTestClient> ConnectAsync(string dir)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(Path.Combine(dir, "s")));
        return new SshAgentTestClient(socket);
    }
}
