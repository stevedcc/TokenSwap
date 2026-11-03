using System.Net.Sockets;
using Xunit;

namespace TswapTests;

/// <summary>
/// The harness's raw exchange: a broker that refuses a connection closes it before reading anything, possibly
/// before the request is written. That is "nothing returned" (zero bytes), never a test failure.
/// </summary>
public sealed class BrokerHarnessTests : IAsyncLifetime
{
    private readonly BrokerHarness _h = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _h.DisposeAsync();

    [Fact]
    public async Task SendRawAsync_ToAPeerThatClosesBeforeTheRequestIsWritten_ReturnsZeroBytes()
    {
        if (OperatingSystem.IsWindows())
            return; // Unix sockets as the broker uses them
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(_h.SocketPath("closer")));
        listener.Listen(1);
        var closed = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptAsync();
            accepted.Close(); // refused at accept: closed unread, like the broker's gate
        });

        // Far more than the socket buffers hold, so the send can't complete before the close is seen.
        var request = "GET /x HTTP/1.1\r\nHost: b\r\nX-Pad: " + new string('a', 8 * 1024 * 1024) + "\r\n\r\n";
        var response = await _h.SendRawAsync("closer", request);

        await closed;
        Assert.Empty(response);
    }
}
