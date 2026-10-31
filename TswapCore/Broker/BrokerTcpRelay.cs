using System.Net;
using System.Net.Sockets;

namespace TswapCore.Broker;

/// <summary>
/// <c>tswap broker forward</c> (brief T8 decision 11), run inside the container: relays each TCP
/// connection on a loopback port to the broker's Unix socket, byte for byte. It needs no vault,
/// home folder, YubiKey or TPM. Any process in the container's network namespace can use the port.
/// </summary>
public sealed class BrokerTcpRelay : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly string _socketPath;
    private readonly TextWriter? _log;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;

    private BrokerTcpRelay(TcpListener listener, string socketPath, TextWriter? log)
    {
        _listener = listener;
        _socketPath = socketPath;
        _log = log;
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    /// <summary>The address actually listened on (port 0 resolves to the chosen port).</summary>
    public IPEndPoint LocalEndPoint => (IPEndPoint)_listener.LocalEndpoint;

    /// <summary>
    /// Parses <c>--listen</c>: <c>127.0.0.1:&lt;port&gt;</c> or <c>[::1]:&lt;port&gt;</c> (also
    /// <c>::1:&lt;port&gt;</c>), written literally. Anything else (0.0.0.0, a host name, a LAN
    /// address, <c>localhost</c>, <c>127.1</c>) is refused.
    /// </summary>
    public static IPEndPoint ParseListen(string listen)
    {
        var colon = listen.LastIndexOf(':');
        if (colon <= 0)
            throw new TswapException($"--listen must be 127.0.0.1:<port> or [::1]:<port> (got '{BrokerPolicy.Printable(listen)}').");
        var host = listen[..colon];
        var portText = listen[(colon + 1)..];
        if (host.StartsWith('[') && host.EndsWith(']'))
            host = host[1..^1];
        var address = host switch
        {
            "127.0.0.1" => IPAddress.Loopback,
            "::1" => IPAddress.IPv6Loopback,
            _ => throw new TswapException(
                $"--listen must be a literal loopback address, 127.0.0.1 or ::1 (got '{BrokerPolicy.Printable(host)}'): " +
                "the forwarded port lets anything that reaches it use this container's routes."),
        };
        if (!int.TryParse(portText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var port) || port > 65535)
            throw new TswapException($"--listen has an invalid port '{BrokerPolicy.Printable(portText)}'.");
        return new IPEndPoint(address, port);
    }

    /// <summary>Starts listening on <paramref name="listen"/> (which must be loopback) and relaying to <paramref name="socketPath"/>.</summary>
    public static BrokerTcpRelay Start(IPEndPoint listen, string socketPath, TextWriter? log = null)
    {
        if (!IPAddress.IsLoopback(listen.Address) || !(listen.Address.Equals(IPAddress.Loopback) || listen.Address.Equals(IPAddress.IPv6Loopback)))
            throw new TswapException("broker forward listens on 127.0.0.1 or ::1 only.");
        var listener = new TcpListener(listen);
        listener.Start();
        return new BrokerTcpRelay(listener, socketPath, log);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptSocketAsync(_stop.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }
            _ = Task.Run(() => RelayAsync(client));
        }
    }

    /// <summary>
    /// One connection: client bytes go to the socket, socket bytes to the client. The client's
    /// end of sending is not passed on (Kestrel would end the request); the broker closes the
    /// connection after its response (<c>Connection: close</c>), which closes the client's.
    /// </summary>
    private async Task RelayAsync(Socket client)
    {
        using var _ = client;
        using var broker = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await broker.ConnectAsync(new UnixDomainSocketEndPoint(_socketPath), _stop.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            _log?.WriteLine($"tswap broker forward: can't reach {_socketPath}: {ex.Message}");
            return;
        }
        using var done = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        var up = PumpAsync(client, broker, done.Token);
        var down = PumpAsync(broker, client, done.Token);
        await down.ConfigureAwait(false);   // the broker finished (or failed): the exchange is over
        try
        {
            client.Shutdown(SocketShutdown.Send);
        }
        catch (SocketException)
        {
            // already gone
        }
        done.Cancel();
        await up.ConfigureAwait(false);
    }

    private static async Task PumpAsync(Socket from, Socket to, CancellationToken token)
    {
        var buffer = new byte[64 * 1024];
        try
        {
            int n;
            while ((n = await from.ReceiveAsync(buffer, SocketFlags.None, token).ConfigureAwait(false)) > 0)
            {
                var sent = 0;
                while (sent < n)
                    sent += await to.SendAsync(buffer.AsMemory(sent, n - sent), SocketFlags.None, token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // one side closed or the relay stops
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        _listener.Stop();
        await _acceptLoop.ConfigureAwait(false);
    }
}
