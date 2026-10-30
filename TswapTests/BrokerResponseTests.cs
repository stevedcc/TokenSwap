using System.IO.Compression;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Http;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T8 item 4: responses (decisions 6 to 8): framing, compressed bodies, redaction of headers,
/// bodies and trailers, streaming, limits, and a fresh unlock per request.
/// </summary>
public class BrokerResponseTests : IAsyncLifetime
{
    private const string Secret = BrokerForwardingTests.Secret;

    private readonly BrokerHarness _h = new();
    private BrokerTestUpstream _up = null!;
    private HttpBrokerForwarder _forwarder = null!;

    public async Task InitializeAsync()
    {
        if (OperatingSystem.IsWindows())
            return;
        _up = await BrokerTestUpstream.StartAsync();
        _forwarder = new HttpBrokerForwarder(_h.Clock, trustedTestCertificate: _up.Certificate);
        _h.Secrets = new FakeBrokerSecrets(_ => Secret);
        await _h.StartAsync(_h.Config(BrokerForwardingTests.Routes(_up.BaseUrl), lane1Routes: "\"bearer\", \"basic\""), _forwarder);
    }

    public async Task DisposeAsync()
    {
        if (OperatingSystem.IsWindows())
            return;

        await _h.DisposeAsync();
        _forwarder.Dispose();
        await _up.DisposeAsync();
    }

    private static IReadOnlyList<string> AllForms() =>
        BrokerRedactor.ForSecret(Encoding.UTF8.GetBytes(Secret), "x-access-token").Forms.Select(f => Encoding.Latin1.GetString(f)).ToList();

    private static string HeadOf(string response) => response[..response.IndexOf("\r\n\r\n", StringComparison.Ordinal)];

    // ------------------------------------------------------------------ redaction

    [Fact]
    public async Task EveryForm_EchoedInAHeader_TheBody_AndSplitAcrossTwoChunks_NeverReachesTheClient()
    {
        if (OperatingSystem.IsWindows())
            return;
        foreach (var form in AllForms())
        {
            _up.Respond = async (http, _) =>
            {
                http.Response.Headers["X-Echo"] = form;
                http.Response.Headers["X-Echo-Inside"] = "token=" + form + ";";
                http.Response.Headers["X-Safe"] = "fine";
                await http.Response.WriteAsync("head-" + form[..(form.Length / 2)]);
                await http.Response.Body.FlushAsync();
                await http.Response.WriteAsync(form[(form.Length / 2)..] + "-tail");
            };

            var response = await _h.GetAsync("lane1", "/basic/echo");

            Assert.Equal(200, BrokerHarness.StatusOf(response));
            var head = HeadOf(response);
            var body = BrokerHarness.BodyOf(response);
            Assert.Equal("head-[REDACTED]-tail", body);
            Assert.DoesNotContain("X-Echo", head);
            Assert.Contains("X-Safe: fine", head);
            foreach (var f in AllForms())
            {
                Assert.DoesNotContain(f, head);
                Assert.DoesNotContain(f, body);
            }
        }
    }

    [Fact]
    public async Task FormsInATrailer_AreNeverForwarded()
    {
        if (OperatingSystem.IsWindows())
            return;
        foreach (var form in AllForms().Take(6))
        {
            var raw = Encoding.Latin1.GetBytes(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\nConnection: close\r\n\r\n" +
                $"5\r\nhello\r\n0\r\nX-T: {form}\r\n\r\n");
            await using var raw1 = new RawTlsUpstream(_up.Certificate, raw);
            await using var h = new BrokerHarness { Secrets = new FakeBrokerSecrets(_ => Secret) };
            await h.StartAsync(h.Config(BrokerForwardingTests.Routes($"https://127.0.0.1:{raw1.Port}"), lane1Routes: "\"bearer\""), _forwarder);

            var response = await h.GetAsync("lane1", "/bearer/t", "TE: trailers\r\n");

            Assert.Equal(1, raw1.Hits);
            Assert.Equal(200, BrokerHarness.StatusOf(response));
            Assert.Equal("hello", BrokerHarness.BodyOf(response));
            Assert.DoesNotContain("X-T", response);
            foreach (var f in AllForms())
                Assert.DoesNotContain(f, response);
        }
    }

    [Fact]
    public async Task ContentLengthBody_WhoseRedactionChangesItsLength_ArrivesIntactAndChunked()
    {
        if (OperatingSystem.IsWindows())
            return;
        var bodyText = "abc" + Secret + "def";
        _up.Respond = async (http, _) =>
        {
            var bytes = Encoding.ASCII.GetBytes(bodyText);
            http.Response.ContentLength = bytes.Length;
            await http.Response.Body.WriteAsync(bytes);
        };

        var response = await _h.GetAsync("lane1", "/bearer/cl");

        var head = HeadOf(response);
        Assert.DoesNotContain("Content-Length", head);
        Assert.Contains("Transfer-Encoding: chunked", head);
        Assert.Equal("abc[REDACTED]def", BrokerHarness.BodyOf(response));
        Assert.EndsWith("0\r\n\r\n", response);
    }

    [Theory]
    [InlineData("gzip")]
    [InlineData("br")]
    [InlineData("deflate")]
    public async Task CompressedBody_Fails502_NothingForwarded(string encoding)
    {
        if (OperatingSystem.IsWindows())
            return;
        var compressed = new MemoryStream();
        Stream zip = encoding switch
        {
            "gzip" => new GZipStream(compressed, CompressionLevel.Fastest, leaveOpen: true),
            "br" => new BrotliStream(compressed, CompressionLevel.Fastest, leaveOpen: true),
            _ => new ZLibStream(compressed, CompressionLevel.Fastest, leaveOpen: true),
        };
        await using (zip)
            await zip.WriteAsync(Encoding.ASCII.GetBytes("payload " + Secret));
        _up.Respond = async (http, _) =>
        {
            http.Response.Headers.ContentEncoding = encoding;
            http.Response.Headers["X-Upstream"] = "seen";
            await http.Response.Body.WriteAsync(compressed.ToArray());
        };

        var response = await _h.GetAsync("lane1", "/bearer/z", "Accept-Encoding: gzip, br\r\n");

        Assert.Equal(502, BrokerHarness.StatusOf(response));
        Assert.Equal("Bad Gateway\n", BrokerHarness.BodyOf(response));
        Assert.DoesNotContain("Content-Encoding", response);
        Assert.DoesNotContain("X-Upstream", response);
        Assert.Contains("reason=compressed", _h.LogText.ToString());
        Assert.Equal("identity", Assert.Single(_up.Hits).Header("Accept-Encoding"));
    }

    [Fact]
    public async Task IdentityContentEncoding_Passes()
    {
        if (OperatingSystem.IsWindows())
            return;
        _up.Respond = async (http, _) =>
        {
            http.Response.Headers.ContentEncoding = "identity";
            await http.Response.WriteAsync("plain");
        };

        var response = await _h.GetAsync("lane1", "/bearer/i");

        Assert.Equal(200, BrokerHarness.StatusOf(response));
        Assert.Equal("plain", BrokerHarness.BodyOf(response));
    }

    // ------------------------------------------------------------------ framing

    [Fact]
    public async Task Head_KeepsItsEmptyBody_AndTheUpstreamsLength()
    {
        if (OperatingSystem.IsWindows())
            return;
        _up.Respond = (http, _) =>
        {
            http.Response.ContentLength = 1234;
            return Task.CompletedTask;
        };

        var response = await _h.GetAsync("lane1", "/bearer/blob", method: "HEAD");

        Assert.Equal(200, BrokerHarness.StatusOf(response));
        Assert.Contains("Content-Length: 1234", HeadOf(response));
        Assert.EndsWith("\r\n\r\n", response); // nothing after the headers
        Assert.Equal("HEAD", Assert.Single(_up.Hits).Method);
    }

    [Theory]
    [InlineData(204)]
    [InlineData(304)]
    public async Task NoContentAndNotModified_PassWithEmptyBodies(int status)
    {
        if (OperatingSystem.IsWindows())
            return;
        _up.Respond = (http, _) =>
        {
            http.Response.StatusCode = status;
            http.Response.Headers.ETag = "\"v1\"";
            return Task.CompletedTask;
        };

        var response = await _h.GetAsync("lane1", "/bearer/n");

        Assert.Equal(status, BrokerHarness.StatusOf(response));
        Assert.Contains("ETag: \"v1\"", response);
        Assert.EndsWith("\r\n\r\n", response);
        Assert.DoesNotContain("Transfer-Encoding", response);
    }

    // ------------------------------------------------------------------ streaming

    /// <summary>Reads a response from a socket, handing each received chunk to <paramref name="onChunk"/>; returns the total.</summary>
    private async Task<long> StreamAsync(string request, Func<ReadOnlyMemory<byte>, Task> onChunk, Func<Socket, Task>? send = null)
    {
        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_h.SocketPath("lane1")));
        await client.SendAsync(Encoding.ASCII.GetBytes(request));
        var sending = send?.Invoke(client) ?? Task.CompletedTask;
        var buffer = new byte[64 * 1024];
        long total = 0;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(120)); // a hang fails, never passes
        int n;
        while ((n = await client.ReceiveAsync(buffer, SocketFlags.None, guard.Token)) > 0)
        {
            total += n;
            await onChunk(buffer.AsMemory(0, n));
        }
        await sending;
        return total;
    }

    [Fact]
    public async Task FiftyMegabytes_Stream_FirstByteArrivesBeforeTheUpstreamFinishes_MemoryStaysBounded()
    {
        if (OperatingSystem.IsWindows())
            return;
        const int chunk = 64 * 1024;
        const int chunks = 800; // 50 MB
        var firstByteSeen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var halfSent = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var upstreamFinished = false;
        _up.Respond = async (http, _) =>
        {
            var block = new byte[chunk];
            Array.Fill(block, (byte)'x');
            for (var i = 0; i < chunks; i++)
            {
                await http.Response.Body.WriteAsync(block);
                if (i == 0)
                {
                    await http.Response.Body.FlushAsync();
                    await firstByteSeen.Task; // the client must see bytes while the upstream is still sending
                }
                if (i == chunks / 2)
                {
                    await http.Response.Body.FlushAsync();
                    halfSent.TrySetResult();
                    await resume.Task;
                }
            }
            upstreamFinished = true;
        };
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var baseline = GC.GetTotalMemory(forceFullCollection: true);
        long liveAtHalf = 0;
        var sawFirstBeforeFinish = false;
        long bodyBytes = 0;
        var checkedHalf = false;

        var total = await StreamAsync("GET /bearer/big HTTP/1.1\r\nHost: b\r\n\r\n", async data =>
        {
            bodyBytes += data.Length;
            if (!firstByteSeen.Task.IsCompleted)
            {
                sawFirstBeforeFinish = !upstreamFinished;
                firstByteSeen.TrySetResult();
            }
            if (!checkedHalf && halfSent.Task.IsCompleted && bodyBytes > chunk * (long)(chunks / 2) - 4 * 1024 * 1024)
            {
                checkedHalf = true;
                // Half the body has gone through; if the broker were holding it, ~25 MB would be live now.
                liveAtHalf = GC.GetTotalMemory(forceFullCollection: true) - baseline;
                resume.TrySetResult();
            }
            await Task.CompletedTask;
        });

        Assert.True(sawFirstBeforeFinish);
        Assert.True(checkedHalf);
        Assert.True(liveAtHalf < 8 * 1024 * 1024, $"live heap grew by {liveAtHalf} bytes mid-stream");
        Assert.True(total > chunk * (long)chunks, $"got {total} bytes");
        Assert.True(upstreamFinished);
    }

    [Fact]
    public async Task Bidirectional_ALargeRequestBodyWhileTheResponseStarts_Completes()
    {
        if (OperatingSystem.IsWindows())
            return;
        const int size = 8 * 1024 * 1024;
        _up.ReadBodyFirst = false;
        _up.Respond = async (http, _) =>
        {
            http.Response.StatusCode = 200;
            await http.Response.WriteAsync("started;");
            await http.Response.Body.FlushAsync();
            long received = 0;
            var buffer = new byte[64 * 1024];
            int n;
            while ((n = await http.Request.Body.ReadAsync(buffer)) > 0)
                received += n;
            await http.Response.WriteAsync($"received={received}");
        };
        var response = new MemoryStream();

        await StreamAsync(
            $"PUT /bearer/upload HTTP/1.1\r\nHost: b\r\nContent-Length: {size}\r\n\r\n",
            data =>
            {
                response.Write(data.Span);
                return Task.CompletedTask;
            },
            async socket =>
            {
                var block = new byte[64 * 1024];
                for (var sent = 0; sent < size; sent += block.Length)
                    await socket.SendAsync(block);
            });

        var text = Encoding.ASCII.GetString(response.ToArray());
        Assert.Equal(200, BrokerHarness.StatusOf(text));
        Assert.Equal($"started;received={size}", BrokerHarness.BodyOf(text));
    }

    [Fact]
    public async Task IdleUpstream_IsCutAfterTheRoutesIdleTimeout_OnTheInjectedClock()
    {
        if (OperatingSystem.IsWindows())
            return;
        var stalled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _up.Respond = async (http, _) =>
        {
            // Longer than the redactor's window, so "partial" itself is passed on at once.
            await http.Response.WriteAsync("partial" + new string('.', 400));
            await http.Response.Body.FlushAsync();
            stalled.TrySetResult();
            await release.Task.WaitAsync(http.RequestAborted);
        };
        var received = new MemoryStream();
        var advanced = false;

        var reading = StreamAsync("GET /bearer/stall HTTP/1.1\r\nHost: b\r\n\r\n", async data =>
        {
            received.Write(data.Span);
            if (!advanced && Encoding.ASCII.GetString(received.ToArray()).Contains("partial"))
            {
                advanced = true;
                await stalled.Task;
                _h.Clock.Advance(TimeSpan.FromSeconds(119));
                Assert.DoesNotContain("idle-timeout", _h.LogText.ToString());
                _h.Clock.Advance(TimeSpan.FromSeconds(1));
            }
        });
        await reading;
        release.TrySetResult();

        var text = Encoding.ASCII.GetString(received.ToArray());
        Assert.Contains("partial", text);
        Assert.DoesNotContain("\r\n0\r\n\r\n", text); // cut, not a complete chunked body
        Assert.Contains("reason=idle-timeout", _h.LogText.ToString());
    }

    [Fact]
    public void TimeoutsAndSizes_HaveTheirSetValues()
    {
        if (OperatingSystem.IsWindows())
            return;
        var kestrel = _h.Server!.KestrelOptions;
        Assert.Null(kestrel.Limits.MaxRequestBodySize);
        Assert.Equal(TimeSpan.FromSeconds(10), kestrel.Limits.RequestHeadersTimeout);
        Assert.Equal(16, kestrel.Limits.MinRequestBodyDataRate!.BytesPerSecond);
        Assert.Equal(TimeSpan.FromSeconds(60), kestrel.Limits.MinRequestBodyDataRate.GracePeriod);
        Assert.Equal(16, kestrel.Limits.MinResponseDataRate!.BytesPerSecond);
        Assert.Equal(TimeSpan.FromSeconds(60), kestrel.Limits.MinResponseDataRate.GracePeriod);
        Assert.False(kestrel.AddServerHeader);
        Assert.Equal(Timeout.InfiniteTimeSpan, _forwarder.Client.Timeout);
        Assert.Equal(TimeSpan.FromSeconds(120), _h.Holder!.Current.Routes["bearer"].IdleTimeout);
        Assert.Equal(TimeSpan.FromSeconds(30), _forwarder.Handler.ConnectTimeout);
    }

    // ------------------------------------------------------------------ unlocks

    [Fact]
    public async Task EveryRequestUnlocksAfresh_AlsoUnderEightConcurrentRequests()
    {
        if (OperatingSystem.IsWindows())
            return;
        for (var i = 0; i < 3; i++)
            Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/bearer/seq")));
        Assert.Equal(3, _h.Secrets.Unlocks);

        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var arrived = 0;
        var allArrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _up.Respond = async (http, _) =>
        {
            if (Interlocked.Increment(ref arrived) == 8)
                allArrived.TrySetResult();
            await gate.Task;
            await http.Response.WriteAsync("ok");
        };
        // Four on each socket: within the per-socket (4) and total (8) limits, all in flight at once.
        await _h.Server!.StopAsync();
        await using var h = new BrokerHarness { Secrets = new FakeBrokerSecrets(_ => Secret) };
        await h.StartAsync(h.Config(BrokerForwardingTests.Routes(_up.BaseUrl), lane1Routes: "\"bearer\"", otherRoutes: "\"second\""), _forwarder);
        var requests = Enumerable.Range(0, 8).Select(i => i % 2 == 0 ? h.GetAsync("lane1", "/bearer/c" + i) : h.GetAsync("other", "/second/c" + i)).ToList();
        await allArrived.Task.WaitAsync(TimeSpan.FromSeconds(60));

        Assert.Equal(8, h.Secrets.Unlocks);
        gate.SetResult();
        foreach (var r in requests)
            Assert.Equal(200, BrokerHarness.StatusOf(await r));
        Assert.Equal(8, h.Secrets.Unlocks);
    }
}
