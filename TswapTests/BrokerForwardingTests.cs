using System.Text;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T8 item 3: building the upstream request and forwarding it (decisions 5 and 6), against a
/// local HTTPS upstream that counts its hits, trusted only through the forwarder's test seam.
/// </summary>
public class BrokerForwardingTests : IAsyncLifetime
{
    internal const string Secret = "s3cr3t-Value_+/=";

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
        await _h.StartAsync(_h.Config(Routes(_up.BaseUrl), lane1Routes: "\"bearer\", \"basic\", \"header\", \"narrow\""), _forwarder);
    }

    public async Task DisposeAsync()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.DisposeAsync();
        _forwarder.Dispose();
        await _up.DisposeAsync();
    }

    internal static string Routes(string baseUrl) => $$$"""
        { "name": "bearer", "upstream": "{{{baseUrl}}}/base", "auth": { "type": "bearer", "secret": "{{tok}}" }, "path": "", "methods": ["GET", "HEAD", "POST", "PUT"] },
        { "name": "basic", "upstream": "{{{baseUrl}}}/b", "auth": { "type": "basic", "user": "x-access-token", "secret": "{{tok}}" }, "path": "" },
        { "name": "header", "upstream": "{{{baseUrl}}}", "auth": { "type": "header", "header": "X-Api-Key", "secret": "{{tok}}" }, "path": "" },
        { "name": "narrow", "upstream": "{{{baseUrl}}}/base", "auth": { "type": "bearer", "secret": "{{tok}}" }, "path": "allowed/", "methods": ["GET"] },
        { "name": "second", "upstream": "{{{baseUrl}}}/second", "auth": { "type": "bearer", "secret": "{{tok2}}" }, "path": "" }
        """;

    private UpstreamHit SingleHit() => Assert.Single(_up.Hits);

    // ------------------------------------------------------------------ allowed requests

    [Fact]
    public async Task Bearer_UpstreamGetsTheAuthHeader_Host_PathAndQueryUnchanged()
    {
        if (OperatingSystem.IsWindows())
            return;
        var response = await _h.GetAsync("lane1", "/bearer/a/b?x=1&y=%2F%2e");

        Assert.Equal(200, BrokerHarness.StatusOf(response));
        Assert.Equal("upstream ok", BrokerHarness.BodyOf(response));
        var hit = SingleHit();
        Assert.Equal("GET", hit.Method);
        Assert.Equal("/base/a/b?x=1&y=%2F%2e", hit.RawTarget);
        Assert.Equal("Bearer " + Secret, hit.Header("Authorization"));
        Assert.Equal($"127.0.0.1:{_up.Port}", hit.Host);
        Assert.Equal(1, _h.Secrets.Unlocks);
    }

    [Fact]
    public async Task Basic_UpstreamGetsBase64OfUserColonSecret()
    {
        if (OperatingSystem.IsWindows())
            return;
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/basic/stevedcc/croft.git/info/refs?service=git-upload-pack")));

        var hit = SingleHit();
        Assert.Equal("/b/stevedcc/croft.git/info/refs?service=git-upload-pack", hit.RawTarget);
        Assert.Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("x-access-token:" + Secret)), hit.Header("Authorization"));
    }

    [Fact]
    public async Task Header_UpstreamGetsTheNamedHeader_AndNoAuthorization()
    {
        if (OperatingSystem.IsWindows())
            return;
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/header/v2/", "Authorization: Bearer client-token\r\n")));

        var hit = SingleHit();
        Assert.Equal("/v2/", hit.RawTarget[..4]);
        Assert.Equal(Secret, hit.Header("X-Api-Key"));
        Assert.False(hit.HasHeader("Authorization"));
    }

    [Fact]
    public async Task ClientAuthorizationAndHost_AreReplaced()
    {
        if (OperatingSystem.IsWindows())
            return;
        var raw = "GET /bearer/x HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer client-token\r\n" +
                  "Proxy-Authorization: Basic Y2xpZW50\r\nCookie: session=client\r\nConnection: close\r\n\r\n";
        Assert.Equal(200, BrokerHarness.StatusOf(Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", raw))));

        var hit = SingleHit();
        Assert.Equal("Bearer " + Secret, hit.Header("Authorization"));
        Assert.Equal($"127.0.0.1:{_up.Port}", hit.Host);
        Assert.Single(hit.Headers, h => h.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase));
        Assert.False(hit.HasHeader("Proxy-Authorization"));
        Assert.False(hit.HasHeader("Cookie"));
        Assert.DoesNotContain(hit.Headers, h => h.Value.Contains("client") || h.Value.Contains("evil.example"));
    }

    [Fact]
    public async Task ConnectionNamedHeaders_AndHopByHopHeaders_AreDropped_OthersPass()
    {
        if (OperatingSystem.IsWindows())
            return;
        var headers = "Connection: x-secret-header, X-Other\r\nX-Secret-Header: drop-me\r\nX-Other: drop-me-too\r\n" +
                      "Keep-Alive: timeout=5\r\nTE: trailers\r\nTrailer: X-T\r\nUpgrade: websocket\r\nProxy-Connection: keep-alive\r\n" +
                      "X-Kept: kept\r\nUser-Agent: git/2.47\r\n";
        // Connection: close is added by GetAsync too.
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/bearer/x", headers)));

        var hit = SingleHit();
        foreach (var dropped in new[] { "X-Secret-Header", "X-Other", "Keep-Alive", "TE", "Trailer", "Upgrade", "Proxy-Connection" })
            Assert.False(hit.HasHeader(dropped), dropped);
        Assert.DoesNotContain(hit.Headers, h => h.Value.Contains("drop-me"));
        Assert.Equal("kept", hit.Header("X-Kept"));
        Assert.Equal("git/2.47", hit.Header("User-Agent"));
    }

    [Fact]
    public async Task RangeIfRangeAndAcceptEncoding_DontReachTheUpstream_ItSeesIdentity()
    {
        if (OperatingSystem.IsWindows())
            return;
        var headers = "Range: bytes=0-3\r\nIf-Range: \"etag\"\r\nAccept-Encoding: gzip, br\r\n";
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/bearer/x", headers)));

        var hit = SingleHit();
        Assert.False(hit.HasHeader("Range"));
        Assert.False(hit.HasHeader("If-Range"));
        Assert.Equal("identity", hit.Header("Accept-Encoding"));
    }

    [Fact]
    public async Task BareChunkedRequest_IsReframed_NeitherFramingHeaderOfTheClientLeaks()
    {
        if (OperatingSystem.IsWindows())
            return;
        // "Chunked" with a capital C: HttpClient's own framing header is lower-case "chunked", so the
        // upstream seeing exactly "chunked" shows the client's header did not pass.
        var raw = "POST /bearer/upload HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: Chunked\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n" +
                  "5;ext=client\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n";
        Assert.Equal(200, BrokerHarness.StatusOf(Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", raw))));

        var hit = SingleHit();
        Assert.Equal("hello world", Encoding.ASCII.GetString(hit.Body));
        Assert.Equal("application/octet-stream", hit.Header("Content-Type"));
        Assert.False(hit.HasHeader("X-Trailer"));
        Assert.False(hit.HasHeader("Content-Length"));
        Assert.Equal(["chunked"], hit.Headers.Where(h => h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)).Select(h => h.Value));
    }

    [Fact]
    public async Task ContentLengthPlusTransferEncoding_NeverReachesTheUpstreamWithTheClientsFraming()
    {
        if (OperatingSystem.IsWindows())
            return;
        // A smuggling attempt: CL says 4 (so "0\r\n\r" would be the body), TE says chunked and a
        // second request hides after the terminating chunk.
        var raw = "POST /bearer/upload HTTP/1.1\r\nHost: b\r\nContent-Length: 4\r\nTransfer-Encoding: Chunked\r\nConnection: close\r\n\r\n" +
                  "5\r\nhello\r\n0\r\n\r\nGET /bearer/smuggled HTTP/1.1\r\nHost: b\r\n\r\n";
        var response = Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", raw));

        Assert.Equal(200, BrokerHarness.StatusOf(response));
        Assert.Single(response.Split("HTTP/1.1 ")[1..]); // one answer: the hidden request is never served
        var hit = SingleHit();
        Assert.Equal("/base/upload", hit.RawTarget);
        Assert.Equal("hello", Encoding.ASCII.GetString(hit.Body));
        Assert.False(hit.HasHeader("Content-Length"));
        Assert.Equal(["chunked"], hit.Headers.Where(h => h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)).Select(h => h.Value));
    }

    [Fact]
    public async Task AQueryWithAFragmentMark_IsTheUniform404_AnEncodedOneIsForwardedUnchanged()
    {
        if (OperatingSystem.IsWindows())
            return;
        var raw = await _h.GetAsync("lane1", "/bearer/x?a=1#frag");
        var encoded = await _h.GetAsync("lane1", "/bearer/x?a=1%23frag");

        Assert.True(BrokerHarness.StatusOf(raw) is 404 or 400, raw); // 400 when Kestrel refuses it first
        Assert.Equal(200, BrokerHarness.StatusOf(encoded));
        Assert.Equal("/base/x?a=1%23frag", SingleHit().RawTarget);
    }

    [Fact]
    public void BuildOutbound_RefusesAQueryWithAFragmentMark_TheQueryIsNeverAltered()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        var route = BrokerPolicy.Parse(_h.Config(Routes("https://upstream.example"), lane1Routes: "\"bearer\"")).Routes["bearer"];

        Assert.Null(BrokerRequestTarget.BuildOutbound(route, ["x"], "?a=1#b"));
        Assert.Equal("?a=1%23b", BrokerRequestTarget.BuildOutbound(route, ["x"], "?a=1%23b")!.Query);
    }

    [Fact]
    public async Task ContentLengthRequest_KeepsItsLength_ReframedByTheForwarder()
    {
        if (OperatingSystem.IsWindows())
            return;
        var raw = "PUT /bearer/blob HTTP/1.1\r\nHost: b\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world";
        Assert.Equal(200, BrokerHarness.StatusOf(Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", raw))));

        var hit = SingleHit();
        Assert.Equal("PUT", hit.Method);
        Assert.Equal("hello world", Encoding.ASCII.GetString(hit.Body));
    }

    [Fact]
    public async Task Segments_AreDecodedOnce_AndReencoded()
    {
        if (OperatingSystem.IsWindows())
            return;
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/bearer/v2/img/blobs/sha256%3Aabc/a%20b/%C3%A9/x+y@z")));

        Assert.Equal("/base/v2/img/blobs/sha256:abc/a%20b/%C3%A9/x+y@z", SingleHit().RawTarget);
    }

    [Fact]
    public async Task TrailingSlash_IsKept_RouteSlashAloneIsTheBasePath()
    {
        if (OperatingSystem.IsWindows())
            return;
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/bearer/")));
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/bearer/v2/")));

        Assert.Equal(["/base/", "/base/v2/"], _up.Hits.Select(h => h.RawTarget));
    }

    [Fact]
    public async Task Redirect_IsPassedBack_NeverFollowed()
    {
        if (OperatingSystem.IsWindows())
            return;
        _up.Respond = (http, _) =>
        {
            http.Response.StatusCode = 302;
            http.Response.Headers.Location = $"https://127.0.0.1:{_up.Port}/base/elsewhere";
            return Task.CompletedTask;
        };

        var response = await _h.GetAsync("lane1", "/bearer/moved");

        Assert.Equal(302, BrokerHarness.StatusOf(response));
        Assert.Contains($"Location: https://127.0.0.1:{_up.Port}/base/elsewhere", response);
        Assert.Single(_up.Hits);
    }

    // ------------------------------------------------------------------ refusals

    public static TheoryData<string> PathTricks => new()
    {
        "/bearer/..",
        "/bearer/../x",
        "/bearer/a/../../x",          // a '..' crossing the upstream's base path
        "/bearer/.",
        "/bearer/%2e%2e",
        "/bearer/%2E%2E/x",
        "/bearer/..%2f",
        "/bearer/..%2fx",
        "/bearer/%252e%252e",
        "/bearer//evil.com",
        "/bearer//evil.com/x",
        "/bearer/..;/x",
        "/bearer/a;b",
        "/bearer/a%2fb",
        "/bearer/a%2Fb",
        "/bearer/a%5cb",
        "/bearer/a%0d%0aX-Injected:%20y",
        "/bearer/a%zz",
        "/bearer/a%",
        "/bearer/%ff",
        "/bearer",
        "/narrow/",                   // the base path itself, outside narrow's regex
        "//evil.com/x",
    };

    [Theory]
    [MemberData(nameof(PathTricks))]
    public async Task PathTricks_AreTheUniform404_WithNoUpstreamHitAndNoUnlock(string target)
    {
        if (OperatingSystem.IsWindows())
            return;
        var response = await _h.GetAsync("lane1", target);

        Assert.Equal(404, BrokerHarness.StatusOf(response));
        Assert.Empty(_up.Hits);
        Assert.Equal(0, _h.Secrets.Unlocks);
    }

    [Theory]
    [InlineData("/bearer/a\\b")]
    [InlineData("/bearer/%00")]
    public async Task RefusedByKestrelOrTheBroker_BackslashAndEncodedNul_NeverReachTheUpstream(string target)
    {
        if (OperatingSystem.IsWindows())
            return;
        // Kestrel itself answers 400 to some of these before the broker sees the request.
        var response = await _h.GetAsync("lane1", target);

        Assert.True(BrokerHarness.StatusOf(response) is 400 or 404, response);
        Assert.Empty(_up.Hits);
        Assert.Equal(0, _h.Secrets.Unlocks);
    }

    [Fact]
    public async Task UnknownRoute_OtherSocketsRoute_MethodOutsideTheRoute_PathOutsideTheRegex_AreTheUniform404()
    {
        if (OperatingSystem.IsWindows())
            return;
        var unknown = await _h.GetAsync("lane1", "/nope/x");
        var otherSockets = await _h.GetAsync("lane1", "/second/x");
        var method = await _h.GetAsync("lane1", "/narrow/allowed/x", method: "POST");
        var regex = await _h.GetAsync("lane1", "/narrow/other/x");
        var reserved = await _h.GetAsync("lane1", "/_admin/x");

        Assert.Equal(404, BrokerHarness.StatusOf(unknown));
        Assert.All(new[] { otherSockets, method, regex, reserved }, r => Assert.Equal(unknown, r));
        Assert.Empty(_up.Hits);
        Assert.Equal(0, _h.Secrets.Unlocks);
        Assert.Contains("reason=route", _h.LogText.ToString());
        Assert.Contains("reason=method", _h.LogText.ToString());
        Assert.Contains("reason=path-regex", _h.LogText.ToString());
    }

    [Fact]
    public async Task TheUniform404_IsByteIdentical_HeadersIncluded()
    {
        if (OperatingSystem.IsWindows())
            return;
        var responses = new List<string>();
        foreach (var target in ((IEnumerable<object[]>)PathTricks).Select(t => (string)t[0]).Concat(["/nope/x", "/second/x", "/narrow/other/x"]))
            responses.Add(await _h.GetAsync("lane1", target));
        responses.Add(await _h.GetAsync("lane1", "/narrow/allowed/x", method: "PUT"));

        Assert.All(responses, r => Assert.Equal(responses[0], r));
        Assert.StartsWith("HTTP/1.1 404 Not Found\r\n", responses[0]);
        Assert.Empty(_up.Hits);
    }

    [Fact]
    public async Task Connect_AndAbsoluteForm_Are400_WithNoUpstreamHit()
    {
        if (OperatingSystem.IsWindows())
            return;
        var connect = Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", $"CONNECT 127.0.0.1:{_up.Port} HTTP/1.1\r\nHost: 127.0.0.1:{_up.Port}\r\nConnection: close\r\n\r\n"));
        var absolute = Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", $"GET {_up.BaseUrl}/bearer/x HTTP/1.1\r\nHost: 127.0.0.1:{_up.Port}\r\nConnection: close\r\n\r\n"));
        var asterisk = Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", "OPTIONS * HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n"));

        Assert.Equal(400, BrokerHarness.StatusOf(connect));
        Assert.Equal(400, BrokerHarness.StatusOf(absolute));
        Assert.Equal(400, BrokerHarness.StatusOf(asterisk));
        Assert.Empty(_up.Hits);
        Assert.Equal(0, _h.Secrets.Unlocks);
    }

    // ------------------------------------------------------------------ building, the assertion and the seam

    [Fact]
    public void OutboundAuthority_EqualsTheUpstreams_EvenForDoubleSlashEvilCom()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        var route = BrokerPolicy.Parse(_h.Config(Routes("https://upstream.example:8443"), lane1Routes: "\"bearer\"")).Routes["bearer"];

        var built = BrokerRequestTarget.BuildOutbound(route, ["", "evil.com", "x"], "");
        var leadingSlash = BrokerRequestTarget.BuildOutbound(route, ["/evil.com", "x"], "?a=//evil.com");

        Assert.NotNull(built);
        Assert.Equal("upstream.example:8443", built.Authority);
        Assert.StartsWith("/base/", built.AbsolutePath);
        Assert.NotNull(leadingSlash);
        Assert.Equal("upstream.example:8443", leadingSlash.Authority);
        Assert.Equal("/base/%2Fevil.com/x", leadingSlash.AbsolutePath);
    }

    [Fact]
    public void TheAssertion_RefusesAnotherAuthority_OrAPathOutsideTheBasePath()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        var route = BrokerPolicy.Parse(_h.Config(Routes("https://upstream.example"), lane1Routes: "\"bearer\"")).Routes["bearer"];

        Assert.True(BrokerRequestTarget.IsWithinUpstream(route, new Uri("https://upstream.example/base/x")));
        Assert.False(BrokerRequestTarget.IsWithinUpstream(route, new Uri("https://evil.com/base/x")));
        Assert.False(BrokerRequestTarget.IsWithinUpstream(route, new Uri("http://upstream.example/base/x")));
        Assert.False(BrokerRequestTarget.IsWithinUpstream(route, new Uri("https://upstream.example:444/base/x")));
        Assert.False(BrokerRequestTarget.IsWithinUpstream(route, new Uri("https://upstream.example/basement/x")));
        Assert.False(BrokerRequestTarget.IsWithinUpstream(route, new Uri("https://upstream.example/other")));
    }

    [Fact]
    public async Task TheCertificateSeam_IsOffByDefault_ASelfSignedUpstreamIsRefused()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var plain = new HttpBrokerForwarder(_h.Clock);
        Assert.Null(plain.Handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.NotNull(_forwarder.Handler.SslOptions.RemoteCertificateValidationCallback);
        await _h.Server!.StopAsync();
        await using var h2 = new BrokerHarness { Secrets = new FakeBrokerSecrets(_ => Secret) };
        await h2.StartAsync(h2.Config(Routes(_up.BaseUrl), lane1Routes: "\"bearer\""), plain);

        var response = await h2.GetAsync("lane1", "/bearer/x");

        Assert.Equal(502, BrokerHarness.StatusOf(response));
        Assert.Empty(_up.Hits); // the TLS handshake failed: no HTTP request reached it
        Assert.Contains("reason=upstream-error", h2.LogText.ToString());
    }

    [Fact]
    public void ForwarderHandler_NeverFollowsRedirects_DecompressesOrUsesCookiesOrProxies()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        using var forwarder = new HttpBrokerForwarder(_h.Clock);
        Assert.False(forwarder.Handler.AllowAutoRedirect);
        Assert.Equal(System.Net.DecompressionMethods.None, forwarder.Handler.AutomaticDecompression);
        Assert.False(forwarder.Handler.UseCookies);
        Assert.False(forwarder.Handler.UseProxy);
        Assert.Null(forwarder.Handler.Credentials);
    }
}
