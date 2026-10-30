using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace TswapCore.Broker;

/// <summary>
/// Sends an allowed request to its route's upstream over HTTPS and streams the answer back (brief T8
/// decisions 5 to 7):
/// <list type="bullet">
/// <item>Request headers: <c>Authorization</c>, <c>Proxy-Authorization</c>, <c>Cookie</c>,
/// <c>Connection</c> and every header it names, the other hop-by-hop headers, <c>Expect</c>,
/// <c>Content-Length</c> (re-framed here), <c>Range</c>, <c>If-Range</c> and <c>Accept-Encoding</c>
/// (replaced by <c>identity</c>) are dropped; <c>Host</c> is the upstream's authority; the route's
/// auth header is added. A secret containing CR, LF or NUL is never a header.</item>
/// <item>Redirects are passed back, never followed; no cookies, no proxy, no decompression.</item>
/// <item>Bodies stream both ways; <see cref="HttpClient.Timeout"/> is infinite.</item>
/// </list>
/// The certificate seam (<c>trustedTestCertificate</c>) exists for the tests' local upstream only:
/// it is null unless a test passes it, and nothing in the CLI can.
/// </summary>
public sealed class HttpBrokerForwarder : IBrokerForwarder, IDisposable
{
    private readonly HttpClient _client;
    private readonly TimeProvider _time;

    /// <summary>Request headers never forwarded (besides those <c>Connection</c> names).</summary>
    private static readonly HashSet<string> DroppedRequestHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Proxy-Authorization", "Cookie",
        "Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade", "Expect", "Proxy-Connection",
        "Content-Length", "Range", "If-Range", "Accept-Encoding", "Host",
    };

    /// <summary>Response headers never passed back (besides those <c>Connection</c> names).</summary>
    private static readonly HashSet<string> DroppedResponseHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade", "Proxy-Connection",
        "Proxy-Authenticate", "Set-Cookie", "Set-Cookie2", "Content-Length",
    };

    public const int BufferSize = 64 * 1024;

    /// <param name="trustedTestCertificate">Tests only: one extra self-signed certificate to trust for the local test upstream.</param>
    public HttpBrokerForwarder(TimeProvider time, X509Certificate2? trustedTestCertificate = null)
    {
        _time = time;
        Handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            UseProxy = false,
            Credentials = null,
            PreAuthenticate = false,
            ConnectTimeout = TimeSpan.FromSeconds(30),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            // Header bytes pass through as they are (a secret's UTF-8 bytes stay those bytes).
            RequestHeaderEncodingSelector = (_, _) => Encoding.Latin1,
            ResponseHeaderEncodingSelector = (_, _) => Encoding.Latin1,
        };
        if (trustedTestCertificate != null)
        {
            var trusted = X509CertificateLoader.LoadCertificate(trustedTestCertificate.RawData);
            Handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
            {
                if (errors == SslPolicyErrors.None)
                    return true;
                if (certificate is null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != 0)
                    return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(trusted);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                using var presented = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                return chain.Build(presented);
            };
        }
        _client = new HttpClient(Handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    /// <summary>The handler (tests assert its settings).</summary>
    internal SocketsHttpHandler Handler { get; }

    /// <summary>The client (tests assert its timeout).</summary>
    internal HttpClient Client => _client;

    public async Task<BrokerForwardOutcome> ForwardAsync(HttpContext http, BrokerForwardRequest request, CancellationToken cancellationToken)
    {
        var route = request.Route;
        if (!BrokerRequestTarget.IsWithinUpstream(route, request.Outbound))
        {
            // BrokerRequestTarget checked this already; never send outside the envelope.
            await BrokerRequestHandler.WriteUniformAsync(http, StatusCodes.Status404NotFound, _time).ConfigureAwait(false);
            return new BrokerForwardOutcome(404, 0, 0, "authority");
        }

        string authValue;
        try
        {
            authValue = AuthHeaderValue(route, request.Secret.Value);
        }
        catch (BrokerSecretException)
        {
            await BrokerRequestHandler.WriteUniformAsync(http, StatusCodes.Status502BadGateway, _time).ConfigureAwait(false);
            return new BrokerForwardOutcome(502, 0, 0, "secret-unusable");
        }

        var requestBody = new CountingStream(http.Request.Body);
        using var outbound = BuildRequest(http, request, authValue, requestBody);

        HttpResponseMessage response;
        try
        {
            response = await _client.SendAsync(outbound, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException
                                       || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            request.Secret.Dispose();
            await BrokerRequestHandler.WriteUniformAsync(http, StatusCodes.Status502BadGateway, _time).ConfigureAwait(false);
            return new BrokerForwardOutcome(502, requestBody.Count, 0, "upstream-error");
        }
        // The outbound headers are written: the secret's bytes are not needed for the request any more.
        request.Secret.Dispose();

        using (response)
        {
            http.Response.StatusCode = (int)response.StatusCode;
            CopyResponseHeaders(response, http.Response);

            long bytesOut = 0;
            if (!HasNoBody(http.Request.Method, (int)response.StatusCode))
            {
                var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                await using (stream.ConfigureAwait(false))
                {
                    var buffer = new byte[BufferSize];
                    int read;
                    while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                    {
                        await http.Response.Body.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                        await http.Response.Body.FlushAsync(cancellationToken).ConfigureAwait(false);
                        bytesOut += read;
                    }
                }
            }
            return new BrokerForwardOutcome((int)response.StatusCode, requestBody.Count, bytesOut);
        }
    }

    /// <summary>HEAD, 1xx, 204 and 304 carry no body; the broker fabricates none.</summary>
    private static bool HasNoBody(string method, int status) =>
        HttpMethods.IsHead(method) || status is 204 or 304 || status < 200;

    /// <summary>The route's auth header value; a secret with CR, LF or NUL is a hard error.</summary>
    internal static string AuthHeaderValue(BrokerRoutePolicy route, ReadOnlySpan<byte> secret)
    {
        if (secret.IndexOfAny((byte)'\r', (byte)'\n', (byte)0) >= 0)
            throw new BrokerSecretException("the secret contains CR, LF or NUL");
        var value = Encoding.Latin1.GetString(secret); // byte for byte on the wire
        return route.AuthType switch
        {
            BrokerAuthType.Bearer => "Bearer " + value,
            BrokerAuthType.Basic => "Basic " + Convert.ToBase64String(BasicComposite(route.User!, secret)),
            _ => value,
        };
    }

    /// <summary>The bytes of <c>user:secret</c> that a basic route base64-encodes.</summary>
    internal static byte[] BasicComposite(string user, ReadOnlySpan<byte> secret)
    {
        var userBytes = Encoding.ASCII.GetBytes(user + ":");
        var composite = new byte[userBytes.Length + secret.Length];
        userBytes.CopyTo(composite, 0);
        secret.CopyTo(composite.AsSpan(userBytes.Length));
        return composite;
    }

    private static HttpRequestMessage BuildRequest(HttpContext http, BrokerForwardRequest request, string authValue, Stream requestBody)
    {
        var outbound = request.Outbound;
        var route = request.Route;
        var message = new HttpRequestMessage(new HttpMethod(http.Request.Method), outbound)
        {
            Version = HttpVersion.Version11,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };

        var hasBody = http.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody == true;
        if (hasBody)
        {
            var content = new StreamContent(requestBody, BufferSize);
            // Re-framed here: chunked when the client sent chunked, else the length Kestrel parsed
            // (HttpClient checks the bytes sent match it). The client's own framing headers never pass.
            if (!http.Request.Headers.ContainsKey("Transfer-Encoding") && http.Request.ContentLength is { } length)
                content.Headers.ContentLength = length;
            message.Content = content;
        }

        // The raw Connection header's names (Kestrel normalises Request.Headers.Connection) plus any
        // Kestrel still shows.
        var named = ConnectionNamed(http.Request.Headers.Connection);
        named.UnionWith(request.ConnectionNamed);
        foreach (var (name, values) in http.Request.Headers)
        {
            if (DroppedRequestHeaders.Contains(name) || named.Contains(name))
                continue;
            if (name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
            {
                message.Content?.Headers.TryAddWithoutValidation(name, (IEnumerable<string>)values!);
                continue;
            }
            message.Headers.TryAddWithoutValidation(name, (IEnumerable<string>)values!);
        }
        message.Headers.TryAddWithoutValidation("Accept-Encoding", "identity");
        message.Headers.Host = outbound.Authority;
        var authName = route.AuthType == BrokerAuthType.Header ? route.HeaderName! : "Authorization";
        message.Headers.Remove(authName);
        message.Headers.TryAddWithoutValidation(authName, authValue);
        return message;
    }

    private static HashSet<string> ConnectionNamed(IEnumerable<string?> connection)
    {
        var named = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var value in connection)
            foreach (var token in (value ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                named.Add(token);
        return named;
    }

    private static void CopyResponseHeaders(HttpResponseMessage response, HttpResponse target)
    {
        var named = ConnectionNamed(response.Headers.Connection);
        foreach (var (name, values) in response.Headers.NonValidated.Concat(response.Content.Headers.NonValidated))
        {
            if (DroppedResponseHeaders.Contains(name) || named.Contains(name))
                continue;
            target.Headers.Append(name, values.ToArray());
        }
    }

    public void Dispose() => _client.Dispose();

    /// <summary>Counts the bytes read through it (the request body, for the log).</summary>
    private sealed class CountingStream(Stream inner) : Stream
    {
        public long Count { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = inner.Read(buffer, offset, count);
            Count += n;
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var n = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            Count += n;
            return n;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
