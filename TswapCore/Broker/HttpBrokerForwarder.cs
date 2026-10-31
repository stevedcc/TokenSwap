using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
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
        if (trustedTestCertificate is not null)
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

        // Decision 8: the forms to redact are derived now; they are zeroed when the response ends.
        var redactor = BrokerRedactor.ForSecret(request.Secret.Value, route.AuthType == BrokerAuthType.Basic ? route.User : null);
        // Decision 7: a stream with no bytes moving for the route's idle timeout is ended.
        using var idle = new CancellationTokenSource(route.IdleTimeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, idle.Token);
        void Moved() => idle.CancelAfter(route.IdleTimeout);
        var requestBody = new CountingStream(http.Request.Body, Moved);
        try
        {
            using var outbound = BuildRequest(http, request, authValue, requestBody);
            HttpResponseMessage response;
            try
            {
                response = await _client.SendAsync(outbound, HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException
                                           || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
            {
                request.Secret.Dispose();
                await BrokerRequestHandler.WriteUniformAsync(http, StatusCodes.Status502BadGateway, _time).ConfigureAwait(false);
                return new BrokerForwardOutcome(502, requestBody.Count, 0, idle.IsCancellationRequested ? "idle-timeout" : "upstream-error");
            }
            // The outbound headers are written: the secret's bytes are not needed for the request any more.
            request.Secret.Dispose();
            Moved();

            using (response)
                return await RelayResponseAsync(http, response, redactor, requestBody, Moved, idle, linked.Token, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            redactor.Clear();
        }
    }

    private async Task<BrokerForwardOutcome> RelayResponseAsync(HttpContext http, HttpResponseMessage response, BrokerRedactor redactor,
        CountingStream requestBody, Action moved, CancellationTokenSource idle, CancellationToken token, CancellationToken clientAborted)
    {
        var status = (int)response.StatusCode;

        // Decision 6: a compressed body can't be redacted, so it fails closed and is not forwarded.
        if (IsCompressed(response))
        {
            await BrokerRequestHandler.WriteUniformAsync(http, StatusCodes.Status502BadGateway, _time).ConfigureAwait(false);
            return new BrokerForwardOutcome(502, requestBody.Count, 0, "compressed");
        }

        http.Response.StatusCode = status;
        CopyResponseHeaders(response, http.Response, redactor);
        var noBody = HasNoBody(http.Request.Method, status);
        // A HEAD answer keeps the upstream's length (no body flows, so redaction can't change it;
        // registry clients read a blob's size from it). Every other body is re-framed as chunked.
        if (HttpMethods.IsHead(http.Request.Method) && response.Content.Headers.ContentLength is { } headLength)
            http.Response.ContentLength = headLength;
        if (noBody)
            return new BrokerForwardOutcome(status, requestBody.Count, 0);
        // The headers go out now: the body may be held back by up to the redactor's window.
        await http.Response.StartAsync(token).ConfigureAwait(false);

        long bytesOut = 0;
        try
        {
            var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            await using (stream.ConfigureAwait(false))
            {
                var buffer = new byte[BufferSize];
                using var redacted = new MemoryStream(BufferSize + redactor.Window + 1024);
                int read;
                while ((read = await stream.ReadAsync(buffer, token).ConfigureAwait(false)) > 0)
                {
                    // Bytes moved: the idle clock restarts here. A write the client doesn't take
                    // for the idle timeout ends the stream too (no bytes moving).
                    moved();
                    redactor.Process(buffer.AsSpan(0, read), redacted);
                    bytesOut += await WriteOutAsync(http, redacted, token).ConfigureAwait(false);
                }
                redactor.Flush(redacted);
                bytesOut += await WriteOutAsync(http, redacted, token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or HttpRequestException)
        {
            // Mid-body: the headers are out, so the only honest signal is a cut connection. The
            // reason is read first: Abort() itself cancels the client's token.
            var reason = idle.IsCancellationRequested ? "idle-timeout" : clientAborted.IsCancellationRequested ? "client-closed" : "upstream-error";
            http.Abort();
            return new BrokerForwardOutcome(status, requestBody.Count, bytesOut, reason);
        }
        return new BrokerForwardOutcome(status, requestBody.Count, bytesOut);
    }

    private static async Task<long> WriteOutAsync(HttpContext http, MemoryStream redacted, CancellationToken token)
    {
        var length = redacted.Length;
        if (length > 0)
        {
            await http.Response.Body.WriteAsync(redacted.GetBuffer().AsMemory(0, (int)length), token).ConfigureAwait(false);
            await http.Response.Body.FlushAsync(token).ConfigureAwait(false);
        }
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(redacted.GetBuffer().AsSpan(0, (int)length));
        redacted.SetLength(0);
        return length;
    }

    /// <summary>True when any Content-Encoding other than <c>identity</c> is present.</summary>
    private static bool IsCompressed(HttpResponseMessage response)
    {
        foreach (var headers in new System.Net.Http.Headers.HttpHeaders[] { response.Content.Headers, response.Headers })
            if (headers.NonValidated.TryGetValues("Content-Encoding", out var values))
                foreach (var value in values)
                    foreach (var token in value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                        if (!token.Equals("identity", StringComparison.OrdinalIgnoreCase))
                            return true;
        return false;
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
            BrokerAuthType.Basic => "Basic " + BasicCompositeBase64(route.User!, secret),
            _ => value,
        };
    }

    /// <summary>The base64 of <c>user:secret</c>; the composite bytes are zeroed once encoded (T13).</summary>
    private static string BasicCompositeBase64(string user, ReadOnlySpan<byte> secret)
    {
        var composite = BasicComposite(user, secret);
        try
        {
            return Convert.ToBase64String(composite);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(composite);
        }
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

    /// <summary>
    /// Copies the upstream's headers except hop-by-hop ones (and those its Connection names),
    /// Set-Cookie, Content-Length, and any header whose name or value contains a redaction form.
    /// Trailers are never read, so never forwarded.
    /// </summary>
    private static void CopyResponseHeaders(HttpResponseMessage response, HttpResponse target, BrokerRedactor redactor)
    {
        var named = ConnectionNamed(response.Headers.NonValidated.TryGetValues("Connection", out var c) ? c : []);
        foreach (var (name, values) in response.Headers.NonValidated.Concat(response.Content.Headers.NonValidated))
        {
            if (DroppedResponseHeaders.Contains(name) || named.Contains(name) || redactor.Contains(name))
                continue;
            var list = values.ToArray();
            if (list.Any(redactor.Contains))
                continue;
            target.Headers.Append(name, list);
        }
    }

    public void Dispose() => _client.Dispose();

    /// <summary>Counts the bytes read through it (the request body, for the log).</summary>
    private sealed class CountingStream(Stream inner, Action moved) : Stream
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
            moved();
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var n = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            Count += n;
            moved();
            return n;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
