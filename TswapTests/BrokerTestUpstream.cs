using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;

namespace TswapTests;

/// <summary>One request the test upstream received.</summary>
public sealed record UpstreamHit(string Method, string RawTarget, string Host, IReadOnlyList<KeyValuePair<string, string>> Headers, byte[] Body)
{
    public string? Header(string name) =>
        Headers.Where(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value).FirstOrDefault();

    public bool HasHeader(string name) => Headers.Any(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// A local HTTPS upstream for broker tests (brief T8 item 3): Kestrel on 127.0.0.1 only, with a
/// self-signed certificate made here (trusted by the broker only through its test seam). It records
/// every request (it counts its hits) and answers with <see cref="Respond"/> (default: 200 "upstream ok").
/// </summary>
public sealed class BrokerTestUpstream : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly List<UpstreamHit> _hits = [];

    public X509Certificate2 Certificate { get; }
    public int Port { get; }
    public string BaseUrl => $"https://127.0.0.1:{Port}";

    /// <summary>The response; the request's body has already been read into the hit.</summary>
    public Func<HttpContext, UpstreamHit, Task> Respond { get; set; } = async (http, _) =>
    {
        http.Response.StatusCode = 200;
        await http.Response.WriteAsync("upstream ok");
    };

    /// <summary>When false, the upstream doesn't read the request body before calling <see cref="Respond"/> (the hit's body is empty).</summary>
    public bool ReadBodyFirst { get; set; } = true;

    public IReadOnlyList<UpstreamHit> Hits
    {
        get
        {
            lock (_hits)
                return [.. _hits];
        }
    }

    private BrokerTestUpstream(WebApplication app, X509Certificate2 certificate, int port)
    {
        _app = app;
        Certificate = certificate;
        Port = port;
    }

    public static async Task<BrokerTestUpstream> StartAsync()
    {
        var certificate = CreateCertificate();
        BrokerTestUpstream? self = null;
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.WebHost.UseKestrelCore();
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Limits.MaxRequestBodySize = null;
            k.Listen(IPAddress.Loopback, 0, listen =>
            {
                listen.Protocols = HttpProtocols.Http1;
                listen.UseHttps(certificate);
            });
        });
        var app = builder.Build();
        app.Run(async http =>
        {
            var raw = http.Features.Get<IHttpRequestFeature>()!.RawTarget;
            var headers = http.Request.Headers.SelectMany(h => h.Value.Select(v => new KeyValuePair<string, string>(h.Key, v ?? ""))).ToList();
            var body = Array.Empty<byte>();
            if (self!.ReadBodyFirst)
            {
                using var ms = new MemoryStream();
                await http.Request.Body.CopyToAsync(ms);
                body = ms.ToArray();
            }
            var hit = new UpstreamHit(http.Request.Method, raw, http.Request.Host.Value ?? "", headers, body);
            lock (self._hits)
                self._hits.Add(hit);
            await self.Respond(http, hit);
        });
        await app.StartAsync();
        var address = app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
            .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!.Addresses.First();
        self = new BrokerTestUpstream(app, certificate, new Uri(address).Port);
        return self;
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=tswap-broker-test-upstream", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        // Round-trip through PKCS#12 so the key is usable by the TLS server on every platform.
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        Certificate.Dispose();
    }
}
