using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T13 item 1: a secret shorter than <see cref="BrokerShortSecretWarnings.ShortSecretBytes"/>
/// bytes that a route or a template reads is named once per serve process in one <c>event</c> log
/// line; it still works exactly as before, and nothing reaches the caller.
/// </summary>
public class BrokerShortSecretWarningTests(ITestOutputHelper output) : IAsyncLifetime
{
    private const string Short15 = "abcdefghijklmno";   // 15 bytes
    private const string Long16 = "abcdefghijklmnop";   // 16 bytes
    private const string Long40 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"; // 40 bytes

    private readonly BrokerHarness _h = new();
    private readonly List<IAsyncDisposable> _cleanup = [];

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _h.DisposeAsync();
        foreach (var d in _cleanup)
            await d.DisposeAsync();
    }

    /// <summary>The message passed to <see cref="BrokerLog.Event"/> for <paramref name="name"/>, built from the constant.</summary>
    private static string Message(string name) =>
        $"secret '{name}' is shorter than {BrokerShortSecretWarnings.ShortSecretBytes} bytes: a caller whose input comes back in a response can test guesses against it (a match is redacted); see BROKER.md \"Redaction confirms whole guesses\"";

    /// <summary>The text of the event line for <paramref name="name"/> (what follows the timestamp).</summary>
    private static string EventLine(string name) => "tswap-broker event " + BrokerLog.Escape(Message(name), 1024);

    private static int Count(string log, string text)
    {
        var n = 0;
        for (var i = log.IndexOf(text, StringComparison.Ordinal); i >= 0; i = log.IndexOf(text, i + text.Length, StringComparison.Ordinal))
            n++;
        return n;
    }

    private static int Warnings(BrokerHarness h) => Count(h.LogText.ToString(), " is shorter than ");

    private static string J(string s) => JsonSerializer.Serialize(s);

    /// <summary>Routes <c>echo</c> and <c>echo2</c>, both with secret <c>{{name}}</c>, on lane1.</summary>
    private static string TwoRoutes(string upstream, string name = "tok") => $$$"""
        { "name": "echo", "upstream": "{{{upstream}}}/base", "auth": { "type": "bearer", "secret": "{{{{{name}}}}}" }, "path": "" },
        { "name": "echo2", "upstream": "{{{upstream}}}/two", "auth": { "type": "bearer", "secret": "{{{{{name}}}}}" }, "path": "" },
        { "name": "second", "upstream": "{{{upstream}}}/second", "auth": { "type": "bearer", "secret": "{{tok2}}" }, "path": "" }
        """;

    private async Task StartFakeForwarderAsync(BrokerHarness h, string secret, string name = "tok")
    {
        h.Secrets = new FakeBrokerSecrets(n => n == name ? secret : "a-long-enough-other-secret-value");
        await h.StartAsync(h.Config(TwoRoutes("https://upstream.example", name), lane1Routes: "\"echo\", \"echo2\""));
    }

    /// <summary>A real forwarder to a test upstream that echoes the bearer token it got into a header and the body.</summary>
    private async Task<BrokerHarness> StartEchoingAsync(BrokerHarness h, string secret, int status = 200)
    {
        var up = await BrokerTestUpstream.StartAsync();
        _cleanup.Add(up);
        var forwarder = new HttpBrokerForwarder(h.Clock, trustedTestCertificate: up.Certificate);
        _cleanup.Add(new DisposeAction(forwarder.Dispose));
        up.Respond = async (http, hit) =>
        {
            var token = (hit.Header("Authorization") ?? "")["Bearer ".Length..];
            http.Response.StatusCode = status;
            http.Response.Headers["X-Echo"] = "got " + token;
            http.Response.Headers["X-Fixed"] = "same";
            await http.Response.WriteAsync("got " + token + " end");
        };
        h.Secrets = new FakeBrokerSecrets(_ => secret);
        await h.StartAsync(h.Config(TwoRoutes(up.BaseUrl), lane1Routes: "\"echo\", \"echo2\""), forwarder);
        return h;
    }

    private sealed class DisposeAction(Action action) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            action();
            return ValueTask.CompletedTask;
        }
    }

    private static string HeadOf(string response) => response[..response.IndexOf("\r\n\r\n", StringComparison.Ordinal)];

    // ------------------------------------------------------------------ routes

    [Fact]
    public async Task ARoute_WithA15ByteSecret_LogsTheWarningOnce_ASecondRequestLogsNothingNew()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartFakeForwarderAsync(_h, Short15);

        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
        Assert.Equal(1, Count(_h.LogText.ToString(), EventLine("tok")));

        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
        Assert.Equal(1, Count(_h.LogText.ToString(), EventLine("tok")));
        Assert.Equal(1, Warnings(_h));
        Assert.Equal(2, _h.Secrets.Unlocks);
    }

    [Fact]
    public async Task ARoute_WithA16ByteSecret_LogsNoWarning()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartFakeForwarderAsync(_h, Long16);

        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));

        Assert.Equal(1, _h.Secrets.Unlocks);
        Assert.Equal(0, Warnings(_h));
    }

    [Fact]
    public async Task TwoRoutesSharingOneShortSecret_LogOneWarningInTotal()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartFakeForwarderAsync(_h, Short15);

        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo2/a")));
        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/b")));

        Assert.Equal(3, _h.Secrets.Unlocks);
        Assert.Equal(1, Count(_h.LogText.ToString(), EventLine("tok")));
        Assert.Equal(1, Warnings(_h));
    }

    [Fact]
    public async Task AShortSecret_AndALongOne_GetTheSameStatus_RedactedBody_AndHeaders()
    {
        if (OperatingSystem.IsWindows())
            return;
        await using var shortH = new BrokerHarness();
        await using var longH = new BrokerHarness();
        await StartEchoingAsync(shortH, Short15);
        await StartEchoingAsync(longH, Long16);

        var shortResponse = await shortH.GetAsync("lane1", "/echo/a");
        var longResponse = await longH.GetAsync("lane1", "/echo/a");

        Assert.Equal(1, Warnings(shortH));
        Assert.Equal(0, Warnings(longH));
        Assert.Equal(200, BrokerHarness.StatusOf(shortResponse));
        Assert.Equal(BrokerHarness.StatusOf(longResponse), BrokerHarness.StatusOf(shortResponse));
        Assert.Equal("got [REDACTED] end", BrokerHarness.BodyOf(shortResponse));
        Assert.Equal(BrokerHarness.BodyOf(longResponse), BrokerHarness.BodyOf(shortResponse));
        // Header names and values, apart from Date (the upstream's own clock).
        static List<string> Headers(string response) =>
            [.. HeadOf(response).Split("\r\n").Where(l => !l.StartsWith("Date:", StringComparison.OrdinalIgnoreCase))];
        Assert.Equal(Headers(longResponse), Headers(shortResponse));
        Assert.DoesNotContain(Short15, shortResponse);
    }

    [Fact]
    public async Task TheFirstRequest_WhoseUpstreamAnswers500_StillLogsTheWarning()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartEchoingAsync(_h, Short15, status: 500);

        var response = await _h.GetAsync("lane1", "/echo/a");

        Assert.Equal(500, BrokerHarness.StatusOf(response));
        Assert.Equal(1, Count(_h.LogText.ToString(), EventLine("tok")));
    }

    [Fact]
    public async Task TheWarningMessage_HoldsNeitherTheSecretNorItsLength()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartFakeForwarderAsync(_h, Short15);

        Assert.Equal(200, BrokerHarness.StatusOf(await _h.GetAsync("lane1", "/echo/a")));

        // The message passed to BrokerLog.Event is everything after "event " on the line (escaped once).
        var line = Assert.Single(_h.LogText.ToString().Split('\n'), l => l.Contains(" is shorter than ", StringComparison.Ordinal));
        var message = line[(line.IndexOf("tswap-broker event ", StringComparison.Ordinal) + "tswap-broker event ".Length)..].TrimEnd('\r');
        Assert.Equal(BrokerLog.Escape(Message("tok"), 1024), message);
        Assert.DoesNotContain(Short15, message);
        Assert.DoesNotContain("15", message);
    }

    // ------------------------------------------------------------------ templates

    [Fact]
    public async Task ATemplateWithTwoSecrets_15And40Bytes_WarnsOnce_NamingThe15ByteOne()
    {
        if (!SandboxBed.CanRun(output))
            return;
        using var bed = new SandboxBed();
        var config = $$$"""
            {
              "version": 1,
              "socket_dir": {{{J(_h.SocketDir)}}},
              "sockets": [ { "name": "lane1", "uids": ["{{{BrokerHarness.MyUid}}}"], "routes": [], "templates": ["t"] } ],
              "routes": [],
              "templates": [ {
                "name": "t",
                "argv": ["/bin/bash", {{{J(bed.Script("printf 'ok %s %s' \"$A\" \"$B\""))}}}],
                "args": {},
                "env": { "A": "{{shorty}}", "B": "{{longer}}" },
                "binds": [ { "path": {{{J(bed.Work)}}} } ]
              } ]
            }
            """;
        _h.Secrets = new FakeBrokerSecrets(n => n == "shorty" ? Short15 : Long40);
        await _h.StartAsync(config);

        var response = Encoding.Latin1.GetString(await _h.SendRawAsync("lane1",
            "POST /_template/t HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"));

        Assert.Equal(200, BrokerHarness.StatusOf(response));
        Assert.Equal(1, _h.Secrets.Unlocks);
        Assert.Equal(1, Count(_h.LogText.ToString(), EventLine("shorty")));
        Assert.Equal(1, Warnings(_h));
        Assert.DoesNotContain("'longer'", _h.LogText.ToString());
    }

    // ------------------------------------------------------------------ ssh-agent

    private static readonly TestHostKey X = TestHostKey.NewEd25519();
    private static readonly byte[] KeyA = SshTestKeyMaker.Ed25519Pem(RandomNumberGenerator.GetBytes(32));
    private static readonly byte[] BlobA = SshTestKeyMaker.PublicBlob(KeyA);

    [Fact]
    public async Task AnSshAgentSign_LogsNoWarning()
    {
        if (SshTestSkip.OnWindows(output))
            return;
        await using var ssh = new SshAgentHarness();
        var config = $$"""
            {
              "version": 1,
              "socket_dir": {{J(ssh.Broker.SocketDir)}},
              "sockets": [ { "name": "lane1", "uids": ["{{BrokerHarness.MyUid}}"], "routes": [], "ssh_keys": ["a"] } ],
              "routes": [],
              "ssh_keys": [ { "name": "a", "secret": "sa", "allowed_host_keys": ["{{X.Fingerprint}}"] } ]
            }
            """;
        var source = new FakeSshKeySource(_ => (byte[])KeyA.Clone());
        await ssh.StartAsync(config, p => new SshAgentOptions { Keys = SshAgentKeyLoader.Load(p, source), KeySource = source });
        using var client = await ssh.ConnectAsync("lane1");
        var sid = RandomNumberGenerator.GetBytes(32);
        Assert.Equal(new[] { SshAgentProtocol.Success }, await client.RequestAsync(SshBindMessages.Bind(X.Blob, sid, X.Sign(sid))));
        var reads = source.Reads;

        var reply = await client.RequestAsync(SshBindMessages.SignRequest(BlobA, SshBindMessages.Userauth(sid, "ssh-ed25519", BlobA)));

        Assert.Equal(SshAgentProtocol.SignResponse, reply![0]);
        Assert.Equal(1, source.Reads - reads);
        Assert.Equal(0, Warnings(ssh.Broker));
    }
}
