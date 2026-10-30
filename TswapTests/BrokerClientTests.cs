using System.Net;
using Microsoft.AspNetCore.Http;
using System.Text;
using TswapCore;
using TswapCore.Broker;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T8 item 5: <c>broker forward</c> (decision 11) and the log (decision 10, #168).
/// </summary>
public class BrokerClientTests : IAsyncLifetime
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
    }

    public async Task DisposeAsync()
    {
        if (OperatingSystem.IsWindows())
            return;
        await _h.DisposeAsync();
        _forwarder.Dispose();
        await _up.DisposeAsync();
    }

    private Task StartAsync() =>
        _h.StartAsync(_h.Config(BrokerForwardingTests.Routes(_up.BaseUrl), lane1Routes: "\"bearer\", \"basic\", \"header\""), _forwarder);

    private static IEnumerable<string> AllForms() =>
        BrokerRedactor.ForSecret(Encoding.UTF8.GetBytes(Secret), "x-access-token").Forms.Select(f => Encoding.Latin1.GetString(f));

    // ------------------------------------------------------------------ forward

    [Fact]
    public async Task Forward_RelaysARequestEndToEnd_ForwardSocketBrokerUpstream()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        await using var relay = BrokerTcpRelay.Start(BrokerTcpRelay.ParseListen("127.0.0.1:0"), _h.SocketPath("lane1"));
        using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{relay.LocalEndPoint.Port}") };

        var get = await http.GetAsync("/bearer/via/forward?x=1");
        var post = await http.PostAsync("/bearer/upload", new StringContent("posted body"));

        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal("upstream ok", await get.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, post.StatusCode);
        Assert.Equal(2, _up.Hits.Count);
        Assert.Equal("/base/via/forward?x=1", _up.Hits[0].RawTarget);
        Assert.Equal("Bearer " + Secret, _up.Hits[0].Header("Authorization"));
        Assert.Equal("posted body", Encoding.UTF8.GetString(_up.Hits[1].Body));
        Assert.Equal(2, _h.Secrets.Unlocks);
    }

    [Fact]
    public async Task Forward_OnIPv6Loopback_Works()
    {
        if (OperatingSystem.IsWindows() || !System.Net.Sockets.Socket.OSSupportsIPv6)
            return;
        await StartAsync();
        await using var relay = BrokerTcpRelay.Start(BrokerTcpRelay.ParseListen("[::1]:0"), _h.SocketPath("lane1"));
        using var http = new HttpClient();

        var response = await http.GetAsync($"http://[::1]:{relay.LocalEndPoint.Port}/bearer/v6");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("0.0.0.0:8080")]
    [InlineData("[::]:8080")]
    [InlineData("localhost:8080")]
    [InlineData("broker.example:8080")]
    [InlineData("192.168.1.10:8080")]
    [InlineData("10.0.0.2:8080")]
    [InlineData("127.0.0.2:8080")]
    [InlineData("127.1:8080")]
    [InlineData("0177.0.0.1:8080")]
    [InlineData("::ffff:127.0.0.1:8080")]
    [InlineData("8080")]
    [InlineData("127.0.0.1:")]
    [InlineData("127.0.0.1:99999")]
    public void Forward_RefusesAnyListenAddressButALiteralLoopback(string listen)
    {
        Assert.Throws<TswapException>(() => BrokerTcpRelay.ParseListen(listen));
    }

    [Theory]
    [InlineData("127.0.0.1:8080", "127.0.0.1")]
    [InlineData("[::1]:8080", "::1")]
    [InlineData("::1:8080", "::1")]
    public void Forward_AcceptsALiteralLoopback(string listen, string address)
    {
        var endPoint = BrokerTcpRelay.ParseListen(listen);
        Assert.Equal(IPAddress.Parse(address), endPoint.Address);
        Assert.Equal(8080, endPoint.Port);
    }

    [Fact]
    public void ForwardCommand_RefusesALanAddress_WithoutTouchingAVault()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var m = new FleetMachine("fwd");
        var (exit, _, err) = m.Run("", "broker", "forward", "--listen", "0.0.0.0:8080");

        Assert.NotEqual(0, exit);
        Assert.Contains("loopback", err);
        Assert.Empty(Directory.GetFileSystemEntries(m.Dir)); // no vault, no config
    }

    // ------------------------------------------------------------------ the log

    [Fact]
    public async Task LogLines_HaveTheirFields()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        _up.Respond = async (http, _) => await http.Response.WriteAsync("twelve bytes");

        var raw = "POST /bearer/a/b%20c?q=1 HTTP/1.1\r\nHost: b\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
        await _h.SendRawAsync("lane1", raw);
        await _h.GetAsync("lane1", "/nope/x");

        var lines = _h.LogText.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var ok = Assert.Single(lines, l => l.Contains("route=bearer"));
        Assert.Matches(@"^2026-10-30T12:00:00\.000Z tswap-broker request socket=lane1 uid=\d+ pid=\d+ route=bearer method=POST " +
                       "path=\"a/b c\" status=200 bytes_in=5 bytes_out=12 unlocks=1 unlock_ms=\\d+$", ok);
        var refused = Assert.Single(lines, l => l.Contains("route=-"));
        Assert.Matches("request socket=lane1 uid=\\d+ pid=\\d+ route=- method=GET path=\"/nope/x\" status=404 bytes_in=0 bytes_out=0 unlocks=0 unlock_ms=0 reason=route$", refused);
    }

    [Fact]
    public async Task CrLfInAPath_CantForgeALogLine()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        const string forged = "2026-01-01T00:00:00.000Z tswap-broker request socket=lane1 uid=0 pid=1 route=bearer method=GET path=\"x\" status=200";

        await _h.GetAsync("lane1", "/bearer/a%0d%0a" + Uri.EscapeDataString(forged));
        await _h.GetAsync("lane1", "/bearer/a%0a" + Uri.EscapeDataString(forged));
        await _h.GetAsync("lane1", "/bearer/a%e2%80%a8" + Uri.EscapeDataString(forged)); // U+2028

        var lines = _h.LogText.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(3, lines.Count(l => l.Contains(" request ")));
        Assert.All(lines, l => Assert.StartsWith("2026-10-30T12:00:00.000Z tswap-broker ", l));
        Assert.DoesNotContain(lines, l => l.StartsWith("2026-01-01", StringComparison.Ordinal));
    }

    [Fact]
    public void Escape_HandlesControlCharacters_Quotes_AndCapsTheLength()
    {
        Assert.Equal(@"a\r\nb\""c\\d\u0007\u2028", BrokerLog.Escape("a\r\nb\"c\\d\u0007\u2028", 100));
        Assert.Equal("abc...", BrokerLog.Escape("abcdef", 3));
        Assert.Equal(BrokerLog.MaxPathLength + 3, BrokerLog.Escape(new string('p', 5000), BrokerLog.MaxPathLength).Length);
    }

    [Fact]
    public async Task NoCredentialAppearsInTheLog_AfterRequestsThatUsedOne()
    {
        if (OperatingSystem.IsWindows())
            return;
        await StartAsync();
        _up.Respond = async (http, _) =>
        {
            http.Response.Headers["X-Echo"] = Secret;
            await http.Response.WriteAsync("echo " + Secret);
        };

        await _h.GetAsync("lane1", "/bearer/x");
        await _h.GetAsync("lane1", "/basic/x", "Authorization: Bearer client-token\r\n");
        await _h.GetAsync("lane1", "/header/x");

        var log = _h.LogText.ToString();
        Assert.Equal(3, log.Split('\n').Count(l => l.Contains(" request ")));
        foreach (var form in AllForms())
            Assert.DoesNotContain(form, log);
        Assert.DoesNotContain("client-token", log);
        Assert.DoesNotContain("echo", log);
    }

    [Fact]
    public async Task BrokerLogFile_Is0600_AndAppended()
    {
        if (OperatingSystem.IsWindows())
            return;
        var path = Path.Combine(_h.Root, BrokerLog.FileName);
        using (var log = new BrokerLog(null, path, _h.Clock))
            log.Event("first");
        using (var log = new BrokerLog(null, path, _h.Clock))
            log.Event("second");

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        var lines = File.ReadAllLines(path);
        Assert.Equal(2, lines.Length);
        Assert.EndsWith("event first", lines[0]);
        Assert.EndsWith("event second", lines[1]);
    }

    // ------------------------------------------------------------------ the real secret source

    [Fact]
    public async Task VaultSecretSource_UnlocksTheSimulatedTpmVault_PerRequest_AndSendsOnlyThatRoutesSecret()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var m = new FleetMachine("brokervault") { Tpm = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) };
        m.Ok("", "init", "--tpm", "--no-recovery");
        m.Ok("vault-token-value\nvault-token-value\n", "add", "tok");
        m.Ok("other-value\nother-value\n", "add", "tok2");
        var unlocker = new VaultUnlocker(m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, m.Tpm)]);
        var source = new VaultBrokerSecretSource(VaultStores.Open(m.Dir), unlocker);

        using (var secret = source.Read("tok"))
            Assert.Equal("vault-token-value", Encoding.UTF8.GetString(secret.Value));
        Assert.Throws<BrokerSecretException>(() => source.Read("missing"));

        await using var h = new BrokerHarness();
        await h.StartAsync(h.Config(BrokerForwardingTests.Routes(_up.BaseUrl), lane1Routes: "\"bearer\""), _forwarder);
        // swap the fake for the real source
        await h.Server!.StopAsync();
        var options = h.Options(_forwarder) with { Secrets = source };
        await using var server = await BrokerServer.StartAsync(options);

        Assert.Equal(200, BrokerHarness.StatusOf(await h.GetAsync("lane1", "/bearer/real")));
        Assert.Equal("Bearer vault-token-value", Assert.Single(_up.Hits).Header("Authorization"));
        Assert.DoesNotContain(_up.Hits[0].Headers, x => x.Value.Contains("other-value"));

        // A TPM that no longer unseals: an unlock failure (502), counted.
        var broken = new VaultBrokerSecretSource(VaultStores.Open(m.Dir),
            new VaultUnlocker(m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, new byte[32])]));
        Assert.Throws<BrokerUnlockException>(() => broken.Read("tok"));
    }
}
