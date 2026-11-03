using System.Text;
using System.Text.Json;
using TswapCore.Broker;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief I224 D7 H2 (task 7): a policy with templates but no host context (which
/// <see cref="BrokerPolicy.Validate"/> never builds) refuses every template call with the "binds"
/// refusal, with or without binds, and never starts the sandbox. Before, a null host skipped the
/// per-run bind re-check.
/// </summary>
public class BrokerTemplateNullHostTests(ITestOutputHelper output) : IAsyncLifetime
{
    private readonly BrokerHarness _h = new();
    private readonly SandboxBed _bed = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _h.DisposeAsync();
        _bed.Dispose();
    }

    private static string J(string s) => JsonSerializer.Serialize(s);

    private string Config() => $$"""
        {
          "version": 1,
          "socket_dir": {{J(_h.SocketDir)}},
          "sockets": [ { "name": "lane1", "uid_only": true, "uids": ["{{BrokerHarness.MyUid}}"], "routes": [], "templates": ["bound", "bare"] } ],
          "routes": [],
          "templates": [
            { "name": "bound", "argv": ["/usr/bin/true"], "binds": [ { "path": {{J(_bed.Work)}} }, { "path": {{J(_bed.Out)}}, "rw": true } ] },
            { "name": "bare", "argv": ["/usr/bin/true"] }
          ]
        }
        """;

    private async Task<string> PostAsync(string template) =>
        Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", $"POST /_template/{template} HTTP/1.1\r\nHost: broker\r\n" +
            "Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"));

    private string LogLineOf(string template) =>
        Assert.Single(_h.LogText.ToString().Split('\n'), l => l.Contains($" template={template} ", StringComparison.Ordinal));

    [Fact]
    public async Task WithoutAHostContext_EveryTemplateCallIsRefused_WithOrWithoutBinds_AndNothingStarts()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await _h.StartAsync(Config());
        var started = 0;
        _h.Server!.Handler.Templates!.Sandbox(_h.Holder!.Current.BwrapPath).Sandbox.Started += _ => Interlocked.Increment(ref started);

        // The positive: with the host context Validate set, both run (and the counter sees them start).
        Assert.NotNull(_h.Holder.Current.Host);
        Assert.Equal(200, BrokerHarness.StatusOf(await PostAsync("bound")));
        Assert.Equal(200, BrokerHarness.StatusOf(await PostAsync("bare")));
        Assert.Equal(2, Volatile.Read(ref started));
        await _h.WaitForLogAsync(" template=bound args=\"\" status=200 ");
        await _h.WaitForLogAsync(" template=bare args=\"\" status=200 ");

        Assert.True(_h.Holder.TryReload(() => BrokerPolicy.WithoutHostForTests(_h.Holder.Current), _ => { }));
        Assert.Null(_h.Holder.Current.Host);
        Assert.NotEmpty(_h.Holder.Current.Templates);
        _h.LogText.GetStringBuilder().Clear();

        var bound = await PostAsync("bound");
        var bare = await PostAsync("bare");

        Assert.Equal(503, BrokerHarness.StatusOf(bound));
        Assert.Equal(503, BrokerHarness.StatusOf(bare));
        Assert.Equal(BrokerHarness.BodyOf(bound), BrokerHarness.BodyOf(bare)); // the uniform 503
        await _h.WaitForLogAsync(" template=bare ");
        Assert.EndsWith("reason=binds", LogLineOf("bound").TrimEnd());
        Assert.EndsWith("reason=binds", LogLineOf("bare").TrimEnd());
        Assert.Equal(2, Volatile.Read(ref started)); // neither started the sandbox
    }
}
