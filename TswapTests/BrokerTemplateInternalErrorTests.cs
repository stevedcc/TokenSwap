using System.Text;
using System.Text.Json;
using TswapCore.Broker;
using TswapCore.Broker.Templates;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief I224 D7 H5, the template handler's half (task 9): an exception escaping a template call
/// becomes the uniform 502 when nothing was sent yet, or an aborted connection after the first
/// frame; never Kestrel's 500. One <c>template</c> log line says <c>internal-error</c> and the
/// exception's type, never its message.
/// </summary>
public class BrokerTemplateInternalErrorTests(ITestOutputHelper output) : IAsyncLifetime
{
    private readonly BrokerHarness _h = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _h.DisposeAsync();

    /// <summary>What the thrown exception says; it must never reach the log or the client.</summary>
    private const string Message = "internal-detail-that-must-not-be-logged";

    private string Config() => $$$"""
        {
          "version": 1,
          "socket_dir": {{{JsonSerializer.Serialize(_h.SocketDir)}}},
          "sockets": [ { "name": "lane1", "uid_only": true, "uids": ["{{{BrokerHarness.MyUid}}}"], "routes": ["echo"], "templates": ["t"] } ],
          "routes": [ { "name": "echo", "upstream": "https://upstream.example/base", "auth": { "type": "bearer", "secret": "{{tok}}" }, "path": "" } ],
          "templates": [ { "name": "t", "argv": ["/usr/bin/true"] } ]
        }
        """;

    private async Task StartAsync(Func<BrokerSandboxLaunch, Func<BrokerOutputKind, ReadOnlyMemory<byte>, ValueTask>, CancellationToken, Task<BrokerSandboxResult>> run)
    {
        await _h.StartAsync(Config());
        _h.Server!.Handler.Templates!.RunForTests = run;
    }

    private async Task<string> CallAsync() =>
        Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", "POST /_template/t HTTP/1.1\r\nHost: broker\r\n" +
            "Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"));

    private string[] InternalErrorLines() =>
        [.. _h.LogText.ToString().Split('\n').Where(l => l.Contains("internal-error", StringComparison.Ordinal))];

    [Fact]
    public async Task AnExceptionBeforeAnyOutput_GetsTheUniform502_AndOneLogLine()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync((_, _, _) => throw new InvalidOperationException(Message));

        var response = await CallAsync();
        Assert.Equal(502, BrokerHarness.StatusOf(response)); // not Kestrel's 500
        await _h.WaitForLogAsync("internal-error");
        // The uniform 502 from the same server and clock: a route whose secret source fails.
        _h.Secrets.Throw = new InvalidOperationException("unlock failed");
        var uniform = await _h.GetAsync("lane1", "/echo/x");

        Assert.Equal(502, BrokerHarness.StatusOf(uniform));
        Assert.Equal(uniform, response); // byte-identical
        var line = Assert.Single(InternalErrorLines());
        Assert.StartsWith("template socket=lane1 ", line[(line.IndexOf(" tswap-broker ", StringComparison.Ordinal) + 14)..]);
        Assert.Contains(" status=502 ", line);
        Assert.EndsWith(" reason=internal-error type=InvalidOperationException", line.TrimEnd());
        Assert.DoesNotContain(Message, _h.LogText.ToString());
        Assert.DoesNotContain(Message, response);
    }

    [Fact]
    public async Task AnExceptionAfterTheFirstFrame_AbortsTheConnection_No502_AndOneLogLine()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(async (_, write, _) =>
        {
            await write(BrokerOutputKind.Stdout, Encoding.ASCII.GetBytes("first frame\n"));
            throw new InvalidOperationException(Message);
        });

        var response = await CallAsync();
        await _h.WaitForLogAsync("internal-error");

        Assert.Equal(200, BrokerHarness.StatusOf(response)); // the stream had started
        Assert.Contains(Convert.ToBase64String(Encoding.ASCII.GetBytes("first frame\n")), response);
        Assert.DoesNotContain("\"ended\"", response); // no last frame
        Assert.DoesNotContain("Bad Gateway", response);
        Assert.DoesNotContain(" 502 ", response);
        Assert.False(response.EndsWith("0\r\n\r\n", StringComparison.Ordinal), "the chunked body must not end cleanly: the connection is aborted");
        var line = Assert.Single(InternalErrorLines());
        Assert.EndsWith(" reason=internal-error type=InvalidOperationException", line.TrimEnd());
        Assert.DoesNotContain(Message, _h.LogText.ToString());
    }
}
