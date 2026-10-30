using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Broker;
using TswapCore.Broker.Templates;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>Brief T9 fix round 1: the review findings that change behaviour, each with its test.</summary>
public class BrokerTemplateFixRound1Tests(ITestOutputHelper output) : IDisposable
{
    private readonly SandboxBed _bed = new();

    public void Dispose() => _bed.Dispose();

    private static string J(string s) => JsonSerializer.Serialize(s);

    /// <summary>A 64-byte secret: its base64 (88 characters) wraps at 76 and 64 columns, its hex at 60.</summary>
    private const string LongSecret = "L0ng-secret-value-for-wrapping_0123456789abcdefghijklmnopqrstuvw";

    // ------------------------------------------------------------------ MiMo I3: wrapped and spaced forms, T8's path

    public static TheoryData<string, string> WrappedShapes()
    {
        var bytes = Encoding.UTF8.GetBytes(LongSecret);
        var b64 = Convert.ToBase64String(bytes);
        var hex = Convert.ToHexString(bytes);
        static string Wrap(string s, int w, string eol) => string.Join(eol, s.Chunk(w).Select(c => new string(c)));
        return new TheoryData<string, string>
        {
            { "base64 at 76 (GNU base64)", Wrap(b64, 76, "\n") + "\n" },
            { "base64 at 76, CRLF (MIME)", Wrap(b64, 76, "\r\n") + "\r\n" },
            { "base64 at 64 (openssl base64)", Wrap(b64, 64, "\n") + "\n" },
            { "spaced lower hex (od -An -tx1 -w, xxd -g1)", " " + string.Join(' ', hex.ToLowerInvariant().Chunk(2).Select(c => new string(c))) + "\n" },
            { "spaced upper hex", string.Join(' ', hex.Chunk(2).Select(c => new string(c))) },
            { "hex at 60 (xxd -p)", Wrap(hex.ToLowerInvariant(), 60, "\n") + "\n" },
        };
    }

    [Theory]
    [MemberData(nameof(WrappedShapes))]
    public void TheSharedRedactor_CatchesWrappedBase64AndSpacedHex_InStreamAndHeaders(string shape, string printed)
    {
        var redactor = BrokerRedactor.ForSecret(Encoding.UTF8.GetBytes(LongSecret), null);
        var input = Encoding.UTF8.GetBytes("before " + printed + " after");
        var outStream = new MemoryStream();
        foreach (var chunk in input.Chunk(7)) // small chunks: the forms span chunk boundaries
            redactor.Process(chunk, outStream);
        redactor.Flush(outStream);

        var text = Encoding.UTF8.GetString(outStream.ToArray());
        var trimmed = printed.Trim();
        var expected = "before " + printed.Replace(trimmed, "[REDACTED]") + " after";
        Assert.True(text == expected, $"{shape}: {text}");
        Assert.True(redactor.Contains(printed.Trim()), shape); // the header check too
        Assert.Equal(redactor.Forms.Max(f => f.Length) - 1, redactor.Window); // T8's window rule still holds
    }

    // ------------------------------------------------------------------ MiMo I3: the same shapes from real tools, template path

    [Fact]
    public async Task ATemplate_PrintingTheSecretThroughBase64OrOd_IsRedacted()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var script = _bed.Script("""
            printf '%s' "$L" | base64
            printf '%s' "$L" | od -An -tx1 -v -w100
            printf '%s' "$L" | od -An -tx1 -v | tr -d ' \n' | fold -w 60; echo
            """);
        var template = _bed.Template(script, extra: """, "env": { "L": "{{long}}" }""");
        var stdout = new MemoryStream();
        var outputter = new BrokerTemplateOutput([Encoding.UTF8.GetBytes(LongSecret)], 1 << 20, (kind, data) =>
        {
            stdout.Write(data.Span);
            return ValueTask.CompletedTask;
        });

        var result = await new BrokerSandbox(SandboxBed.BwrapPath).RunAsync(
            new BrokerSandboxLaunch(template, template.BuildArgv(new Dictionary<string, string>()), [new BrokerSandboxEnv("L", Encoding.UTF8.GetBytes(LongSecret))], []),
            outputter.WriteAsync, CancellationToken.None);
        await outputter.CompleteAsync();

        Assert.Equal(BrokerSandboxEnded.Exit, result.Ended);
        var lines = Encoding.UTF8.GetString(stdout.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Trim()).ToList();
        Assert.Equal(["[REDACTED]", "[REDACTED]", "[REDACTED]"], lines); // each tool's whole output was the secret's form
    }

    // ------------------------------------------------------------------ GLM 1 / MiMo M3: cross-stream, deterministic

    private static async Task<(string Stdout, string Stderr)> FeedAsync(params (BrokerOutputKind Kind, string Text)[] chunks)
    {
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        var output = new BrokerTemplateOutput([Encoding.UTF8.GetBytes(LongSecret)], 1 << 20, (kind, data) =>
        {
            (kind == BrokerOutputKind.Stdout ? stdout : stderr).Append(Encoding.UTF8.GetString(data.Span));
            return ValueTask.CompletedTask;
        });
        foreach (var (kind, text) in chunks)
            await output.WriteAsync(kind, Encoding.UTF8.GetBytes(text));
        await output.CompleteAsync();
        return (stdout.ToString(), stderr.ToString());
    }

    [Fact]
    public async Task ASecretSplitBetweenStdoutAndStderr_ReadInWriteOrder_IsCaught()
    {
        var (stdout, stderr) = await FeedAsync((BrokerOutputKind.Stdout, "a" + LongSecret[..20]), (BrokerOutputKind.Stderr, LongSecret[20..] + "b"));

        Assert.Equal("a[REDACTED]", stdout); // the replacement goes to the stream the match started in
        Assert.Equal("b", stderr);
    }

    [Fact]
    public async Task ASecretSplitBetweenTheStreams_ReadInTheOtherOrder_IsNotCaught_AsBrokerMdSays()
    {
        // Two pipes have no common order: if the suffix is read first, no known form is ever seen.
        // This pins the documented limitation, so a change in either direction is noticed.
        var (stdout, stderr) = await FeedAsync((BrokerOutputKind.Stderr, LongSecret[20..]), (BrokerOutputKind.Stdout, LongSecret[..20]));

        Assert.Equal(LongSecret[..20], stdout);
        Assert.Equal(LongSecret[20..], stderr);
    }

    // ------------------------------------------------------------------ MiMo I2: bwrap_path's ancestors

    [Fact]
    public void ABwrapPathReachedThroughAFolderAnotherUidOwns_IsRefused_TheRealOneIsNot()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var link = Path.Combine(_bed.Root, "bwrap");
        File.CreateSymbolicLink(link, SandboxBed.BwrapPath); // a root-owned target, but the link's folder is ours

        var problem = new BrokerSandbox(link).Probe();

        Assert.NotNull(problem);
        Assert.Contains("above bwrap_path", problem);
        Assert.Null(new BrokerSandbox(SandboxBed.BwrapPath).Probe());
    }

    [Fact]
    public async Task ABwrapPathThatTurnsBadAfterTheProbe_IsRefusedAtTheNextRun()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var dir = Path.Combine(_bed.Root, "bin");
        Directory.CreateDirectory(dir);
        var link = Path.Combine(dir, "bwrap");
        File.CreateSymbolicLink(link, SandboxBed.BwrapPath);
        var template = _bed.Template(_bed.Script($"touch {_bed.Out}/ran"));

        var run = await BrokerSandboxTests.RunAsync(template, sandbox: new BrokerSandbox(link));

        Assert.Equal(BrokerSandboxEnded.Refused, run.Result.Ended);
        Assert.Contains("above bwrap_path", run.Result.Reason);
        Assert.False(File.Exists(Path.Combine(_bed.Out, "ran")));
    }

    // ------------------------------------------------------------------ MiMo M5: every way out kills the sandbox

    [Fact]
    public async Task AnOutputCallbackThatThrows_KillsTheSandbox_AtOnce()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var marker = $"3600.{Random.Shared.Next(100000, 999999)}7";
        var script = _bed.Script($"echo first; /usr/bin/sleep {marker}");
        var template = _bed.Template(script, extra: ", \"timeout_sec\": 600");
        var started = new TaskCompletionSource();
        var sandbox = new BrokerSandbox(SandboxBed.BwrapPath);

        var run = sandbox.RunAsync(new BrokerSandboxLaunch(template, template.BuildArgv(new Dictionary<string, string>()), [], []),
            async (_, _) =>
            {
                Assert.True(await BrokerSandboxTests.EventuallyAsync(() => BrokerSandboxTests.HostPidsWith(marker).Count == 1), "the sleep never started");
                started.TrySetResult();
                throw new InvalidOperationException("the response broke");
            }, CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(() => run.WaitAsync(TimeSpan.FromSeconds(60)));
        Assert.True(started.Task.IsCompleted);
        Assert.Empty(BrokerSandboxTests.HostPidsWith(marker)); // reaped before RunAsync returned
    }

    // ------------------------------------------------------------------ found in fix round 1: --die-with-parent is per thread

    [Fact]
    public async Task ARun_Survives_TheThreadThatStartedItEnding()
    {
        if (!SandboxBed.CanRun(output))
            return;
        // bwrap's --die-with-parent is PR_SET_PDEATHSIG, tied to the spawning thread: a retired
        // thread-pool thread would SIGKILL a running template. RunAsync spawns before its first
        // await, so here the spawn happens on a thread that then ends.
        var template = _bed.Template(_bed.Script("/usr/bin/sleep 1; echo survived"));
        var stdout = new StringBuilder();
        Task<BrokerSandboxResult>? run = null;
        using var started = new ManualResetEventSlim();
        var sandbox = new BrokerSandbox(SandboxBed.BwrapPath);
        sandbox.Started += _ => started.Set();
        var thread = new Thread(() =>
        {
            run = sandbox.RunAsync(
                new BrokerSandboxLaunch(template, template.BuildArgv(new Dictionary<string, string>()), [], []),
                (_, data) =>
                {
                    lock (stdout)
                        stdout.Append(Encoding.UTF8.GetString(data.Span));
                    return ValueTask.CompletedTask;
                }, CancellationToken.None);
            // bwrap is set up (its prctl done) before this thread ends.
            Assert.True(started.Wait(TimeSpan.FromSeconds(30)));
        });
        thread.Start();
        thread.Join();

        var result = await run!.WaitAsync(TimeSpan.FromSeconds(60));

        Assert.Equal(new BrokerSandboxResult(BrokerSandboxEnded.Exit, 0), result);
        Assert.Equal("survived\n", stdout.ToString());
    }

    // ------------------------------------------------------------------ GLM (nit): NPROC enforced, not only shown

    [Fact]
    public async Task TheProcessLimit_IsEnforcedInsideTheSandbox()
    {
        if (!SandboxBed.CanRun(output))
            return;
        if (!File.Exists("/usr/bin/python3"))
            Assert.Fail("this test forks from python3, which the Linux CI runner has");
        var script = _bed.Script("""
            /usr/bin/python3 -c '
            import os, time
            ok = fail = 0
            for i in range(8):
                try:
                    if os.fork() == 0:
                        time.sleep(1); os._exit(0)
                    ok += 1
                except OSError:
                    fail += 1
            print(ok, fail)'
            """);

        var run = await BrokerSandboxTests.RunAsync(_bed.Template(script, extra: """, "limits": { "nproc": 4 }"""));

        // pid 1 (bwrap), bash and python take 3 of the 4; one fork succeeds, seven fail.
        Assert.Equal("1 7", run.Stdout.Trim());
    }

    // ------------------------------------------------------------------ GLM 6 / MiMo M7, M6: config refusals

    [Theory]
    [InlineData("BASH_ENV")]
    [InlineData("ENV")]
    [InlineData("PS4")]
    [InlineData("NODE_OPTIONS")]
    [InlineData("PYTHONSTARTUP")]
    [InlineData("GIT_SSH_COMMAND")]
    [InlineData("GIT_CONFIG_COUNT")]
    [InlineData("GIT_CONFIG_KEY_0")]
    [InlineData("GLIBC_TUNABLES")]
    [InlineData("PWD")]
    public void CodeRunningEnvNames_AreRefused(string name)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only
        var ex = Assert.Throws<BrokerConfigException>(() => _bed.Template(_bed.Script("true"), extra: $", \"env\": {{ {J(name)}: \"x\" }}"));
        Assert.Contains(name, ex.Message);
        _bed.Template(_bed.Script("true"), extra: ", \"env\": { \"PGHOST\": \"x\" }"); // the positive: an ordinary name
    }

    [Fact]
    public void AnArgvThatCanOutgrowExecve_IsRefusedAtLoad()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only
        var names = Enumerable.Range(0, 12).Select(i => "a" + i).ToList();
        var args = "{" + string.Join(", ", names.Select(n => $"\"{n}\": {{ \"pattern\": \"x+\", \"max_length\": 4096 }}")) + "}";
        var oneEntry = $"[\"/bin/bash\", {J(_bed.Script("true"))}, \"{string.Concat(names.Select(n => "{" + n + "}"))}\"]";

        var ex = Assert.Throws<BrokerConfigException>(() => _bed.Template("", argv: oneEntry, args: args));
        Assert.Contains("MAX_ARG_STRLEN", ex.Message);
        // The positive: the same arguments as separate entries fit.
        var separate = $"[\"/bin/bash\", {J(_bed.Script("true"))}, {string.Join(", ", names.Select(n => "\"{" + n + "}\""))}]";
        _bed.Template("", argv: separate, args: args);
    }

    [Fact]
    public void TemplateAdd_WithADuplicateKeyInEnvOrArgs_IsACleanRefusal()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only
        using var m = new FleetMachine("tplfix");
        var file = Path.Combine(_bed.Root, "dup.json");
        File.WriteAllText(file, $$"""{ "name": "t", "argv": ["/usr/bin/true"], "env": { "A": "1", "A": "2" } }""");

        var (exit, _, err) = m.Run("", "broker", "template", "add", file);

        Assert.NotEqual(0, exit);
        Assert.Contains("can't be read", err);
        Assert.False(File.Exists(BrokerConfigFile.PathIn(m.Dir)));
    }

    // ------------------------------------------------------------------ GLM 4 / MiMo M10: the vault folder found without a store

    [Fact]
    public void ForVault_FindsTheRecordStoresVaultFolder_FromTheConfigFolderAlone()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only
        using var m = new FleetMachine("tplvault") { Tpm = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) };
        m.Ok("", "init", "--tpm", "--no-recovery");
        m.Ok("", "migrate", "--to-records");

        var host = BrokerHostContext.ForVault(m.Dir, null);

        Assert.Contains(Path.GetFullPath(m.VaultDir!), host.Protected);
        Assert.Contains(Path.GetFullPath(m.Dir), host.Protected);
    }
}

/// <summary>Fix round 1 (GLM 5, GLM 7 / MiMo M1): the rate isn't spent by a call that can't run; the output's secret copies are zeroed.</summary>
public class BrokerTemplateFixRound1CallTests(ITestOutputHelper output) : IAsyncLifetime
{
    private readonly BrokerHarness _h = new();
    private readonly SandboxBed _bed = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _h.DisposeAsync();
        _bed.Dispose();
    }

    [Fact]
    public async Task ACallRefusedForTheSandbox_DoesNotUseUpTheRate()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var script = JsonSerializer.Serialize(_bed.Script("true"));
        var config = $$"""
            {
              "version": 1, "socket_dir": {{JsonSerializer.Serialize(_h.SocketDir)}},
              "bwrap_path": {{JsonSerializer.Serialize(Path.Combine(_bed.Root, "no-bwrap"))}},
              "sockets": [ { "name": "lane1", "uids": ["{{BrokerHarness.MyUid}}"], "routes": [], "templates": ["t"] },
                           { "name": "other", "uids": ["{{BrokerHarness.MyUid}}"], "routes": [] } ],
              "routes": [],
              "templates": [ { "name": "t", "argv": ["/bin/bash", {{script}}], "binds": [ { "path": {{JsonSerializer.Serialize(_bed.Work)}} } ], "rate": 1 } ]
            }
            """;
        await _h.StartAsync(config);
        string Post() => "POST /_template/t HTTP/1.1\r\nHost: b\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

        var first = BrokerHarness.StatusOf(Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", Post())));
        var second = BrokerHarness.StatusOf(Encoding.Latin1.GetString(await _h.SendRawAsync("lane1", Post())));

        Assert.Equal(503, first);
        Assert.Equal(503, second); // not 429: the refused first call took no rate
    }

    [Fact]
    public void TheOutput_ZeroesTheSecretCopiesItWasGiven()
    {
        var copy = Encoding.UTF8.GetBytes("copy-of-a-secret-value");
        _ = new BrokerTemplateOutput([copy], 100, (_, _) => ValueTask.CompletedTask);

        Assert.All(copy, b => Assert.Equal(0, b));
    }
}
