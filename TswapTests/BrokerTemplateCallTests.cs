using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Broker;
using TswapCore.Broker.Templates;
using TswapCore.Vault;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T9 item 3: calling a template over a broker socket (decisions 5 to 8): the secret reaches
/// the child only through env or a file, output comes back redacted (one redactor across both
/// streams), binary-safe and cut at the limit without leaking a fragment; every refusal happens
/// before anything unlocks or runs; one line per call in the log.
/// </summary>
public class BrokerTemplateCallTests(ITestOutputHelper output) : IAsyncLifetime
{
    private readonly BrokerHarness _h = new();
    private readonly SandboxBed _bed = new();

    private const string Secret = "tpl-S3CRET-value_0123456789";

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _h.DisposeAsync();
        _bed.Dispose();
    }

    private static string J(string s) => JsonSerializer.Serialize(s);

    private const string TokRef = "\"{{tok}}\"";

    private string Ran => Path.Combine(_bed.Out, "ran");

    /// <summary>A template "t" running <paramref name="body"/> (after touching the "ran" marker) with secret {{tok}} in $S.</summary>
    private string TemplateJson(string body, string name = "t", string args = "{}", string argvExtra = "", string extra = "") => $$"""
        {
          "name": {{J(name)}},
          "argv": ["/bin/bash", {{J(_bed.Script("touch " + Ran + "\n" + body, name + ".sh"))}} {{argvExtra}}],
          "args": {{args}},
          "env": { "S": {{TokRef}} },
          "binds": [ { "path": {{J(_bed.Work)}} }, { "path": {{J(_bed.Out)}}, "rw": true } ],
          "cwd": {{J(_bed.Out)}}
          {{extra}}
        }
        """;

    /// <summary>A config: lane1 may call <paramref name="lane1Templates"/>; "other" lists none.</summary>
    private string Config(string templatesJson, string lane1Templates = "\"t\"", string top = "") => $$"""
        {
          "version": 1,
          "socket_dir": {{J(_h.SocketDir)}},
          {{top}}
          "sockets": [
            { "name": "lane1", "uids": ["{{BrokerHarness.MyUid}}"], "routes": [], "templates": [{{lane1Templates}}] },
            { "name": "other", "uids": ["{{BrokerHarness.MyUid}}"], "routes": [] }
          ],
          "routes": [],
          "templates": [ {{templatesJson}} ]
        }
        """;

    private async Task StartAsync(string config)
    {
        _h.Secrets = new FakeBrokerSecrets(name => name == "tok" ? Secret : "other-" + name);
        await _h.StartAsync(config);
    }

    /// <summary>A raw POST; the whole response as Latin-1 text.</summary>
    private async Task<string> PostAsync(string socket, string target, string body, string method = "POST") =>
        Encoding.Latin1.GetString(await _h.SendRawAsync(socket, $"{method} {target} HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n" +
            $"Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}"));

    private static string Args(params (string Name, string Value)[] args) =>
        JsonSerializer.Serialize(new Dictionary<string, Dictionary<string, string>> { ["args"] = args.ToDictionary(a => a.Name, a => a.Value) });

    /// <summary>The frames of a 200 answer: stdout and stderr bytes, and the last frame.</summary>
    private static (byte[] Stdout, byte[] Stderr, JsonElement Last) Frames(string response)
    {
        Assert.Equal(200, BrokerHarness.StatusOf(response));
        var stdout = new MemoryStream();
        var stderr = new MemoryStream();
        JsonElement? last = null;
        foreach (var line in BrokerHarness.BodyOf(response).Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var frame = JsonDocument.Parse(line).RootElement.Clone();
            if (frame.TryGetProperty("stream", out var stream))
                (stream.GetString() == "stdout" ? stdout : stderr).Write(Convert.FromBase64String(frame.GetProperty("data").GetString()!));
            else
                last = frame;
        }
        Assert.NotNull(last);
        return (stdout.ToArray(), stderr.ToArray(), last!.Value);
    }

    private async Task<(int Exit, byte[] Stdout, string Stderr, string Errors)> CallAsync(string template, params (string, string)[] args)
    {
        var stdout = new MemoryStream();
        var stderr = new MemoryStream();
        var errors = new StringWriter();
        var exit = await BrokerTemplateClient.CallAsync(_h.SocketPath("lane1"), template, args.ToDictionary(a => a.Item1, a => a.Item2), stdout, stderr, errors);
        return (exit, stdout.ToArray(), Encoding.UTF8.GetString(stderr.ToArray()), errors.ToString());
    }

    // ------------------------------------------------------------------ running and redaction

    [Fact]
    public async Task ACall_RunsWithTheSecretInEnv_AndOutputEchoingItIsRedacted()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("""printf 'value=%s\n' "$S"; printf '%s' "$S" | base64""")));

        var (stdout, _, last) = Frames(await PostAsync("lane1", "/_template/t", Args()));

        var text = Encoding.UTF8.GetString(stdout);
        Assert.Equal("value=[REDACTED]\n[REDACTED]\n", text); // the raw value and its base64 both
        Assert.Equal("exit", last.GetProperty("ended").GetString());
        Assert.Equal(0, last.GetProperty("exit_code").GetInt32());
        Assert.Equal(1, _h.Secrets.Unlocks);
        Assert.True(File.Exists(Ran));
    }

    [Fact]
    public async Task ASecretSplitAcrossPipeReads_IsStillRedacted()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("""printf 'a%s' "${S:0:9}"; sleep 0.3; printf '%sb' "${S:9}" """)));

        var (stdout, _, _) = Frames(await PostAsync("lane1", "/_template/t", Args()));

        Assert.Equal("a[REDACTED]b", Encoding.UTF8.GetString(stdout));
    }

    [Fact]
    public async Task BinaryOutput_SurvivesTheRoundTrip_ByteForByte()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var file = Path.Combine(_bed.Out, "blob");
        var bytes = new byte[70000];
        new Random(9).NextBytes(bytes);
        File.WriteAllBytes(file, bytes);
        await StartAsync(Config(TemplateJson($"cat {file}")));

        var (exit, stdout, _, errors) = await CallAsync("t");

        Assert.Equal(0, exit);
        Assert.Equal(bytes, stdout);
        Assert.Equal("", errors);
    }

    [Fact]
    public async Task TruncationAtAMidSecretBoundary_LeaksNoFragment()
    {
        if (!SandboxBed.CanRun(output))
            return;
        // 20 bytes, then the secret: the limit cuts 4 bytes into it.
        await StartAsync(Config(TemplateJson("""printf '01234567890123456789%s' "$S"; printf 'tail' >&2""", extra: ", \"max_output_bytes\": 24")));

        var (stdout, stderr, last) = Frames(await PostAsync("lane1", "/_template/t", Args()));

        var text = Encoding.UTF8.GetString(stdout) + Encoding.UTF8.GetString(stderr);
        Assert.DoesNotContain(Secret[..4], text);
        Assert.StartsWith("01234567890123456789", text);
        Assert.True(last.GetProperty("truncated").GetBoolean());
        Assert.Equal(24, stdout.Length + stderr.Length);
        Assert.Equal(0, last.GetProperty("exit_code").GetInt32()); // the child ran to its end
    }

    [Fact]
    public async Task AFilesSecret_AndTheEnvSecret_ComeFromOneUnlock_ReadingOnlyTheTemplatesSecrets()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("""wc -c < /run/secrets/key""",
            extra: """, "files": [ { "path": "/run/secrets/key", "secret": "signing-key" } ]""")));

        var (stdout, _, _) = Frames(await PostAsync("lane1", "/_template/t", Args()));

        Assert.Equal("other-signing-key".Length.ToString(), Encoding.UTF8.GetString(stdout).Trim());
        Assert.Equal(1, _h.Secrets.Unlocks);
        Assert.Equal(["signing-key", "tok"], Assert.Single(_h.Secrets.ManyReads).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task ATemplateWithoutSecrets_RunsWithoutAnUnlock()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var json = TemplateJson("echo plain").Replace("\"env\": { \"S\": \"{{tok}}\" },", "");
        await StartAsync(Config(json));

        var (exit, stdout, _, _) = await CallAsync("t");

        Assert.Equal(0, exit);
        Assert.Equal("plain\n", Encoding.UTF8.GetString(stdout));
        Assert.Equal(0, _h.Secrets.Unlocks);
    }

    // ------------------------------------------------------------------ exit codes

    [Fact]
    public async Task TheExitCode_PassesThrough_AndABrokerErrorExits125()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("echo out; echo err >&2; exit 7")));

        var (exit, stdout, stderr, _) = await CallAsync("t");
        Assert.Equal(7, exit);
        Assert.Equal("out\n", Encoding.UTF8.GetString(stdout));
        Assert.Equal("err\n", stderr);

        var (refused, _, _, errors) = await CallAsync("nope");
        Assert.Equal(125, refused);
        Assert.Contains("404", errors);
    }

    [Fact]
    public async Task TheCallCommand_ExitsWithTheTemplatesCode_Or125()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("""echo "hello $1"; exit 3""", args: """{ "who": { "pattern": "[a-z]+" } }""", argvExtra: ", \"{who}\"")));
        using var m = new FleetMachine("tplcall");

        var (exit, stdout, _) = m.Run("", "broker", "call", "t", "who=world", "--socket", _h.SocketPath("lane1"));
        Assert.Equal(3, exit);
        Assert.Equal("hello world\n", stdout);

        var (badArg, _, err) = m.Run("", "broker", "call", "t", "who=World", "--socket", _h.SocketPath("lane1"));
        Assert.Equal(125, badArg);
        Assert.Contains("does not match", err);

        var (unreachable, _, err2) = m.Run("", "broker", "call", "t", "--socket", Path.Combine(_h.Root, "missing.sock"));
        Assert.Equal(125, unreachable);
        Assert.NotEmpty(err2);
    }

    [Fact]
    public async Task ATimeout_Reports124()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("sleep 30", extra: ", \"timeout_sec\": 1")));

        var (_, _, last) = Frames(await PostAsync("lane1", "/_template/t", Args()));

        Assert.Equal("timeout", last.GetProperty("ended").GetString());
        Assert.Equal(124, last.GetProperty("exit_code").GetInt32());
    }

    // ------------------------------------------------------------------ refusals: nothing runs, nothing unlocks

    private string ArgTemplate => TemplateJson("""echo "$1" """,
        args: """{ "branch": { "pattern": "brief/[a-z0-9-]+", "max_length": 16 } }""", argvExtra: ", \"{branch}\"");

    [Theory]
    [InlineData("{}", "'branch' is required")]
    [InlineData("""{"args": {"branch": "main"}}""", "does not match")]
    [InlineData("""{"args": {"branch": "brief/aaaaaaaaaaaaaaa"}}""", "longer than 16")]
    [InlineData("""{"args": {"branch": "-brief/x"}}""", "may not start with '-'")]
    [InlineData("""{"args": {"branch": "brief/x", "extra": "y"}}""", "'extra' is not declared")]
    [InlineData("""{"args": {"branch": "brief/x\u0000--force"}}""", "control character")]
    [InlineData("""{"args": {"branch": "brief/x\n"}}""", "control character")]
    [InlineData("""{"args": {"branch": "brief/x\u001b[2J"}}""", "control character")]
    [InlineData("""{"args": {"branch": 5}}""", "must be a string")]
    [InlineData("""{"argz": {}}""", "may only hold")]
    [InlineData("""not json""", "not valid JSON")]
    public async Task ABadCall_IsRefused_WithNothingRunAndNoUnlock(string body, string expected)
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(ArgTemplate));

        var response = await PostAsync("lane1", "/_template/t", body);

        Assert.Equal(400, BrokerHarness.StatusOf(response));
        Assert.Contains(expected, response);
        Assert.False(File.Exists(Ran));
        Assert.Equal(0, _h.Secrets.Unlocks);
        // The positive: a valid call to the same template runs.
        var ok = Frames(await PostAsync("lane1", "/_template/t", Args(("branch", "brief/x"))));
        Assert.Equal("brief/x\n", Encoding.UTF8.GetString(ok.Stdout));
        Assert.True(File.Exists(Ran));
    }

    [Fact]
    public async Task AnUnknownTemplate_AndOneNotAllowed_GetByteIdenticalAnswers_WithNothingRunAndNoUnlock()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("echo t") + ", " + TemplateJson("echo hidden", name: "hidden")));

        var unknown = await PostAsync("lane1", "/_template/nope", Args());
        var notAllowed = await PostAsync("lane1", "/_template/hidden", Args());
        var wrongMethod = await PostAsync("lane1", "/_template/t", Args(), method: "PUT");
        var routeNotFound = await _h.GetAsync("lane1", "/nope/x");

        Assert.Equal(404, BrokerHarness.StatusOf(unknown));
        Assert.Equal(unknown, notAllowed);
        Assert.Equal(unknown, wrongMethod);
        Assert.Equal(unknown, routeNotFound);
        Assert.False(File.Exists(Ran));
        Assert.Equal(0, _h.Secrets.Unlocks);
    }

    [Fact]
    public async Task ASocketWithNoTemplatesEntry_CanCallNone()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("echo t")));

        var fromOther = await PostAsync("other", "/_template/t", Args());
        var unknown = await PostAsync("other", "/_template/nope", Args());

        Assert.Equal(404, BrokerHarness.StatusOf(fromOther));
        Assert.Equal(unknown, fromOther);
        Assert.False(File.Exists(Ran));
        Assert.Equal(0, _h.Secrets.Unlocks);
        Frames(await PostAsync("lane1", "/_template/t", Args())); // the positive: lane1 lists it
        Assert.True(File.Exists(Ran));
    }

    [Fact]
    public async Task OverTheRateLimit_Is429_WithNothingRunAndNoUnlock_UntilAMinutePasses()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("echo run >> " + Path.Combine(_bed.Out, "count"), extra: ", \"rate\": 2")));

        Frames(await PostAsync("lane1", "/_template/t", Args()));
        Frames(await PostAsync("lane1", "/_template/t", Args()));
        var third = await PostAsync("lane1", "/_template/t", Args());

        Assert.Equal(429, BrokerHarness.StatusOf(third));
        Assert.Equal(2, File.ReadAllLines(Path.Combine(_bed.Out, "count")).Length);
        Assert.Equal(2, _h.Secrets.Unlocks);

        _h.Clock.Advance(TimeSpan.FromSeconds(61));
        Frames(await PostAsync("lane1", "/_template/t", Args()));
        Assert.Equal(3, File.ReadAllLines(Path.Combine(_bed.Out, "count")).Length);
    }

    [Fact]
    public async Task WithTheSandboxUnusable_TheCallIsRefused_Exit125_WithNothingRunAndNoUnlock()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("echo t"), top: $"\"bwrap_path\": {J(Path.Combine(_bed.Root, "no-bwrap"))},"));

        var (exit, _, _, errors) = await CallAsync("t");

        Assert.Equal(125, exit);
        Assert.Contains("503", errors);
        Assert.False(File.Exists(Ran));
        Assert.Equal(0, _h.Secrets.Unlocks);
        await _h.WaitForLogAsync("templates are refused: the sandbox can't run");
        Assert.Contains("reason=sandbox-unavailable", _h.LogText.ToString());
    }

    // ------------------------------------------------------------------ the log

    [Fact]
    public async Task TheLogLine_HasItsFields_AndNoSecret()
    {
        if (!SandboxBed.CanRun(output))
            return;
        await StartAsync(Config(TemplateJson("""echo "$S"; echo "$S" >&2; exit 4""",
            args: """{ "branch": { "pattern": "brief/[a-z\"]+" } }""", argvExtra: ", \"--to={branch}\"")));

        Frames(await PostAsync("lane1", "/_template/t", Args(("branch", "brief/a\"b"))));
        await PostAsync("lane1", "/_template/t", Args(("branch", "nope")));

        var log = _h.LogText.ToString();
        Assert.Contains($"template socket=lane1 uid={BrokerHarness.MyUid} pid={Environment.ProcessId} template=t args=\"branch=brief/a\\\"b\" status=200 exit=4 ended=exit", log);
        Assert.Contains("unlocks=1", log);
        Assert.Matches(@"bytes_in=\d+ bytes_out=\d+ truncated=false unlocks=1 ms=\d+", log);
        Assert.Contains("args=\"branch=nope\" status=400 exit=- ended=- bytes_in=0 bytes_out=0 truncated=false unlocks=0", log);
        Assert.Contains("reason=argument", log);
        Assert.DoesNotContain(Secret, log);
        Assert.DoesNotContain("--to=", log); // argv after substitution is never logged
    }
}

/// <summary>Brief T9 decision 7: one unlock per call, decrypting only the template's own records.</summary>
public class BrokerTemplateVaultReadTests : IDisposable
{
    private readonly FleetMachine _m = new("tplrec") { Tpm = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) };

    public void Dispose() => _m.Dispose();

    [Fact]
    public void ATemplateUsingTwoOfFiftySecrets_DecryptsTwoRecords_InOneUnlock()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", "init", "--tpm", "--no-recovery");
        for (var i = 0; i < 50; i++)
            _m.Ok($"value-{i}\n", "ingest", "s" + i);
        _m.Ok("", "migrate", "--to-records");
        var store = Assert.IsType<RecordVaultStore>(VaultStores.Open(_m.Dir));
        var decrypted = new List<string>();
        store.RecordDecrypted = decrypted.Add;
        var unlocks = 0;
        var hardware = new CountingHardware(new SimulatedHardwareService(HardwareBackend.Tpm, _m.Tpm!), () => unlocks++);
        var source = new VaultBrokerSecretSource(store, new VaultUnlocker(_m.Keys, overrideKey: null, additionalBackends: [hardware]));

        var values = source.ReadMany(["s7", "s31"]);

        Assert.Equal("value-7", Encoding.UTF8.GetString(values["s7"].Value));
        Assert.Equal("value-31", Encoding.UTF8.GetString(values["s31"].Value));
        Assert.Equal(2, decrypted.Count);
        Assert.Equal(2, decrypted.Distinct().Count());
        Assert.Equal(1, unlocks);
        foreach (var v in values.Values)
            v.Dispose();
    }

    [Fact]
    public void AMissingSecret_FailsTheCall_AndZeroesWhatWasRead()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("", "init", "--tpm", "--no-recovery");
        _m.Ok("value-0\n", "ingest", "s0");
        _m.Ok("", "migrate", "--to-records");
        var store = Assert.IsType<RecordVaultStore>(VaultStores.Open(_m.Dir));
        var source = new VaultBrokerSecretSource(store,
            new VaultUnlocker(_m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, _m.Tpm!)]));

        Assert.Throws<BrokerSecretException>(() => source.ReadMany(["s0", "missing"]));
    }

    /// <summary>Counts unlocks of a hardware backend.</summary>
    private sealed class CountingHardware(IHardwareKeyService inner, Action onUnlock) : IHardwareKeyService
    {
        public HardwareBackend Backend => inner.Backend;
        public bool IsSimulated => inner.IsSimulated;
        public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
        {
            onUnlock();
            return inner.Unlock(config, chooseSerial);
        }
    }
}
