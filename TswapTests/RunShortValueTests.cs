using System.Text.Json;
using TswapCli;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T30 (#314): <c>run</c> masks a value shorter than 8 characters only where it stands as a whole word
/// or number, for the vault's fingerprinted values and for its own substituted, <c>--env</c> and file values
/// (all their written forms); longer values anywhere. <see cref="RecordingPty"/> streams the child's output
/// through the real <c>StreamRedactor</c>, as <see cref="RunVaultRedactionTests"/> does.
/// </summary>
public sealed class RunShortValueTests : IDisposable
{
    private readonly FleetMachine _m = new("run-short", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();
    private FilledFilesEnvironment? _files;

    public RunShortValueTests()
    {
        InitRecordVault(_m);
        _m.Ok("token-value-1", "ingest", "token");
    }

    public void Dispose() => _m.Dispose();

    private (int Exit, string Text) Run(params string[] args)
    {
        var console = new FakeConsole("") { Interleaved = true };
        string[] command = ["run", .. args];
        var ctx = _m.Context(console, command) with { PtyRunner = () => _pty, FilledFilesEnvironment = _files };
        var exit = CliRunner.Run(ctx, command);
        return (exit, console.OutText);
    }

    private string Output => _pty.Output.ToString();

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(4096)]
    public void Run_VaultShortValue_InsideNumbers_OutputUnchangedAndParses(int chunkSize)
    {
        _m.Ok("465", "ingest", "k8s-mail-email-port");
        const string json = "{\"in\":65465,\"out\":1465,\"sum\":4650}\n";
        _pty.ChunkSize = chunkSize;
        _pty.Child = _ => json;

        var (exit, text) = Run("curl", "{{token}}");

        Assert.True(exit == 0, text);
        Assert.Equal(json, Output);
        using (JsonDocument.Parse(Output)) { }
    }

    [Fact]
    public void Run_VaultShortValue_Delimited_Masked()
    {
        _m.Ok("465", "ingest", "k8s-mail-email-port");
        _pty.Child = _ => "smtp: 465\nurl=mail:465/\n\"465\"\n";

        Run("curl", "{{token}}");

        const string label = "[REDACTED: k8s-mail-email-port]";
        Assert.Equal($"smtp: {label}\nurl=mail:{label}/\n\"{label}\"\n", Output);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4096)]
    public void Run_ShortToken_WholeTokenOnly(int chunkSize)
    {
        _m.Ok("web", "ingest", "user");
        _pty.ChunkSize = chunkSize;
        _pty.Child = _ => "web-ngx /home/webster user=web b64=d2Vi\n";

        Run("curl", "{{user}}");

        Assert.Equal("web-ngx /home/webster user=[REDACTED: user] b64=[REDACTED: user]\n", Output);
    }

    [Fact]
    public void Run_LongToken_InsideWord_StillMasked()
    {
        _pty.Child = _ => "xtoken-value-1x\n";

        Run("curl", "{{token}}");

        Assert.Equal("x[REDACTED: token]x\n", Output);
    }

    [Fact]
    public void Run_ShortEnvValue_WholeTokenOnly()
    {
        _m.Ok("4711", "ingest", "pin");
        _pty.Child = _ => "pin 4711 and 147110\n";

        var (exit, text) = Run("--env", "PIN={{pin}}", "curl", "x");

        Assert.True(exit == 0, text);
        Assert.Equal("pin [REDACTED: pin] and 147110\n", Output);
    }

    [Fact]
    public void RunFileToken_ShortValue_WholeTokenOnly()
    {
        _m.Ok("a\"b", "ingest", "q");
        var work = _m.PathOf("work");
        var xdg = _m.PathOf("xdg");
        Directory.CreateDirectory(work);
        Directory.CreateDirectory(xdg);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(xdg, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        _files = FilledFilesEnvironment.FromSystem() with
        {
            XdgRuntimeDir = xdg,
            TempRoot = _m.PathOf("tmp"),
            CurrentDirectory = work,
            RegisterSignals = _ => new NoSignals(),
            SignalChildren = _ => 0,
        };
        File.WriteAllText(Path.Combine(work, "values.yaml"), "p: \"\"  # tswap: q\n");
        string? filled = null;
        _pty.Child = argv =>
        {
            filled = File.ReadAllText(argv[^1]);
            return filled + "glued: za\"bz\n";
        };

        var (exit, text) = Run("helm", "upgrade", "app", "./chart", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, text);
        Assert.Contains("a\\\"b", filled); // the escaped form was written inside the quotes
        Assert.Contains("p: \"[REDACTED: q]\"", Output);
        Assert.Contains("glued: za\"bz\n", Output);
        Assert.DoesNotContain("a\\\"b", Output);
    }

    private sealed class NoSignals : IDisposable
    {
        public void Dispose() { }
    }
}
