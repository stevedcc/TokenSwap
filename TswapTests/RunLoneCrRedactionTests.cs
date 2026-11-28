using TswapCli;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T65 (#434): <c>run</c> masks a multi-line value the child prints with lone <c>\r</c> line breaks, another
/// vault value (through the fingerprint matcher) and its own substituted one alike. The fake runner streams through
/// RedactingPty's real <c>StreamRedactor</c> with the matchers <c>run</c> passes (as <see cref="RunVaultRedactionTests"/>).
/// </summary>
public sealed class RunLoneCrRedactionTests : IDisposable
{
    private readonly FleetMachine _m = new("run-lone-cr", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();

    public RunLoneCrRedactionTests() => VaultKey(_m, InitRecordVault(_m));

    public void Dispose() => _m.Dispose();

    /// <summary><c>run</c> through the fake runner; stdout and stderr interleaved in one text.</summary>
    private (int Exit, string Text) Run(params string[] args)
    {
        var console = new FakeConsole("") { Interleaved = true };
        string[] command = ["run", .. args];
        var ctx = _m.Context(console, command) with { PtyRunner = () => _pty };
        var exit = CliRunner.Run(ctx, command);
        return (exit, console.OutText);
    }

    private string Output => _pty.Output.ToString();

    private void Vault()
    {
        _m.Ok("token-value-1", "ingest", "token");
        _m.Ok(LoneCrRedactionTests.V2("\n"), "ingest", "other");
        _pty.Child = _ => "log: " + LoneCrRedactionTests.V2("\r") + "\n";
    }

    [Fact]
    public void Run_AnotherVaultValue_PrintedWithLoneCrs_Masked()
    {
        Vault();

        var (exit, text) = Run("curl", "{{token}}");

        Assert.True(exit == 0, text);
        Assert.Equal("log: [REDACTED: other]\n", Output);
    }

    [Fact]
    public void Run_ItsOwnValue_PrintedWithLoneCrs_Masked()
    {
        Vault();

        var (exit, text) = Run("curl", "{{other}}");

        Assert.True(exit == 0, text);
        Assert.Equal("log: [REDACTED: other]\n", Output);
    }
}
