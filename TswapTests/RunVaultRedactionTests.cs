using System.Text;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S3 T4: <c>run</c> masks every fingerprinted value of the vault in the child's output, not
/// only the ones it substitutes, and warns before and after the child when some records can't be
/// matched (owner decision D1: it keeps working). The fake runner streams through RedactingPty's real
/// <c>StreamRedactor</c> with the matcher <c>run</c> passes.
/// </summary>
public sealed class RunVaultRedactionTests : IDisposable
{
    private static readonly string Fix = ElevatedCommand.For("tswap", "vault reindex");

    private readonly FleetMachine _m = new("run-vault", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly RecordingPty _pty = new();
    private byte[] _key = [];

    public void Dispose() => _m.Dispose();

    private static string Coverage(int n, int m = 0) =>
        $"Warning: {n} record(s) are not fully fingerprinted{(m > 0 ? $", {m} can't be read" : "")}: 'run' masks the secrets " +
        $"it substitutes and the fingerprinted values, not these. Ask the user to run {Fix}.";

    private void RecordVault() => _key = VaultKey(_m, InitRecordVault(_m));

    private FakeConsole _console = new("");

    /// <summary><c>run</c> through the fake runner; stdout and stderr interleaved in one text.</summary>
    private (int Exit, string Text) Run(params string[] args)
    {
        var console = _console = new FakeConsole("") { Interleaved = true };
        string[] command = ["run", .. args];
        var ctx = _m.Context(console, command) with { PtyRunner = () => _pty };
        var exit = CliRunner.Run(ctx, command);
        return (exit, console.OutText);
    }

    private string Output => _pty.Output.ToString();

    // ── other secrets ────────────────────────────────────────────────────────────────

    [Fact]
    public void Run_OtherVaultSecret_Masked()
    {
        RecordVault();
        _m.Ok("token-value-1", "ingest", "token");
        _m.Ok("other-secret-value", "ingest", "other");
        _pty.Child = _ => "log: other-secret-value used\n";

        var (exit, text) = Run("curl", "{{token}}");

        Assert.True(exit == 0, text);
        Assert.Equal("log: [REDACTED: other] used\n", Output);
        Assert.Single(_pty.Options!.Matchers);
        Assert.True(_pty.Options.ReleaseWhenAwaitingInput);
    }

    [Fact]
    public void Run_OtherSecret_Base64AndStripped_Masked()
    {
        RecordVault();
        _m.Ok("token-value-1", "ingest", "token");
        _m.Ok("pass word 42", "ingest", "other");
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("pass word 42"));
        _pty.Child = _ => $"b64={base64} stripped=password42 raw=pass word 42\n";

        Run("curl", "{{token}}");

        Assert.Equal("b64=[REDACTED: other] stripped=[REDACTED: other] raw=[REDACTED: other]\n", Output);
    }

    [Fact]
    public void Run_OtherSecretsPreviousValue_Masked()
    {
        RecordVault();
        _m.Ok("token-value-1", "ingest", "token");
        _m.Ok("old-other-value", "ingest", "other");
        _m.Ok("new-other-value", "ingest", "--rotate", "other");
        _pty.Child = _ => "was old-other-value now new-other-value\n";

        Run("curl", "{{token}}");

        Assert.Equal("was [REDACTED: other:previous] now [REDACTED: other]\n", Output);
    }

    [Fact]
    public void Run_PemSizedOtherSecret_OnlcrAndBase64_Masked()
    {
        RecordVault();
        _m.Ok("token-value-1", "ingest", "token");
        var rng = new Random(3300);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var lines = Enumerable.Range(0, 52).Select(_ => new string([.. Enumerable.Range(0, 62).Select(_ => alphabet[rng.Next(alphabet.Length)])]));
        var pem = "-----BEGIN KEY-----\n" + string.Join("\n", lines) + "\n-----END KEY-----";
        _m.Ok(pem, "ingest", "pem");
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(pem));
        // Through ONLCR in 4096-character chunks; the padding puts the first chunk boundary right after the
        // \r of the PEM's last line break, before its \n, so the occurrence is only complete in the next
        // window and its raw span (3,366 characters) is longer than the value (3,313). Whether
        // MaxMatchLength counts that slack is pinned by MaxRawLength_PemSized_IncludesFoldSlack (here the
        // base64 variant, 4,416 characters, keeps MaxMatchLength above the span either way).
        var lastBreak = pem.Replace("\n", "\r\n").LastIndexOf('\r');
        var pad = new string('.', 4096 - (lastBreak + 1));
        _pty.Onlcr = true;
        _pty.Child = _ => $"{pad}{pem}\nb64: {base64}\n";

        Run("curl", "{{token}}");

        Assert.Equal($"{pad}[REDACTED: pem]\r\nb64: [REDACTED: pem]\r\n", Output);
    }

    // ── coverage warning (D1) ────────────────────────────────────────────────────────

    [Fact]
    public void Run_PartlyFingerprinted_WarnsTwice_RunsAndMasksFingerprinted()
    {
        _key = VaultKey(_m, InitFormatTwoVault(_m));
        _m.Ok("old-format-value", "ingest", "old");
        WriteMarker(_m);
        _m.Ok("token-value-1", "ingest", "token");
        _m.Ok("new-format-value", "ingest", "new");
        _pty.ExitCode = 3;
        _pty.Child = _ => "new-format-value old-format-value\n";
        var warningsWhileChildRuns = -1;
        _pty.During = () => warningsWhileChildRuns = Count(_console.OutText, Coverage(1));

        var (exit, text) = Run("curl", "{{token}}");

        Assert.Equal(3, exit);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal("[REDACTED: new] old-format-value\n", Output); // D1: the format 2 record is not masked
        Assert.Equal(1, warningsWhileChildRuns); // before the child
        Assert.Equal(2, Count(text, Coverage(1))); // and again after it
    }

    [Fact]
    public void Run_UnreadableRecord_InWarning()
    {
        RecordVault();
        _m.Ok("token-value-1", "ingest", "token");
        _m.Ok("broken-value", "ingest", "broken");
        var path = RecordFile(_m, _key, "broken");
        File.WriteAllBytes(path, File.ReadAllBytes(path)[..150]);

        var (exit, text) = Run("curl", "{{token}}");

        Assert.True(exit == 0, text);
        Assert.Contains(Coverage(0, 1), text);
    }

    [Fact]
    public void Run_FullyFingerprinted_NoWarning()
    {
        RecordVault();
        _m.Ok("token-value-1", "ingest", "token");

        var (exit, text) = Run("curl", "{{token}}");

        Assert.Equal(0, exit);
        Assert.DoesNotContain("fingerprinted", text);
        Assert.DoesNotContain("Warning", text);
    }

    [Fact]
    public void Run_ChildFails_WarningStillAfterOutput()
    {
        _key = VaultKey(_m, InitFormatTwoVault(_m));
        _m.Ok("old-format-value", "ingest", "old");
        WriteMarker(_m);
        _m.Ok("token-value-1", "ingest", "token");
        _pty.ExitCode = 7;
        var warningsWhileChildRuns = -1;
        _pty.During = () => warningsWhileChildRuns = Count(_console.OutText, Coverage(1));

        var (exit, text) = Run("curl", "{{token}}");

        Assert.Equal(7, exit);
        Assert.Equal(1, warningsWhileChildRuns);
        Assert.Equal(2, Count(text, Coverage(1)));
    }

    /// <summary>
    /// The older-variant note (unreachable at variant set 1, so built by hand): printed with the coverage
    /// warning, and on its own when the vault is otherwise fully fingerprinted.
    /// </summary>
    [Fact]
    public void RunCoverage_OlderVariantSet_Noted()
    {
        var note = $"Note: 2 record(s) were fingerprinted by an older tswap and are matched with the fingerprints they have; " +
                   $"{Fix} adds the newer variants.";
        var alone = new StringWriter();
        RunCoverage.Warn(alone, "tswap", new VaultMetadata([], 0, 2, []));
        Assert.Equal(note + Environment.NewLine, alone.ToString());

        var both = new StringWriter();
        RunCoverage.Warn(both, "tswap", new VaultMetadata([], 1, 2, ["f00d"]));
        Assert.Equal(Coverage(1, 1) + Environment.NewLine + note + Environment.NewLine, both.ToString());

        var neither = new StringWriter();
        RunCoverage.Warn(neither, "tswap", new VaultMetadata([], 0, 0, []));
        Assert.Equal("", neither.ToString());
    }

    // ── pinned gaps ──────────────────────────────────────────────────────────────────

    /// <summary>A pinned gap: base64url is stored unpadded, so padded base64url shows its "=".</summary>
    [Fact]
    public void Run_OtherSecretBase64UrlPadded_CoreMasked_PaddingShown()
    {
        RecordVault();
        _m.Ok("token-value-1", "ingest", "token");
        const string value = "ÿÿx"; // UTF-8 c3 bf c3 bf 78: base64 "w7/Dv3g=", base64url "w7_Dv3g"
        _m.Ok(value, "ingest", "binary");
        _pty.Child = _ => "url=w7_Dv3g= end\n";

        Run("curl", "{{token}}");

        Assert.Equal("url=[REDACTED: binary]= end\n", Output);
    }

    [Fact]
    public void Run_SecretAddedDuringChild_NotMasked()
    {
        RecordVault();
        _m.Ok("token-value-1", "ingest", "token");
        _pty.During = () => _m.Ok("added-while-running", "ingest", "late");
        _pty.Child = _ => "late: added-while-running\n";

        Run("curl", "{{token}}");

        Assert.Equal("late: added-while-running\n", Output);
    }

    // ── overlaps ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Run_NestedAndOverlappingTokenValues_FullyMasked()
    {
        RecordVault();
        _m.Ok("inner-123", "ingest", "a");
        _m.Ok("outer-inner-123-outer", "ingest", "b");
        _m.Ok("left-overlap", "ingest", "c");
        _m.Ok("overlap-right", "ingest", "d");
        _pty.Child = _ => "1 outer-inner-123-outer 2 left-overlap-right 3\n";

        Run("curl", "{{a}}", "{{b}}", "{{c}}", "{{d}}");

        Assert.Equal("1 [REDACTED: b] 2 [REDACTED: d] 3\n", Output);
    }

    [Fact]
    public void Run_ChainedOverlappingSecrets_FullyMasked()
    {
        RecordVault();
        _m.Ok("chain-one-", "ingest", "x");      // substituted
        _m.Ok("-one-two-", "ingest", "y");       // fingerprint only
        _m.Ok("-two-three", "ingest", "z");      // fingerprint only
        _pty.Child = _ => "[chain-one-two-three]\n";

        Run("curl", "{{x}}");

        // One run over all three; x and z are the longest (10), x the leftmost.
        Assert.Equal("[[REDACTED: x]]\n", Output);
    }

    // ── failure ──────────────────────────────────────────────────────────────────────

    /// <summary>A runner whose redaction fails as RedactingPty's do: the marker, then the exception after the child.</summary>
    private sealed class FailingPty : RedactingPty.IPtyRunner
    {
        public StringBuilder Output { get; } = new();

        public int Run(string[] argv, IReadOnlyList<RedactingPty.StreamReplacement> replacements) => throw new NotSupportedException();

        public int Run(string[] argv, IReadOnlyList<RedactingPty.StreamReplacement> replacements, RedactingPty.RedactionOptions options)
        {
            var redactor = new RedactingPty.StreamRedactor(replacements, options.Matchers);
            Output.Append(redactor.ProcessChunk("first chunk of child output\n"));
            Output.Append("[output truncated: redaction failed]\n");
            throw new InvalidOperationException("Redaction failed: a matcher reported a match at 3 of length 9000 in a window of 40 characters.");
        }
    }

    /// <summary>
    /// When the redaction fails (the runner rethrows after the child), the warnings that follow the child
    /// still come, before the error: the coverage warning a second time and the format 2 line.
    /// </summary>
    [Fact]
    public void Run_MatcherFailure_WarningsAfterTheChildStillPrinted()
    {
        _key = VaultKey(_m, InitFormatTwoVault(_m));
        _m.Ok("old-format-value", "ingest", "old");
        WriteMarker(_m);
        var console = new FakeConsole("") { Interleaved = true };
        string[] command = ["run", "curl", "{{old}}"];
        var ctx = _m.Context(console, command) with { PtyRunner = () => new FailingPty() };

        var exit = CliRunner.Run(ctx, command);

        var text = console.OutText;
        Assert.NotEqual(0, exit);
        Assert.Equal(2, Count(text, Coverage(1)));
        var formatTwo = $"Warning: 1 of the records used here are stored in the old record format 2, which tswap can only decrypt " +
                        $"whole; the value versions not used were wiped. Ask the user to run {Fix} once to convert the vault.";
        Assert.Equal(1, Count(text, formatTwo));
        var error = text.IndexOf("Redaction failed", StringComparison.Ordinal);
        Assert.True(error > text.LastIndexOf(Coverage(1), StringComparison.Ordinal) && error > text.IndexOf(formatTwo, StringComparison.Ordinal), text);
    }

    [Fact]
    public void Run_MatcherFailure_ExitsNonZero_MessageClean()
    {
        RecordVault();
        _m.Ok("token-value-1", "ingest", "token");
        var failing = new FailingPty();
        var console = new FakeConsole("");
        string[] command = ["run", "curl", "{{token}}"];
        var ctx = _m.Context(console, command) with { PtyRunner = () => failing };

        var exit = CliRunner.Run(ctx, command);

        Assert.NotEqual(0, exit);
        Assert.Contains("Redaction failed", console.ErrorText);
        Assert.DoesNotContain("child output", console.ErrorText);
        Assert.DoesNotContain("token-value-1", console.ErrorText + console.OutText);
    }

    private static int Count(string text, string value)
    {
        var count = 0;
        for (var i = text.IndexOf(value, StringComparison.Ordinal); i >= 0; i = text.IndexOf(value, i + value.Length, StringComparison.Ordinal))
            count++;
        return count;
    }
}
