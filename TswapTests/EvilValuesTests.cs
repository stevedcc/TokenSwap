using TswapCli;
using TswapCore;
using TswapCore.Vault;
using Xunit;
using Xunit.Abstractions;
using static TswapTests.EvilValues;

namespace TswapTests;

/// <summary>
/// Brief T46 (#392): every <see cref="EvilValues"/> case through the commands that store, substitute or mask a value,
/// in process with <see cref="CommandTests"/>' set-up (a fresh vault per test, the test key, <c>SudoBypass</c>) and
/// <see cref="RecordingPty"/> for <c>run</c>'s child. Each theory is one invariant; a case tswap fails is a finding
/// (<see cref="EvilValues.KnownFindings"/>) with its own skipped fact, never a weaker assertion. Failure messages name
/// the case and a position, never the value.
/// </summary>
public sealed class EvilValuesTests : IDisposable
{
    /// <summary>The secret every case is stored under (A11: no case's value or window is in it).</summary>
    private const string Name = "name";
    private const string Label = "[REDACTED: name]";

    private readonly string _tempDir;
    private readonly string _configDir;
    private readonly string _work;
    private readonly string _filesRoot;
    private readonly byte[] _testKey =
        Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
    private readonly ITestOutputHelper _output;

    public EvilValuesTests(ITestOutputHelper output)
    {
        _output = output;
        _tempDir = Path.Combine(Path.GetTempPath(), "tswap-evil-test-" + Guid.NewGuid().ToString("N")[..8]);
        _configDir = Path.Combine(_tempDir, "config");
        _work = Path.Combine(_tempDir, "work");
        _filesRoot = Path.Combine(_tempDir, "tmp");
        foreach (var dir in new[] { _configDir, _work, _filesRoot })
            Directory.CreateDirectory(dir);

        Assert.Equal(0, Execute("", ["init", "--yubikey"]).Exit);
        var other = Execute(OtherSecretValue, ["ingest", OtherSecretName]);
        Assert.True(other.Exit == 0, other.Err);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private sealed class Nothing : IDisposable
    {
        public void Dispose() { }
    }

    /// <summary>One tswap invocation, as <see cref="CommandTests"/> runs it, with <paramref name="pty"/> as run's runner.</summary>
    private (int Exit, string Out, string Err) Execute(string stdin, string[] args, RecordingPty? pty = null, string? configDir = null)
    {
        configDir ??= _configDir;
        var console = new FakeConsole(stdin);
        var (verbose, commandArgs) = CliEnvironment.SplitGlobalFlags(args);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = configDir, Verbose = verbose, CommandArgs = commandArgs };
        var storage = VaultStores.Open(configDir, warnings: console.Error);
        var yubiKeys = new TestKeyYubiKeyService(_testKey);
        var unlocker = new VaultUnlocker(yubiKeys, overrideKey: _testKey);
        var ctx = new CommandContext(console, env, storage, yubiKeys, unlocker, _testKey, SudoBypass: true)
        {
            PtyRunner = () => pty ?? throw new InvalidOperationException("this invocation starts no child"),
            FilledFilesEnvironment = FilledFilesEnvironment.FromSystem() with
            {
                XdgRuntimeDir = null,
                TempRoot = _filesRoot,
                CurrentDirectory = _work,
                RegisterSignals = _ => new Nothing(),
            },
        };
        var exit = CliRunner.Run(ctx, env.CommandArgs);
        return (exit, console.OutText, console.ErrorText);
    }

    /// <summary>The value as ingest stores it: its documented trailing-whitespace trim (ReadBoundedStdin, A3).</summary>
    private static string Stored(string value) => value.TrimEnd();

    private static bool IsShort(string value) => value.Length < Validation.ShortValueLength;

    private void IngestCase(string caseName, string value, string? configDir = null)
    {
        var (exit, _, err) = Execute(value, ["ingest", Name], configDir: configDir);
        Assert.True(exit == 0, $"{caseName}: ingest failed: {err}");
    }

    /// <summary><c>get</c>'s value: its stdout without the one line ending it writes.</summary>
    private string GetValue(string caseName, string name = Name, string? configDir = null)
    {
        var (exit, stdout, err) = Execute("", ["get", name], configDir: configDir);
        Assert.True(exit == 0, $"{caseName}: get failed: {err}");
        Assert.True(stdout.EndsWith(Environment.NewLine, StringComparison.Ordinal), $"{caseName}: get's output doesn't end in a line ending");
        return stdout[..^Environment.NewLine.Length];
    }

    /// <summary>
    /// Every text tswap or the child produced, for every case: no unpaired surrogate (A5); for a value of 8 or more
    /// characters, neither the value nor any 8-code-point window of it.
    /// </summary>
    private static void AssertNoValueIn(string caseName, string stored, string where, string text)
    {
        var lone = UnpairedSurrogate(text);
        Assert.True(lone < 0, $"{caseName}: an unpaired surrogate at index {lone} of {where}");
        if (IsShort(stored))
            return;
        Assert.False(text.Contains(stored, StringComparison.Ordinal), $"{caseName}: the value appears in {where}");
        var window = FirstWindowOf(stored, text);
        Assert.True(window < 0, $"{caseName}: an 8-code-point window of the value appears at index {window} of {where}");
    }

    /// <summary>What the child prints: the value inside a line, and for a short value the T30 pair (alone, inside a word).</summary>
    private static string ChildLines(string value) =>
        IsShort(value) ? $"before {value} after\n{value}\n{value}ylophone\n" : $"before {value} after\n";

    /// <summary>Invariant 4 on the child's (redacted) output.</summary>
    private static void AssertMasked(string caseName, string stored, string output)
    {
        if (IsShort(stored))
        {
            // T30: the short value is masked where it stands alone, and left inside a word.
            Assert.True($"before {Label} after\n{Label}\n{stored}ylophone\n" == output,
                $"{caseName}: the short value's whole-word masking differs ({output.Length} chars of output)");
            return;
        }
        Assert.True(output.Contains(Label, StringComparison.Ordinal), $"{caseName}: '{Label}' missing from the child's output");
        AssertNoValueIn(caseName, stored, "the child's output", output);
    }

    // ── Task 1, invariant 1: stored exactly (after the documented trailing-whitespace trim) ─────────────────

    public static TheoryData<string> StoredExactlyCases => CasesFor(StoredExactly);

    [Theory, MemberData(nameof(StoredExactlyCases))]
    public void StoredExactly_IngestThenGet(string caseName) => CheckStoredExactly(caseName);

    private void CheckStoredExactly(string caseName)
    {
        var value = EvilValues.Get(caseName).Value;

        IngestCase(caseName, value);

        Assert.True(Stored(value) == GetValue(caseName), $"{caseName}: get doesn't return the ingested value (after TrimEnd)");
    }

    [Fact]
    public void StoredExactly_OneCharacterOverTheMaximum_Refused()
    {
        var (exit, _, err) = Execute(LongValue(MaxLength + 1), ["ingest", Name]);

        Assert.Equal(1, exit);
        Assert.Contains($"Secret value is too long. Maximum allowed is {MaxLength} characters.", err);
        Assert.Contains("not found", Execute("", ["get", Name]).Err);
    }

    [Theory]
    [InlineData("spaces", "   ")]
    [InlineData("tab-and-newline", "\t\n")]
    [InlineData("line-separator", "\u2028")]
    public void StoredExactly_WhitespaceOnly_Refused(string inputName, string input)
    {
        var (exit, _, err) = Execute(input, ["ingest", Name]);

        Assert.True(exit == 1, $"{inputName}: exit {exit}");
        Assert.Contains("Empty input received. Nothing to store.", err);
        Assert.Contains("not found", Execute("", ["get", Name]).Err);
    }

    [Fact]
    public void StoredExactly_NulInside_Refused()
    {
        var (exit, _, err) = Execute("abcdefg\0hijklmno", ["ingest", Name]);

        Assert.Equal(1, exit);
        Assert.Contains("Secret value contains a NUL byte (\\0), which cannot be used as a process argument.", err);
        Assert.Contains("not found", Execute("", ["get", Name]).Err);
    }

    // ── Task 1, invariant 2: substituted as one argument ──────────────────────────────────────────────────────

    public static TheoryData<string> OneArgumentCases => CasesFor(OneArgument);

    [Theory, MemberData(nameof(OneArgumentCases))]
    public void OneArgument_RunSubstitutesTheValueAsOneArgvElement(string caseName) => CheckOneArgument(caseName);

    private void CheckOneArgument(string caseName)
    {
        var stored = Stored(EvilValues.Get(caseName).Value);
        IngestCase(caseName, EvilValues.Get(caseName).Value);
        var pty = new RecordingPty();

        var (exit, _, err) = Execute("", ["run", "tool", "{{" + Name + "}}"], pty);

        Assert.True(exit == 0, $"{caseName}: run failed: {err}");
        Assert.Equal(1, pty.Starts);
        var argv = pty.Argv!;
        Assert.True(argv.Length == 2, $"{caseName}: {argv.Length} argv elements, expected 2");
        Assert.Equal("tool", argv[0]);
        Assert.True(argv[1] == stored, $"{caseName}: argv[1] isn't exactly the stored value ({argv[1].Length} chars, expected {stored.Length})");
    }

    // ── Task 1, invariant 2b (A2): run --env ──────────────────────────────────────────────────────────────────

    public static TheoryData<string> EnvExactCases => CasesFor(EnvExact);

    [Theory, MemberData(nameof(EnvExactCases))]
    public void EnvExact_RunEnvSetsExactlyTheValue_NotInArgv_Masked(string caseName) => CheckEnvExact(caseName);

    private void CheckEnvExact(string caseName)
    {
        var stored = Stored(EvilValues.Get(caseName).Value);
        IngestCase(caseName, EvilValues.Get(caseName).Value);
        var pty = new RecordingPty();
        pty.Child = _ => ChildLines(pty.Options!.Environment!["X"]);

        var (exit, stdout, err) = Execute("", ["run", "--env", "X={{" + Name + "}}", "tool"], pty);

        Assert.True(exit == 0, $"{caseName}: run failed: {err}");
        var environment = pty.Options!.Environment!;
        Assert.Equal(new[] { "X" }, environment.Keys.ToArray());
        Assert.True(environment["X"] == stored, $"{caseName}: X isn't exactly the stored value");
        // Review fix F3: a failure names the case, never the argv it got (it could hold the value).
        Assert.True(pty.Argv!.SequenceEqual(["tool"]), $"{caseName}: argv isn't exactly [tool]");
        AssertMasked(caseName, stored, pty.Output.ToString());
        AssertNoValueIn(caseName, stored, "run's stdout", stdout);
        AssertNoValueIn(caseName, stored, "run's stderr", err);
    }

    // ── Task 1, invariant 3: never expanded twice ─────────────────────────────────────────────────────────────

    public static TheoryData<string> NoReexpansionCases => CasesFor(NoReexpansion, c => c.Class == TswapSyntax);

    [Theory, MemberData(nameof(NoReexpansionCases))]
    public void NoReexpansion_TswapSyntaxInAValue_IsLiteral(string caseName) => CheckNoReexpansion(caseName);

    private void CheckNoReexpansion(string caseName)
    {
        var stored = Stored(EvilValues.Get(caseName).Value);
        IngestCase(caseName, EvilValues.Get(caseName).Value);
        // The file a re-expanded {{@file.yaml}} would name exists, with a marker for the other secret.
        File.WriteAllText(Path.Combine(_work, "file.yaml"), $"key: \"\"  # tswap: {OtherSecretName}\n");
        var pty = new RecordingPty();

        var (exit, _, err) = Execute("", ["run", "tool", "{{" + Name + "}}"], pty);

        Assert.True(exit == 0, $"{caseName}: run failed: {err}");
        Assert.True(pty.Argv is ["tool", var literal] && literal == stored, $"{caseName}: argv isn't [tool, the literal value]");
        Assert.All(pty.Argv!, word => Assert.DoesNotContain(OtherSecretValue, word));
        Assert.All(pty.Argv!, word => Assert.DoesNotContain(_filesRoot, word));
        Assert.Empty(Directory.EnumerateFileSystemEntries(_filesRoot));
    }

    // ── Task 1, invariant 4: masked in the child's output ─────────────────────────────────────────────────────

    public static TheoryData<string> MaskedOutputCases => CasesFor(MaskedOutput);

    [Theory, MemberData(nameof(MaskedOutputCases))]
    public void MaskedOutput_ChildPrintsTheValue_Masked(string caseName) => CheckMaskedOutput(caseName);

    private void CheckMaskedOutput(string caseName)
    {
        var stored = Stored(EvilValues.Get(caseName).Value);
        IngestCase(caseName, EvilValues.Get(caseName).Value);

        MaskedRun(caseName, stored, new RecordingPty());

        // A5: a value holding a surrogate pair runs again with the pair split across two chunks.
        var pair = Enumerable.Range(0, stored.Length - 1).FirstOrDefault(i => char.IsSurrogatePair(stored, i), -1);
        if (pair >= 0)
        {
            var split = new RecordingPty { ChunkSize = "before ".Length + pair + 1 };
            MaskedRun(caseName + " (pair split across chunks)", stored, split);
            Assert.True(split.Pieces.Count > 2, $"{caseName}: the output wasn't streamed in several chunks");
        }
    }

    private void MaskedRun(string caseName, string stored, RecordingPty pty)
    {
        pty.Child = _ => ChildLines(stored);

        var (exit, stdout, err) = Execute("", ["run", "tool", "{{" + Name + "}}"], pty);

        Assert.True(exit == 0, $"{caseName}: run failed: {err}");
        AssertMasked(caseName, stored, pty.Output.ToString());
        foreach (var (piece, i) in pty.Pieces.Select((p, i) => (p, i)))
            Assert.True(UnpairedSurrogate(piece) < 0, $"{caseName}: chunk {i} of the redacted output ends or starts inside a surrogate pair");
        AssertNoValueIn(caseName, stored, "run's stdout", stdout);
        AssertNoValueIn(caseName, stored, "run's stderr", err);
    }

    // ── Task 1 (A2, A15): ingest --rotate, then {{name:previous}} ─────────────────────────────────────────────

    public static TheoryData<string> RotatePreviousCases => CasesFor(RotatePrevious);

    [Theory, MemberData(nameof(RotatePreviousCases))]
    public void RotatePrevious_PreviousSubstitutesTheCaseValue(string caseName) => CheckRotatePrevious(caseName);

    private void CheckRotatePrevious(string caseName)
    {
        var stored = Stored(EvilValues.Get(caseName).Value);
        IngestCase(caseName, EvilValues.Get(caseName).Value);
        var (rotateExit, _, rotateErr) = Execute(RotatedSibling, ["ingest", "--rotate", Name]);
        Assert.True(rotateExit == 0, $"{caseName}: ingest --rotate failed: {rotateErr}");
        var pty = new RecordingPty();

        var (exit, _, err) = Execute("", ["run", "tool", "{{" + Name + ":previous}}"], pty);

        Assert.True(exit == 0, $"{caseName}: run failed: {err}");
        Assert.True(pty.Argv is ["tool", var previous] && previous == stored, $"{caseName}: {{{{name:previous}}}} isn't exactly the case value");
        Assert.True(GetValue(caseName) == RotatedSibling, $"{caseName}: get doesn't return the rotated sibling value"); // F3
    }

    /// <summary>A11: the first of <paramref name="candidates"/> that holds no part of <paramref name="value"/>.</summary>
    private static string FileNameFor(string caseName, string value, params string[] candidates)
    {
        var name = candidates.FirstOrDefault(c => NameIsSafeFor(c, value));
        Assert.True(name is not null, $"{caseName}: no candidate file name is safe for this value (A11)");
        return name!;
    }

    /// <summary>The lines a masking command reads: the value inside a line, and for a short value the T30 pair.</summary>
    private static string FileLines(string stored) =>
        IsShort(stored) ? $"token: {stored}\nother: {stored}ylophone\n" : $"token: {stored}\n";

    // ── Task 2, invariant 1: the {{@file}} fill ─────────────────────────────────────────────────────────────────

    public static TheoryData<string> FillRoundtripCases => CasesFor(FillRoundtrip);

    [Theory, MemberData(nameof(FillRoundtripCases))]
    public void FillRoundtrip_FilledCopyDecodesToTheStoredValue(string caseName) => CheckFillRoundtrip(caseName);

    private void CheckFillRoundtrip(string caseName)
    {
        var stored = Stored(EvilValues.Get(caseName).Value);
        IngestCase(caseName, EvilValues.Get(caseName).Value);
        var file = FileNameFor(caseName, stored, "file.yaml", "values.yml");
        File.WriteAllText(Path.Combine(_work, file), $"key: \"\"  # tswap: {Name}\n");
        string? copy = null;
        var pty = new RecordingPty();
        pty.Child = argv =>
        {
            copy = File.ReadAllText(argv[1]);
            return "";
        };

        var (exit, stdout, err) = Execute("", ["run", "tool", "{{@" + file + "}}"], pty);

        Assert.True(exit == 0, $"{caseName}: run failed: {err}");
        Assert.True(pty.Argv is ["tool", _], $"{caseName}: argv isn't [tool, the copy's path]");
        Assert.True(copy is not null, $"{caseName}: the child never read the filled copy");
        // Review fix F4: against the value this test stored, not get's.
        Assert.True(DecodeFilledLine(caseName, copy!) == stored, $"{caseName}: the filled copy decodes to another value than the stored one");
        AssertNoValueIn(caseName, stored, "run's stdout", stdout);
        AssertNoValueIn(caseName, stored, "run's stderr", err);
    }

    /// <summary>
    /// A14: the value of the filled line <c>key: "…"  # tswap: name</c>, decoded by the escapes docs/security-model.md
    /// documents for a double-quoted value ("Files with secrets": <c>\\</c>, <c>\"</c>, <c>\n</c>, <c>\r</c>,
    /// <c>\t</c>, <c>\uXXXX</c>). An unescaped quote, any other escape or a raw control character (one the doc says is
    /// escaped) fails, naming the position.
    /// </summary>
    private static string DecodeFilledLine(string caseName, string copy)
    {
        const string prefix = "key: \"";
        var suffix = $"\"  # tswap: {Name}\n";
        Assert.True(copy.StartsWith(prefix, StringComparison.Ordinal), $"{caseName}: the filled line doesn't start with the key and a double quote");
        Assert.True(copy.EndsWith(suffix, StringComparison.Ordinal), $"{caseName}: the filled line doesn't end with a double quote and the marker");
        var body = copy[prefix.Length..^suffix.Length];
        var decoded = new System.Text.StringBuilder(body.Length);
        for (var i = 0; i < body.Length; i++)
        {
            var c = body[i];
            if (c == '"')
                Assert.Fail($"{caseName}: an unescaped double quote at index {i} of the scalar");
            if (c < ' ' || c is >= '\u007F' and <= '\u009F' or '\u2028' or '\u2029')
                Assert.Fail($"{caseName}: a raw control character U+{(int)c:X4} at index {i} of the scalar");
            if (c != '\\')
            {
                decoded.Append(c);
                continue;
            }
            Assert.True(i + 1 < body.Length, $"{caseName}: the scalar ends in a lone backslash");
            var escape = body[++i];
            switch (escape)
            {
                case '\\': decoded.Append('\\'); break;
                case '"': decoded.Append('"'); break;
                case 'n': decoded.Append('\n'); break;
                case 'r': decoded.Append('\r'); break;
                case 't': decoded.Append('\t'); break;
                case 'u':
                    Assert.True(i + 4 < body.Length
                        && int.TryParse(body.AsSpan(i + 1, 4), System.Globalization.NumberStyles.AllowHexSpecifier, null, out _),
                        $"{caseName}: a \\u escape without four hex digits at index {i}");
                    decoded.Append((char)int.Parse(body.AsSpan(i + 1, 4), System.Globalization.NumberStyles.AllowHexSpecifier));
                    i += 4;
                    break;
                default:
                    Assert.Fail($"{caseName}: an undocumented escape '\\{escape}' at index {i - 1} of the scalar");
                    break;
            }
        }
        return decoded.ToString();
    }

    // ── Task 2, invariant 2: redact ────────────────────────────────────────────────────────────────────────────

    public static TheoryData<string> RedactMasksCases => CasesFor(RedactMasks);

    [Theory, MemberData(nameof(RedactMasksCases))]
    public void RedactMasks_ValueInsideALine_Masked(string caseName) => CheckRedactMasks(caseName);

    private void CheckRedactMasks(string caseName)
    {
        var stored = Stored(EvilValues.Get(caseName).Value);
        IngestCase(caseName, EvilValues.Get(caseName).Value);
        var path = Path.Combine(_work, FileNameFor(caseName, stored, "redact.txt", "masked.log"));
        File.WriteAllText(path, FileLines(stored));

        var (exit, stdout, err) = Execute("", ["redact", path]);

        Assert.True(exit == 0, $"{caseName}: redact failed: {err}");
        if (IsShort(stored))
            Assert.True(stdout == $"token: {Label}\nother: {stored}ylophone\n",
                $"{caseName}: the short value's whole-word masking differs ({stdout.Length} chars of output)");
        Assert.True(stdout.Contains(Label, StringComparison.Ordinal), $"{caseName}: '{Label}' missing from redact's output");
        AssertNoValueIn(caseName, stored, "redact's stdout", stdout);
        AssertNoValueIn(caseName, stored, "redact's stderr", err);
    }

    // ── Task 2, invariant 3: tocomment --dry-run ───────────────────────────────────────────────────────────────

    public static TheoryData<string> TocommentDryrunCases => CasesFor(TocommentDryrun);

    [Theory, MemberData(nameof(TocommentDryrunCases))]
    public void TocommentDryrun_NamesTheSecret_PrintsNoValue(string caseName) => CheckTocommentDryrun(caseName);

    private void CheckTocommentDryrun(string caseName)
    {
        var stored = Stored(EvilValues.Get(caseName).Value);
        IngestCase(caseName, EvilValues.Get(caseName).Value);
        var path = Path.Combine(_work, FileNameFor(caseName, stored, "tocomment.txt", "config.txt"));
        var content = FileLines(stored);
        File.WriteAllText(path, content);

        var (exit, stdout, err) = Execute("", ["tocomment", path, "--dry-run"]);

        Assert.True(exit == 0, $"{caseName}: tocomment failed: {err.Length} chars of stderr");
        Assert.True(err.Contains($"  + token: \"\"  # tswap: {Name}", StringComparison.Ordinal), $"{caseName}: the change doesn't replace the value with '# tswap: {Name}'");
        Assert.False(err.Contains($"# tswap: {OtherSecretName}", StringComparison.Ordinal), $"{caseName}: the change names {OtherSecretName}");
        // Only the line with the value; for a short value, not the line where it is inside a word (T30, A4).
        Assert.True(err.Contains("(dry run) 1 line(s) would be modified.", StringComparison.Ordinal), $"{caseName}: not exactly one line would be modified");
        Assert.True(File.ReadAllText(path) == content, $"{caseName}: --dry-run changed the file");
        AssertNoValueIn(caseName, stored, "tocomment's stdout", stdout);
        // tocomment prints its replacement, '""  # tswap: name', by design; for a value that is itself marker syntax
        // ('# tswap: other-secret') that text holds an 8-code-point window of the value without being a fragment of it.
        AssertNoValueIn(caseName, stored, "tocomment's stderr (its replacements left out)", err.Replace(TocommentReplacement, ""));
    }

    /// <summary>What tocomment puts in place of the value (ToCommentProcessor.Replacement).</summary>
    private const string TocommentReplacement = "\"\"  # tswap: " + Name;

    // Findings (A1): each pair is left out of its theory by KnownFindings; the full assertion is here, skipped.

    [Fact(Skip = "T46 finding 1: redact turns the file's CRLF into LF before matching, so a value holding CRLF is not masked")]
    public void Finding1_CrlfInside_RedactMasks() => CheckRedactMasks("crlf-inside");

    [Fact(Skip = "T46 finding 2: tocomment matches line by line, so a value holding a line break inside a line is not found")]
    public void Finding2_LfInside_TocommentDryrun() => CheckTocommentDryrun("lf-inside");

    [Fact(Skip = "T46 finding 2: tocomment matches line by line, so a value holding a line break inside a line is not found")]
    public void Finding2_CrlfInside_TocommentDryrun() => CheckTocommentDryrun("crlf-inside");

    // ── Task 2, invariant 4: export, then import into a fresh vault ────────────────────────────────────────────

    public static TheoryData<string> ExportImportCases => CasesFor(ExportImport);

    [Theory, MemberData(nameof(ExportImportCases))]
    public void ExportImport_IntoAFreshVault_GetReturnsTheValue(string caseName) => CheckExportImport(caseName);

    private void CheckExportImport(string caseName)
    {
        var stored = Stored(EvilValues.Get(caseName).Value);
        IngestCase(caseName, EvilValues.Get(caseName).Value);
        var export = Path.Combine(_tempDir, FileNameFor(caseName, stored, "backup.json", "archive.json"));
        var (exportExit, _, exportErr) = Execute("pass\npass\n", ["export", export]);
        Assert.True(exportExit == 0, $"{caseName}: export failed: {exportErr}");
        var fresh = Path.Combine(_tempDir, "fresh");
        Directory.CreateDirectory(fresh);
        Assert.Equal(0, Execute("", ["init", "--yubikey"], configDir: fresh).Exit);

        var (importExit, _, importErr) = Execute("pass\n", ["import", export], configDir: fresh);

        Assert.True(importExit == 0, $"{caseName}: import failed: {importErr}");
        Assert.True(GetValue(caseName, configDir: fresh) == stored, $"{caseName}: get after import doesn't return the stored value");
    }

    // ── Task 2: NFD, an owner decision (#392); nothing asserted about the NFD form's masking ────────────────────

    private static string NfdLine(string output) => output.Split('\n')[1];

    [Fact]
    public void Nfd_InRunOutput_RecordedForTheOwner()
    {
        var nfc = EvilValues.Get("nfc-e-acute").Value;
        var nfd = nfc.Normalize(System.Text.NormalizationForm.FormD);
        Assert.NotEqual(nfc, nfd);
        IngestCase("nfc-e-acute", nfc);
        var pty = new RecordingPty { Child = _ => $"nfc {nfc} end\nnfd {nfd} end\n" };

        var (exit, _, err) = Execute("", ["run", "tool", "{{" + Name + "}}"], pty);

        Assert.True(exit == 0, err);
        var output = pty.Output.ToString();
        // The stored (NFC) form is masked. F3: Assert.StartsWith's own comparison (current culture), without printing the output.
        Assert.True(output.StartsWith($"nfc {Label} end\n", StringComparison.CurrentCulture), "nfc-e-acute: run's output doesn't start with the masked NFC line");
        _output.WriteLine($"T46 owner decision (NFC/NFD), run: the NFD form was {(NfdLine(output) == $"nfd {Label} end" ? "masked" : "not masked")}");
    }

    [Fact]
    public void Nfd_InRedactInput_RecordedForTheOwner()
    {
        var nfc = EvilValues.Get("nfc-e-acute").Value;
        var nfd = nfc.Normalize(System.Text.NormalizationForm.FormD);
        IngestCase("nfc-e-acute", nfc);
        var path = Path.Combine(_work, "redact.txt");
        File.WriteAllText(path, $"nfc {nfc} end\nnfd {nfd} end\n");

        var (exit, stdout, err) = Execute("", ["redact", path]);

        Assert.True(exit == 0, err);
        // The stored (NFC) form is masked. F3: Assert.StartsWith's own comparison (current culture), without printing the output.
        Assert.True(stdout.StartsWith($"nfc {Label} end\n", StringComparison.CurrentCulture), "nfc-e-acute: redact's output doesn't start with the masked NFC line");
        _output.WriteLine($"T46 owner decision (NFC/NFD), redact: the NFD form was {(NfdLine(stdout) == $"nfd {Label} end" ? "masked" : "not masked")}");
    }
}
