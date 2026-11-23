using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S2 task 5: today's <c>redact</c> and <c>tocomment</c> output, pinned before the engine
/// switch (task 6). Each pin holds for the engine behind <see cref="Redact"/> and for the frozen
/// plaintext copy (<see cref="PlaintextRedactOracle"/>), so the copy is checked too.
/// </summary>
public class RedactBehaviourPinTests
{
    private static Secret S(string value, bool burned = false, string? previous = null, bool previousBurned = false) =>
        new(value, TestTime.Fixed, TestTime.Fixed, burned ? TestTime.Fixed : null, burned ? "test" : null)
        {
            PreviousValue = previous,
            PreviousBurned = previousBurned,
        };

    private static SecretsDb Db(params (string Name, Secret Secret)[] secrets) =>
        new(secrets.ToDictionary(s => s.Name, s => s.Secret)) { KeepsPreviousValues = true };

    private static void AssertRedact(string expected, string content, SecretsDb db)
    {
        Assert.Equal(expected, Redact.RedactContent(content, db));
        Assert.Equal(expected, PlaintextRedactOracle.RedactContent(content, db));
    }

    private static void AssertToComment(string expected, string content, SecretsDb db, params LineDiff[] changes)
    {
        var (actual, actualChanges) = Redact.ToComment(content, db);
        var (oracle, oracleChanges) = PlaintextRedactOracle.ToComment(content, db);
        Assert.Equal(expected, actual);
        Assert.Equal(expected, oracle);
        Assert.Equal(changes, actualChanges);
        Assert.Equal(changes, oracleChanges);
    }

    [Fact]
    public void OverlappingSecrets_TheOrdinallySmallerTextWins()
    {
        var db = Db(("s1", S("foo bar")), ("s2", S("bar baz")));
        AssertRedact("k: foo [REDACTED: s2]", "k: foo bar baz", db);
        // Brief T50b (owner decision 1): 'foo bar' fails rule (b), 'bar baz' rule (a): no change, both reported.
        AssertToComment("k: foo bar baz", "k: foo bar baz", db);
        Assert.Equal(new[] { new SkippedValue(1, 1, "s1", SkippedReason.NotWholeValue), new SkippedValue(1, 1, "s2", SkippedReason.NotWholeValue) },
            Redact.ToCommentReport("k: foo bar baz", db).Skipped);
    }

    [Fact]
    public void EqualLengthTies_DecidedByText_NotPosition()
    {
        // The names sort the other way round ("a-…" before "z-…"), so only the text decides.
        // Brief T30: values of 8 characters (a shorter one is matched only as a whole word).
        var db = Db(("a-xab-secret", S("xabcdefg")), ("z-abz-secret", S("abcdefgz")));
        AssertRedact("x[REDACTED: z-abz-secret]", "xabcdefgz", db);

        var spaced = Db(("a-xab-secret", S("x ab")), ("z-abz-secret", S("ab z")));
        // Brief T50b (owner decision 1): neither is a whole value on the line, so neither is replaced.
        AssertToComment("k: x ab z", "k: x ab z", spaced);
        Assert.Equal(
            new[] { new SkippedValue(1, 1, "a-xab-secret", SkippedReason.NotWholeValue), new SkippedValue(1, 1, "z-abz-secret", SkippedReason.NotWholeValue) },
            Redact.ToCommentReport("k: x ab z", spaced).Skipped);
    }

    [Fact]
    public void Containment_TheLongerValueFirst()
    {
        var db = Db(("long", S("secretvalue")), ("short", S("value")));
        AssertRedact("k=[REDACTED: long] v=[REDACTED: short]", "k=secretvalue v=value", db);
        AssertToComment("k: \"\"  # tswap: long\nv: \"\"  # tswap: short", "k: secretvalue\nv: value", db,
            new LineDiff(1, "k: secretvalue", "k: \"\"  # tswap: long"),
            new LineDiff(2, "v: value", "v: \"\"  # tswap: short"));
    }

    [Fact]
    public void SelfOverlappingValue_LeftmostNonOverlapping()
    {
        // Brief T30: an 8-character value (a shorter one is matched only as a whole word).
        var db = Db(("s", S(new string('a', 8))));
        AssertRedact("x [REDACTED: s]a", "x " + new string('a', 9), db);
        AssertRedact("[REDACTED: s][REDACTED: s]", new string('a', 16), db);
        AssertToComment("k: " + new string('a', 9), "k: " + new string('a', 9), db); // no boundary on either side: unchanged
    }

    [Fact]
    public void BurnedAndLiveWithOneValue_TheLiveNameWins()
    {
        var db = Db(("a-burned", S("samevalue", burned: true)), ("b-live", S("samevalue")));
        AssertRedact("k: [REDACTED: b-live]", "k: samevalue", db);
        AssertToComment("k: \"\"  # tswap: b-live", "k: samevalue", db, new LineDiff(1, "k: samevalue", "k: \"\"  # tswap: b-live"));
    }

    [Fact]
    public void BurnedCurrentAndAPreviousValue_ThePreviousCountsAsNotBurned()
    {
        // b:previous never looks burned to the sort (no secret is called "b:previous"), even when its
        // version was burned: today's quirk, kept.
        var db = Db(("a", S("xvalue", burned: true)), ("b", S("other", previous: "xvalue", previousBurned: true)));
        AssertRedact("k: [REDACTED: b:previous]", "k: xvalue", db);
        AssertToComment("k: \"\"  # tswap: b:previous", "k: xvalue", db, new LineDiff(1, "k: xvalue", "k: \"\"  # tswap: b:previous"));
    }

    [Fact]
    public void PreviousValue_IsLabelledNamePrevious()
    {
        var db = Db(("p", S("newval1", previous: "oldval1")));
        AssertRedact("n=[REDACTED: p] o=[REDACTED: p:previous]", "n=newval1 o=oldval1", db);
        AssertToComment("n: \"\"  # tswap: p\no: \"\"  # tswap: p:previous", "n: newval1\no: oldval1", db,
            new LineDiff(1, "n: newval1", "n: \"\"  # tswap: p"),
            new LineDiff(2, "o: oldval1", "o: \"\"  # tswap: p:previous"));
    }

    [Fact]
    public void WhitespaceStrippedVariant_IsMatched()
    {
        var db = Db(("s", S("abc def\nghi")));
        AssertRedact("k: [REDACTED: s]", "k: abcdefghi", db);
        AssertToComment("k: \"\"  # tswap: s", "k: abcdefghi", db, new LineDiff(1, "k: abcdefghi", "k: \"\"  # tswap: s"));
    }

    [Fact]
    public void Base64AndBase64Url_Labels()
    {
        var db = Db(("s", S("??>")));
        AssertRedact("a=[REDACTED: s (base64)] b=[REDACTED: s (base64url)]", "a=Pz8+ b=Pz8-", db);
        AssertToComment("a: \"\"  # tswap: s\nb: \"\"  # tswap: s", "a: Pz8+\nb: Pz8-", db,
            new LineDiff(1, "a: Pz8+", "a: \"\"  # tswap: s"),
            new LineDiff(2, "b: Pz8-", "b: \"\"  # tswap: s"));
    }

    [Fact]
    public void CrlfInput_ComesOutLfOnly()
    {
        var db = Db(("pw", S("secret")));
        AssertRedact("a: [REDACTED: pw]\nb: ok\n", "a: secret\r\nb: ok\r\n", db);
        AssertToComment("a: \"\"  # tswap: pw\nb: ok\n", "a: secret\r\nb: ok\r\n", db, new LineDiff(1, "a: secret", "a: \"\"  # tswap: pw"));
    }

    [Fact]
    public void RegexMetacharacters_AreLiteral()
    {
        var db = Db(("m", S("a.b*c(d)$1")));
        AssertRedact("x [REDACTED: m] y and aXbbc(d)$1", "x a.b*c(d)$1 y and aXbbc(d)$1", db);
        AssertToComment("k: \"\"  # tswap: m", "k: a.b*c(d)$1", db, new LineDiff(1, "k: a.b*c(d)$1", "k: \"\"  # tswap: m"));
    }

    [Fact]
    public void QuotesBoundariesAndAnExistingMarker()
    {
        var db = Db(("s", S("val12345")));
        const string content = "a: \"val12345\"\nb: 'val12345'\nc: myval12345-x\nd: \"val12345\"  # tswap: s\ne: val12345";
        AssertRedact(
            "a: \"[REDACTED: s]\"\nb: '[REDACTED: s]'\nc: my[REDACTED: s]-x\nd: \"[REDACTED: s]\"  # tswap: s\ne: [REDACTED: s]",
            content, db);
        AssertToComment(
            "a: \"\"  # tswap: s\nb: \"\"  # tswap: s\nc: myval12345-x\nd: \"\"  # tswap: s\ne: \"\"  # tswap: s",
            content, db,
            new LineDiff(1, "a: \"val12345\"", "a: \"\"  # tswap: s"),
            new LineDiff(2, "b: 'val12345'", "b: \"\"  # tswap: s"),
            new LineDiff(4, "d: \"val12345\"  # tswap: s", "d: \"\"  # tswap: s"),
            new LineDiff(5, "e: val12345", "e: \"\"  # tswap: s"));
    }

    [Fact]
    public void ContinuationLines_RemovedAfterAReplacement()
    {
        var db = Db(("c", S("AAAABBBBCCCCDDDD")));
        const string content = "cert: AAAABBBBCCCCDDDD\n  EEEEFFFFGGGGHHHH\n  IIIIJJJJKKKKLLLL\nnext: 1";
        AssertRedact("cert: [REDACTED: c]\n  EEEEFFFFGGGGHHHH\n  IIIIJJJJKKKKLLLL\nnext: 1", content, db);
        AssertToComment("cert: \"\"  # tswap: c\nnext: 1", content, db,
            new LineDiff(1, "cert: AAAABBBBCCCCDDDD", "cert: \"\"  # tswap: c"),
            new LineDiff(2, "  EEEEFFFFGGGGHHHH", ""),
            new LineDiff(3, "  IIIIJJJJKKKKLLLL", ""));
    }
}

/// <summary>Brief T16-S2 task 5: <c>tocomment --dry-run</c>'s report (its "before" lines redacted), through the command.</summary>
public sealed class ToCommentDryRunPinTests : IDisposable
{
    private readonly FleetMachine _m = new("tocomment-pin", SimulatedYubiKeyService.WithKeys(SerialA));

    public ToCommentDryRunPinTests() => InitRecordVault(_m);

    public void Dispose() => _m.Dispose();

    [Fact]
    public void DryRun_ReportsRedactedBeforeLines_AndLeavesTheFile()
    {
        _m.Ok("hunter2-pass", "ingest", "db");
        _m.Ok("tok-12345678", "ingest", "api");
        var file = _m.PathOf("values.yaml");
        const string content = "db: \"hunter2-pass\"  # note tok-12345678\napi: tok-12345678\nplain: 1\n";
        File.WriteAllText(file, content);

        var (exit, stdout, stderr) = _m.Run("", "tocomment", file, "--dry-run");

        Assert.Equal(0, exit);
        Assert.Equal("", stdout);
        Assert.Equal(
            "  line 1:\n" +
            "  - db: \"[REDACTED: db]\"  # note [REDACTED: api]\n" +
            "  + db: \"\"  # tswap: db  # note [REDACTED: api]\n" +
            "  line 2:\n" +
            "  - api: [REDACTED: api]\n" +
            "  + api: \"\"  # tswap: api\n" +
            "Warning: line 1: the value of 'api' (or an encoded form of it) was left in place: it is not a whole value that apply " +
            "fills back ('key: value', or 'KEY=value' without control characters). If it is the secret there, move it out by hand.\n" +
            "\n(dry run) 2 line(s) would be modified.\n",
            stderr.Replace("\r\n", "\n"));
        Assert.Equal(content, File.ReadAllText(file));
    }
}
