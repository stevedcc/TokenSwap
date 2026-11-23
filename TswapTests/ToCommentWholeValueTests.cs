using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T50b Task 1 (#394): <c>tocomment</c> replaces an occurrence only where <c>apply</c> fills it back as the
/// whole value (rules (a), (a′), (b) and (m), evaluated on the original line); every other occurrence stays and is
/// reported as a <see cref="SkippedValue"/>. Each row also compares the frozen oracle's content and changes.
/// </summary>
public sealed class ToCommentWholeValueTests
{
    private static Secret S(string value) => new(value, TestTime.Fixed, TestTime.Fixed, null, null);

    private static SecretsDb Db(params (string Name, string Value)[] secrets) =>
        new(secrets.ToDictionary(s => s.Name, s => S(s.Value))) { KeepsPreviousValues = true };

    private static readonly SecretsDb AppUser = Db(("app-user", "authentik"));

    /// <summary>The engine's report, with the oracle's content and changes compared to it.</summary>
    internal static ToCommentReport Report(string content, SecretsDb db)
    {
        var report = Redact.ToCommentReport(content, db);
        var (oracle, oracleChanges) = PlaintextRedactOracle.ToComment(content, db);
        Assert.Equal(report.Content, oracle);
        Assert.Equal(report.Changes, oracleChanges);
        return report;
    }

    private static (int, int, string, SkippedReason)[] Skipped(ToCommentReport report) =>
        [.. report.Skipped.Select(s => (s.FirstLine, s.LastLine, s.Token, s.Reason))];

    private static SecretsDb RowDb(int row) => row switch
    {
        24 or 25 => Db(("cr", "line-one\rline-two")),
        26 => Db(("v", "val-12345")),
        30 => Db(("fb", "foo bar baz"), ("bb", "bar baz")),
        _ => AppUser,
    };

    /// <summary>The Task 1 table: the line, the content after (null: unchanged), and the skipped tokens (all R1, line 1).</summary>
    public static TheoryData<int, string, string?, string[]> Rows => new()
    {
        { 1, "namespace: authentik", "namespace: \"\"  # tswap: app-user", [] },
        { 2, "  - authentik.sources.ldap.auth.LDAPBackend", null, ["app-user"] },
        { 3, "  command: python -m authentik.core.management.commands.import_flow /f.yaml", null, ["app-user"] },
        { 4, "- authentik", null, ["app-user"] },
        { 5, "args: --user=authentik --verbose", null, ["app-user"] },
        { 6, "KEY=authentik", "KEY=\"\"  # tswap: app-user", [] },
        { 7, "export APP_USER=\"authentik\"", "export APP_USER=\"\"  # tswap: app-user", [] },
        { 8, "user:authentik", "user:\"\"  # tswap: app-user", [] },
        { 9, "user: authentik  # owner", "user: \"\"  # tswap: app-user  # owner", [] },
        { 10, "user: 'authentik'  # tswap: old-name", "user: \"\"  # tswap: app-user", [] },
        { 11, "user: authentik#x", null, ["app-user"] },
        { 12, "{user: authentik, host: db}", null, ["app-user"] },
        { 13, "users: [authentik]", null, ["app-user"] },
        { 14, "url: https://authentik:pw@db", null, ["app-user"] },
        { 15, "# the authentik user", null, ["app-user"] },
        { 16, "# deprecated: authentik", null, ["app-user"] },
        { 17, "\"k#1\": authentik", "\"k#1\": \"\"  # tswap: app-user", [] },
        { 18, "k#1: authentik", null, ["app-user"] },
        { 19, "user: authentik-admin", null, [] },
        { 20, "user: authentik  # also authentik", "user: \"\"  # tswap: app-user  # also authentik", ["app-user"] },
        { 21, "user: authentik authentik", null, ["app-user", "app-user"] },
        { 22, "TOKEN=YXV0aGVudGlr", null, ["app-user"] },
        { 23, "token: YXV0aGVudGlr", "token: \"\"  # tswap: app-user", [] },
        { 24, "TOKEN=line-one\rline-two", null, ["cr"] },
        { 25, "token: line-one\rline-two", "token: \"\"  # tswap: cr", [] },
        { 26, "k: val-12345# tswap: note", null, ["v"] },
        { 27, "k: \"#tswap: x\" v: authentik", null, ["app-user"] },
        { 28, "k: '\"\"  # tswap: x': authentik", null, ["app-user"] },
        { 29, "user: authentik  # was # tswap: old.field", null, ["app-user"] },
        { 30, "k: foo bar baz", "k: \"\"  # tswap: fb", [] },
    };

    [Theory, MemberData(nameof(Rows))]
    public void Row_ReplacedOnlyAsAWholeValue(int row, string line, string? after, string[] skipped)
    {
        var report = Report(line, RowDb(row));

        Assert.Equal(after ?? line, report.Content);
        if (after is null)
            Assert.Empty(report.Changes);
        else
            Assert.Equal(new[] { new LineDiff(1, line, after) }, report.Changes);
        Assert.Equal(skipped.Select(t => (1, 1, t, SkippedReason.NotWholeValue)).ToArray(), Skipped(report));
        Assert.Empty(report.Unreplaced);
    }

    // ------------------------------------------------------------------ the username note

    [Theory]
    [InlineData("k8s-authentik-pg-local-app-username", true)]
    [InlineData("app-user", true)]
    [InlineData("LOGIN-name", true)]
    [InlineData("svc-Account", true)]
    [InlineData("ops-email", true)]
    [InlineData("db-pw", false)]
    [InlineData("api-token", false)]
    [InlineData("pem", false)]
    public void IsUsernameName_ReadsTheNameOnly(string name, bool expected)
    {
        Assert.Equal(expected, ToCommentProcessor.IsUsernameName(name));
    }

    [Fact]
    public void ReplacedNames_UsernameSecret()
    {
        var report = Report("namespace: authentik", Db(("k8s-authentik-pg-local-app-username", "authentik")));

        Assert.Equal("namespace: \"\"  # tswap: k8s-authentik-pg-local-app-username", report.Content);
        Assert.Equal(new[] { "k8s-authentik-pg-local-app-username" }, report.ReplacedNames);
    }

    [Fact]
    public void ReplacedNames_PasswordSecret()
    {
        var report = Report("namespace: authentik", Db(("db-pw", "authentik")));

        Assert.Equal("namespace: \"\"  # tswap: db-pw", report.Content);
        Assert.Equal(new[] { "db-pw" }, report.ReplacedNames);
        Assert.False(ToCommentProcessor.IsUsernameName("db-pw"));
    }

    [Fact]
    public void ReplacedNames_OncePerSecret()
    {
        var report = Report("a: authentik\nb: authentik\n- authentik", AppUser);

        Assert.Equal("a: \"\"  # tswap: app-user\nb: \"\"  # tswap: app-user\n- authentik", report.Content);
        Assert.Equal(new[] { "app-user" }, report.ReplacedNames);
        Assert.Equal(new[] { (3, 3, "app-user", SkippedReason.NotWholeValue) }, Skipped(report));
    }

    // ------------------------------------------------------------------ two more engine tests

    [Fact]
    public void ValueInTheCommentOfAReplacedLine_Skipped()
    {
        var report = Report("k: alpha-value-1  # beta-value-22", Db(("a-1", "alpha-value-1"), ("b-2", "beta-value-22")));

        Assert.Equal("k: \"\"  # tswap: a-1  # beta-value-22", report.Content);
        Assert.Equal(new[] { (1, 1, "b-2", SkippedReason.NotWholeValue) }, Skipped(report));
    }

    [Fact]
    public void MultiLineValueNotInTheFile_LinesReplacedOneByOne()
    {
        var db = Db(("v-1", "v1-value-aaaa"), ("v-2", "v2-value-bbbb"), ("m", "x: v1-value-aaaa\ny: v2-value-bbbb"));

        var report = Report("x: v1-value-aaaa\nother: 1\ny: v2-value-bbbb\n", db);

        Assert.Equal("x: \"\"  # tswap: v-1\nother: 1\ny: \"\"  # tswap: v-2\n", report.Content);
        LineDiff[] expected =
        [
            new(1, "x: v1-value-aaaa", "x: \"\"  # tswap: v-1"),
            new(3, "y: v2-value-bbbb", "y: \"\"  # tswap: v-2"),
        ];
        Assert.Equal(expected, report.Changes);
        Assert.Empty(report.Skipped);
    }
}
