using System.Text.Json;
using TswapCli;
using TswapCli.Commands;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T32 (#7): <c>tswap names [&lt;pattern&gt;...] [--json]</c>. A pattern is a glob over whole names (<c>*</c> any
/// run of characters, <c>?</c> one), case ignored; several are a union. The output is exactly plain <c>names</c>' lines
/// (or JSON entries) for the matching names, the column width still that of the whole vault. No match: exit 0, nothing
/// on stdout, one line on stderr. A pattern with any other character is refused before the vault is read. Every
/// <c>names</c> run here is without sudo (amendment A2: only the setup's <c>add</c> has it).
/// </summary>
public sealed class NamesPatternTests : IDisposable
{
    private const int Serial = 11111111;

    private static readonly DateTimeOffset Now = new(TestTime.Fixed);

    /// <summary>The stored names and their values (amendment A3: the last one is the longest, under 40 characters).</summary>
    private static readonly (string Name, string Value)[] Stored =
    [
        ("k8s-authentik-pg-password", "t32-value-authentik-pg"),
        ("k8s-authentik-secret-key", "t32-value-authentik-key"),
        ("k8s-paperless-pg-app-password", "t32-value-paperless-pg"),
        ("db", "t32-value-db"),
        ("db1", "t32-value-db1"),
        ("db12", "t32-value-db12"),
        ("Db-Admin", "t32-value-db-admin"),
        ("api-key", "t32-value-api-key"),
        ("zz-the-longest-name-in-the-vault", "t32-value-longest"),
    ];

    private const string Burned = "k8s-authentik-secret-key";

    private readonly List<FleetMachine> _machines = [];
    private readonly List<string> _outputs = [];

    public void Dispose()
    {
        foreach (var m in _machines)
            m.Dispose();
    }

    private FleetMachine NewMachine(string name)
    {
        var m = new FleetMachine(name, SimulatedYubiKeyService.WithKeys(Serial)) { Time = new FuncTimeProvider(() => Now) };
        m.Keys.PluggedIn = [Serial];
        _machines.Add(m);
        return m;
    }

    private FleetMachine Vault()
    {
        var m = NewMachine("names-pattern");
        m.Ok("", "init", "--yubikey", "--no-password", "--no-recovery");
        m.Sudo = true; // add needs sudo (A2)
        foreach (var (name, value) in Stored)
            m.Ok(value + "\n" + value + "\n", "add", name);
        m.Ok("", "burn", Burned, "t32 test");
        Assert.True(Stored.Max(s => s.Name.Length) < 40);
        return m;
    }

    private (int Exit, string Out, string Err) Names(FleetMachine m, params string[] args)
    {
        m.Sudo = false;
        var run = m.Run("", ["names", .. args]);
        _outputs.Add(run.Out);
        _outputs.Add(run.Err);
        return run;
    }

    private static string[] Lines(string text) => text.ReplaceLineEndings("\n").Split('\n', StringSplitOptions.RemoveEmptyEntries);

    private static string NameOf(string line) => line.Split(' ')[0];

    /// <summary>The lines of plain <c>names</c>' output whose name <paramref name="keep"/> says, in its order, as it prints them.</summary>
    private static string PlainLinesOf(string plain, Func<string, bool> keep) =>
        string.Concat(Lines(plain).Where(l => keep(NameOf(l))).Select(l => l + Environment.NewLine));

    private static readonly string NoMatchLine = NamesCommand.NoMatchText + Environment.NewLine;

    [Fact]
    public void Pattern_PrintsExactlyThePlainLinesOfTheMatchingNames()
    {
        var m = Vault();
        var plain = Names(m).Out;

        var (exit, stdout, stderr) = Names(m, "k8s-*");

        Assert.Equal(0, exit);
        Assert.Equal(PlainLinesOf(plain, n => n.StartsWith("k8s-", StringComparison.Ordinal)), stdout);
        Assert.Equal(3, Lines(stdout).Length);
        Assert.Contains($"{Burned} ", stdout);
        Assert.EndsWith(" [BURNED]", Lines(stdout).Single(l => NameOf(l) == Burned));
        Assert.DoesNotContain("No secret name matches", stderr);
    }

    [Fact]
    public void SeveralPatterns_AreAUnion_EachNameOnce()
    {
        var m = Vault();
        var plain = Names(m).Out;

        var (exit, stdout, _) = Names(m, "k8s-*", "*-pg-*", "k8s-authentik-*");

        Assert.Equal(0, exit);
        Assert.Equal(PlainLinesOf(plain, n => n.StartsWith("k8s-", StringComparison.Ordinal)), stdout);
        Assert.Equal(3, Lines(stdout).Length);
    }

    [Fact]
    public void QuestionMark_IsExactlyOneCharacter()
    {
        var m = Vault();
        var plain = Names(m).Out;

        var (exit, stdout, _) = Names(m, "db?");

        Assert.Equal(0, exit);
        Assert.Equal(PlainLinesOf(plain, n => n == "db1"), stdout);
    }

    [Fact]
    public void Case_IsIgnored()
    {
        var m = Vault();
        var plain = Names(m).Out;

        var (exit, stdout, _) = Names(m, "DB*");

        Assert.Equal(0, exit);
        Assert.Equal(PlainLinesOf(plain, n => n is "db" or "db1" or "db12" or "Db-Admin"), stdout);
        Assert.Equal(4, Lines(stdout).Length);
    }

    [Fact]
    public void Pattern_MatchesWholeNames()
    {
        var m = Vault();
        var plain = Names(m).Out;

        var (bareExit, bareOut, bareErr) = Names(m, "pg");
        var (exit, stdout, _) = Names(m, "*pg*");

        Assert.Equal(0, bareExit);
        Assert.Equal("", bareOut);
        Assert.Equal(NoMatchLine, bareErr);
        Assert.Equal(0, exit);
        Assert.Equal(PlainLinesOf(plain, n => n is "k8s-authentik-pg-password" or "k8s-paperless-pg-app-password"), stdout);
    }

    [Fact]
    public void Json_IsThePlainJsonFiltered()
    {
        var m = Vault();
        var plain = JsonSerializer.Deserialize(Names(m, "--json").Out, CliJsonContext.Default.ListNameEntry)!;
        var expected = plain.Where(e => e.Name.StartsWith("k8s-", StringComparison.Ordinal)).ToList();
        Assert.Equal(3, expected.Count);
        Assert.Contains(expected, e => e is { Name: Burned, Burned: true, BurnedAt: not null });

        string[][] runs = [["--json", "k8s-*"], ["k8s-*", "--json"]];
        foreach (var args in runs)
        {
            var (exit, stdout, _) = Names(m, args);

            Assert.Equal(0, exit);
            Assert.Equal(expected, JsonSerializer.Deserialize(stdout, CliJsonContext.Default.ListNameEntry)!);
        }
    }

    [Fact]
    public void NoMatch_EmptyStdout_ExitZero()
    {
        var m = Vault();

        var (exit, stdout, stderr) = Names(m, "nothing-*");
        Assert.Equal(0, exit);
        Assert.Equal("", stdout);
        Assert.Equal(NoMatchLine, stderr);

        var (jsonExit, jsonOut, jsonErr) = Names(m, "--json", "nothing-*");
        Assert.Equal(0, jsonExit);
        Assert.Equal("[]" + Environment.NewLine, jsonOut);
        Assert.Equal(NoMatchLine, jsonErr);

        var empty = NewMachine("names-empty");
        empty.Ok("", "init", "--yubikey", "--no-password", "--no-recovery");
        var (emptyExit, emptyOut, emptyErr) = Names(empty, "x*");
        Assert.Equal(0, emptyExit);
        Assert.Equal("", emptyOut);
        Assert.Equal(NoMatchLine, emptyErr);
        var (plainExit, plainOut, _) = Names(empty);
        Assert.Equal(0, plainExit);
        Assert.Equal("No secrets stored." + Environment.NewLine, plainOut);
    }

    [Fact]
    public void NoValueInTheOutput()
    {
        var m = Vault();
        string[][] runs = [[], ["--json"], ["k8s-*"], ["k8s-*", "*-pg-*", "k8s-authentik-*"], ["db?"], ["DB*"], ["pg"], ["*pg*"],
            ["--json", "k8s-*"], ["k8s-*", "--json"], ["nothing-*"], ["--json", "nothing-*"], ["--filter", "k8s-*"], ["--version"]];
        foreach (var args in runs)
            Assert.Equal(0, Names(m, args).Exit);

        Assert.Equal(28, _outputs.Count);
        foreach (var text in _outputs)
            foreach (var (_, value) in Stored)
                Assert.DoesNotContain(value, text, StringComparison.Ordinal);
    }

    public static TheoryData<string[]> BadPatterns =>
    [
        ["k8s-notes.txt"],
        [""],
        ["a[b]"],
        ["a\\b"],
        ["a b"],
        ["k8s-*", "x.y"],
    ];

    [Theory]
    [MemberData(nameof(BadPatterns))]
    public void BadPattern_RefusedBeforeTheVaultIsRead(string[] patterns)
    {
        var m = NewMachine("names-bad"); // no init: a check after the vault load would fail with another text

        var (exit, stdout, stderr) = Names(m, patterns);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Equal($"\n❌ Error: {NamesCommand.PatternText}{Environment.NewLine}", stderr);
    }

    [Fact]
    public void UnknownOption_StillIgnored()
    {
        var m = Vault();
        var plain = Names(m);
        var pattern = Names(m, "k8s-*");

        var filter = Names(m, "--filter", "k8s-*");
        var version = Names(m, "--version");

        Assert.Equal((pattern.Exit, pattern.Out), (filter.Exit, filter.Out));
        Assert.Equal(3, Lines(filter.Out).Length);
        Assert.Equal((plain.Exit, plain.Out), (version.Exit, version.Out));
        Assert.Equal(Stored.Length, Lines(version.Out).Length);
    }

    [Fact]
    public void HelpShowsThePatterns()
    {
        var m = NewMachine("names-help");

        var (exit, stdout, _) = Names(m, "--help");

        Assert.Equal(0, exit);
        Assert.Contains("tswap names [<pattern>...] [--json]", stdout);
    }
}
