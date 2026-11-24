using System.Text.Json;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T56 task 1 (#396): <c>burned</c>'s text output starts with a count line and every row line starts with its
/// state (<c>outstanding</c> or <c>rotated</c>), so no slice of the output (<c>tswap burned | tail -8</c>) reads as a
/// to-do list. A reason is printed on one line; the <c>BURNED AT</c> column is 16 wide, also for a clamped date.
/// </summary>
public sealed class BurnedOutputTests : IDisposable
{
    private static bool IsDashLine(string line) => line.Length >= 60 && line.All(c => c == '-');

    private readonly FleetMachine _m = new("burned-out", SimulatedYubiKeyService.WithKeys(SerialA));
    private DateTimeOffset _now = new(2026, 1, 2, 3, 4, 0, TimeSpan.Zero);

    public BurnedOutputTests()
    {
        _m.Time = new FuncTimeProvider(() => _now);
        InitRecordVault(_m);
    }

    public void Dispose() => _m.Dispose();

    private void Tick() => _now = _now.AddMinutes(1);

    private void Outstanding(string name, string reason = "seen")
    {
        _m.Ok($"{name}-value", "ingest", name);
        Tick();
        _m.Ok("", "burn", name, reason);
        Tick();
    }

    private void Rotated(string name)
    {
        Outstanding(name);
        _m.Ok($"{name}-new", "ingest", "--rotate", name);
        Tick();
    }

    private string[] Burned()
    {
        var (exit, stdout, stderr) = _m.Run("", "burned");
        Assert.Equal(0, exit);
        Assert.Equal("", stderr);
        return stdout.Replace("\r\n", "\n").Split('\n');
    }

    /// <summary>The row lines of the table under <paramref name="heading"/>: after its dash line, up to the blank line.</summary>
    private static string[] Rows(string[] lines, string heading)
    {
        var at = Array.FindIndex(lines, l => l.StartsWith(heading, StringComparison.Ordinal));
        Assert.True(at >= 0, $"no heading '{heading}'");
        Assert.StartsWith("STATE ", lines[at + 1]);
        Assert.True(IsDashLine(lines[at + 2]), $"no dash line under '{heading}'");
        return lines.Skip(at + 3).TakeWhile(l => l != "").ToArray();
    }

    [Fact]
    public void NothingBurned_SaysAllClean()
    {
        _m.Ok("v", "ingest", "clean");

        var (exit, stdout, _) = _m.Run("", "burned");

        Assert.Equal(0, exit);
        Assert.Equal("No burned secrets. All secrets are clean.\n", stdout.Replace("\r\n", "\n"));
    }

    [Fact]
    public void OnlyRotated_FirstLineSaysNothingNeedsRotation_AndEveryRowIsRotated()
    {
        Rotated("r1");
        Rotated("r2");

        var lines = Burned();

        Assert.Equal("No burned secrets need rotation: 0 outstanding, 2 rotated (history, nothing to do).", lines[0]);
        var rows = Rows(lines, "Rotated (burn superseded by a newer value) (2):");
        Assert.Equal(2, rows.Length);
        Assert.All(rows, r => Assert.StartsWith("rotated  ", r));
        Assert.DoesNotContain(lines, l => l.StartsWith("⚠ Burned Secrets", StringComparison.Ordinal));
    }

    [Fact]
    public void OnlyOutstanding_FirstLineCountsThem_AndEveryRowIsOutstanding()
    {
        Outstanding("o1");
        Outstanding("o2");

        var lines = Burned();

        Assert.Equal("⚠ 2 outstanding (rotate these), 0 rotated (history, nothing to do).", lines[0]);
        var rows = Rows(lines, "⚠ Burned Secrets (2):");
        Assert.Equal(2, rows.Length);
        Assert.All(rows, r => Assert.StartsWith("outstanding  ", r));
    }

    [Fact]
    public void ALongName_BothItsLinesStartWithTheState()
    {
        var name = new string('n', 45);
        Rotated(name);

        var rows = Rows(Burned(), "Rotated (burn superseded by a newer value) (1):");

        Assert.Equal(2, rows.Length);
        Assert.Equal($"rotated  {name}", rows[0]);
        Assert.StartsWith("rotated  ", rows[1]);
        Assert.EndsWith("  seen", rows[1]);
    }

    [Fact]
    public void AMultiLineReason_IsPrintedOnOneLine_AndStoredAsGiven()
    {
        const string reason = "seen\nfake-name  2026-01-02 03:14  rotate me\r\x1b[2Kx";
        Outstanding("db", reason);

        var rows = Rows(Burned(), "⚠ Burned Secrets (1):");

        var row = Assert.Single(rows);
        Assert.StartsWith("outstanding  ", row);
        Assert.EndsWith("seen fake-name  2026-01-02 03:14  rotate me  [2Kx", row);

        var (exit, json, _) = _m.Run("", "burned", "--json");
        Assert.Equal(0, exit);
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(reason, doc.RootElement.EnumerateArray().Single().GetProperty("reason").GetString());
    }

    [Fact]
    public void AFarFutureDate_KeepsTheReasonsInOneColumn()
    {
        _m.Ok("a-value", "ingest", "normal");
        _m.Ok("b-value", "ingest", "later");
        Tick();
        _m.Ok("", "burn", "normal", "reason-normal");
        _now = DateTimeOffset.MaxValue;
        _m.Ok("", "burn", "later", "reason-later");

        var rows = Rows(Burned(), "⚠ Burned Secrets (2):");

        Assert.Equal(2, rows.Length);
        Assert.Single(rows, r => r.Contains("far future", StringComparison.Ordinal));
        var normal = rows.Single(r => r.Contains("reason-normal", StringComparison.Ordinal));
        var later = rows.Single(r => r.Contains("reason-later", StringComparison.Ordinal));
        Assert.Equal(normal.IndexOf("reason-", StringComparison.Ordinal), later.IndexOf("reason-", StringComparison.Ordinal));
    }

    [Fact]
    public void TheLastEightLines_OfNineRotated_NoneLooksOutstanding()
    {
        for (var i = 1; i <= 9; i++)
            Rotated($"rot{i}");

        var lines = Burned();

        Assert.StartsWith("No burned secrets need rotation: 0 outstanding, 9 rotated", lines[0]);
        var tail = lines.TakeLast(8).Where(l => l != "").ToArray();
        Assert.NotEmpty(tail);
        Assert.All(tail, l => Assert.True(
            l.StartsWith("rotated  ", StringComparison.Ordinal) || IsDashLine(l) || l.StartsWith("STATE ", StringComparison.Ordinal),
            $"line looks like something else: '{l}'"));
    }
}
