using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Fix round 3, item 6: a ':previous' value whose version was burned is warned about in run and
/// apply; an unknown suffix is an error naming the token; the merge tie-break covers Previous.
/// </summary>
public sealed class PreviousValueWarningTests : IDisposable
{
    private readonly FleetMachine _m = new("previous-warn", SimulatedYubiKeyService.WithKeys(SerialA));

    public PreviousValueWarningTests()
    {
        InitRecordVault(_m);
        _m.Ok("leaked-pw", "ingest", "db-pw");
        _m.Ok("", "burn", "db-pw", "pasted in chat");
        _m.Ok("", "rotate", "db-pw");
    }

    public void Dispose() => _m.Dispose();

    [Fact]
    public void RunAndApply_WarnWhenThePreviousValueWasBurned()
    {
        var template = _m.PathOf("t.yaml");
        File.WriteAllText(template, "old: \"\" # tswap: db-pw:previous\n");

        var run = _m.Run("", "run", "true", "{{db-pw:previous}}");
        var apply = _m.Run("", "apply", template);

        Assert.Contains("db-pw:previous", run.Err);
        Assert.Contains("burned", run.Err);
        Assert.Equal(0, apply.Exit);
        Assert.Contains("db-pw:previous", apply.Err);
        Assert.Contains("burned", apply.Err);
    }

    [Fact]
    public void AnUnknownSuffix_IsAnErrorNamingTheToken()
    {
        var template = _m.PathOf("t.yaml");
        File.WriteAllText(template, "old: \"\" # tswap: db-pw:foo\n");

        var run = _m.Run("", "run", "true", "{{db-pw:previus}}");
        var apply = _m.Run("", "apply", template);

        Assert.NotEqual(0, run.Exit);
        Assert.Contains("db-pw:previus", run.Err);
        Assert.NotEqual(0, apply.Exit);
        Assert.Contains("db-pw:foo", apply.Err);
        Assert.DoesNotContain(_m.Get("db-pw"), apply.Out);
    }

    [Fact]
    public void Apply_ChecksEveryMarkerOnALine()
    {
        // Fix round 4, item 2: every '# tswap:' marker's tail is 'name' or 'name:previous'.
        _m.Ok("x-value", "ingest", "x");
        var ok = _m.PathOf("ok.yaml");
        File.WriteAllText(ok, "a: \"\" # tswap: x # tswap: db-pw:previous\n");
        var bad = _m.PathOf("bad.yaml");
        File.WriteAllText(bad, "a: \"\" # tswap: db-pw:previous # tswap: x:foo\n");
        var doubled = _m.PathOf("doubled.yaml");
        File.WriteAllText(doubled, "a: \"\" # tswap: a:b:previous\n");

        var accepted = _m.Run("", "apply", ok);
        var refused = _m.Run("", "apply", bad);
        var refusedDoubled = _m.Run("", "apply", doubled);

        Assert.True(accepted.Exit == 0, accepted.Err);
        Assert.Contains("a: \"x-value\"", accepted.Out);
        Assert.NotEqual(0, refused.Exit);
        Assert.Contains("x:foo", refused.Err);
        Assert.NotEqual(0, refusedDoubled.Exit);
        Assert.Contains("a:b:previous", refusedDoubled.Err);
    }

    [Fact]
    public void TheMergeTieBreak_CoversThePreviousValue()
    {
        var origin = Enumerable.Repeat((byte)1, 16).ToArray();
        var version = new Stamp(new Hlc(1000, 0), origin);
        SecretRecord Rec(string previous) => RecordMerge.Normalize(new SecretRecord(
            new byte[32], version, RecordType.Value, version, "s", 1, "v"u8.ToArray(), [],
            new PreviousValue(new Stamp(new Hlc(500, 0), origin), System.Text.Encoding.UTF8.GetBytes(previous))));
        var a = Rec("p1");
        var b = Rec("p2");

        Assert.True(RecordMerge.Merge(a, b).SameState(RecordMerge.Merge(b, a)));
        // Fix round 4, item 3: the documented winner, the larger previous value bytewise.
        Assert.Equal("p2"u8.ToArray(), RecordMerge.Merge(a, b).Previous!.Value);
    }
}
