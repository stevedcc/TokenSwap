using System.Text;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T6 item 3 (decisions 3 and 4): the hybrid logical clock and the merge rules as pure
/// functions. Every pair is checked in both orders (commutativity) and repeated (idempotence).
/// </summary>
public class RecordMergeTests
{
    private static readonly byte[] OriginA = Enumerable.Repeat((byte)0x0A, 16).ToArray();
    private static readonly byte[] OriginB = Enumerable.Repeat((byte)0x0B, 16).ToArray();
    private static readonly byte[] Id = new byte[32];

    private static Stamp S(long ms, uint logical = 0, byte[]? origin = null) => new(new Hlc(ms, logical), origin ?? OriginA);

    private static SecretRecord Value(Stamp version, string value, params BurnEntry[] burns) =>
        RecordMerge.Normalize(new SecretRecord(Id, version, RecordType.Value, version, "s", 1, Encoding.UTF8.GetBytes(value), burns));

    private static SecretRecord Tombstone(Stamp version, params BurnEntry[] burns) =>
        RecordMerge.Normalize(new SecretRecord(Id, version, RecordType.Tombstone, version, "s", 1, [], burns));

    private static BurnEntry Burn(Stamp version, Stamp at, string reason) => new(version, at, reason);

    /// <summary>Merges both ways and repeatedly, asserts they agree, and returns the result.</summary>
    private static SecretRecord MergeBothWays(SecretRecord a, SecretRecord b)
    {
        var ab = RecordMerge.Merge(a, b);
        var ba = RecordMerge.Merge(b, a);
        Assert.True(ab.SameState(ba), $"merge is not commutative: {ab} vs {ba}");
        Assert.True(RecordMerge.Merge(ab, a).SameState(ab), "merging a again changed the result");
        Assert.True(RecordMerge.Merge(ab, b).SameState(ab), "merging b again changed the result");
        Assert.True(RecordMerge.Merge(ab, ab).SameState(ab), "merge is not idempotent");
        return ab;
    }

    // ------------------------------------------------------------------ HLC

    [Fact]
    public void Hlc_Next_TakesNowWhenItIsAhead()
    {
        Assert.Equal(new Hlc(2000, 0), Hlc.Next(new Hlc(1000, 5), 2000));
    }

    [Fact]
    public void Hlc_Next_WithTheClockSetBack_StillMovesForward()
    {
        var first = Hlc.Next(Hlc.Zero, 2000);
        var second = Hlc.Next(first, 500);

        Assert.True(second > first);
        Assert.Equal(new Hlc(2000, 1), second);
    }

    [Fact]
    public void Hlc_Next_InTheSameMillisecond_GivesDistinctIncreasingStamps()
    {
        var stamps = new List<Hlc>();
        var last = Hlc.Zero;
        for (var i = 0; i < 5; i++)
            stamps.Add(last = Hlc.Next(last, 1000));

        Assert.Equal(stamps.Distinct().Count(), stamps.Count);
        Assert.Equal(stamps.Order().ToList(), stamps);
    }

    [Fact]
    public void Hlc_Next_AfterSeeingAStampFromTheFuture_OrdersAfterIt()
    {
        var future = new Hlc(9_000_000_000_000, 7);

        Assert.True(Hlc.Next(future, 1000) > future);
    }

    [Fact]
    public void Hlc_ParsesWhatItPrints()
    {
        var hlc = new Hlc(1_800_000_000_123, 42);

        Assert.Equal(hlc, Hlc.TryParse(hlc.ToString()));
        Assert.Null(Hlc.TryParse("garbage"));
    }

    [Fact]
    public void Hlc_Display_ClampsBeyondDateTimeMax_ToFarFuture()
    {
        Assert.Equal("far future", Hlc.Display(Hlc.ToDisplayDate(long.MaxValue)));
        Assert.Equal("2027-01-15 08:00", Hlc.Display(Hlc.ToDisplayDate(new DateTimeOffset(2027, 1, 15, 8, 0, 0, TimeSpan.Zero).ToUnixTimeMilliseconds())));
    }

    [Fact]
    public void Stamp_EqualHlc_IsDecidedByOrigin()
    {
        Assert.True(S(1000, 0, OriginB).CompareTo(S(1000, 0, OriginA)) > 0);
        Assert.True(S(1001, 0, OriginA).CompareTo(S(1000, 0, OriginB)) > 0);
    }

    // ------------------------------------------------------------------ merge table

    [Fact]
    public void ValueValue_TheNewerHlcWins()
    {
        var merged = MergeBothWays(Value(S(1000), "old"), Value(S(2000, 0, OriginB), "new"));

        Assert.Equal("new", Encoding.UTF8.GetString(merged.Value));
    }

    [Fact]
    public void ValueValue_EqualHlc_TheLargerOriginWins()
    {
        var merged = MergeBothWays(Value(S(1000, 3, OriginA), "from-a"), Value(S(1000, 3, OriginB), "from-b"));

        Assert.Equal("from-b", Encoding.UTF8.GetString(merged.Value));
    }

    [Fact]
    public void TombstoneValue_TheNewerWins_EitherWay()
    {
        Assert.Equal(RecordType.Tombstone, MergeBothWays(Value(S(1000), "v"), Tombstone(S(2000, 0, OriginB))).Type);

        var revived = MergeBothWays(Tombstone(S(1000)), Value(S(2000, 0, OriginB), "again"));
        Assert.Equal(RecordType.Value, revived.Type);
        Assert.Equal("again", Encoding.UTF8.GetString(revived.Value));
    }

    [Fact]
    public void BurnOfTheCurrentVersion_VsTheSameValueUnburned_IsBurned()
    {
        var v = S(1000);
        var merged = MergeBothWays(Value(v, "v", Burn(v, S(1500, 0, OriginB), "leaked")), Value(v, "v"));

        Assert.Equal(RecordType.Burned, merged.Type);
        Assert.Equal("leaked", merged.OutstandingBurn!.Reason);
    }

    [Fact]
    public void BurnOfAnOlderVersion_VsANewerValue_TheNewerValueWins_AndTheBurnIsHistory()
    {
        var v1 = S(1000);
        var burned = Value(v1, "old", Burn(v1, S(1500), "leaked"));
        var rotated = Value(S(2000, 0, OriginB), "new");

        var merged = MergeBothWays(burned, rotated);

        Assert.Equal(RecordType.Value, merged.Type);
        Assert.Equal("new", Encoding.UTF8.GetString(merged.Value));
        Assert.Null(merged.OutstandingBurn);
        var history = Assert.Single(merged.Burns);
        Assert.Equal("leaked", history.Reason);
        Assert.Equal(v1, history.Version);
    }

    [Fact]
    public void BurnBurn_OfTheSameVersion_KeepsTheEarliest()
    {
        var v = S(1000);
        var merged = MergeBothWays(
            Value(v, "v", Burn(v, S(3000, 0, OriginA), "second")),
            Value(v, "v", Burn(v, S(2000, 0, OriginB), "first")));

        Assert.Equal("first", merged.OutstandingBurn!.Reason);
        Assert.Single(merged.Burns);
    }

    [Fact]
    public void DeleteThenBurn_StaysDeleted_TheBurnIsHistory()
    {
        // A deleted v1 at 2000; B, not having seen the delete, burned v1 at 3000.
        var v1 = S(1000);
        var merged = MergeBothWays(Tombstone(S(2000)), Value(v1, "v", Burn(v1, S(3000, 0, OriginB), "late burn")));

        Assert.Equal(RecordType.Tombstone, merged.Type);
        Assert.Null(merged.OutstandingBurn);
        Assert.Equal("late burn", Assert.Single(merged.Burns).Reason);
    }

    [Fact]
    public void BurnThenDelete_StaysDeleted_TheBurnIsHistory()
    {
        var v1 = S(1000);
        var merged = MergeBothWays(Value(v1, "v", Burn(v1, S(2000), "burn")), Tombstone(S(3000, 0, OriginB)));

        Assert.Equal(RecordType.Tombstone, merged.Type);
        Assert.Equal("burn", Assert.Single(merged.Burns).Reason);
    }

    [Fact]
    public void BurnHistories_MergeToTheSameTruncatedList_InBothOrders()
    {
        // 20 rotated-away versions, each burned once; half the burns known to each copy.
        var aBurns = new List<BurnEntry>();
        var bBurns = new List<BurnEntry>();
        for (var i = 0; i < 20; i++)
            (i % 2 == 0 ? aBurns : bBurns).Add(Burn(S(1000 + i * 10), S(1005 + i * 10, 0, i % 2 == 0 ? OriginA : OriginB), $"burn {i}"));
        var current = S(5000);
        var a = Value(current, "current", [.. aBurns]);
        var b = Value(current, "current", [.. bBurns]);

        var merged = MergeBothWays(a, b);

        Assert.Equal(RecordMerge.MaxBurns, merged.Burns.Count);
        // The 16 most recent burns: burn 4 .. burn 19.
        Assert.Equal(Enumerable.Range(4, 16).Select(i => $"burn {i}"), merged.Burns.Select(x => x.Reason));
    }

    [Fact]
    public void TheOutstandingBurn_IsNeverTruncatedAway()
    {
        var current = S(1000);
        var burns = Enumerable.Range(0, 20).Select(i => Burn(S(10 + i), S(2000 + i), $"old {i}")).ToList();
        burns.Add(Burn(current, S(1500), "current"));

        var normalized = Value(current, "v", [.. burns]);

        Assert.Equal(RecordMerge.MaxBurns, normalized.Burns.Count);
        Assert.Equal("current", normalized.OutstandingBurn!.Reason);
    }

    [Fact]
    public void Merge_KeepsTheLargerWriteStamp()
    {
        var a = Value(S(1000), "v") with { Write = S(4000) };
        var b = Value(S(1000), "v") with { Write = S(3000, 0, OriginB) };

        Assert.Equal(S(4000), RecordMerge.Merge(a, b).Write);
        Assert.Equal(S(4000), RecordMerge.Merge(b, a).Write);
    }
}
