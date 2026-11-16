using TswapCore.Fields;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Issue #311, task 2: the per-field merge of the <c>Fields</c> extension (<see cref="FieldMerge"/>,
/// spec "Merge" rules 2-5): the lineage stamp, newest change per field, equal-stamp damage, histories
/// as a union by identity with concurrent losers kept, trimmed to five.
/// </summary>
public sealed class FieldMergeTests
{
    private static readonly byte[] OriginA = [.. Enumerable.Repeat((byte)0xA1, 16)];
    private static readonly byte[] OriginB = [.. Enumerable.Repeat((byte)0xB2, 16)];

    private static Stamp At(long ms, uint logical = 0, byte[]? origin = null) => new(new Hlc(ms, logical), origin ?? OriginA);

    private static readonly FieldWho Claude = new("a1a1a1a1", "steve", Elevated: false, Terminal: false, By: "claude");
    private static readonly FieldWho Owner = new("b2b2b2b2", null, Elevated: true, Terminal: true, By: null);
    // Claude's origin with other details: same identity as Claude's changes, other content (damage only).
    private static readonly FieldWho ClaudeElevated = new("a1a1a1a1", "steve", Elevated: true, Terminal: false, By: "claude");

    private static FieldEntry Live(string name, string value, Stamp changed, FieldWho? who = null, params FieldChange[] history) =>
        new(name, value, Deleted: false, changed, who ?? Claude, history);

    private static FieldEntry Marker(string name, Stamp changed, FieldWho? who = null, params FieldChange[] history) =>
        new(name, null, Deleted: true, changed, who ?? Claude, history);

    private static FieldSet Set(Stamp since, params FieldEntry[] entries) => new(since, entries);

    private static byte[] Bytes(FieldSet set) => FieldsCodec.Encode(set);

    /// <summary>Merges <paramref name="inputs"/> in every order, asserts identical bytes, returns the result.</summary>
    private static FieldSet MergeEveryOrder(params FieldSet[] inputs)
    {
        byte[]? first = null;
        FieldSet? result = null;
        foreach (var order in Permutations(inputs))
        {
            var merged = FieldMerge.Merge(order);
            var bytes = Bytes(merged);
            first ??= bytes;
            result ??= merged;
            Assert.True(first.AsSpan().SequenceEqual(bytes), "FieldMerge depends on the order of its inputs");
        }
        return result!;
    }

    private static IEnumerable<List<T>> Permutations<T>(IReadOnlyList<T> items)
    {
        if (items.Count <= 1)
        {
            yield return [.. items];
            yield break;
        }
        for (var i = 0; i < items.Count; i++)
        {
            var rest = items.Where((_, j) => j != i).ToList();
            foreach (var tail in Permutations(rest))
                yield return [items[i], .. tail];
        }
    }

    private static readonly Stamp[] StampPool =
        [At(1000), At(1000, 0, OriginB), At(2000), At(3000), At(3000, 0, OriginB), At(4000), At(5000), At(5000, 0, OriginB), At(6000)];
    private static readonly Stamp[] SincePool = [Stamp.Zero, At(1000), At(2500), At(3000, 0, OriginB)];
    private static readonly string[] NamePool = ["a", "b", "c"];
    private static readonly string?[] ValuePool = ["x", "y", "x2", "é", null];
    private static readonly FieldWho[] WhoPool = [Claude, Owner, ClaudeElevated];

    /// <summary>
    /// A random <b>valid</b> set as a write produces it (canonical: every entry and history change at or
    /// after its <c>Since</c>, each history older than its entry, of distinct identities, at most three long),
    /// drawn from small pools so equal stamps, equal identities and lineage drops are common.
    /// </summary>
    internal static FieldSet RandomSet(Random random)
    {
        var since = SincePool[random.Next(SincePool.Length)];
        List<FieldEntry> entries = [];
        foreach (var name in NamePool)
        {
            if (random.Next(3) == 0)
                continue;
            var stamps = StampPool.Where(s => s.CompareTo(since) >= 0).ToArray();
            if (stamps.Length == 0)
                continue;
            var changed = stamps[random.Next(stamps.Length)];
            var who = WhoPool[random.Next(WhoPool.Length)];
            List<FieldChange> history = [];
            var older = StampPool.Where(s => s.CompareTo(changed) < 0 && s.CompareTo(since) >= 0).ToList();
            for (var h = random.Next(4); h > 0 && older.Count > 0; h--)
            {
                var at = older[random.Next(older.Count)];
                var by = WhoPool[random.Next(WhoPool.Length)];
                if (history.Any(c => c.Changed.Equals(at) && c.Who.Origin == by.Origin))
                    continue;
                history.Add(new FieldChange(ValuePool[random.Next(ValuePool.Length)], at, by));
            }
            var value = ValuePool[random.Next(ValuePool.Length)];
            entries.Add(new FieldEntry(name, value, value is null, changed, who, history));
        }
        // Through the codec, so the set is in canonical order.
        return FieldsCodec.Decode(FieldsCodec.Encode(new FieldSet(since, entries)));
    }

    [Fact]
    public void FieldMerge_Commutative_Idempotent_ThreeOrders()
    {
        var random = new Random(3_11);
        int threeWay = 0, equalStampConflicts = 0, losers = 0, droppedBySince = 0, trimmed = 0;
        for (var round = 0; round < 400; round++)
        {
            var inputs = Enumerable.Range(0, random.Next(1, 4)).Select(_ => RandomSet(random)).ToArray();
            var merged = MergeEveryOrder(inputs);
            var mergedBytes = Bytes(merged);

            // Idempotent, byte for byte: Merge([x, x]) == x, Merge([Merge(xs), x]) == Merge(xs).
            foreach (var x in inputs)
            {
                Assert.Equal(Bytes(x), Bytes(FieldMerge.Merge([x, x])));
                Assert.Equal(mergedBytes, Bytes(FieldMerge.Merge([merged, x])));
            }
            Assert.Equal(mergedBytes, Bytes(FieldMerge.Merge([merged, merged])));
            if (inputs.Length >= 2)
                Assert.Equal(Bytes(FieldMerge.Merge([inputs[0], inputs[1]])),
                    Bytes(FieldMerge.Merge([FieldMerge.Merge([inputs[0], inputs[1]]), inputs[1]])));

            // What the round exercised.
            threeWay += inputs.Length == 3 ? 1 : 0;
            var since = inputs.Select(s => s.Since).Aggregate(Stamp.Max);
            droppedBySince += inputs.Any(s => s.Entries.Any(e => e.Changed.CompareTo(since) < 0)) ? 1 : 0;
            var candidates = inputs.SelectMany(s => s.Entries).Where(e => e.Changed.CompareTo(since) >= 0).GroupBy(e => e.Name).ToList();
            losers += candidates.Any(g => g.Select(e => (e.Value, e.Changed, e.Who)).Distinct().Count() > 1) ? 1 : 0;
            equalStampConflicts += candidates.Any(g =>
            {
                var top = g.Select(e => e.Changed).Aggregate(Stamp.Max);
                return g.Where(e => e.Changed.Equals(top)).Select(e => (e.Value, e.Who)).Distinct().Count() > 1;
            }) ? 1 : 0;
            trimmed += candidates.Any(g => g.SelectMany(e => e.History.Select(c => (c.Changed, c.Who.Origin)))
                .Concat(g.Select(e => (e.Changed, e.Who.Origin))).Distinct().Count() > FieldsCodec.MaxHistory + 1) ? 1 : 0;
        }

        Assert.True(threeWay > 100 && equalStampConflicts > 20 && losers > 100 && droppedBySince > 50 && trimmed > 10,
            $"three-way {threeWay}, equal-stamp conflicts {equalStampConflicts}, losers {losers}, dropped {droppedBySince}, trimmed {trimmed}");
    }

    [Fact]
    public void FieldMerge_IdenticalCopies_NoHistoryAdded()
    {
        var x = Set(At(500), Live("host", "db", At(5000), Claude, new FieldChange("old", At(4000), Owner)), Marker("port", At(4500), Owner));

        var merged = MergeEveryOrder(x, x, x);

        Assert.Equal(Bytes(x), Bytes(merged));
        Assert.Equal([new FieldChange("old", At(4000), Owner)], merged.Get("host")!.History);
        Assert.Empty(merged.Get("port")!.History);
    }

    [Fact]
    public void FieldMerge_DeleteMarkerNewer_Wins()
    {
        var edited = Set(At(500), Live("host", "db", At(5000), Claude));
        var deleted = Set(At(500), Marker("host", At(6000, 0, OriginB), Owner, new FieldChange("db0", At(1000), Claude)));

        var host = MergeEveryOrder(edited, deleted).Get("host")!;

        Assert.True(host.Deleted);
        Assert.Null(host.Value);
        Assert.Equal(At(6000, 0, OriginB), host.Changed);
        Assert.Equal(Owner, host.Who);
        Assert.Equal([new FieldChange("db", At(5000), Claude), new FieldChange("db0", At(1000), Claude)], host.History);
    }

    [Fact]
    public void FieldMerge_LaterEdit_RestoresDeleted()
    {
        var deleted = Set(At(500), Marker("host", At(5000), Owner));
        var edited = Set(At(500), Live("host", "db2", At(6000), Claude));
        var olderEdit = Set(At(500), Live("host", "db1", At(4000), Claude));

        var host = MergeEveryOrder(deleted, edited).Get("host")!;
        Assert.False(host.Deleted);
        Assert.Equal("db2", host.Value);
        Assert.Equal([new FieldChange(null, At(5000), Owner)], host.History);

        // An older edit can't restore it.
        var stillDeleted = MergeEveryOrder(deleted, olderEdit).Get("host")!;
        Assert.True(stillDeleted.Deleted);
        Assert.Equal([new FieldChange("db1", At(4000), Claude)], stillDeleted.History);
    }

    /// <summary>
    /// Review Focus 4: two machines change one field from the same base; the newer change wins and the
    /// older one's value lands in the winner's history with its own stamp and who, beside the base.
    /// </summary>
    [Fact]
    public void FieldMerge_SameFieldConcurrent_NewerWinsLoserInHistory()
    {
        var baseChange = new FieldChange("v0", At(1000), Owner);
        var onA = Set(At(500), Live("host", "vA", At(5000), Claude, baseChange));
        var onB = Set(At(500), Live("host", "vB", At(5100, 0, OriginB), Owner, baseChange));

        var merged = MergeEveryOrder(onA, onB);

        var host = Assert.Single(merged.Entries);
        Assert.Equal("vB", host.Value);
        Assert.Equal(At(5100, 0, OriginB), host.Changed);
        Assert.Equal(Owner, host.Who);
        Assert.Equal([new FieldChange("vA", At(5000), Claude), baseChange], host.History);
        // A second merge with either copy adds nothing.
        Assert.Equal(Bytes(merged), Bytes(FieldMerge.Merge([merged, onA, onB])));
    }

    [Fact]
    public void FieldMerge_EqualStamps_Converge()
    {
        // Same stamp, different values: the smallest value bytes win ("aa" < "b", although "b" is shorter),
        // and the other lands in the history with the same identity (what `field show` reports as damage).
        var b = Set(At(500), Live("host", "b", At(5000), Claude));
        var aa = Set(At(500), Live("host", "aa", At(5000), Claude));

        var host = MergeEveryOrder(b, aa).Get("host")!;

        Assert.Equal("aa", host.Value);
        Assert.Equal([new FieldChange("b", At(5000), Claude)], host.History);

        // Same stamp, a value and a marker: the value (deleted flag 0) is smaller.
        var marker = Set(At(500), Marker("host", At(5000), Claude));
        var valueWins = MergeEveryOrder(b, marker).Get("host")!;
        Assert.Equal("b", valueWins.Value);
        Assert.Equal([new FieldChange(null, At(5000), Claude)], valueWins.History);

        // Same stamp and value, different who: the smaller who encoding decides, in every order.
        var elevated = Set(At(500), Live("host", "b", At(5000), ClaudeElevated));
        var whoDecided = MergeEveryOrder(b, elevated).Get("host")!;
        Assert.Equal(Claude, whoDecided.Who); // who flags 0x00 before 0x01
        Assert.Equal([new FieldChange("b", At(5000), ClaudeElevated)], whoDecided.History);
    }

    [Fact]
    public void FieldMerge_HistoryTrimmedToFive()
    {
        var onA = Set(At(500), Live("host", "v", At(9000), Claude,
            new FieldChange("4", At(4000), Claude), new FieldChange("3", At(3000), Claude),
            new FieldChange("2", At(2000), Claude), new FieldChange("1", At(1000), Claude)));
        var onB = Set(At(500), Live("host", "v", At(9000), Claude,
            new FieldChange("3.5", At(3500), Owner), new FieldChange("2.5", At(2500), Owner), new FieldChange("1.5", At(1500), Owner)));

        var host = MergeEveryOrder(onA, onB).Get("host")!;

        Assert.Equal(["4", "3.5", "3", "2.5", "2"], host.History.Select(c => c.OldValue));
    }

    [Fact]
    public void FieldMerge_OlderThanSince_Dropped()
    {
        // An earlier life (since 1000) and the current one (since 3000): its entries and markers older
        // than 3000 are gone; an old-lineage change stamped after the re-creation lands (spec rule 2).
        var earlierLife = Set(At(1000), Live("host", "old", At(2000)), Marker("port", At(1500)), Live("note", "late", At(3500)));
        var current = Set(At(3000), Live("user", "u", At(4000), Owner));

        var merged = MergeEveryOrder(earlierLife, current);

        Assert.Equal(At(3000), merged.Since);
        Assert.Equal(["note", "user"], merged.Entries.Select(e => e.Name));
        Assert.Equal("late", merged.Get("note")!.Value);
    }

    /// <summary>Review M2 ruling: history entries older than the lineage stamp belong to an earlier life too.</summary>
    [Fact]
    public void FieldMerge_HistoryOlderThanSince_Dropped()
    {
        var earlier = Set(At(1000), Live("host", "v", At(5000), Claude,
            new FieldChange("at-since", At(3000), Owner), new FieldChange("before", At(2000), Owner)));
        var current = Set(At(3000), Live("user", "u", At(4000), Owner));

        var merged = MergeEveryOrder(earlier, current);

        Assert.Equal([new FieldChange("at-since", At(3000), Owner)], merged.Get("host")!.History);
        Assert.Empty(merged.Get("user")!.History);
    }

    [Fact]
    public void FieldMerge_EqualIdentityHistory_SmallestEncodingWins()
    {
        var withP = Set(At(500), Live("host", "v", At(5000), Claude, new FieldChange("p", At(4000), Claude)));
        var withQ = Set(At(500), Live("host", "v", At(5000), Claude, new FieldChange("q", At(4000), Claude)));

        var host = MergeEveryOrder(withP, withQ).Get("host")!;

        Assert.Equal([new FieldChange("p", At(4000), Claude)], host.History);
    }
}
