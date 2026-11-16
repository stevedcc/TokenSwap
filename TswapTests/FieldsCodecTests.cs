using TswapCore;
using TswapCore.Fields;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Issue #311, task 1: the <c>Fields</c> extension's deterministic encoding (<see cref="FieldsCodec"/>)
/// and its place in a record's extension list.
/// </summary>
public sealed class FieldsCodecTests
{
    private static readonly byte[] OriginA = [.. Enumerable.Repeat((byte)0xA1, 16)];
    private static readonly byte[] OriginB = [.. Enumerable.Repeat((byte)0xB2, 16)];

    private static Stamp At(long ms, uint logical = 0, byte[]? origin = null) => new(new Hlc(ms, logical), origin ?? OriginA);

    private static readonly FieldWho Claude = new("a1a1a1a1", "steve", Elevated: false, Terminal: false, By: "claude");
    private static readonly FieldWho Owner = new("b2b2b2b2", null, Elevated: true, Terminal: true, By: null);

    private static FieldEntry Live(string name, string value, Stamp changed, FieldWho? who = null, params FieldChange[] history) =>
        new(name, value, Deleted: false, changed, who ?? Claude, history);

    private static FieldEntry Marker(string name, Stamp changed, FieldWho? who = null, params FieldChange[] history) =>
        new(name, null, Deleted: true, changed, who ?? Claude, history);

    /// <summary>Every part of the model in use: values, a marker, histories with null and multi-line old values.</summary>
    private static FieldSet Rich() => new(At(1000, 2, OriginB),
    [
        Live("host", "db.example", At(5000), Owner,
            new FieldChange("old-host", At(4000), Claude),
            new FieldChange(null, At(3000, 1, OriginB), Owner)),
        Marker("port", At(6000, 0, OriginB), Owner,
            new FieldChange("5432", At(2000), Claude)),
        Live("rotate", "line one\nline two é", At(7000), Claude),
        Live("username", "admin", At(8000, 7), new FieldWho("c3c3c3c3", @"DOMAIN\user", true, false, "owner")),
    ]);

    [Fact]
    public void FieldsCodec_RoundTrip_PreservesEverything()
    {
        var set = Rich();

        var decoded = FieldsCodec.Decode(FieldsCodec.Encode(set));

        Assert.Equal(At(1000, 2, OriginB), decoded.Since);
        Assert.Equal(4, decoded.Entries.Count);
        Assert.Equal(set, decoded);

        var host = decoded.Get("host")!;
        Assert.Equal("db.example", host.Value);
        Assert.False(host.Deleted);
        Assert.Equal(At(5000), host.Changed);
        Assert.Equal(Owner, host.Who);
        Assert.Equal([new FieldChange("old-host", At(4000), Claude), new FieldChange(null, At(3000, 1, OriginB), Owner)], host.History);

        var port = decoded.Get("port")!;
        Assert.True(port.Deleted);
        Assert.Null(port.Value);
        Assert.Equal(At(6000, 0, OriginB), port.Changed);

        Assert.Equal("line one\nline two é", decoded.Get("rotate")!.Value);
        Assert.Equal(new FieldWho("c3c3c3c3", @"DOMAIN\user", true, false, "owner"), decoded.Get("username")!.Who);

        Assert.Equal(["host", "rotate", "username"], decoded.Live.Select(e => e.Name));
        Assert.Null(decoded.Get("missing"));
    }

    [Fact]
    public void FieldsCodec_RoundTrip_EmptySetKeepsSince()
    {
        var set = new FieldSet(At(42, 3), []);

        var decoded = FieldsCodec.Decode(FieldsCodec.Encode(set));

        Assert.Equal(At(42, 3), decoded.Since);
        Assert.Empty(decoded.Entries);
    }

    [Fact]
    public void FieldsCodec_EntryOrder_DoesNotChangeBytes()
    {
        var h1 = new FieldChange("v1", At(1000), Claude);
        var h2 = new FieldChange("v2", At(2000), Claude);
        var h3a = new FieldChange("v3a", At(3000), Claude);  // same stamp, two origins: ordered by origin
        var h3b = new FieldChange("v3b", At(3000), Owner);
        var forward = new FieldSet(At(1),
        [
            Live("alpha", "a", At(9000), Claude, h3a, h3b, h2, h1),
            Live("beta", "b", At(9000)),
            Marker("gamma", At(9000)),
        ]);
        var shuffled = new FieldSet(At(1),
        [
            Marker("gamma", At(9000)),
            Live("beta", "b", At(9000)),
            Live("alpha", "a", At(9000), Claude, h1, h3b, h2, h3a),
        ]);

        var bytes = FieldsCodec.Encode(forward);

        Assert.Equal(bytes, FieldsCodec.Encode(shuffled));
        var decoded = FieldsCodec.Decode(bytes);
        Assert.Equal(["alpha", "beta", "gamma"], decoded.Entries.Select(e => e.Name));
        Assert.Equal(["v3b", "v3a", "v2", "v1"], decoded.Get("alpha")!.History.Select(h => h.OldValue));
    }

    [Fact]
    public void FieldsCodec_Names_SortOrdinally()
    {
        // Ordinal, not culture: '-' (0x2D) sorts before '0' (0x30) before '_' (0x5F) before 'a'.
        var set = new FieldSet(At(1), [Live("a", "1", At(2)), Live("_x", "2", At(2)), Live("0x", "3", At(2)), Live("-x", "4", At(2))]);

        var decoded = FieldsCodec.Decode(FieldsCodec.Encode(set));

        Assert.Equal(["-x", "0x", "_x", "a"], decoded.Entries.Select(e => e.Name));
    }

    [Fact]
    public void FieldsCodec_Encode_DuplicateNames_Throws()
    {
        var set = new FieldSet(At(1), [Live("user", "a", At(2)), Live("user", "b", At(3))]);

        var ex = Assert.Throws<ArgumentException>(() => FieldsCodec.Encode(set));
        Assert.Contains("'user'", ex.Message);
    }

    [Fact]
    public void FieldsCodec_With_ReplacesOnlyFields()
    {
        var before = new RecordExtension(0x7777, [1, 2, 3]);
        var after = new RecordExtension(0x7777, [4, 5]);
        var oldFields = new FieldSet(At(1), [Live("user", "old", At(2))]);
        var newFields = new FieldSet(At(1), [Live("user", "new", At(3))]);
        IReadOnlyList<RecordExtension> list = [before, new(FieldsExtension.Type, FieldsCodec.Encode(oldFields)), after];

        var replaced = FieldsCodec.With(list, newFields);

        Assert.Equal(3, replaced.Count);
        Assert.Equal(before, replaced[0]);
        Assert.Equal(new RecordExtension(FieldsExtension.Type, FieldsCodec.Encode(newFields)), replaced[1]);
        Assert.Equal(after, replaced[2]);
        Assert.Equal("new", FieldsCodec.TryGet(replaced)!.Get("user")!.Value);

        var removed = FieldsCodec.With(list, null);
        Assert.Equal([before, after], removed);
        Assert.Null(FieldsCodec.TryGet(removed));
    }

    [Fact]
    public void FieldsCodec_With_AddsFieldsAfterOthers()
    {
        var other = new RecordExtension(0x7777, [1]);
        var fields = new FieldSet(At(1), []);

        var added = FieldsCodec.With([other], fields);

        Assert.Equal([other, new RecordExtension(FieldsExtension.Type, FieldsCodec.Encode(fields))], added);
        Assert.Equal([other], FieldsCodec.With([other], null));
    }

    [Fact]
    public void FieldsCodec_TryGet_WithoutFields_IsNull()
    {
        Assert.Null(FieldsCodec.TryGet([]));
        Assert.Null(FieldsCodec.TryGet([new RecordExtension(0x7777, [1])]));
    }

    [Fact]
    public void FieldsCodec_Decode_Malformed_Throws()
    {
        var bytes = FieldsCodec.Encode(Rich());

        for (var length = 0; length < bytes.Length; length++)
        {
            var ex = Assert.Throws<TswapException>(() => FieldsCodec.Decode(bytes.AsSpan(0, length)));
            Assert.StartsWith("Malformed record: fields extension", ex.Message);
        }
    }

    [Fact]
    public void FieldsCodec_Decode_TrailingBytes_Throws()
    {
        var bytes = FieldsCodec.Encode(Rich());

        var ex = Assert.Throws<TswapException>(() => FieldsCodec.Decode([.. bytes, 0]));
        Assert.StartsWith("Malformed record: fields extension", ex.Message);
    }

    [Fact]
    public void FieldsCodec_Decode_UnknownVersion_Throws()
    {
        var bytes = FieldsCodec.Encode(new FieldSet(At(1), []));
        bytes[0] = 2;

        var ex = Assert.Throws<TswapException>(() => FieldsCodec.Decode(bytes));
        Assert.StartsWith("Malformed record: fields extension", ex.Message);
        Assert.Contains("version 2", ex.Message);
    }

    [Fact]
    public void FieldsCodec_Encode_TooLongHistory_Throws()
    {
        FieldChange[] six = [.. Enumerable.Range(1, 6).Select(i => new FieldChange($"v{i}", At(i), Claude))];

        var ex = Assert.Throws<ArgumentException>(() => FieldsCodec.Encode(new FieldSet(At(1), [Live("user", "x", At(100), Claude, six)])));
        Assert.Contains("6 history entries", ex.Message);
    }

    [Fact]
    public void FieldsCodec_Decode_TooLongHistory_Throws()
    {
        // Same-sized changes: the last entry's history count byte sits just before its five changes.
        FieldChange[] Changes(int n) => [.. Enumerable.Range(1, n).Select(i => new FieldChange($"v{i}", At(i), Claude))];
        var four = FieldsCodec.Encode(new FieldSet(At(1), [Live("user", "x", At(100), Claude, Changes(4))]));
        var five = FieldsCodec.Encode(new FieldSet(At(1), [Live("user", "x", At(100), Claude, Changes(5))]));
        var changeSize = five.Length - four.Length;
        five[five.Length - 5 * changeSize - 1] = 6;

        var ex = Assert.Throws<TswapException>(() => FieldsCodec.Decode(five));
        Assert.StartsWith("Malformed record: fields extension", ex.Message);
        Assert.Contains("6 history entries", ex.Message);
    }

    [Fact]
    public void FieldsCodec_TryGet_TwoFieldsExtensions_Throws()
    {
        var data = FieldsCodec.Encode(new FieldSet(At(1), []));

        var ex = Assert.Throws<TswapException>(() =>
            FieldsCodec.TryGet([new RecordExtension(FieldsExtension.Type, data), new RecordExtension(FieldsExtension.Type, data)]));
        Assert.StartsWith("Malformed record: fields extension", ex.Message);
    }
}
