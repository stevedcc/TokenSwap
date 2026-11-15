using System.Text;
using TswapCore;
using TswapCore.Fields;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Issue #311 task 3: field writes through <see cref="VaultWriter"/> (spec "Writes"): a metadata-only
/// write that changes the record's write stamp and its <c>Fields</c> extension only, never its value
/// version or sections; the lineage anchor; histories; the caps; refusals on a missing or deleted
/// secret; legacy (format 2, 0.3.0-shaped) records.
/// </summary>
public sealed class FieldWriteTests : IDisposable
{
    private static readonly FieldWho Claude = new("a1a1a1a1", "steve", Elevated: false, Terminal: false, By: "claude");
    private static readonly FieldWho Owner = new("b2b2b2b2", "steve", Elevated: true, Terminal: true, By: null);

    private DateTimeOffset _now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
    private readonly FleetMachine _m;
    private readonly byte[] _key;

    public FieldWriteTests()
    {
        _m = new FleetMachine("field-writes", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
        _key = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    private RecordVaultStore NewStore() => new(_m.Dir, time: new FuncTimeProvider(() => _now), warnings: TextWriter.Null);

    private VaultWriter Writer() => new(NewStore(), _key, TextWriter.Null);

    private SecretRecord Read(string name) => ReadRecord(_m, _key, name);

    private byte[] Bytes(string name) => File.ReadAllBytes(RecordFile(_m, _key, name));

    private void Plant(string name, Func<SecretRecord, SecretRecord> change, byte format = KeyringFormat.RecordFormatVersion)
    {
        var path = RecordFile(_m, _key, name);
        File.WriteAllBytes(path, SecretRecordCodec.Encode(change(SecretRecordCodec.Decode(File.ReadAllBytes(path), _key)), _key, format));
    }

    private IReadOnlyDictionary<string, SecretInfo?> SetFields(string name, FieldWho who, params FieldEdit[] edits)
    {
        _now = _now.AddSeconds(1);
        using var writer = Writer();
        writer.SetFields(name, edits, who);
        return writer.Commit();
    }

    private FieldSet? FieldsOf(string name)
    {
        using var writer = Writer();
        return writer.Fields(name);
    }

    private static FieldSet FieldsIn(SecretRecord record) => Assert.IsType<FieldSet>(FieldsCodec.TryGet(record.Extensions));

    [Fact]
    public void SetFields_KeepsVersionAndValue_ChangesWriteOnly()
    {
        _m.Ok("the-value", "ingest", "s");
        var before = Read("s");
        var sectionsBefore = ValueSections(Bytes("s"));

        var written = SetFields("s", Claude, new FieldEdit("owner", "platform"));

        Assert.Contains("s", written.Keys);
        var after = Read("s");
        Assert.Equal(before.Version, after.Version);
        Assert.Equal(before.Value, after.Value);
        Assert.Equal(before.Type, after.Type);
        Assert.Equal(before.Burns, after.Burns);
        Assert.Equal(before.Fingerprints, after.Fingerprints);
        Assert.Equal(before.CreatedMs, after.CreatedMs);
        Assert.True(after.Write.CompareTo(before.Write) > 0, $"write stamp {after.Write} not after {before.Write}");
        Assert.Equal(sectionsBefore, ValueSections(Bytes("s")));
        var fields = FieldsIn(after);
        Assert.Equal(before.Version, fields.Since);
        var entry = Assert.Single(fields.Entries);
        Assert.Equal(("owner", "platform", false, Claude), (entry.Name, entry.Value, entry.Deleted, entry.Who));
        Assert.True(entry.Changed.CompareTo(fields.Since) > 0);
    }

    [Fact]
    public void SetFields_DoesNotChangeTokenResolution()
    {
        _m.Ok("the-value", "ingest", "s");

        SetFields("s", Claude, new FieldEdit("owner", "{{s}}"), new FieldEdit("kind", "token"));

        using var view = new VaultView(NewStore(), _key, TextWriter.Null);
        Assert.Equal("the-value", view.ResolveToken("s"));
        Assert.Equal("the-value", _m.Get("s"));
        Assert.Equal("{{s}}", view.Fields("s")!.Get("owner")!.Value);
        Assert.Equal("token", view.Fields("s")!.Get("kind")!.Value);
    }

    [Fact]
    public void SetFields_OnMissingName_Refused()
    {
        using var writer = Writer();
        var error = Assert.Throws<TswapException>(() => writer.SetFields("nope", [new FieldEdit("owner", "x")], Claude));
        Assert.Equal("No secret 'nope'.", error.Message);
        Assert.Null(writer.Fields("nope"));
    }

    [Fact]
    public void SetFields_OnTombstone_Refused()
    {
        _m.Ok("v", "ingest", "s");
        SetFields("s", Claude, new FieldEdit("owner", "x"));
        _m.Ok("", "delete", "s");
        var before = Bytes("s");

        using (var writer = Writer())
        {
            var error = Assert.Throws<TswapException>(() => writer.SetFields("s", [new FieldEdit("owner", "y")], Claude));
            Assert.Equal("No secret 's'.", error.Message);
            Assert.Null(writer.Fields("s"));
            Assert.Empty(writer.Commit());
        }
        Assert.Equal(before, Bytes("s"));
    }

    [Fact]
    public void SetFields_UnchangedValue_WritesNothing()
    {
        _m.Ok("v", "ingest", "s");
        SetFields("s", Claude, new FieldEdit("owner", "x"));
        var before = Bytes("s");

        // The same value, and a removal of a field that isn't there: no stamp, no history, no write.
        var written = SetFields("s", Owner, new FieldEdit("owner", "x"), new FieldEdit("kind", null));

        Assert.Empty(written);
        Assert.Equal(before, Bytes("s"));
        var entry = Assert.Single(FieldsOf("s")!.Entries);
        Assert.Equal(Claude, entry.Who);
        Assert.Empty(entry.History);
    }

    [Fact]
    public void SetFields_WritesHistory_OldValueWhoAndStamp_OldChangesTrimmed()
    {
        _m.Ok("v", "ingest", "s");
        var since = FieldsIn(Read("s")).Since;
        FieldWho[] whos = [Claude, Owner, Claude with { By = "codex" }, Owner with { Terminal = false }, Claude, Owner, Claude with { Elevated = true }];
        List<Stamp> stamps = [];
        for (var i = 0; i < 7; i++)
        {
            SetFields("s", whos[i], new FieldEdit("owner", $"team-{i}"));
            stamps.Add(FieldsOf("s")!.Get("owner")!.Changed);
        }

        var fields = FieldsIn(Read("s"));
        var entry = Assert.Single(fields.Entries);
        Assert.Equal("team-6", entry.Value);
        Assert.Equal(stamps[6], entry.Changed);
        Assert.Equal(whos[6], entry.Who);
        // The five replaced states before it, newest first; the first change is trimmed.
        Assert.Equal(
            [.. Enumerable.Range(1, 5).Reverse().Select(i => new FieldChange($"team-{i}", stamps[i], whos[i]))],
            entry.History);
        Assert.Equal(7, stamps.Distinct().Count());
        Assert.All(stamps, s => Assert.True(s.CompareTo(since) > 0, $"{s} not after since {since}"));
        Assert.Equal(since, fields.Since);
    }

    [Fact]
    public void SetFields_Remove_LeavesAMarker_AndASetRestoresIt()
    {
        _m.Ok("v", "ingest", "s");
        SetFields("s", Claude, new FieldEdit("owner", "x"));
        var set = FieldsOf("s")!.Get("owner")!;

        SetFields("s", Owner, new FieldEdit("owner", null));
        var marker = FieldsOf("s")!.Get("owner")!;
        SetFields("s", Claude, new FieldEdit("owner", "y"));
        var restored = FieldsOf("s")!.Get("owner")!;

        Assert.True(marker.Deleted);
        Assert.Null(marker.Value);
        Assert.Equal(Owner, marker.Who);
        Assert.Equal([new FieldChange("x", set.Changed, Claude)], marker.History);
        Assert.Equal("y", restored.Value);
        Assert.Equal([new FieldChange(null, marker.Changed, Owner), new FieldChange("x", set.Changed, Claude)], restored.History);
    }

    [Fact]
    public void SetFields_OverCap_GrowingRefused_ShrinkingAllowed()
    {
        _m.Ok("v", "ingest", "s");
        var since = FieldsIn(Read("s")).Since;
        var at = new Stamp(new Hlc(since.Hlc.PhysicalMs + 1, 0), since.Origin);
        // Over the 64-field cap, as only a merge of two legal copies makes it (spec Merge rule 7).
        Plant("s", r => r with
        {
            Extensions = FieldsCodec.With(r.Extensions, new FieldSet(since,
                [.. Enumerable.Range(0, 66).Select(i => new FieldEntry($"f{i:D2}", "value-long", false, at, Claude, []))])),
        });
        var before = Bytes("s");

        AssertRefused(new FieldEdit("new", "x"), "would have 67 fields");
        AssertRefused(new FieldEdit("f00", "value-longer"), "would have 66 fields");
        AssertRefused(new FieldEdit("f00", "value-lon2"), "would have 66 fields"); // as long is not shorter
        Assert.Equal(before, Bytes("s"));

        SetFields("s", Owner, new FieldEdit("f00", null));
        Assert.Equal(65, FieldsOf("s")!.Live.Count());
        SetFields("s", Owner, new FieldEdit("f01", "short"));
        Assert.Equal("short", FieldsOf("s")!.Get("f01")!.Value);

        // Under the caps a write may grow: 65 → 63 live, one more is 64, the next one (65) is refused.
        SetFields("s", Owner, new FieldEdit("f02", null), new FieldEdit("f03", null));
        Assert.Equal(63, FieldsOf("s")!.Live.Count());
        SetFields("s", Owner, new FieldEdit("new", "x"));
        AssertRefused(new FieldEdit("new2", "x"), "would have 65 fields");

        void AssertRefused(FieldEdit edit, string cap)
        {
            using var writer = Writer();
            writer.SetFields("s", [edit], Claude);
            var error = Assert.Throws<TswapException>(() => writer.Commit());
            Assert.Contains("'s'", error.Message);
            Assert.Contains(cap, error.Message);
            Assert.Contains($"at most {FieldRules.MaxLiveFields}", error.Message);
        }
    }

    [Fact]
    public void SetFields_OverByteCap_GrowingRefused_ShrinkingAllowed()
    {
        _m.Ok("v", "ingest", "s");
        var since = FieldsIn(Read("s")).Since;
        var at = new Stamp(new Hlc(since.Hlc.PhysicalMs + 1, 0), since.Origin);
        var big = new string('a', FieldRules.MaxValueLength);
        Plant("s", r => r with
        {
            Extensions = FieldsCodec.With(r.Extensions, new FieldSet(since,
                [.. Enumerable.Range(0, 17).Select(i => new FieldEntry($"f{i:D2}", big, false, at, Claude, []))])),
        });
        Assert.True(FieldsCodec.Encode(FieldsIn(Read("s"))).Length > FieldRules.MaxEncodedBytes);

        using (var writer = Writer())
        {
            writer.SetFields("s", [new FieldEdit("tiny", "x")], Claude);
            var error = Assert.Throws<TswapException>(() => writer.Commit());
            Assert.Contains("'s'", error.Message);
            Assert.Contains($"at most {FieldRules.MaxEncodedBytes}", error.Message);
        }

        // A shorter value shrinks the live fields, though its old value moves into the history.
        SetFields("s", Owner, new FieldEdit("f00", "short"));
        Assert.Equal("short", FieldsOf("s")!.Get("f00")!.Value);
    }

    [Fact]
    public void ValueWrite_SameValue_WithEdits_WritesFieldsOnly()
    {
        _m.Ok("the-value", "ingest", "s");
        var before = Read("s");

        _now = _now.AddSeconds(1);
        using (var writer = Writer())
        {
            writer.SetValue("s", "the-value", _now.UtcDateTime, fields: [new FieldEdit("owner", "x")], who: Claude);
            Assert.Contains("s", writer.Commit().Keys);
        }

        var after = Read("s");
        Assert.Equal(before.Version, after.Version);
        Assert.Equal(before.Value, after.Value);
        Assert.True(after.Write.CompareTo(before.Write) > 0);
        Assert.Equal("x", FieldsIn(after).Get("owner")!.Value);
        Assert.Equal(before.Version, FieldsIn(after).Since);
    }

    [Fact]
    public void ValueWrite_NewValue_WithEdits_KeepsSince_ChangeAfterTheNewVersion()
    {
        _m.Ok("v1", "ingest", "s");
        var created = Read("s");

        _now = _now.AddSeconds(1);
        using (var writer = Writer())
        {
            writer.SetValue("s", "v2", _now.UtcDateTime, always: true, fields: [new FieldEdit("owner", "x")], who: Claude);
            writer.Commit();
        }

        var after = Read("s");
        Assert.True(after.Version.CompareTo(created.Version) > 0);
        var fields = FieldsIn(after);
        Assert.Equal(created.Version, fields.Since);
        Assert.True(fields.Get("owner")!.Changed.CompareTo(after.Version) > 0);
    }

    [Fact]
    public void Create_WithFields_SinceIsTheVersion_ChangesAfterIt()
    {
        using (var writer = Writer())
        {
            writer.SetValue("s", "v", _now.UtcDateTime, fields: [new FieldEdit("owner", "x"), new FieldEdit("kind", "token")], who: Claude);
            writer.Commit();
        }

        var record = Read("s");
        var fields = FieldsIn(record);
        Assert.Equal(record.Version, fields.Since);
        Assert.Equal(["kind", "owner"], fields.Entries.Select(e => e.Name));
        Assert.All(fields.Entries, e => Assert.True(e.Changed.CompareTo(record.Version) > 0));
        Assert.NotEqual(fields.Entries[0].Changed, fields.Entries[1].Changed);
    }

    [Fact]
    public void SetFields_LegacyRecord_SinceZero()
    {
        _m.Ok("v", "ingest", "s");
        Plant("s", r => r with { Extensions = [] }); // written before fields existed

        Assert.Empty(FieldsOf("s")!.Entries);
        SetFields("s", Claude, new FieldEdit("owner", "x"));

        var fields = FieldsIn(Read("s"));
        Assert.Equal(Stamp.Zero, fields.Since);
        Assert.Equal("x", fields.Get("owner")!.Value);
    }

    /// <summary>
    /// The spec's "0.3.0-shaped record round trip": a record carrying only a later build's extension
    /// gets a field write, then is merged with its old copy; the unknown extension keeps its bytes and
    /// its place, the fields survive, in both merge paths.
    /// </summary>
    [Fact]
    public void SetFields_OverZeroThreeShapedRecord_KeepsUnknownExtension()
    {
        _m.Ok("v", "ingest", "s");
        var unknown = new RecordExtension(0x7777, [9, 8, 7, 6]);
        Plant("s", r => r with { Extensions = [unknown] });
        var old = Bytes("s");

        SetFields("s", Claude, new FieldEdit("owner", "x"));

        var written = Read("s");
        Assert.Equal(unknown, written.Extensions[0]);
        Assert.Equal(2, written.Extensions.Count);
        var copies = new[] { Bytes("s"), old };
        var merged = RecordMerge.MergeAll([.. copies.Select(b => SecretRecordCodec.Decode(b, _key))]);
        var mergedMetadata = RecordMerge.MergeAllMetadata([.. copies.Select(b => SecretRecordCodec.DecodeMetadataAndSections(b, _key)!.Value)]).Metadata;
        foreach (var extensions in new[] { merged.Extensions, mergedMetadata.Extensions })
        {
            Assert.Equal(unknown, extensions[0]);
            Assert.Equal(FieldsExtension.Type, extensions[1].Type);
            Assert.Equal("x", FieldsCodec.TryGet(extensions)!.Get("owner")!.Value);
        }
    }

    [Fact]
    public void SetFields_FormatTwoRecord_ConvertedToV3()
    {
        using var m = new FleetMachine("field-writes-v2", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
        var key = VaultKey(m, InitFormatTwoVault(m));
        m.Ok("the-value", "ingest", "s");
        var path = RecordFile(m, key, "s");
        Assert.Equal((byte?)2, SecretRecordCodec.FormatVersionOf(File.ReadAllBytes(path)));
        var before = SecretRecordCodec.Decode(File.ReadAllBytes(path), key);

        _now = _now.AddSeconds(1);
        int formatTwo;
        using (var writer = new VaultWriter(new RecordVaultStore(m.Dir, time: new FuncTimeProvider(() => _now), warnings: TextWriter.Null), key,
                   TextWriter.Null))
        {
            writer.SetFields("s", [new FieldEdit("owner", "x")], Claude);
            writer.Commit();
            formatTwo = writer.FormatTwoDecoded;
        }

        Assert.Equal(1, formatTwo); // the commands' WarnFormatTwo(..., FormatTwoUse.Write) reports it
        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(File.ReadAllBytes(path)));
        var after = SecretRecordCodec.Decode(File.ReadAllBytes(path), key);
        Assert.Equal(before.Version, after.Version);
        Assert.Equal("the-value", Encoding.UTF8.GetString(after.Value));
        Assert.Equal(Fingerprints(key, after.Value), after.Fingerprints);
        var fields = FieldsIn(after);
        Assert.Equal(Stamp.Zero, fields.Since); // format 2 had no anchor
        Assert.Equal("x", fields.Get("owner")!.Value);
        Assert.Equal("the-value", m.Get("s"));
    }

    [Fact]
    public void Create_WithFields_InAnUnmarkedFolder_WritesV3()
    {
        using var m = new FleetMachine("field-writes-unmarked", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
        var key = VaultKey(m, InitFormatTwoVault(m));

        using (var writer = new VaultWriter(new RecordVaultStore(m.Dir, time: new FuncTimeProvider(() => _now), warnings: TextWriter.Null), key,
                   TextWriter.Null))
        {
            writer.SetValue("s", "v", _now.UtcDateTime, fields: [new FieldEdit("owner", "x")], who: Claude);
            writer.Commit();
        }

        var bytes = File.ReadAllBytes(RecordFile(m, key, "s"));
        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(bytes));
        var record = SecretRecordCodec.Decode(bytes, key);
        Assert.Equal(record.Version, FieldsIn(record).Since);
        Assert.Equal("x", FieldsIn(record).Get("owner")!.Value);
    }
}
