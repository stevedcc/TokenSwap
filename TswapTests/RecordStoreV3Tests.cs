using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 6: the record store writes format 3 once the vault folder holds the
/// <c>record-format</c> marker (or a format 3 record was read), copies value sections byte for byte
/// on metadata-only writes, merges every copy of a record at once and treats a conflict as one
/// unreadable record, never a failed load.
/// </summary>
public sealed class RecordStoreV3Tests : IDisposable
{
    private readonly FleetMachine _m = new("store-v3", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly FleetMachine _other = new("store-v3-other", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _key;

    public RecordStoreV3Tests()
    {
        _key = VaultKey(_m, InitFormatTwoVault(_m));
    }

    public void Dispose()
    {
        _m.Dispose();
        _other.Dispose();
    }

    private string File(string name) => RecordFile(_m, _key, name);

    private byte[] Bytes(string name) => System.IO.File.ReadAllBytes(File(name));

    private SecretRecord Read(string name) => ReadRecord(_m, _key, name);

    private static void Plant(string path, SecretRecord record, byte[] key, byte format = 3) =>
        System.IO.File.WriteAllBytes(path, SecretRecordCodec.Encode(record, key, format));

    private Dictionary<string, string> RecordsSnapshot() =>
        Directory.GetFiles(_m.RecordsDir).ToDictionary(f => Path.GetFileName(f), f => Convert.ToHexString(System.IO.File.ReadAllBytes(f)));

    [Fact]
    public void NoMarker_WritesV2()
    {
        _m.Ok("", "create", "s");

        Assert.Equal((byte?)2, SecretRecordCodec.FormatVersionOf(Bytes("s")));
        Assert.Null(Read("s").Fingerprints);
    }

    [Fact]
    public void Marker_WritesV3WithFingerprints()
    {
        WriteMarker(_m);

        _m.Ok("", "create", "s");

        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(Bytes("s")));
        var record = Read("s");
        Assert.Equal(Fingerprints(_key, record.Value), record.Fingerprints);
        Assert.Equal(SecretVariants.CurrentSetVersion, record.Fingerprints!.VariantSetVersion);
        Assert.NotEmpty(record.Fingerprints.Entries);
    }

    [Fact]
    public void AnyV3RecordRead_WritesV3EvenWithoutMarker()
    {
        WriteMarker(_m);
        _m.Ok("a-value", "ingest", "a");
        System.IO.File.Delete(Path.Combine(_m.VaultDir!, RecordVaultStore.RecordFormatMarkerFileName));

        _m.Ok("b-value", "ingest", "b");

        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(Bytes("b")));
        var store = Store(_m);
        store.LoadSecrets(_key, TextWriter.Null);
        Assert.True(store.WritesV3);
    }

    [Theory]
    [InlineData("4")]
    [InlineData("99999999999")] // fix round 1 (GLM N1): a number above 3 that doesn't fit an int is still above 3
    public void MarkerNewerVersion_RefusesWrites(string marker)
    {
        _m.Ok("a-value", "ingest", "a");
        WriteMarker(_m, marker);
        var before = RecordsSnapshot();

        var (exit, _, err) = _m.Run("", "create", "s");
        var (burnExit, _, burnErr) = _m.Run("", "burn", "a", "r");

        Assert.NotEqual(0, exit);
        Assert.Contains("newer tswap", err);
        Assert.Contains("Upgrade tswap", err);
        Assert.Contains($"record format {marker},", err); // the marker's own digits, not a clamped number
        Assert.NotEqual(0, burnExit);
        Assert.Contains("newer tswap", burnErr);
        Assert.Equal(before, RecordsSnapshot());
        Assert.Equal("a-value", _m.Get("a")); // reading still works
    }

    /// <summary>
    /// Fix round 1 (GLM N2): only a format 3 record that decodes selects format 3 writes (ruling 3:
    /// "has read any v3 record"); a damaged file with a format 3 byte doesn't.
    /// </summary>
    [Fact]
    public void ADamagedFormat3File_DoesNotSelectFormat3()
    {
        _m.Ok("a-value", "ingest", "a");
        var damaged = SecretRecordCodec.Encode(Read("a") with { Name = "b", RecordId = FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(_key), "b") }, _key, 3);
        damaged[^1] ^= 0xFF; // fails authentication
        System.IO.File.WriteAllBytes(File("b"), damaged);

        _m.Ok("c-value", "ingest", "c");

        Assert.Equal((byte?)2, SecretRecordCodec.FormatVersionOf(Bytes("c")));
        var store = Store(_m);
        Assert.Contains(Path.GetFileName(File("b")), store.LoadSecrets(_key, TextWriter.Null).UnreadableFiles!);
        Assert.False(store.WritesV3);
    }

    [Fact]
    public void MarkerWithCrlfOrBom_IsV3()
    {
        System.IO.File.WriteAllBytes(Path.Combine(_m.VaultDir!, RecordVaultStore.RecordFormatMarkerFileName), [0xEF, 0xBB, 0xBF, (byte)'3', 0x0D, 0x0A]);

        _m.Ok("", "create", "s");

        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(Bytes("s")));
    }

    [Theory]
    [InlineData("")]
    [InlineData("x")]
    [InlineData("2")]
    public void MarkerEmptyGarbageOrBelow3_WarnsAndCountsAsAbsent(string content)
    {
        WriteMarker(_m, content);

        var (exit, _, err) = _m.Run("", "create", "s");

        Assert.True(exit == 0, err);
        Assert.Contains(RecordVaultStore.RecordFormatMarkerFileName, err);
        Assert.Contains("ignored", err);
        Assert.Contains("write 3 into it", err); // ruling 3's repair hint
        Assert.Contains("delete it", err);
        Assert.Equal((byte?)2, SecretRecordCodec.FormatVersionOf(Bytes("s")));
    }

    [Fact]
    public void MarkerConflictCopy_IsIgnored()
    {
        // Only a conflicted copy says 3: still format 2.
        System.IO.File.WriteAllText(Path.Combine(_m.VaultDir!, RecordVaultStore.RecordFormatMarkerFileName + " (1)"), "3");
        _m.Ok("a-value", "ingest", "a");
        Assert.Equal((byte?)2, SecretRecordCodec.FormatVersionOf(Bytes("a")));

        // The marker says 3 and a conflicted copy says 4: the copy doesn't block writes.
        WriteMarker(_m);
        System.IO.File.WriteAllText(Path.Combine(_m.VaultDir!, RecordVaultStore.RecordFormatMarkerFileName + ".sync-conflict-20261102-120000-ABCDEF"), "4");
        _m.Ok("b-value", "ingest", "b");
        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(Bytes("b")));
    }

    [Fact]
    public void Burn_CopiesValueSectionsByteForByte()
    {
        WriteMarker(_m);
        _m.Ok("s-1", "ingest", "s");
        _m.Ok("", "rotate", "s");
        _m.Ok("t-1", "ingest", "t");
        _m.Ok("", "rotate", "t");
        var sBefore = ValueSections(Bytes("s"));
        var tBefore = ValueSections(Bytes("t"));
        var (sWrite, tWrite) = (Read("s").Write, Read("t").Write);
        Assert.Equal(2, sBefore.Count);
        var otherVault = CopyVault(_m, _other);

        _m.Ok("", "burn", "s", "seen");
        // A vault merge that changes only burns: t is burned on the other copy.
        _other.Ok("", "burn", "t", "seen there");
        var (exit, _, err) = _m.Run("", "vault", "merge", otherVault);
        Assert.True(exit == 0, err);

        Assert.Equal(RecordType.Burned, Read("s").Type);
        Assert.Equal(sBefore, ValueSections(Bytes("s")));
        Assert.Equal(RecordType.Burned, Read("t").Type);
        Assert.Equal(tBefore, ValueSections(Bytes("t")));
        // The write stamps did change: these are rewrites, not untouched files.
        Assert.NotEqual(sWrite, Read("s").Write);
        Assert.NotEqual(tWrite, Read("t").Write);
    }

    [Fact]
    public void Rotate_KeepsPreviousSectionBytes_AddsNewSection()
    {
        WriteMarker(_m);
        _m.Ok("first", "ingest", "s");
        var before = ValueSections(Bytes("s"));
        var firstFingerprints = Read("s").Fingerprints;

        _m.Ok("second", "ingest", "--rotate", "s");

        var after = ValueSections(Bytes("s"));
        Assert.Equal(2, after.Count);
        Assert.Equal(before[0], after[1]); // the previous value's section, copied
        Assert.NotEqual(before[0], after[0]);
        var record = Read("s");
        Assert.Equal("second"u8.ToArray(), record.Value);
        Assert.Equal("first"u8.ToArray(), record.Previous!.Value);
        Assert.Equal(firstFingerprints, record.Previous.Fingerprints);
        Assert.Equal(Fingerprints(_key, "second"u8.ToArray()), record.Fingerprints);
    }

    /// <summary>
    /// Fix round 1 (MiMo S1): restore makes the previous value current again as a <b>new</b> version
    /// (a new stamp, so a new value key: its old section, bound to the old stamp, can't serve it).
    /// No version that already has a section is sealed again: the replaced current value's section is
    /// carried into the previous slot byte for byte.
    /// </summary>
    [Fact]
    public void Restore_KeepsTheRestoredSectionBytes()
    {
        WriteMarker(_m);
        _m.Ok("first", "ingest", "s");
        _m.Ok("second", "ingest", "--rotate", "s");
        var before = Read("s");
        var sectionsBefore = ValueSections(Bytes("s")); // [current "second", previous "first"]

        _m.Ok("", "restore", "s");

        var after = Read("s");
        var sectionsAfter = ValueSections(Bytes("s"));
        Assert.Equal("first"u8.ToArray(), after.Value);
        Assert.Equal("second"u8.ToArray(), after.Previous!.Value);
        Assert.NotEqual(before.Previous!.Version, after.Version); // the restored value is a new version
        Assert.True(after.Version.CompareTo(before.Version) > 0 && after.Version.CompareTo(before.Previous.Version) > 0,
            "the restored value's stamp must be newer than both retained stamps (merges keep the newest)");
        Assert.Equal(before.Version, after.Previous.Version);
        Assert.Equal(2, after.Sealed!.Count); // the superseded version's section is dropped
        Assert.Equal(sectionsBefore[0], sectionsAfter[1]); // "second"'s section, copied byte for byte
        Assert.Equal(sectionsBefore[0], after.Sealed![before.Version]);
        Assert.Equal(Fingerprints(_key, "first"u8.ToArray()), after.Fingerprints);
        Assert.Equal(before.Fingerprints, after.Previous.Fingerprints);
    }

    [Fact]
    public void EmptyValue_IsFingerprintedWithZeroEntries()
    {
        WriteMarker(_m);
        var store = Store(_m);
        var db = store.LoadSecrets(_key, TextWriter.Null);
        db.Secrets["empty"] = new Secret("", DateTime.UtcNow, DateTime.UtcNow);
        store.SaveSecrets(db, _key);

        var record = Read("empty");
        Assert.Empty(record.Value);
        Assert.NotNull(record.Fingerprints);
        Assert.Empty(record.Fingerprints.Entries);
        var metadata = Store(_m).LoadMetadata(_key, TextWriter.Null);
        Assert.Equal(0, metadata.NotFingerprinted);
        Assert.True(metadata.IsFullyFingerprinted);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void V2CopyAgainstV3Main_MergesAndNextWriteIsV3(bool mainIsV3)
    {
        WriteMarker(_m);
        _m.Ok("old-value", "ingest", "s");
        _m.Ok("new-value", "ingest", "--rotate", "s");
        var v3 = Bytes("s");
        var state = SecretRecordCodec.Decode(v3, _key);
        var v2 = SecretRecordCodec.Encode(state, _key, KeyringFormat.RecordFormatVersionV2);
        var copy = File("s") + " (1)";
        System.IO.File.WriteAllBytes(File("s"), mainIsV3 ? v3 : v2);
        System.IO.File.WriteAllBytes(copy, mainIsV3 ? v2 : v3);
        Assert.Equal("new-value", _m.Get("s"));

        _m.Ok("", "burn", "s", "seen");

        Assert.False(System.IO.File.Exists(copy));
        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(Bytes("s")));
        var record = Read("s");
        Assert.Equal(RecordType.Burned, record.Type);
        Assert.Equal(Fingerprints(_key, "new-value"u8.ToArray()), record.Fingerprints);
        Assert.Equal(Fingerprints(_key, "old-value"u8.ToArray()), record.Previous!.Fingerprints);
        Assert.Equal(ValueSections(v3), ValueSections(Bytes("s"))); // the v3 side's sections were carried
    }

    [Fact]
    public void NewerExtension_SurvivesBurnAndMerge()
    {
        WriteMarker(_m);
        _m.Ok("s-value", "ingest", "s");
        _m.Ok("t-value", "ingest", "t");
        var data = RandomNumberGenerator.GetBytes(40);
        var planted = Read("s") with { Write = new Stamp(new Hlc(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 1, 0), new byte[16]) };
        Plant(File("s"), planted with { Extensions = [new RecordExtension(0x7777, data)] }, _key);
        CopyVault(_m, _other);

        _m.Ok("", "burn", "s", "seen");
        var afterBurn = Assert.Single(Read("s").Extensions);
        Assert.Equal(0x7777, afterBurn.Type);
        Assert.Equal(data, afterBurn.Data);

        // The other copy merges the burn in: a rewrite of s by this build.
        var (exit, _, err) = _other.Run("", "vault", "merge", _m.VaultDir!);
        Assert.True(exit == 0, err);
        var merged = ReadRecord(_other, _key, "s");
        Assert.Equal(RecordType.Burned, merged.Type);
        Assert.Equal(new RecordExtension(0x7777, data), Assert.Single(merged.Extensions));
        Assert.NotEqual(planted.Write, merged.Write);
    }

    /// <summary>
    /// Fix round 1 (MiMo S2): a format 3 tombstone has no value sections, so "incoming state carries
    /// sections" can't be what selects format 3. Merged from a copy that holds format 3 records into a
    /// folder without the marker, it is written in format 3 (ruling 3: a format 3 record was read),
    /// keeping a later build's extension byte for byte (ruling 6) instead of dropping it in format 2.
    /// </summary>
    [Fact]
    public void VaultMerge_V3TombstoneWithAnExtension_IntoAnUnmarkedFolder_KeepsItAndWritesV3()
    {
        _m.Ok("s-value", "ingest", "s"); // no marker: format 2
        var otherVault = CopyVault(_m, _other);
        var live = ReadRecord(_other, _key, "s");
        var later = new Stamp(new Hlc(live.Write.Hlc.PhysicalMs + 10_000, 0), Enumerable.Repeat((byte)0x0E, 16).ToArray());
        var data = RandomNumberGenerator.GetBytes(24);
        var tombstone = new SecretRecord(live.RecordId, later, RecordType.Tombstone, later, "s", live.CreatedMs, [], [])
        {
            Extensions = [new RecordExtension(0x7777, data)],
        };
        Plant(RecordFile(_other, _key, "s"), tombstone, _key);
        Assert.False(System.IO.File.Exists(Path.Combine(otherVault, RecordVaultStore.RecordFormatMarkerFileName)));

        var (exit, _, err) = _m.Run("", "vault", "merge", otherVault);

        Assert.True(exit == 0, err);
        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(Bytes("s")));
        var merged = Read("s");
        Assert.Equal(RecordType.Tombstone, merged.Type);
        Assert.Equal(new RecordExtension(0x7777, data), Assert.Single(merged.Extensions));
    }

    [Fact]
    public void FullLoad_TamperedFingerprints_MarksOnlyThatRecordUnreadable()
    {
        WriteMarker(_m);
        _m.Ok("s-value", "ingest", "s");
        _m.Ok("t-value", "ingest", "t");
        var copy = File("s") + " (1)";
        var lying = Read("s") with { Write = new Stamp(new Hlc(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 5, 0), new byte[16]) };
        Plant(copy, lying with { Fingerprints = Fingerprints(_key, "something-else"u8.ToArray()), Sealed = null }, _key);
        var before = RecordsSnapshot();

        Assert.Equal("t-value", _m.Get("t"));
        var (getExit, _, getErr) = _m.Run("", "get", "s");
        _m.Ok("", "create", "u");

        Assert.NotEqual(0, getExit);
        Assert.Contains(Path.GetFileName(File("s")), getErr);
        var after = RecordsSnapshot();
        Assert.Equal(before[Path.GetFileName(File("s"))], after[Path.GetFileName(File("s"))]);
        Assert.Equal(before[Path.GetFileName(copy)], after[Path.GetFileName(copy)]);
        var db = Store(_m).LoadSecrets(_key, TextWriter.Null);
        Assert.Contains(Path.GetFileName(File("s")), db.UnreadableFiles!);
        Assert.Equal(["t", "u"], db.Secrets.Keys.Order());
    }

    [Fact]
    public void FullLoad_SameStampDifferentValues_MarksOnlyThatRecordUnreadable()
    {
        WriteMarker(_m);
        _m.Ok("s-value", "ingest", "s");
        _m.Ok("t-value", "ingest", "t");
        var copy = File("s") + ".sync-conflict-20261102-120000-ABCDEF";
        var damaged = Read("s") with { Value = "other-value"u8.ToArray(), Sealed = null };
        Plant(copy, damaged with { Fingerprints = Fingerprints(_key, damaged.Value) }, _key);
        var before = RecordsSnapshot();

        var warnings = new StringWriter();
        var db = Store(_m).LoadSecrets(_key, warnings);
        Assert.Equal("t-value", _m.Get("t"));
        var (getExit, _, _) = _m.Run("", "get", "s");
        var (burnExit, _, _) = _m.Run("", "burn", "s", "r");
        _m.Ok("", "create", "u");

        Assert.Contains(Path.GetFileName(File("s")), db.UnreadableFiles!);
        Assert.Contains("can't be merged", warnings.ToString());
        Assert.DoesNotContain("s-value", warnings.ToString());
        Assert.DoesNotContain("other-value", warnings.ToString());
        Assert.NotEqual(0, getExit);
        Assert.NotEqual(0, burnExit);
        var after = RecordsSnapshot();
        Assert.Equal(before[Path.GetFileName(File("s"))], after[Path.GetFileName(File("s"))]);
        Assert.Equal(before[Path.GetFileName(copy)], after[Path.GetFileName(copy)]);
    }

    [Fact]
    public void MergeRecords_UnmergeableRecord_SkipsIt_OthersStillMerge()
    {
        WriteMarker(_m);
        _m.Ok("s-value", "ingest", "s");
        _m.Ok("t-value", "ingest", "t");
        var otherVault = CopyVault(_m, _other);
        _other.Ok("t-new\n", "ingest", "--rotate", "t");
        // On the other copy, s is damaged: its version stamp, a different value.
        var otherS = ReadRecord(_other, _key, "s");
        Plant(RecordFile(_other, _key, "s"), otherS with { Value = "forged"u8.ToArray(), Sealed = null, Fingerprints = Fingerprints(_key, "forged"u8.ToArray()) }, _key);
        var sBefore = Bytes("s");

        var (exit, _, err) = _m.Run("", "vault", "merge", otherVault);

        Assert.True(exit == 0, err);
        Assert.Contains(Path.GetFileName(File("s")), err);
        Assert.Contains("can't be merged", err);
        Assert.DoesNotContain("s-value", err);
        Assert.DoesNotContain("forged", err);
        Assert.Equal(sBefore, Bytes("s"));
        Assert.Equal("s-value", _m.Get("s"));
        Assert.Equal("t-new", _m.Get("t"));
    }

    [Fact]
    public void VaultMerge_RemovesARedundantIdenticalCopy()
    {
        WriteMarker(_m);
        _m.Ok("s-value", "ingest", "s");
        var otherVault = CopyVault(_m, _other);
        var copy = File("s") + " (1)";
        System.IO.File.Copy(File("s"), copy);
        var sectionsBefore = ValueSections(Bytes("s"));

        var (exit, stdout, err) = _m.Run("", "vault", "merge", otherVault);

        Assert.True(exit == 0, err);
        Assert.Contains("1 record(s) written", stdout);
        Assert.False(System.IO.File.Exists(copy));
        Assert.Equal(sectionsBefore, ValueSections(Bytes("s")));
        Assert.Equal("s-value", _m.Get("s"));
    }

    [Fact]
    public void ReadSecretValue_DecryptsOnlyTheRequestedValueSection()
    {
        WriteMarker(_m);
        _m.Ok("old-value", "ingest", "s");
        _m.Ok("new-value", "ingest", "--rotate", "s");
        _m.Ok("t-value", "ingest", "t");
        var record = Read("s");
        var store = Store(_m);
        List<(string File, Stamp Version)> values = [];
        List<string> records = [];
        store.ValueDecrypted = (file, version) => values.Add((file, version));
        store.RecordDecrypted = records.Add;

        var current = store.ReadSecretValue("s", _key);
        Assert.Equal("new-value"u8.ToArray(), current);
        Assert.Equal([(Path.GetFileName(File("s")), record.Version)], values);
        Assert.Equal([Path.GetFileName(File("s"))], records);

        values.Clear();
        var previous = store.ReadSecretValue("s", _key, previous: true);
        Assert.Equal("old-value"u8.ToArray(), previous);
        Assert.Equal([(Path.GetFileName(File("s")), record.Previous!.Version)], values);

        values.Clear();
        Assert.Null(store.ReadSecretValue("t", _key, previous: true));
        Assert.Empty(values);
        Assert.Null(store.ReadSecretValue("missing", _key));
    }

    /// <summary>
    /// The read path checks the one value it decrypts against that version's stored fingerprints (as a
    /// full load validates every copy): a record whose value section doesn't match its fingerprints
    /// is refused, so a value can't be returned under fingerprints that describe another one.
    /// </summary>
    [Fact]
    public void ReadSecretValue_AValueThatDoesNotMatchItsFingerprints_IsRefused()
    {
        WriteMarker(_m);
        _m.Ok("s-value", "ingest", "s");
        _m.Ok("t-value", "ingest", "t");
        var lying = Read("s") with { Fingerprints = Fingerprints(_key, "something-else"u8.ToArray()) };
        Plant(File("s"), lying, _key); // its section is copied: the value is unchanged, the fingerprints are not its own

        var ex = Assert.Throws<TswapException>(() => Store(_m).ReadSecretValue("s", _key));

        Assert.Contains("fingerprints don't match", ex.Message);
        Assert.DoesNotContain("s-value", ex.Message);
        Assert.Equal("t-value"u8.ToArray(), Store(_m).ReadSecretValue("t", _key));
    }

    /// <summary>
    /// Fix round 2 (MiMo 4): the read path recomputes and compares only sets of this build's
    /// variant-set version (the mismatch case above). A set of an older version (reported by
    /// LoadMetadata as OlderVariantSet, recomputed by vault reindex) or of a newer one (a later build's
    /// variants) can't be recomputed here: the read returns the value, and the set is kept as it is.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(9)]
    public void ReadSecretValue_ASetOfAnotherVariantSetVersion_IsKept_AndTheReadWorks(byte setVersion)
    {
        WriteMarker(_m);
        _m.Ok("s-value", "ingest", "s");
        var otherSet = new FingerprintSet(setVersion, [new FingerprintEntry(VariantKind.Plain, 3, 42, new byte[16])]);
        Plant(File("s"), Read("s") with { Fingerprints = otherSet }, _key); // its section is copied

        Assert.Equal("s-value"u8.ToArray(), Store(_m).ReadSecretValue("s", _key));
        Assert.Equal(otherSet, Read("s").Fingerprints);
        Assert.Equal(otherSet, Store(_m).LoadMetadata(_key, TextWriter.Null).Records.Single().Fingerprints);
    }

    [Fact]
    public void RawFileBytes_HoldNoFingerprintMaterial()
    {
        WriteMarker(_m);
        // A fixed value of 24 random characters (brief): a space for the whitespace-stripped variant,
        // and "?>" so its base64 has a '+' (the base64url variant).
        const string value = "Kq7?>vM2 xR9~pL4?>wZ8&nT";
        Assert.Equal(24, value.Length);
        Assert.Equal(4, SecretVariants.For(value).Count);
        _m.Ok(value, "ingest", "s");
        var file = Bytes("s");
        var record = Read("s");
        var set = record.Fingerprints!;
        Assert.Equal(4, set.Entries.Count);

        foreach (var (_, text) in SecretVariants.For(value))
            Assert.False(Contains(file, Encoding.UTF8.GetBytes(text)), "a variant's text is in the file");
        foreach (var entry in set.Entries)
        {
            Assert.False(Contains(file, entry.Hmac), "an HMAC is in the file");
            var le = BitConverter.GetBytes(entry.RollingHash);
            if (!BitConverter.IsLittleEndian) Array.Reverse(le);
            Assert.False(Contains(file, le), "a rolling hash (little-endian) is in the file");
            Assert.False(Contains(file, [.. le.Reverse()]), "a rolling hash (big-endian) is in the file");
        }
        // The fingerprint block as the metadata plaintext lays it out: no 32-byte window of it appears.
        List<byte> block = [1, set.VariantSetVersion, (byte)set.Entries.Count];
        foreach (var entry in set.Entries)
        {
            block.Add((byte)entry.Kind);
            block.AddRange(BitConverter.GetBytes((uint)entry.Length));
            block.AddRange(BitConverter.GetBytes(entry.RollingHash));
            block.AddRange(entry.Hmac);
        }
        for (var i = 0; i + 32 <= block.Count; i++)
            Assert.False(Contains(file, [.. block.Skip(i).Take(32)]), $"a 32-byte window of the fingerprint block (offset {i}) is in the file");
    }

    private static bool Contains(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle) >= 0;
}
