using System.Text;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S2 task 3: <see cref="RecordVaultStore.OpenSecret"/> reads one secret's record (main
/// file and conflicted copies) and decrypts no value until <see cref="SecretEntry.DecryptValue"/>
/// asks for one version; <see cref="RecordVaultStore.LoadMetadata"/> with
/// <see cref="FormatTwoRecords.Decode"/> decodes exactly the records that have a format 2 file and
/// writes the full load's warning texts. The <c>ValueDecrypted</c> seam is the zero-decryption
/// counter; every test that expects none also checks something was read, so it can't pass vacuously.
/// </summary>
public sealed class RecordStoreSelectiveReadTests : IDisposable
{
    private static readonly byte[] OriginA = Enumerable.Repeat((byte)0x0A, 16).ToArray();

    private readonly FleetMachine _m = new("selective", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _key;

    public RecordStoreSelectiveReadTests()
    {
        _key = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    private string FileName(string name) => Path.GetFileName(RecordFile(_m, _key, name));

    private byte[] IdOf(string name) => FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(_key), name);

    private static Stamp S(long ms) => new(new Hlc(ms, 0), OriginA);

    private SecretRecord NewRecord(string name, Stamp version, string value) =>
        new(IdOf(name), version, RecordType.Value, version, name, 1, Encoding.UTF8.GetBytes(value), [])
        {
            Fingerprints = Fingerprints(_key, Encoding.UTF8.GetBytes(value)),
        };

    private (RecordVaultStore Store, List<(string File, Stamp Version)> Values) Watched(FleetMachine? machine = null)
    {
        var store = Store(machine ?? _m);
        List<(string, Stamp)> values = [];
        store.ValueDecrypted = (file, version) => values.Add((file, version));
        return (store, values);
    }

    [Fact]
    public void OpenSecret_FormatThree_DecryptsNoValue()
    {
        _m.Ok("first-value", "ingest", "a");
        _m.Ok("second-value", "ingest", "--rotate", "a");
        _m.Ok("", "burn", "a", "seen in a log");
        _m.Ok("other-value", "ingest", "b");
        var (store, values) = Watched();
        List<string> metadataRead = [];
        store.RecordDecrypted = metadataRead.Add;

        using var entry = store.OpenSecret("a", _key);

        Assert.NotNull(entry);
        Assert.Empty(values);
        Assert.Equal([FileName("a")], metadataRead); // its metadata was read, and no other record
        Assert.Equal(FileName("a"), entry.FileName);
        Assert.False(entry.IsFormatTwo);
        Assert.Equal("a", entry.Metadata.Name);
        Assert.Equal(RecordType.Burned, entry.Metadata.Type);
        var info = Assert.IsType<SecretInfo>(entry.Info);
        Assert.Equal("a", info.Name);
        Assert.NotNull(info.BurnedAt);
        Assert.Equal("seen in a log", info.BurnReason);
        Assert.True(info.HasPrevious);
        Assert.False(info.PreviousBurned);
        Assert.Null(store.OpenSecret("missing", _key));
    }

    [Fact]
    public void OpenSecret_Tombstone_HasNoInfoAndNoValue()
    {
        _m.Ok("gone-value", "ingest", "a");
        _m.Ok("", "delete", "a");
        var (store, values) = Watched();

        using var entry = store.OpenSecret("a", _key);

        Assert.NotNull(entry);
        Assert.Equal(RecordType.Tombstone, entry.Metadata.Type);
        Assert.Null(entry.Info);
        Assert.Null(entry.DecryptValue(previous: false));
        Assert.Empty(values);
    }

    [Fact]
    public void DecryptValue_DecryptsOnlyThatVersion()
    {
        _m.Ok("old-value", "ingest", "a");
        _m.Ok("new-value", "ingest", "--rotate", "a");
        var file = FileName("a");

        var (store, values) = Watched();
        using (var entry = store.OpenSecret("a", _key)!)
        {
            Assert.Equal("new-value", Encoding.UTF8.GetString(entry.DecryptValue(previous: false)!));
            Assert.Equal([(file, entry.Metadata.Version)], values);
        }

        (store, values) = Watched();
        using (var entry = store.OpenSecret("a", _key)!)
        {
            Assert.Equal("old-value", Encoding.UTF8.GetString(entry.DecryptValue(previous: true)!));
            Assert.Equal([(file, entry.Metadata.PreviousVersion!)], values);
        }
    }

    [Fact]
    public void OpenSecret_FormatTwo_DecodesOnlyThatRecord()
    {
        using var m2 = new FleetMachine("selective-v2", SimulatedYubiKeyService.WithKeys(SerialA));
        var key = VaultKey(m2, InitFormatTwoVault(m2));
        m2.Ok("a-old", "ingest", "a");
        m2.Ok("a-new", "ingest", "--rotate", "a");
        m2.Ok("b-value", "ingest", "b");
        var file = Path.GetFileName(RecordFile(m2, key, "a"));
        var (store, values) = Watched(m2);
        List<string> decrypted = [];
        store.RecordDecrypted = decrypted.Add;

        using var entry = store.OpenSecret("a", key)!;

        Assert.True(entry.IsFormatTwo);
        Assert.Equal([file], decrypted);
        Assert.Equal(2, values.Count); // a format 2 record holds both versions in one block
        Assert.All(values, v => Assert.Equal(file, v.File));
        Assert.Null(entry.Metadata.Fingerprints);
        Assert.Equal("a-new", Encoding.UTF8.GetString(entry.DecryptValue(previous: false)!));
        Assert.Equal("a-old", Encoding.UTF8.GetString(entry.DecryptValue(previous: true)!));
        Assert.Equal(2, values.Count); // nothing decrypted again
    }

    [Fact]
    public void OpenSecret_Unreadable_CarriesTheFileName()
    {
        _m.Ok("a-value", "ingest", "a");
        var path = RecordFile(_m, _key, "a");
        var truncated = File.ReadAllBytes(path)[..150];
        File.WriteAllBytes(path, truncated);
        var reason = Assert.ThrowsAny<TswapException>(() => SecretRecordCodec.DecodeMetadata(truncated, _key)).Message;
        var expected = $"The record of 'a' can't be read ({reason}).";

        var ex = Assert.Throws<UnreadableRecordException>(() => Store(_m).OpenSecret("a", _key));

        Assert.Equal(expected, ex.Message);
        Assert.Equal(FileName("a"), ex.FileName);
        Assert.Equal("a", ex.Name);
        Assert.Equal(reason, ex.Reason);
        // The broker's one-record read keeps today's text exactly.
        Assert.Equal(expected, Assert.ThrowsAny<TswapException>(() => Store(_m).ReadSecretValue("a", _key)).Message);
    }

    [Fact]
    public void OpenSecret_FoldsConflictCopiesLikeReadSecretValue()
    {
        _m.Ok("main-value", "ingest", "a");
        var path = RecordFile(_m, _key, "a");
        var newer = S(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 60_000);
        File.WriteAllBytes(path + " (1)", SecretRecordCodec.Encode(NewRecord("a", newer, "copy-value"), _key));
        File.WriteAllBytes(path + ".sync-conflict-20261107-120000-ABCDEF", [1, 2, 3, 4, 3, 9, 9, 9]);
        var openWarnings = new StringWriter();
        var readWarnings = new StringWriter();

        byte[]? opened;
        using (var entry = new RecordVaultStore(_m.Dir, warnings: openWarnings).OpenSecret("a", _key)!)
        {
            Assert.Equal(newer, entry.Metadata.Version);
            opened = entry.DecryptValue(previous: false);
        }
        var read = new RecordVaultStore(_m.Dir, warnings: readWarnings).ReadSecretValue("a", _key);

        Assert.Equal("copy-value", Encoding.UTF8.GetString(opened!));
        Assert.Equal(read, opened);
        Assert.Contains("sync-conflict-20261107-120000-ABCDEF", openWarnings.ToString());
        Assert.Equal(readWarnings.ToString(), openWarnings.ToString());
    }

    [Fact]
    public void LoadMetadata_Decode_ListsFormatTwoRecords_DecodingOnlyThem()
    {
        using var m2 = new FleetMachine("selective-decode", SimulatedYubiKeyService.WithKeys(SerialA));
        var key = VaultKey(m2, InitFormatTwoVault(m2));
        m2.Ok("a-value", "ingest", "a");
        m2.Ok("b-old", "ingest", "b");
        m2.Ok("b-new", "ingest", "--rotate", "b");
        m2.Ok("c-value", "ingest", "c");
        m2.Ok("", "delete", "c");
        WriteMarker(m2);
        m2.Ok("d-value", "ingest", "d"); // format 3
        string F(string name) => Path.GetFileName(RecordFile(m2, key, name));

        var (skipStore, skipValues) = Watched(m2);
        var skipped = skipStore.LoadMetadata(key, TextWriter.Null);
        Assert.Empty(skipValues);
        Assert.Equal(0, skipped.FormatTwoDecoded);
        Assert.Equal(["d"], skipped.Records.Select(r => r.Name));

        var (store, values) = Watched(m2);
        var metadata = store.LoadMetadata(key, TextWriter.Null, FormatTwoRecords.Decode);

        Assert.Equal(3, metadata.FormatTwoDecoded); // a, b and c's tombstone
        Assert.Equal(3, metadata.NotFingerprinted);
        Assert.Equal(["a", "b", "c", "d"], metadata.Records.Select(r => r.Name).Order(StringComparer.Ordinal));
        Assert.Equal(RecordType.Tombstone, metadata.Records.Single(r => r.Name == "c").Type);
        Assert.All(metadata.Records.Where(r => r.Name != "d"), r => Assert.Null(r.Fingerprints));
        Assert.Equal(["a", "b", "d"], metadata.Secrets.Select(s => s.Name));
        Assert.True(metadata.Secrets.Single(s => s.Name == "b").HasPrevious);
        // Only the format 2 records' values were decrypted (both of b's versions); d's never.
        Assert.Equal(new[] { F("a"), F("b"), F("b") }.Order(StringComparer.Ordinal), values.Select(v => v.File).Order(StringComparer.Ordinal));
        Assert.DoesNotContain(values, v => v.File == F("d") || v.File == F("c"));
    }

    /// <summary>
    /// Diagnostics parity: on one folder, <c>LoadSecrets</c> and <c>LoadMetadata(Decode)</c> write
    /// the same lines for an unreadable main file, a newer and an undecryptable conflicted copy of
    /// each sync tool, and a stamp more than a year ahead, on format 2 and on format 3.
    /// </summary>
    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public void LoadMetadata_WarnsLikeTheFullLoad(byte format)
    {
        Directory.CreateDirectory(_m.RecordsDir);
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        void Plant(string name, SecretRecord record, string suffix = "") =>
            File.WriteAllBytes(RecordFile(_m, _key, name) + suffix, SecretRecordCodec.Encode(record, _key, format));

        Plant("broken", NewRecord("broken", S(now - 1000), "broken-value"));
        var broken = RecordFile(_m, _key, "broken");
        File.WriteAllBytes(broken, File.ReadAllBytes(broken)[..150]);
        string[] suffixes = [" (1)", "-DESKTOP-ABC123", ".sync-conflict-20261107-120000-ABCDEF"];
        for (var i = 0; i < suffixes.Length; i++)
        {
            var name = $"copied{i}";
            Plant(name, NewRecord(name, S(now - 5000), "main-value"));
            Plant(name, NewRecord(name, S(now - 4000), "newer-value"), suffixes[i]);
            File.WriteAllBytes(RecordFile(_m, _key, name) + suffixes[(i + 1) % suffixes.Length], [1, 2, 3, 4, format, 7, 7, 7, 7, 7]);
        }
        const long year = 365L * 24 * 60 * 60 * 1000;
        Plant("future", NewRecord("future", S(now + 2 * year), "future-value"));
        if (format == 3) WriteMarker(_m);

        var full = new StringWriter();
        Store(_m).LoadSecrets(_key, full);
        var metadata = new StringWriter();
        Store(_m).LoadMetadata(_key, metadata, FormatTwoRecords.Decode);

        var fullLines = full.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains(fullLines, l => l.Contains("can't be read") && l.Contains(Path.GetFileName(broken)));
        Assert.Contains(fullLines, l => l.Contains("OneDrive conflicted copy"));
        Assert.Contains(fullLines, l => l.Contains("Syncthing conflicted copy") && l.Contains("can't be used"));
        Assert.Contains(fullLines, l => l.Contains("Dropbox / Google Drive conflicted copy") && l.StartsWith("Note:"));
        Assert.Contains(fullLines, l => l.Contains("more than a year ahead"));
        Assert.Equal(string.Join('\n', fullLines), string.Join('\n', metadata.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries)));
    }

    /// <summary>
    /// The parity above needs the codec's two entry points to name a malformed file alike: a file
    /// too short for the envelope header (with or without the magic) fails with one message.
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 1, 2, 3, 4, 3, 7, 7, 7, 7, 7 })]
    [InlineData(new byte[] { 0x54, 0x53, 0x52, 0x31, 3, 7, 7 })] // "TSR1", format 3
    [InlineData(new byte[] { 1, 2 })]
    public void DecodeMetadata_ShortFile_FailsLikeDecode(byte[] bytes)
    {
        var full = Assert.ThrowsAny<TswapException>(() => SecretRecordCodec.Decode(bytes, _key)).Message;
        Assert.Equal(full, Assert.ThrowsAny<TswapException>(() => SecretRecordCodec.DecodeMetadata(bytes, _key)).Message);
    }

    // ------------------------------------------------------------------ code review: mixed record sets

    /// <summary>
    /// Code review (MiMo A I-1): a format 3 record with a conflicted copy that isn't a record at all
    /// (garbage, or a file that can't be read) is not format 2: it is read on the metadata path, the
    /// copy warned about and skipped, and only the version asked for is decrypted.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OpenSecret_FormatThreeWithAnUnusableCopy_IsNotFormatTwo(bool unreadableCopy)
    {
        if (unreadableCopy && (OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess))
            return; // mode 000 can't stop an administrator from reading the copy
        _m.Ok("old-value", "ingest", "a");
        _m.Ok("new-value", "ingest", "--rotate", "a");
        var copy = RecordFile(_m, _key, "a") + " (1)";
        File.WriteAllBytes(copy, [1, 2, 3, 4, 3, 7, 7, 7, 7, 7]);
        if (unreadableCopy)
            File.SetUnixFileMode(copy, UnixFileMode.None);
        try
        {
            var warnings = new StringWriter();
            var store = new RecordVaultStore(_m.Dir, warnings: warnings);
            List<(string File, Stamp Version)> values = [];
            store.ValueDecrypted = (file, version) => values.Add((file, version));

            using var entry = store.OpenSecret("a", _key)!;

            Assert.False(entry.IsFormatTwo);
            Assert.Empty(values);
            Assert.Equal("new-value", Encoding.UTF8.GetString(entry.DecryptValue(previous: false)!));
            Assert.Equal([(FileName("a"), entry.Metadata.Version)], values);
            Assert.Contains($"{Path.GetFileName(copy)} (Dropbox / Google Drive conflicted copy of record {FileName("a")}) can't be used", warnings.ToString());
        }
        finally
        {
            if (unreadableCopy)
                File.SetUnixFileMode(copy, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    /// <summary>
    /// Code review (GLM B-1, MiMo B-M2): a record with a format 2 file anywhere in its set (here a
    /// format 2 conflicted copy beside a format 3 main file, and the reverse) is decoded whole, both
    /// versions reported, counted as one format 2 record, and agrees with ReadSecretValue.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OpenSecret_MixedFormatRecordSet_IsDecodedWholeAsOneFormatTwoRecord(bool formatTwoMain)
    {
        _m.Ok("old-value", "ingest", "a");
        _m.Ok("main-value", "ingest", "--rotate", "a");
        var path = RecordFile(_m, _key, "a");
        var state = ReadRecord(_m, _key, "a");
        var newer = new Stamp(new Hlc(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 60_000, 0), OriginA);
        var copyState = state with { Write = newer };
        if (formatTwoMain)
        {
            File.WriteAllBytes(path, SecretRecordCodec.Encode(state, _key, KeyringFormat.RecordFormatVersionV2));
            File.WriteAllBytes(path + " (1)", SecretRecordCodec.Encode(copyState, _key, KeyringFormat.RecordFormatVersion));
        }
        else
            File.WriteAllBytes(path + " (1)", SecretRecordCodec.Encode(copyState, _key, KeyringFormat.RecordFormatVersionV2));
        var (store, values) = Watched();

        byte[]? opened;
        using (var entry = store.OpenSecret("a", _key)!)
        {
            Assert.True(entry.IsFormatTwo);
            Assert.Equal(4, values.Count); // two files, both versions of each, decoded whole
            Assert.All(values, v => Assert.StartsWith(FileName("a"), v.File)); // the main file or its copy
            opened = entry.DecryptValue(previous: false);
        }

        Assert.Equal("main-value", Encoding.UTF8.GetString(opened!));
        Assert.Equal(opened, Store(_m).ReadSecretValue("a", _key));
        var metadata = Store(_m).LoadMetadata(_key, TextWriter.Null, FormatTwoRecords.Decode);
        Assert.Equal(1, metadata.FormatTwoDecoded);
        Assert.Equal(1, metadata.NotFingerprinted);
        using var view = new VaultView(Store(_m), _key, TextWriter.Null);
        Assert.Equal("main-value", view.ResolveToken("a"));
        Assert.Equal(1, view.FormatTwoDecoded);
    }

    /// <summary>
    /// Code review (GLM B-4): the lifecycle the wiping rests on: a disposed entry (format 3 and format 2)
    /// and a disposed view refuse to decrypt, so nothing reads values after they were wiped.
    /// </summary>
    [Fact]
    public void DisposedEntriesAndViews_RefuseToDecrypt()
    {
        _m.Ok("a-value", "ingest", "a");
        var entry = Store(_m).OpenSecret("a", _key)!;
        entry.Dispose();
        Assert.Throws<ObjectDisposedException>(() => entry.DecryptValue(previous: false));

        using var m2 = new FleetMachine("selective-dispose", SimulatedYubiKeyService.WithKeys(SerialA));
        var key2 = VaultKey(m2, InitFormatTwoVault(m2));
        m2.Ok("b-value", "ingest", "b");
        var formatTwo = Store(m2).OpenSecret("b", key2)!;
        Assert.True(formatTwo.IsFormatTwo);
        formatTwo.Dispose();
        Assert.Throws<ObjectDisposedException>(() => formatTwo.DecryptValue(previous: false));

        var view = new VaultView(Store(_m), _key, TextWriter.Null);
        Assert.Equal("a-value", view.ResolveToken("a"));
        view.Dispose();
        Assert.Throws<ObjectDisposedException>(() => view.ResolveToken("a"));
    }
}
