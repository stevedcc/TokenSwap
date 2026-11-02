using System.Text;
using TswapCore;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 7: <c>sudo tswap vault reindex</c> rewrites every record as format 3 with
/// fingerprints (value sections copied where they exist), refuses before writing anything when a
/// record is unreadable, writes the <c>record-format</c> marker last, prints counts only, and is
/// idempotent; two machines reindexing copies of one vault converge through <c>vault merge</c>.
/// </summary>
public sealed class VaultReindexTests : IDisposable
{
    private const uint UserUid = 1000;
    private const uint UserGid = 1001;

    private readonly FleetMachine _m = new("reindex", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly FleetMachine _other = new("reindex-other", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _key;

    public VaultReindexTests()
    {
        _key = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose()
    {
        _m.Dispose();
        _other.Dispose();
    }

    private string Marker(FleetMachine m) => Path.Combine(m.VaultDir!, RecordVaultStore.RecordFormatMarkerFileName);

    private static Dictionary<string, string> Files(string folder) =>
        Directory.GetFiles(folder, "*", SearchOption.AllDirectories)
            .ToDictionary(f => Path.GetRelativePath(folder, f), f => Convert.ToHexString(File.ReadAllBytes(f)));

    /// <summary>A format 2 vault: three secrets with previous values, one burned, one tombstone.</summary>
    private void V2Vault()
    {
        _m.Ok("alpha-1", "ingest", "alpha");
        _m.Ok("alpha-2", "ingest", "--rotate", "alpha");
        _m.Ok("beta-1", "ingest", "beta");
        _m.Ok("", "burn", "beta", "seen");
        _m.Ok("gamma-1", "ingest", "gamma");
        _m.Ok("gamma-2", "ingest", "--rotate", "gamma");
        _m.Ok("delta-1", "ingest", "delta");
        _m.Ok("", "delete", "delta");
        Assert.All(_m.RecordFiles, f => Assert.Equal((byte?)2, SecretRecordCodec.FormatVersionOf(File.ReadAllBytes(Path.Combine(_m.RecordsDir, f)))));
    }

    private void AssertAllV3WithFingerprints(FleetMachine m)
    {
        Assert.NotEmpty(m.RecordFiles);
        foreach (var file in m.RecordFiles)
        {
            var bytes = File.ReadAllBytes(Path.Combine(m.RecordsDir, file));
            Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(bytes));
            var record = SecretRecordCodec.Decode(bytes, _key);
            if (record.Type == RecordType.Tombstone)
            {
                Assert.Null(record.Fingerprints);
                continue;
            }
            Assert.Equal(Fingerprints(_key, record.Value), record.Fingerprints);
            if (record.Previous is { } previous)
                Assert.Equal(Fingerprints(_key, previous.Value), previous.Fingerprints);
        }
    }

    [Fact]
    public void Reindex_RequiresSudo()
    {
        if (Environment.IsPrivilegedProcess)
            return; // the refusal can't happen when the test runner is elevated (Windows CI)
        V2Vault();
        var before = Files(_m.VaultDir!);
        _m.Sudo = false;

        var (exit, _, err) = _m.Run("", "vault", "reindex");

        Assert.NotEqual(0, exit);
        Assert.Contains("requires", err);
        Assert.Equal(before, Files(_m.VaultDir!));
    }

    [Fact]
    public void Reindex_ConvertsEveryRecord_WritesMarkerLast()
    {
        V2Vault();
        var store = Store(_m);
        var written = 0;
        store.AfterRecordWritten = () =>
        {
            if (++written == 3)
                throw new IOException("simulated crash after the third record");
        };

        Assert.Throws<IOException>(() => store.Reindex(_key));

        Assert.False(File.Exists(Marker(_m)), "the marker was written before every record was");
        var formats = _m.RecordFiles.Select(f => SecretRecordCodec.FormatVersionOf(File.ReadAllBytes(Path.Combine(_m.RecordsDir, f)))).ToList();
        Assert.Equal(3, formats.Count(f => f == 3));
        Assert.Equal(1, formats.Count(f => f == 2));

        var (exit, stdout, err) = _m.Run("", "vault", "reindex");

        Assert.True(exit == 0, err);
        Assert.Contains("1 record(s) rewritten", stdout);
        Assert.Contains("3 already current", stdout);
        Assert.Equal("3", File.ReadAllText(Marker(_m)).Trim());
        AssertAllV3WithFingerprints(_m);
        Assert.Equal("alpha-2", _m.Get("alpha"));
        Assert.Equal("gamma-1", Encoding.UTF8.GetString(ReadRecord(_m, _key, "gamma").Previous!.Value));
        Assert.Equal(RecordType.Burned, ReadRecord(_m, _key, "beta").Type);
        Assert.Equal(RecordType.Tombstone, ReadRecord(_m, _key, "delta").Type);
    }

    [Fact]
    public void Reindex_SecondRun_RewritesNothing()
    {
        V2Vault();
        var (_, first, _) = _m.Run("", "vault", "reindex");
        Assert.Contains("4 record(s) rewritten", first);
        Assert.Contains("1 tombstone", first);
        var before = Files(_m.VaultDir!);

        var (exit, second, err) = _m.Run("", "vault", "reindex");

        Assert.True(exit == 0, err);
        Assert.Contains("0 record(s) rewritten", second);
        Assert.Contains("4 already current", second);
        Assert.Equal(before, Files(_m.VaultDir!));
    }

    [Fact]
    public void Reindex_CopiesExistingSections_AndRecomputesOlderVariantSets()
    {
        WriteMarker(_m);
        _m.Ok("s-1", "ingest", "s");
        _m.Ok("s-2", "ingest", "--rotate", "s");
        var record = ReadRecord(_m, _key, "s");
        var sections = ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "s")));
        var older = record with { Fingerprints = record.Fingerprints! with { VariantSetVersion = 0 } };
        File.WriteAllBytes(RecordFile(_m, _key, "s"), SecretRecordCodec.Encode(older, _key, 3));
        Assert.Equal(1, Store(_m).LoadMetadata(_key, TextWriter.Null).OlderVariantSet);

        _m.Ok("", "vault", "reindex");

        var after = ReadRecord(_m, _key, "s");
        Assert.Equal(SecretVariants.CurrentSetVersion, after.Fingerprints!.VariantSetVersion);
        Assert.Equal(sections, ValueSections(File.ReadAllBytes(RecordFile(_m, _key, "s"))));
        Assert.Equal(0, Store(_m).LoadMetadata(_key, TextWriter.Null).OlderVariantSet);
    }

    [Fact]
    public void Reindex_UnreadableRecord_RefusesBeforeWriting()
    {
        V2Vault();
        var damaged = RecordFile(_m, _key, "beta");
        File.WriteAllBytes(damaged, File.ReadAllBytes(damaged)[..100]);
        var before = Files(_m.VaultDir!);

        var (exit, _, err) = _m.Run("", "vault", "reindex");

        Assert.NotEqual(0, exit);
        Assert.Contains(Path.GetFileName(damaged), err);
        Assert.Equal(before, Files(_m.VaultDir!));
        Assert.False(File.Exists(Marker(_m)));
    }

    [Fact]
    public void Reindex_OutputHasNoNamesOrValues()
    {
        V2Vault();

        var (exit, stdout, err) = _m.Run("", "vault", "reindex");

        Assert.True(exit == 0, err);
        foreach (var text in new[] { "alpha", "beta", "gamma", "delta", "alpha-1", "alpha-2", "beta-1", "gamma-1", "gamma-2", "delta-1" })
        {
            Assert.DoesNotContain(text, stdout);
            Assert.DoesNotContain(text, err);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Reindex_ConcurrentOnTwoMachines_ConvergesCleanly(bool aFirst)
    {
        V2Vault();
        var otherVault = CopyVault(_m, _other);
        _m.Ok("", "vault", "reindex");
        _other.Ok("", "vault", "reindex");
        var reindexedA = _m.RecordFiles.ToDictionary(f => f, f => ValueSections(File.ReadAllBytes(Path.Combine(_m.RecordsDir, f))));
        var reindexedB = _other.RecordFiles.ToDictionary(f => f, f => ValueSections(File.ReadAllBytes(Path.Combine(_other.RecordsDir, f))));
        Assert.Contains(reindexedA, kv => kv.Value.Count > 0 && !kv.Value[0].SequenceEqual(reindexedB[kv.Key][0])); // random nonces

        if (aFirst)
        {
            _m.Ok("", "vault", "merge", otherVault);
            _other.Ok("", "vault", "merge", _m.VaultDir!);
        }
        else
        {
            _other.Ok("", "vault", "merge", _m.VaultDir!);
            _m.Ok("", "vault", "merge", otherVault);
        }

        Assert.Equal(_m.RecordFiles, _other.RecordFiles);
        foreach (var file in _m.RecordFiles)
        {
            var a = ValueSections(File.ReadAllBytes(Path.Combine(_m.RecordsDir, file)));
            var b = ValueSections(File.ReadAllBytes(Path.Combine(_other.RecordsDir, file)));
            Assert.Equal(a, b);
            for (var i = 0; i < a.Count; i++)
            {
                var min = reindexedA[file][i].AsSpan().SequenceCompareTo(reindexedB[file][i]) <= 0 ? reindexedA[file][i] : reindexedB[file][i];
                Assert.Equal(min, a[i]);
            }
        }
        Assert.Contains("Nothing to merge", _m.Ok("", "vault", "merge", otherVault));
        Assert.Contains("Nothing to merge", _other.Ok("", "vault", "merge", _m.VaultDir!));
        Assert.Equal("alpha-2", _other.Get("alpha"));
    }

    [Fact]
    public void Reindex_HealsALingeringV2Copy()
    {
        WriteMarker(_m);
        _m.Ok("s-value", "ingest", "s");
        var main = RecordFile(_m, _key, "s");
        var copy = main + " (1)";
        File.WriteAllBytes(copy, SecretRecordCodec.Encode(ReadRecord(_m, _key, "s"), _key, KeyringFormat.RecordFormatVersionV2));
        Assert.Equal(1, Store(_m).LoadMetadata(_key, TextWriter.Null).NotFingerprinted);

        var (exit, stdout, err) = _m.Run("", "vault", "reindex");

        Assert.True(exit == 0, err);
        Assert.Contains("1 record(s) rewritten", stdout);
        Assert.False(File.Exists(copy));
        Assert.Equal(0, Store(_m).LoadMetadata(_key, TextWriter.Null).NotFingerprinted);
    }

    [Fact]
    public void Reindex_ThenOlderFormatWrite_IsReportedNotFingerprinted()
    {
        V2Vault();
        _m.Ok("", "vault", "reindex");
        Assert.True(Store(_m).LoadMetadata(_key, TextWriter.Null).IsFullyFingerprinted);
        // An older machine writes alpha again (format 2, newer write stamp).
        var alpha = ReadRecord(_m, _key, "alpha");
        var later = alpha with { Write = new Stamp(new Hlc(alpha.Write.Hlc.PhysicalMs + 1000, 0), new byte[16]) };
        File.WriteAllBytes(RecordFile(_m, _key, "alpha"), SecretRecordCodec.Encode(later, _key, KeyringFormat.RecordFormatVersionV2));

        var metadata = Store(_m).LoadMetadata(_key, TextWriter.Null);

        Assert.Equal(1, metadata.NotFingerprinted);
        Assert.False(metadata.IsFullyFingerprinted);
    }

    [Fact]
    public void Reindex_EmptyVault_WritesMarkerOnly()
    {
        var (exit, stdout, err) = _m.Run("", "vault", "reindex");

        Assert.True(exit == 0, err);
        Assert.Contains("0 record(s) rewritten", stdout);
        Assert.Equal("3", File.ReadAllText(Marker(_m)).Trim());
        Assert.Empty(_m.RecordFiles);
    }

    [Fact]
    public void Reindex_UnderSudo_KeepsTheVaultOwnerAndModes()
    {
        if (OperatingSystem.IsWindows())
            return; // no identity switch on Windows
        V2Vault();
        var fake = new FileOwnershipTests.FakeOwnership(privileged: true, euid: 0);
        _m.Ownership = new DirectoryOwnerMatcher(fake);

        _m.Ok("", "vault", "reindex");

        var switched = fake.Switches.Select(s => s.Path).ToList();
        foreach (var file in _m.RecordFiles)
        {
            var path = Path.GetFullPath(Path.Combine(_m.RecordsDir, file));
            Assert.Contains(path, switched);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        }
        Assert.Contains(Path.GetFullPath(Marker(_m)), switched);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Marker(_m)));
        Assert.Contains(Path.GetFullPath(_m.ConfigPath), switched);
        Assert.All(fake.Switches, s => Assert.Equal((UserUid, UserGid), (s.Uid, s.Gid)));
    }

    [Fact]
    public void VaultMerge_CopiesTheMarker_InBothDirections()
    {
        V2Vault();
        var otherVault = CopyVault(_m, _other);
        _m.Ok("", "vault", "reindex");

        // The reindexed folder merged into the unreindexed one gives it the marker.
        _other.Ok("", "vault", "merge", _m.VaultDir!);
        Assert.Equal("3", File.ReadAllText(Path.Combine(otherVault, RecordVaultStore.RecordFormatMarkerFileName)).Trim());
        // Every live record took the reindexed state (fingerprints are state, so it was written, as
        // format 3). The tombstone's state is equal on both sides and it has no sections, so ruling
        // 11 doesn't rewrite it: it stays format 2 until a write of it or a reindex here.
        foreach (var name in new[] { "alpha", "beta", "gamma" })
        {
            Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(File.ReadAllBytes(RecordFile(_other, _key, name))));
            Assert.NotNull(ReadRecord(_other, _key, name).Fingerprints);
        }
        _other.Ok("", "vault", "reindex");
        AssertAllV3WithFingerprints(_other);

        // The reverse leaves the marker in place: a copy of this vault without a marker (and without
        // records) merged into the reindexed folder.
        var bare = Path.Combine(_other.Dir, "bare");
        Directory.CreateDirectory(bare);
        File.Copy(Path.Combine(_m.VaultDir!, "keyring"), Path.Combine(bare, "keyring"));
        _m.Ok("", "vault", "merge", bare);
        Assert.Equal("3", File.ReadAllText(Marker(_m)).Trim());
    }
}
