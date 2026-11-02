using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 3 (the spec's "verify with tests against the v0.1.x code path"): a build that
/// meets a record written in a newer record format never deletes or overwrites it. Every command
/// that writes, merges or converts is run on a vault holding such a file; afterwards the file is
/// byte-identical and the load reports it unreadable (fail closed). This is the evidence for the
/// v0.2.0 release notes' mixed-fleet rule: older machines refuse reindexed records until upgraded,
/// and can't clobber them meanwhile.
/// </summary>
public sealed class NewerFormatRecordTests : IDisposable
{
    private readonly FleetMachine _m = new("newer-format", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly FleetMachine _other = new("newer-format-other", SimulatedYubiKeyService.WithKeys(SerialA));

    public void Dispose()
    {
        _m.Dispose();
        _other.Dispose();
    }

    /// <summary>
    /// The format bytes this build does not read: one newer than the current one (written as that
    /// expression, so it stays "one newer" when the format moves on). Task 3's commit also ran the
    /// literal 3, before format 3 became readable; brief T16-S1 task 4 removed that row.
    /// </summary>
    public static TheoryData<string, byte> NewerFormats => new()
    {
        { "current + 1", (byte)(KeyringFormat.RecordFormatVersion + 1) },
    };

    [Theory]
    [MemberData(nameof(NewerFormats))]
    public void OlderBuild_NeverDeletesOrOverwritesANewerFormatRecord(string label, byte formatVersion)
    {
        Assert.NotEmpty(label);
        var recoveryKey = InitRecordVault(_m);
        var vaultKey = VaultKey(_m, recoveryKey);
        _m.Ok("planted-value", "ingest", "planted");
        _m.Ok("keep-value", "ingest", "keep");
        var export = _m.PathOf("backup.json");
        _m.Ok("pass\npass\n", "export", export);

        // A second copy of the folder that holds a newer (valid, current-format) write of the same record.
        var otherVault = Path.Combine(_other.Dir, "vault");
        CopyFolder(_m.VaultDir!, otherVault);
        File.WriteAllText(_other.ConfigPath, JsonSerializer.Serialize(
            _m.Config with { VaultDir = otherVault, OriginId = RecordVaultStore.NewOriginId(), LastHlc = null }, TswapJsonContext.Default.Config));
        _other.Ok("", "rotate", "planted");

        var plantedPath = RecordFile(_m, vaultKey, "planted");
        var planted = PlantNewerFormat(File.ReadAllBytes(plantedPath), formatVersion);
        File.WriteAllBytes(plantedPath, planted);

        void AssertPlantedUntouched(string after)
        {
            Assert.True(File.Exists(plantedPath), $"the newer-format record was deleted by: {after}");
            Assert.True(planted.AsSpan().SequenceEqual(File.ReadAllBytes(plantedPath)), $"the newer-format record was rewritten by: {after}");
            var store = new RecordVaultStore(_m.Dir);
            var db = store.LoadSecrets(vaultKey, TextWriter.Null);
            Assert.Contains(Path.GetFileName(plantedPath), db.UnreadableFiles ?? []);
            Assert.False(db.Secrets.ContainsKey("planted"), $"the newer-format record read as a secret after: {after}");
        }

        AssertPlantedUntouched("planting");

        _m.Ok("", "create", "other");
        AssertPlantedUntouched("create other");
        _m.Ok("", "burn", "other", "test");
        AssertPlantedUntouched("burn other");
        _m.Ok("", "delete", "other");
        AssertPlantedUntouched("delete other");

        var (mergeExit, _, mergeErr) = _m.Run("", "vault", "merge", otherVault);
        Assert.True(mergeExit == 0, mergeErr);
        Assert.Contains(Path.GetFileName(plantedPath), mergeErr);
        AssertPlantedUntouched("vault merge of a folder with a newer write of that record");

        var (rotateExit, _, _) = _m.Run("", "rotate", "planted");
        Assert.NotEqual(0, rotateExit);
        AssertPlantedUntouched("rotate planted");
        _m.Ok("", "rotate", "keep");
        AssertPlantedUntouched("rotate keep");

        var (importExit, _, importErr) = _m.Run("pass\n", "import", export);
        Assert.NotEqual(0, importExit);
        Assert.Contains(Path.GetFileName(plantedPath), importErr);
        AssertPlantedUntouched("import of an export holding that secret");

        var (migrateExit, _, migrateErr) = _m.Run("", "migrate", "--to-records");
        Assert.NotEqual(0, migrateExit);
        Assert.Contains("already a record store", migrateErr);
        AssertPlantedUntouched("migrate --to-records");

        var (getExit, _, _) = _m.Run("", "get", "planted");
        Assert.NotEqual(0, getExit);
        AssertPlantedUntouched("get planted");
    }

    /// <summary>
    /// A plausible newer-format record: the real file's magic, record id and write stamp (so it
    /// sits under its secret's file name and its header parses), the given format byte, and a
    /// random payload of a padded size behind a matching length prefix.
    /// </summary>
    private static byte[] PlantNewerFormat(byte[] current, byte formatVersion)
    {
        var header = current[..SecretRecordCodec.HeaderSize];
        header[4] = formatVersion;
        var payload = RandomNumberGenerator.GetBytes(12 + 16 + 512);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(SecretRecordCodec.HeaderSize - 4), (uint)payload.Length);
        return [.. header, .. payload];
    }

    private static void CopyFolder(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var file in Directory.GetFiles(from))
            File.Copy(file, Path.Combine(to, Path.GetFileName(file)));
        foreach (var dir in Directory.GetDirectories(from))
            CopyFolder(dir, Path.Combine(to, Path.GetFileName(dir)));
    }
}
