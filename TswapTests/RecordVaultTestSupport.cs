using System.Text.Json;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// The record store's earlier <c>Func&lt;DateTimeOffset&gt;</c> time seam as a
/// <see cref="TimeProvider"/> (brief T14 item 4 changed the store's parameter), so the tests that
/// move a captured <c>_now</c> keep doing so.
/// </summary>
internal sealed class FuncTimeProvider(Func<DateTimeOffset> now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now();
}

/// <summary>
/// Brief T6 test support: records of a record store read directly (with the vault key a test
/// knows), and a record-store vault made on a <see cref="FleetMachine"/> without going through
/// <c>migrate --to-records</c> (so the store's own tests don't depend on the migration).
/// </summary>
internal static class RecordVaultTestSupport
{
    public const int SerialA = 31111111;
    public const int SerialB = 32222222;

    /// <summary>
    /// <c>init</c> on <paramref name="machine"/> (one YubiKey slot + recovery), a record-store vault
    /// in <paramref name="vaultDir"/> (default <c>&lt;dir&gt;/vault</c>), marked <c>record-format 3</c>
    /// as <c>init</c> makes it. Returns the recovery key (base64).
    /// <para>
    /// Brief T16-S2: the fixtures follow what <c>init</c> makes (format 3), because a format 2 vault
    /// makes <c>redact</c>/<c>tocomment</c> refuse and the reading commands warn. Tests of format 2
    /// use <see cref="InitFormatTwoVault"/>.
    /// </para>
    /// </summary>
    public static string InitRecordVault(FleetMachine machine, string? vaultDir = null) =>
        RecoveryKeyFrom(vaultDir is null ? machine.Ok("", "init", "--yubikey") : machine.Ok("", "init", "--yubikey", "--folder", vaultDir));

    /// <summary>
    /// <see cref="InitRecordVault"/> with the <c>record-format</c> marker removed, so the folder is
    /// what tswap 0.1 made (records written in format 2); tests of format 3 on such a folder write
    /// the marker themselves (<see cref="WriteMarker"/>).
    /// </summary>
    public static string InitFormatTwoVault(FleetMachine machine, string? vaultDir = null)
    {
        var recoveryKey = InitRecordVault(machine, vaultDir);
        File.Delete(Path.Combine(machine.VaultDir!, RecordVaultStore.RecordFormatMarkerFileName));
        return recoveryKey;
    }

    /// <summary>The recovery key line printed by init.</summary>
    public static string RecoveryKeyFrom(string initOutput)
    {
        var lines = initOutput.Split('\n').Select(l => l.Trim()).ToList();
        var index = lines.IndexOf("Recovery Private Key (base64):");
        Assert.True(index >= 0, "init printed no recovery key");
        return lines[index + 1];
    }

    /// <summary>The vault key, opened with the recovery key (test-side, no CLI).</summary>
    public static byte[] VaultKey(FleetMachine machine, string recoveryKey) =>
        RecoveryKeyUnlock.Unlock(machine.Keyring, Convert.FromBase64String(recoveryKey));

    /// <summary>The record file of <paramref name="name"/> (hashed name).</summary>
    public static string RecordFile(FleetMachine machine, byte[] vaultKey, string name) =>
        Path.Combine(machine.RecordsDir, FilenameHasher.ComputeFilename(RecordKeyDerivation.DeriveNamesKey(vaultKey), name));

    /// <summary>Decodes <paramref name="name"/>'s record file.</summary>
    public static SecretRecord ReadRecord(FleetMachine machine, byte[] vaultKey, string name) =>
        SecretRecordCodec.Decode(File.ReadAllBytes(RecordFile(machine, vaultKey, name)), vaultKey);

    // ---------------------------------------------------------------- brief T16-S1 (record format v3)

    /// <summary>Writes the vault folder's <c>record-format</c> marker (default <c>3</c>).</summary>
    public static void WriteMarker(FleetMachine machine, string content = "3") =>
        File.WriteAllText(Path.Combine(machine.VaultDir!, RecordVaultStore.RecordFormatMarkerFileName), content);

    /// <summary>The value sections of a format 3 file, in file order, from its framing (nothing decrypted).</summary>
    public static List<byte[]> ValueSections(byte[] file)
    {
        Assert.Equal(3, file[4]);
        List<byte[]> sections = [];
        var offset = SecretRecordCodec.V3HeaderSize;
        var first = true;
        while (offset < file.Length)
        {
            var length = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(offset, 4));
            if (!first)
                sections.Add(file.AsSpan(offset + 4, length).ToArray());
            first = false;
            offset += 4 + length;
        }
        return sections;
    }

    /// <summary>
    /// Gives <paramref name="to"/> its own copy of <paramref name="from"/>'s vault folder (scp / USB)
    /// with a config of its own (new origin id); returns the copy's folder.
    /// </summary>
    public static string CopyVault(FleetMachine from, FleetMachine to)
    {
        var copy = Path.Combine(to.Dir, "vault");
        CopyFolder(from.VaultDir!, copy);
        File.WriteAllText(to.ConfigPath, JsonSerializer.Serialize(
            from.Config with { VaultDir = copy, OriginId = RecordVaultStore.NewOriginId(), LastHlc = null }, TswapJsonContext.Default.Config));
        return copy;
    }

    public static void CopyFolder(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var file in Directory.GetFiles(from))
            File.Copy(file, Path.Combine(to, Path.GetFileName(file)));
        foreach (var dir in Directory.GetDirectories(from))
            CopyFolder(dir, Path.Combine(to, Path.GetFileName(dir)));
    }

    /// <summary>The fingerprint set of <paramref name="value"/> under <paramref name="vaultKey"/>.</summary>
    public static TswapCore.Fingerprints.FingerprintSet Fingerprints(byte[] vaultKey, byte[] value)
    {
        using var keys = TswapCore.Fingerprints.FingerprintKeys.Derive(vaultKey);
        return TswapCore.Fingerprints.Fingerprinter.Compute(value, keys);
    }

    /// <summary>The store of <paramref name="machine"/>, as the CLI opens it.</summary>
    public static RecordVaultStore Store(FleetMachine machine) =>
        Assert.IsType<RecordVaultStore>(VaultStores.Open(machine.Dir));

    /// <summary>
    /// Brief T16-S1: gives a machine that joined with a plain <c>slot accept</c> (a record vault of its
    /// own since fix round 2; before, a classic keyring vault, which is converted first)
    /// <paramref name="source"/>'s record files, as sharing the vault folder would; it replaces the
    /// copy of the source's <c>secrets.json.enc</c> those tests made.
    /// </summary>
    public static void ConvertAndTakeRecords(FleetMachine joiner, FleetMachine source)
    {
        if (joiner.Config.Store != RecordVaultStore.StoreName)
            joiner.Ok("", "migrate", "--to-records");
        var records = Path.Combine(joiner.VaultDir!, RecordVaultStore.RecordsFolderName);
        Directory.CreateDirectory(records);
        foreach (var file in Directory.GetFiles(source.RecordsDir))
            File.Copy(file, Path.Combine(records, Path.GetFileName(file)), overwrite: true);
    }
}
