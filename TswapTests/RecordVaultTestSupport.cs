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
    /// <c>init --keyring</c> on <paramref name="machine"/> (one YubiKey slot + recovery), then the
    /// same vault turned into a record store in <paramref name="vaultDir"/> (default
    /// <c>&lt;dir&gt;/vault</c>): the keyring moves to the vault folder, config.json gets
    /// <c>Store</c>, <c>VaultDir</c> and a new <c>OriginId</c>. Returns the recovery key (base64).
    /// </summary>
    public static string InitRecordVault(FleetMachine machine, string? vaultDir = null)
    {
        var output = machine.Ok("", "init", "--keyring");
        var config = machine.Config;
        vaultDir ??= Path.Combine(machine.Dir, "vault");
        Directory.CreateDirectory(vaultDir);
        File.WriteAllBytes(Path.Combine(vaultDir, "keyring"), Convert.FromBase64String(config.Keyring!));
        var recordConfig = config with
        {
            Keyring = null,
            Store = RecordVaultStore.StoreName,
            VaultDir = Path.GetFullPath(vaultDir),
            OriginId = RecordVaultStore.NewOriginId(),
        };
        File.WriteAllText(machine.ConfigPath, JsonSerializer.Serialize(recordConfig, TswapJsonContext.Default.Config));
        File.Delete(machine.SecretsPath);
        return RecoveryKeyFrom(output);
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
}
