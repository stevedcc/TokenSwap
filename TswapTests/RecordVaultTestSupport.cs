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
}
