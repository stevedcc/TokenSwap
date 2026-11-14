using System.Security.Cryptography;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;

namespace TswapTests;

/// <summary>
/// Brief T17: builds a record vault whose own slot is a simulated TPM password slot, without going
/// through <c>init --password</c> (so Task 5's tests don't depend on Task 6). The Argon2id parameters
/// are the cheapest the decoder accepts, to keep the tests fast; the stretching itself is pinned in
/// <see cref="StretchedPasswordTests"/>.
/// </summary>
internal static class PasswordVaultTestSupport
{
    /// <summary>The cheapest parameters <see cref="VaultPasswordFile.Decode"/> accepts.</summary>
    public static readonly VaultPasswordParams Cheap = new(VaultPasswordParams.MinMemoryKiB, 1, 1);

    /// <summary>
    /// Makes <paramref name="machine"/> (whose <see cref="FleetMachine.Tpm"/> must be set) a record vault in
    /// <c>&lt;dir&gt;/vault</c> with one TPM password slot for <paramref name="password"/> and the matching
    /// <c>vault-password</c> file. Returns <c>K_v</c>.
    /// </summary>
    public static byte[] InitTpmPasswordVault(FleetMachine machine, string password, VaultPasswordParams? p = null)
    {
        p ??= Cheap;
        var salt = RandomNumberGenerator.GetBytes(VaultPasswordKdf.SaltSize);
        using var stretched = VaultPasswordKdf.Stretch(password, salt, p);
        var (kek, hwBlob) = new SimulatedHardwareService(HardwareBackend.Tpm, machine.Tpm!).Enroll(stretched);
        var backendConfig = new Config([], "", TestTime.Fixed, RequiresTouch: false, RngMode: RngMode.System, Backend: HardwareBackend.Tpm);
        var (config, vaultKey, _) = InitCommand.AssembleKeyring(kek, backendConfig, includeRecovery: false, hwBlob);

        var vaultDir = Path.Combine(machine.Dir, "vault");
        var machineConfig = config with
        {
            Keyring = null,
            Store = RecordVaultStore.StoreName,
            VaultDir = vaultDir,
            OriginId = RecordVaultStore.NewOriginId(),
        };
        var folderStore = RecordVaultStore.ForFolder(vaultDir, machineConfig);
        folderStore.SaveConfig(machineConfig with { Keyring = config.Keyring });
        folderStore.WriteFormatMarker();
        new RecordVaultStore(machine.Dir).SaveConfig(machineConfig);

        var vaultId = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!)).VaultId;
        folderStore.WriteVaultPassword(VaultPasswordFile.Create(vaultKey, vaultId, stretched, salt, p));
        return vaultKey;
    }

    /// <summary>The vault folder's <c>vault-password</c> file.</summary>
    public static string VaultPasswordPath(FleetMachine machine) =>
        Path.Combine(machine.VaultDir!, RecordVaultStore.VaultPasswordFileName);
}
