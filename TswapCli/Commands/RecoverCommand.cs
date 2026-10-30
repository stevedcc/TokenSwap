using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;

namespace TswapCli.Commands;

/// <summary>
/// <c>recover --yubikey|--tpm|--secure-enclave</c> (brief T5 decision 3, issue #187): the
/// break-glass path. Opens the vault with the recovery private key, read from stdin only (the
/// optional <c>--recovery-key-stdin</c> flag says so explicitly; the key is never taken from argv,
/// the environment or a file path), and enrolls this machine's hardware as a new slot. The recovery
/// slot stays.
///
/// <list type="bullet">
/// <item>Refused before sudo or reading stdin: a vault without a keyring, a version 2 keyring (the
/// message <c>slot add</c> gives), a keyring without a recovery slot.</item>
/// <item>Sudo, like <c>slot add</c>: a new slot is a new way to decrypt the vault.</item>
/// <item>A bad key gets <see cref="RecoveryKeyUnlock.FailureMessage"/>; nothing is enrolled or
/// written. Hardware is enrolled only after the key has opened the vault.</item>
/// <item><c>--yubikey</c> adds a one-key YubiKey slot. Unlike <c>slot add</c> it accepts a key
/// that already has a slot (after a reprogrammed HMAC secret its old slot is dead; unlock tries
/// each of a key's slots in turn). <c>Config.Backend</c> is left as it is.</item>
/// <item><c>--tpm</c> / <c>--secure-enclave</c> seal a new <c>KEK_slot</c> to this machine's
/// hardware and make the new slot this machine's own (<c>Config.Backend</c>,
/// <c>Config.KeyringSlotId</c>), as <c>init</c> would.</item>
/// <item><c>config.json</c> is backed up first. <c>K_v</c> and <c>KEK_slot</c> are zeroed.</item>
/// </list>
/// </summary>
public sealed class RecoverCommand : ICliCommand
{
    public string Name => "recover";
    public string HelpUsage => "recover --yubikey|--tpm|--secure-enclave [--recovery-key-stdin]  (recovery key on stdin)";
    public string Description => "Break glass: open the vault with the recovery private key (piped on stdin) and enroll this machine's YubiKey, TPM or Secure Enclave as a new slot";
    public bool RequiresSudo => true;

    private static readonly string[] Devices = ["--yubikey", "--tpm", "--secure-enclave"];

    public int Execute(CommandContext ctx, string[] args)
    {
        var usage = $"{ctx.Prefix} recover --yubikey|--tpm|--secure-enclave [{SlotCommand.RecoveryKeyFlag}] " +
                    $"(the recovery key is read from stdin only, e.g. sudo {ctx.Prefix} get recovery-key | sudo {ctx.Prefix} recover --yubikey)";
        var (rest, _) = SlotCommand.SplitRecoveryKeyFlag(args);
        if (rest is not [var device] || !Devices.Contains(device))
            throw new UsageException(usage);
        HardwareBackend? hardware = device switch
        {
            "--tpm" => HardwareBackend.Tpm,
            "--secure-enclave" => HardwareBackend.SecureEnclave,
            _ => null,
        };
        var c = ctx.Console;

        var config = ctx.Storage.LoadConfig();
        if (config.Keyring == null)
            throw new TswapException(
                "This vault has no keyring, so it has no recovery slot. Only keyring vaults ('tswap init --keyring', " +
                "'--tpm' or '--secure-enclave') have a recovery key.");
        var keyring = SlotCommand.DecodeKeyringOrCorrupt(config);
        SlotCommand.RequireKeyringThatTakesYubiKeySlots(keyring);
        if (!keyring.Slots.Any(s => s.Kind == SlotKind.Recovery))
            throw new TswapException(RecoveryKeyUnlock.NoRecoverySlotMessage);

        ctx.RequireSudo("recover");

        // Throws a clear TswapException on an OS without this hardware, before the key is read.
        var enrollment = hardware == null ? null : HardwareServices.Enrollment(hardware.Value, ctx.TestKey);

        var vaultKey = SlotCommand.UnlockWithRecoveryKey(ctx, keyring);
        Slot newSlot;
        string deviceName;
        YubiKeySlotBlob? yubiKey = null;
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        try
        {
            byte[] kekSlot, hwBlob;
            if (enrollment == null)
            {
                c.Out.WriteLine("Recovery key accepted. Enrolling a YubiKey as a new slot.");
                (yubiKey, kekSlot) = YubiKeySlotEnrollment.Enroll(ctx, slotId);
                hwBlob = yubiKey.Encode();
                deviceName = $"YubiKey {yubiKey.Serial}";
            }
            else
            {
                deviceName = hardware == HardwareBackend.Tpm ? "this machine's TPM" : "this machine's Secure Enclave";
                c.Out.WriteLine($"Recovery key accepted. Enrolling {deviceName} as a new slot.");
                (kekSlot, hwBlob) = enrollment.Enroll();
            }
            try
            {
                var slotKeyPair = SlotKeyPair.Generate();
                try
                {
                    newSlot = MachineSlotWrap.Wrap(
                        vaultKey, slotKeyPair.PrivateKey, slotKeyPair.PublicKey, slotId, kekSlot,
                        keyring.FormatVersion, keyring.VaultId, keyring.K) with { HwBlob = hwBlob };
                }
                finally
                {
                    // Review minor: the slot's private key now lives only inside the wrap.
                    CryptographicOperations.ZeroMemory(slotKeyPair.PrivateKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kekSlot);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(vaultKey);
        }

        var extended = keyring with { Slots = [.. keyring.Slots, newSlot] };
        var newConfig = config with { Keyring = Convert.ToBase64String(KeyringCodec.Encode(extended)) };
        if (hardware != null)
            newConfig = newConfig with
            {
                Backend = hardware,
                KeyringSlotId = Convert.ToBase64String(slotId),
                RequiresTouch = hardware == HardwareBackend.SecureEnclave,
            };
        if (yubiKey != null) // brief T7 item 5: its posture is explained below
            newConfig = SecurityWarnings.Acknowledge(newConfig, [Convert.ToBase64String(slotId)]);

        if (ctx.Storage is IFileVaultStore fileStore && fileStore.Owner.FileExists(fileStore.ConfigFile))
        {
            var backup = fileStore.BackupConfig();
            c.Out.WriteLine($"\nPrevious config backed up to: {backup}");
        }
        ctx.Storage.SaveConfig(newConfig);

        c.Out.WriteLine($"\n✓ Recovered: {deviceName} now opens this vault as its own slot. The recovery slot stays.");
        if (yubiKey != null)
            YubiKeySlotEnrollment.PrintTouchPolicy(c, yubiKey);
        SlotCommand.PrintFingerprint(c, "New slot", newSlot.PublicKey);
        c.Out.WriteLine($"Slots in this machine's keyring: {extended.Slots.Count}");
        c.Out.WriteLine("Other copies of the vault don't have the new slot yet: on each, run");
        c.Out.WriteLine($"  sudo {ctx.Prefix} slot merge <this machine's config.json> --yes");
        return 0;
    }
}
