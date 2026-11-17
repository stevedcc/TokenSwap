using System.Text;
using TswapCore;
using TswapCore.Keyring;

namespace TswapCli.Commands;

/// <summary>
/// Read-only keyring inspection (issue #123, Phase 6): lists a keyring vault's
/// (<see cref="Config.Keyring"/>) enrolled slots and, honestly, what actually protects each
/// one. Requires no hardware and no unlock — <see cref="Slot"/>/<see cref="Keyring"/> metadata
/// lives in plaintext in <c>config.json</c> (only <see cref="Slot.Wrapped"/> is encrypted, and
/// this command never touches it), so this never prompts for a YubiKey the way <c>names</c>/
/// <c>get</c> do to decrypt the secrets database itself.
///
/// <para><b>The core requirement this issue calls out by name:</b> a no-touch YubiKey machine
/// slot must never be reported as a bare "unprotected"/"insecure" — see
/// <c>docs/design/multi-machine-keying.md</c> §Why not k &gt;= 2 (yet), which documents custody (physically
/// controlling who has the key at all) as a real, if unusual, control distinct from no
/// protection whatsoever. See <see cref="DescribeMachineProtection"/> and
/// <see cref="DescribeRecoveryProtection"/> for how each slot kind's actual guarantee is
/// surfaced.</para>
///
/// <para><b>Known limitation, not an oversight:</b> a <see cref="Slot"/> carries no
/// backend/label/enrolledAt field (see that type's doc comment). Each machine slot's kind is read from
/// its own hardware blob instead (brief T36, #350, <see cref="HardwareSlotKinds"/>): a YubiKey blob names
/// its key and touch policy, a TPM or Secure Enclave blob its kind by header or package layout, never the
/// machine doing the listing. Which slot is this machine's own is what its <c>config.json</c> names
/// (<see cref="Config.KeyringSlotId"/>, as the unlock finds it), and only that row says "this machine's"
/// or "this Mac's"; a Secure Enclave slot's touch setting is shown only there, since it lives in that
/// Mac's config and key, not in the blob. There is still no per-slot label (a machine name), so the other
/// rows say "the machine it was made on", and this command never attempts a hardware unwrap to tell
/// (it would turn a passive listing into a hardware-touching operation).</para>
/// </summary>
public sealed class SlotsCommand : ICliCommand
{
    public string Name => "slots";
    public string HelpUsage => "slots [--ack]";
    public string Description => "List the vault's slots and what protects each one (--ack: acknowledge the YubiKeys' touch settings)";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args is not ([] or ["--ack"]))
            throw new UsageException($"{ctx.Prefix} slots [--ack]");
        var config = ctx.Storage.LoadConfig();
        if (args is ["--ack"])
        {
            // Brief T7 item 5: record every YubiKey slot's current touch posture as acknowledged, so
            // everyday commands stop the changed-posture notice. Machine-local (config.json).
            var postures = SecurityWarnings.Current(config);
            ctx.Storage.SaveConfig(SecurityWarnings.Acknowledge(config));
            ctx.Console.Out.WriteLine(postures.Count == 0
                ? "This vault has no YubiKey slot: nothing to acknowledge."
                : "Acknowledged the touch setting of: " + string.Join("; ", postures.Select(p => $"{p.Label} ({p.Posture})")));
            return 0;
        }
        ctx.Console.Out.WriteLine(Format(config, ctx.RememberedSlots, ctx.Os));
        return 0;
    }

    /// <summary>
    /// Task 4b: the mark of a key's slot that isn't the one this machine remembers it last opened the vault with. Not
    /// "dead" or "older": that can't be known without a challenge, and a merge can bring in newer slots.
    /// </summary>
    internal const string OtherSlotOfKeyMark = "another slot of this key (not the one it last opened with)";

    /// <summary>
    /// Pure formatting, factored out from <see cref="Execute"/> so it's unit-testable without
    /// spinning up a full <see cref="CommandContext"/>. Never returns a bare "unprotected" or
    /// "insecure" for a no-touch machine slot — see this class's doc comment.
    /// </summary>
    /// <param name="remembered">Task 4b: this machine's remembered slots (null: nothing is marked).</param>
    internal static string Format(Config config, TswapCore.Vault.RememberedYubiKeySlots? remembered = null,
        System.Runtime.InteropServices.OSPlatform? os = null)
    {
        if (config.Keyring is null)
        {
            return "This vault has no keyring — it's a single derived-key or hardware-wrapped\n" +
                   "vault with no multi-slot concept (see 'tswap init' to create a\n" +
                   "keyring vault instead)." + DescribeClassicPosture(config);
        }

        byte[] keyringBytes;
        try
        {
            keyringBytes = Convert.FromBase64String(config.Keyring);
        }
        catch (FormatException)
        {
            throw new TswapException(
                "Config is corrupted: Keyring is not valid base64. Restore config.json from backup.");
        }

        var keyring = KeyringCodec.Decode(keyringBytes);

        if (keyring.Slots.Count == 0)
            return "This vault has a keyring but no enrolled slots — it is not usable as-is; " +
                   "restore config.json from backup or re-run 'tswap init'.";

        var machineSlotCount = keyring.Slots.Count(s => s.Kind == SlotKind.Machine);

        var sb = new StringBuilder();
        sb.Append($"Keyring slots ({keyring.Slots.Count}, k = {keyring.K}):\n");

        const int slotColumnWidth = 10;
        const int kindColumnWidth = 10;
        sb.Append($"{"SLOT".PadRight(slotColumnWidth)}  {"KIND".PadRight(kindColumnWidth)}  PROTECTION\n");
        sb.Append(new string('-', slotColumnWidth + 2 + kindColumnWidth + 2 + 40) + "\n");

        // Task 4b: only one-key slots are remembered; nothing marks a legacy pair slot, or a key nothing is remembered for.
        var lastOpened = remembered?.ForVault(keyring.VaultId) ?? new Dictionary<int, byte[]>();
        // Brief T36 (#350): the one row that may say "this machine's" / "this Mac's".
        var ownRow = OwnHardwareRow(config, keyring);
        foreach (var slot in keyring.Slots)
        {
            var shortId = AbbreviateSlotId(slot.SlotId);
            var kindLabel = slot.Kind == SlotKind.Machine ? "machine" : "recovery";
            var isOwn = ownRow is not null && slot.SlotId.AsSpan().SequenceEqual(ownRow.SlotId);
            var protection = slot.Kind == SlotKind.Machine
                ? DescribeMachineProtection(config, slot, isOwn)
                : DescribeRecoveryProtection();
            // Only OTP slots are remembered (FIDO2 plan, task 2: a FIDO2 slot is never marked).
            if (slot.Kind == SlotKind.Machine && YubiKeySlotKinds.Classify(slot.HwBlob) is YubiKeySlotKind.Otp(var blob)
                && lastOpened.TryGetValue(blob.Serial, out var last) && !last.AsSpan().SequenceEqual(slot.SlotId))
                protection += $" — {OtherSlotOfKeyMark}";
            sb.Append($"{shortId.PadRight(slotColumnWidth)}  {kindLabel.PadRight(kindColumnWidth)}  {protection}\n");
        }

        // Brief T17 ruling 3 / task 6: with at least one password slot, say how many open without it. FIDO2 plan,
        // task 8: a password-free FIDO2 slot still needs its key's PIN and a touch, so it is counted apart.
        var kinds = keyring.Slots.Where(s => s.Kind == SlotKind.Machine)
            .Select(s => (Password: SlotPassword.Classify(s), Fido2: YubiKeySlotKinds.Classify(s.HwBlob) is YubiKeySlotKind.Fido2))
            .ToList();
        if (kinds.Any(k => k.Password == SlotPasswordKind.Password))
        {
            var withoutPassword = kinds.Count(k => k is { Password: SlotPasswordKind.None, Fido2: false });
            var fido2WithoutPassword = kinds.Count(k => k is { Password: SlotPasswordKind.None, Fido2: true });
            if (withoutPassword > 0 || fido2WithoutPassword > 0)
                sb.Append('\n');
            if (withoutPassword > 0)
                sb.Append($"{withoutPassword} slot(s) open without the password: keep them away from shared machines.\n");
            if (fido2WithoutPassword > 0)
                sb.Append(Fido2WithoutPasswordLine(fido2WithoutPassword) + "\n");
        }

        var changed = SecurityWarnings.Changed(config);
        if (changed.Count > 0)
            sb.Append("\nTouch setting not acknowledged on this machine: " +
                string.Join("; ", changed.Select(c => c.Slot.Label)) + ". Run 'tswap slots --ack' once you've decided.\n");

        if (machineSlotCount > 1 && ownRow is not null)
            sb.Append("\n" + MultiSlotOwnRowNote);
        else if (machineSlotCount > 1)
        {
            sb.Append(
                "\nNote: this keyring has more than one machine slot. Slot data alone (no\n" +
                "per-slot label yet) can't tell you which one is this machine's own without an\n" +
                "actual hardware unlock, which this listing deliberately doesn't attempt.");
        }

        if (os == System.Runtime.InteropServices.OSPlatform.Linux && OwnRsaTpmSlot(config, keyring) is { } rsaSlot)
            sb.Append("\n\n" + RsaPrimaryNote(AbbreviateSlotId(rsaSlot.SlotId)));

        return sb.ToString().TrimEnd('\n');
    }

    /// <summary>
    /// Brief T36: the multi-slot note when one row says it is this machine's (the old note stays word for word when
    /// none does: a YubiKey machine, or an own slot that is corrupt, needs a newer tswap or holds the other chip's data).
    /// </summary>
    internal const string MultiSlotOwnRowNote =
        "Note: this keyring has more than one machine slot. The row that says\n" +
        "\"this machine's TPM\" or \"this Mac's Secure Enclave\" is the slot this machine's\n" +
        "config.json names as its own; the other rows show what their slot data records\n" +
        "(slots carry no machine name yet).";

    /// <summary>
    /// Issue #261: the note for this machine's Linux TPM slot sealed under the RSA-2048 primary. Its only variable part
    /// is the slot's short id.
    /// </summary>
    internal static string RsaPrimaryNote(string id8) =>
        $"Note: this machine's TPM slot ({id8}) was made before tswap 0.3.0 and uses an RSA-2048 key, so every unlock " +
        "is slower than it needs to be. A TPM slot made by tswap 0.3.0 or later uses ECC P-256 and unlocks two to four " +
        "times faster (measured on two TPMs); re-enrolling a slot in place isn't supported yet (issue #264).";

    /// <summary>
    /// This machine's own TPM slot when it is a usable one sealed under the RSA-2048 primary (a header-less package or
    /// a <c>TSTP</c> header without the ECC bit); otherwise null. Found as the unlock finds it
    /// (<c>HardwareBlobLocator</c>): a TPM vault's machine slot named by <see cref="Config.KeyringSlotId"/>, or its
    /// first machine slot when that is unset. A corrupt slot or one from a newer tswap gets no note: it is already
    /// marked. YubiKey and Secure Enclave blobs are told apart by their magic. The note fires on any own non-ECC slot,
    /// a Windows-shaped package included (brief T36 left the note's rules as they were): this machine's own slot in a
    /// TPM vault on Linux is a Linux one unless the config was copied from Windows, and then the unlock fails anyway.
    /// </summary>
    private static Slot? OwnRsaTpmSlot(Config config, Keyring keyring)
    {
        if (config.Backend != HardwareBackend.Tpm)
            return null;
        var own = OwnHardwareSlot(config, keyring);
        if (own?.HwBlob is not { Length: > 0 } hwBlob || YubiKeySlotKinds.IsYubiKey(hwBlob) || SecureEnclaveSlotBlob.HasHeader(hwBlob))
            return null;
        if (SlotPassword.Classify(own) is not (SlotPasswordKind.None or SlotPasswordKind.Password))
            return null;
        return TpmSlotBlob.SealedUnderEccPrimary(hwBlob) ? null : own;
    }

    /// <summary>
    /// Brief T36: this machine's own slot on a TPM or Secure Enclave machine, found as the unlock finds it
    /// (<c>VaultUnlocker.FindOwnMachineSlot</c>): the machine slot <see cref="Config.KeyringSlotId"/> names, or the
    /// first machine slot when that is unset. Null for any other backend, and for a <see cref="Config.KeyringSlotId"/>
    /// that is not base64 (no throw: the unlock reports that itself).
    /// </summary>
    private static Slot? OwnHardwareSlot(Config config, Keyring keyring)
    {
        if (config.Backend != HardwareBackend.Tpm && config.Backend != HardwareBackend.SecureEnclave)
            return null;
        byte[]? ownId;
        try
        {
            ownId = config.KeyringSlotId is null ? null : Convert.FromBase64String(config.KeyringSlotId);
        }
        catch (FormatException)
        {
            return null;
        }
        return ownId is null
            ? keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine)
            : keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine && s.SlotId.AsSpan().SequenceEqual(ownId));
    }

    /// <summary>
    /// Brief T36: the row that says "this machine's TPM" or "this Mac's Secure Enclave": this machine's own slot
    /// (<see cref="OwnHardwareSlot"/>) when its blob agrees with the backend (a TPM kind or not recorded on a TPM
    /// machine, Secure Enclave or not recorded on a Mac) and the row describes it as hardware: not a legacy pair slot
    /// (no blob), a YubiKey blob, or a blob that is corrupt or needs a newer tswap. A slot whose data says the other
    /// chip (a config copied from another machine) is described as any other machine's.
    /// </summary>
    private static Slot? OwnHardwareRow(Config config, Keyring keyring)
    {
        var own = OwnHardwareSlot(config, keyring);
        if (own?.HwBlob is not { Length: > 0 } hwBlob || YubiKeySlotKinds.IsYubiKey(hwBlob))
            return null;
        if (SlotPassword.Classify(own) is not (SlotPasswordKind.None or SlotPasswordKind.Password))
            return null;
        var agrees = (config.Backend, HardwareSlotKinds.Classify(hwBlob)) switch
        {
            (_, HardwareSlotKind.NotRecorded) => true,
            (HardwareBackend.Tpm, HardwareSlotKind.LinuxTpmEcc or HardwareSlotKind.LinuxTpmRsa or HardwareSlotKind.WindowsTpm
                or HardwareSlotKind.TpmPlatformNotRecorded) => true,
            (HardwareBackend.SecureEnclave, HardwareSlotKind.SecureEnclave) => true,
            _ => false,
        };
        return agrees ? own : null;
    }

    /// <summary>Brief T7 item 5: a classic YubiKey vault's touch posture (both keys share it).</summary>
    private static string DescribeClassicPosture(Config config)
    {
        var posture = SecurityWarnings.Current(config).FirstOrDefault();
        if (posture is null)
            return "";
        var line = $"\n{posture.Label}: {DescribeYubiKeyProtection(config.RequiresTouch)}.";
        return SecurityWarnings.Changed(config).Count > 0
            ? line + "\nTouch setting not acknowledged on this machine. Run 'tswap slots --ack' once you've decided."
            : line;
    }

    /// <summary>
    /// The first 8 hex characters of <see cref="Slot.SlotId"/>, lowercase — the same
    /// abbreviate-a-long-identifier convention as a git short hash. Slots have no human label
    /// yet (see <see cref="Slot"/>'s doc comment); this is the best available stand-in.
    /// </summary>
    private static string AbbreviateSlotId(byte[] slotId)
    {
        var hex = Convert.ToHexString(slotId);
        return (hex.Length <= 8 ? hex : hex[..8]).ToLowerInvariant();
    }

    /// <summary>
    /// Honest per-machine-slot protection description. v0 keyrings are YubiKey-only (issue
    /// #119), and the only hardware fact available is <see cref="Config.RequiresTouch"/>
    /// (vault-wide, not per-slot — see this class's doc comment). This is the exact case the
    /// issue calls out: <c>false</c> (or <c>null</c>, unknown) must never collapse to a bare
    /// "unprotected"/"insecure" — a no-touch YubiKey is still only usable by whoever has
    /// physical custody of it, which is a real, if unusual, control (see
    /// <c>docs/design/multi-machine-keying.md</c> §Why not k &gt;= 2 (yet)).
    /// </summary>
    private static string DescribeMachineProtection(Config config, Slot slot, bool isOwn) => SlotPassword.Classify(slot) switch
    {
        // Brief T17 ruling 3: a slot this build can't use is named, never described as if it worked.
        SlotPasswordKind.NeedsNewerTswap => NeedsNewerTswapMark,
        SlotPasswordKind.Corrupt => CorruptMark,
        var kind => DescribeHardware(config, slot, isOwn) + (kind == SlotPasswordKind.Password ? ", vault password" : ", no password"),
    };

    /// <summary>FIDO2 plan, task 8: what protects a FIDO2 slot, after its key's name.</summary>
    internal const string Fido2Protection = "FIDO2: PIN + touch";

    /// <summary>FIDO2 plan, task 8: the password-free FIDO2 slots of a vault that has a password slot.</summary>
    internal static string Fido2WithoutPasswordLine(int count) =>
        $"{count} FIDO2 slot(s) open without the vault password (each still needs its key's FIDO2 PIN and a touch).";

    /// <summary>Brief T17: the PROTECTION of a slot whose blob needs a newer tswap.</summary>
    internal const string NeedsNewerTswapMark = "needs a newer tswap";

    /// <summary>Brief T17: the PROTECTION of a slot whose blob is corrupt.</summary>
    internal const string CorruptMark = "corrupt (restore config.json from backup)";

    private static string DescribeHardware(Config config, Slot slot, bool isOwn) => YubiKeySlotKinds.Classify(slot.HwBlob) switch
    {
        // Brief T4: a one-key YubiKey slot names its own key and touch policy, whatever the
        // vault's backend (a TPM vault on the router may hold the owner's YubiKeys as slots).
        YubiKeySlotKind.Otp(var blob) => DescribeYubiKeySlot(blob),
        // FIDO2 plan, task 8: the key (its model from the AAGUID when the serial is unknown); always PIN and touch.
        YubiKeySlotKind.Fido2(var blob) => $"{Fido2SlotBlob.DisplayName(blob.Serial, blob.Aaguid)}, {Fido2Protection}",
        // Not reached for a TSYK blob this build can't read: DescribeMachineProtection names it first.
        // A legacy YubiKey pair slot has no blob: its touch setting is the vault's (config.json).
        _ when slot.HwBlob is not { Length: > 0 } => DescribeYubiKeyProtection(config.RequiresTouch),
        // Brief T36 (#350): every other kind comes from the slot's own blob, never from the machine doing the listing,
        // except this machine's own slot, whose config.json says what it is. Issue #261's ECC bit names that primary;
        // a header-less or TSTP 0x01 package is told Windows from Linux (RSA-2048) by its layout.
        _ => DescribeHardwareKind(HardwareSlotKinds.Classify(slot.HwBlob), isOwn, config),
    };

    /// <summary>Brief T36: a TPM slot's words before "sealed to …", by its kind.</summary>
    internal static string TpmKindName(HardwareSlotKind kind) => kind switch
    {
        HardwareSlotKind.LinuxTpmEcc => "TPM (Linux, ECC P-256)",
        HardwareSlotKind.LinuxTpmRsa => "TPM (Linux, RSA-2048)",
        HardwareSlotKind.WindowsTpm => "TPM (Windows)",
        _ => "TPM (platform not recorded)",
    };

    /// <summary>Brief T36: how a TPM row ends, this machine's slot or any other.</summary>
    internal static string TpmSealedTo(bool isOwn) => isOwn ? "sealed to this machine's TPM" : "sealed to the TPM of the machine it was made on";

    /// <summary>Brief T36: this Mac's own Secure Enclave slot; its touch setting lives only in this Mac's config.json.</summary>
    internal static string OwnSecureEnclave(bool? requiresTouch) =>
        (requiresTouch == false ? "Secure Enclave, no touch required" : "Secure Enclave, touch required (Touch ID or password)") +
        ", sealed to this Mac's Secure Enclave";

    /// <summary>Brief T36: another Mac's Secure Enclave slot: its touch setting isn't in the blob.</summary>
    internal const string OtherSecureEnclave = "Secure Enclave, sealed to the Mac it was made on (touch setting recorded only there)";

    /// <summary>Brief T36: an own slot whose blob none of the rules recognises, on a TPM machine.</summary>
    internal const string OwnTpmNotRecorded = "TPM, sealed to this machine's TPM";

    /// <summary>Brief T36: any other slot whose blob none of the rules recognises.</summary>
    internal const string HardwareNotRecorded = "hardware-sealed (kind not recorded)";

    private static string DescribeHardwareKind(HardwareSlotKind kind, bool isOwn, Config config) => kind switch
    {
        HardwareSlotKind.SecureEnclave => isOwn ? OwnSecureEnclave(config.RequiresTouch) : OtherSecureEnclave,
        HardwareSlotKind.NotRecorded when isOwn && config.Backend == HardwareBackend.SecureEnclave => OwnSecureEnclave(config.RequiresTouch),
        HardwareSlotKind.NotRecorded when isOwn => OwnTpmNotRecorded,
        HardwareSlotKind.NotRecorded => HardwareNotRecorded,
        _ => $"{TpmKindName(kind)}, {TpmSealedTo(isOwn)}",
    };

    private static string DescribeYubiKeySlot(YubiKeySlotBlob blob) =>
        $"YubiKey {blob.Serial}, " + blob.RequiresTouch switch
        {
            true => "touch required",
            false => "no touch required — protected by physical custody of the YubiKey",
            null => "touch requirement unknown — protected by physical custody of the YubiKey",
        };

    private static string DescribeYubiKeyProtection(bool? requiresTouch) => requiresTouch switch
    {
        true => "YubiKey, touch required",
        false => "YubiKey, no touch required — protected by physical custody of the YubiKey",
        null => "YubiKey, touch requirement unknown — protected by physical custody of the YubiKey",
    };

    /// <summary>
    /// A recovery slot's presence guarantee is not a weaker machine slot — it's a deliberately
    /// different kind of slot with a different job: a break-glass credential that must work
    /// offline, with nobody present, potentially years after enrolment (see
    /// <c>docs/design/multi-machine-keying.md</c>'s "The recovery slot" section and its per-backend table,
    /// where the recovery row is explicitly "none — this is the deliberately presence-free,
    /// offline-capable break-glass slot"). Custody of the recovery private key is the only real
    /// control, by design.
    /// </summary>
    private static string DescribeRecoveryProtection() =>
        "break-glass recovery credential — no presence required by design (offline-capable); " +
        "protected only by custody of the recovery private key";
}
