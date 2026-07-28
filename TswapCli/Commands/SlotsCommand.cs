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
/// <c>MULTI_MACHINE_KEYING.md</c> §Why not k &gt;= 2 (yet), which documents custody (physically
/// controlling who has the key at all) as a real, if unusual, control distinct from no
/// protection whatsoever. See <see cref="DescribeMachineProtection"/> and
/// <see cref="DescribeRecoveryProtection"/> for how each slot kind's actual guarantee is
/// surfaced.</para>
///
/// <para><b>Known limitation, not an oversight:</b> a <see cref="Slot"/> carries no
/// backend/label/enrolledAt field yet (see that type's doc comment) — v0 keyrings are YubiKey-only
/// (issue #119), so every <see cref="SlotKind.Machine"/> slot is implicitly YubiKey-backed and
/// its touch requirement is read off <see cref="Config.RequiresTouch"/> (vault-wide, since v0
/// has exactly one machine slot). Nothing here invents per-slot backend/presence data that
/// doesn't exist; a future multi-backend keyring (design doc's v0 step 2) would need real
/// per-slot metadata for this to stay accurate once a keyring can mix backends. Likewise, if a
/// keyring ever holds more than one <see cref="SlotKind.Machine"/> slot (possible today per
/// <see cref="KeyringCodec"/>'s format even though only #121's hand-carried enrollment, not yet
/// landed, would produce one), there is no data available to say which slot is "this machine's
/// own" without attempting an actual hardware unwrap per slot — this command deliberately does
/// not do that (it would turn a passive listing into a hardware-touching operation), so it lists
/// every machine slot on equal footing and says so when more than one is present.</para>
/// </summary>
public sealed class SlotsCommand : ICliCommand
{
    public string Name => "slots";
    public string HelpUsage => "slots";
    public string Description => "List a keyring vault's enrolled slots and what protects each one";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        var config = ctx.Storage.LoadConfig();
        ctx.Console.Out.WriteLine(Format(config));
        return 0;
    }

    /// <summary>
    /// Pure formatting, factored out from <see cref="Execute"/> so it's unit-testable without
    /// spinning up a full <see cref="CommandContext"/>. Never returns a bare "unprotected" or
    /// "insecure" for a no-touch machine slot — see this class's doc comment.
    /// </summary>
    internal static string Format(Config config)
    {
        if (config.Keyring == null)
        {
            return "This vault has no keyring — it's a single derived-key or hardware-wrapped\n" +
                   "vault with no multi-slot concept (see 'tswap init --keyring' to create a\n" +
                   "keyring vault instead).";
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
                   "restore config.json from backup or re-run 'tswap init --keyring'.";

        var machineSlotCount = keyring.Slots.Count(s => s.Kind == SlotKind.Machine);

        var sb = new StringBuilder();
        sb.Append($"Keyring slots ({keyring.Slots.Count}, k = {keyring.K}):\n");

        const int slotColumnWidth = 10;
        const int kindColumnWidth = 10;
        sb.Append($"{"SLOT".PadRight(slotColumnWidth)}  {"KIND".PadRight(kindColumnWidth)}  PROTECTION\n");
        sb.Append(new string('-', slotColumnWidth + 2 + kindColumnWidth + 2 + 40) + "\n");

        foreach (var slot in keyring.Slots)
        {
            var shortId = AbbreviateSlotId(slot.SlotId);
            var kindLabel = slot.Kind == SlotKind.Machine ? "machine" : "recovery";
            var protection = slot.Kind == SlotKind.Machine
                ? DescribeMachineProtection(config)
                : DescribeRecoveryProtection();
            sb.Append($"{shortId.PadRight(slotColumnWidth)}  {kindLabel.PadRight(kindColumnWidth)}  {protection}\n");
        }

        if (machineSlotCount > 1)
        {
            sb.Append(
                "\nNote: this keyring has more than one machine slot. Slot data alone (no\n" +
                "per-slot label yet) can't tell you which one is this machine's own without an\n" +
                "actual hardware unlock, which this listing deliberately doesn't attempt.");
        }

        return sb.ToString().TrimEnd('\n');
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
    /// <c>MULTI_MACHINE_KEYING.md</c> §Why not k &gt;= 2 (yet)).
    /// </summary>
    private static string DescribeMachineProtection(Config config) => config.RequiresTouch switch
    {
        true => "YubiKey, touch required",
        false => "YubiKey, no touch required — protected by physical custody of the YubiKey",
        null => "YubiKey, touch requirement unknown — protected by physical custody of the YubiKey",
    };

    /// <summary>
    /// A recovery slot's presence guarantee is not a weaker machine slot — it's a deliberately
    /// different kind of slot with a different job: a break-glass credential that must work
    /// offline, with nobody present, potentially years after enrollment (see
    /// <c>MULTI_MACHINE_KEYING.md</c>'s "The recovery slot" section and its per-backend table,
    /// where the recovery row is explicitly "none — this is the deliberately presence-free,
    /// offline-capable break-glass slot"). Custody of the recovery private key is the only real
    /// control, by design.
    /// </summary>
    private static string DescribeRecoveryProtection() =>
        "break-glass recovery credential — no presence required by design (offline-capable); " +
        "protected only by custody of the recovery private key";
}
