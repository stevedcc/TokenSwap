using TswapCore;
using TswapCore.Keyring;

namespace TswapCli;

/// <summary>
/// The YubiKey touch posture, told without harassing (brief T7 item 5, #185: "Users should make an
/// informed decision and not be harassed"):
/// <list type="bullet">
/// <item>explained once where it is chosen (init, slot add, slot request, migrate):
/// <see cref="ExplainTouch"/>, and acknowledged in config (<see cref="Acknowledge"/>);</item>
/// <item>shown per slot by <c>tswap slots</c>;</item>
/// <item>on everyday commands, at most one line, only for a posture that differs from what was last
/// acknowledged (<see cref="NoticeIfChanged"/>).</item>
/// </list>
/// Everything goes to stderr. Only YubiKey slots have a touch posture; TPM and Secure Enclave slots
/// have their own presence models and their own init-time caveats.
/// </summary>
public static class SecurityWarnings
{
    public const string Touch = "touch";
    public const string NoTouch = "no-touch";
    public const string Unknown = "unknown";

    /// <summary>The <see cref="Config.AcknowledgedTouch"/> key of a classic XOR vault (one posture for both keys).</summary>
    public const string ClassicVault = "vault";

    /// <summary>The stored name of a posture.</summary>
    public static string PostureName(bool? requiresTouch) => requiresTouch switch
    {
        true => Touch,
        false => NoTouch,
        null => Unknown,
    };

    private static string Words(string posture) => posture switch
    {
        Touch => "touch required",
        NoTouch => "no touch",
        _ => "touch unknown",
    };

    /// <summary>One YubiKey posture of a vault: its <see cref="Config.AcknowledgedTouch"/> key, posture and display label.</summary>
    public sealed record SlotPosture(string Key, string Posture, string Label);

    /// <summary>
    /// The touch posture of every YubiKey slot of <paramref name="config"/>: each one-key slot (its
    /// recorded posture), a legacy pair slot or classic XOR vault (<see cref="Config.RequiresTouch"/>,
    /// one posture for both keys), and a pending one-key slot request. Empty when there is none, or
    /// when the keyring can't be read (the unlock reports that).
    /// </summary>
    public static List<SlotPosture> Current(Config config)
    {
        List<SlotPosture> result = [];
        var yubiKeyVault = config.Backend is null or HardwareBackend.YubiKey;
        var pair = config.YubiKeySerials is { Count: 2 } ? $"YubiKeys {string.Join(", ", config.YubiKeySerials)}" : null;
        if (config.Keyring is null)
        {
            if (config.PendingSlotId is not null && config.PendingSlotHwBlob is not null
                && TryDecodeBlob(TryBase64(config.PendingSlotHwBlob), out var pending))
                result.Add(new(config.PendingSlotId, PostureName(pending.RequiresTouch), $"YubiKey {pending.Serial} (pending slot)"));
            else if (yubiKeyVault && pair is not null)
                result.Add(new(ClassicVault, PostureName(config.RequiresTouch), pair));
            return result;
        }

        Keyring keyring;
        try
        {
            keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring));
        }
        catch (Exception ex) when (ex is FormatException or TswapException)
        {
            return result;
        }
        var ownSlotId = config.KeyringSlotId is null ? null : TryBase64(config.KeyringSlotId);
        var firstMachine = keyring.Slots.FirstOrDefault(s => s.Kind == SlotKind.Machine);
        foreach (var slot in keyring.Slots.Where(s => s.Kind == SlotKind.Machine))
        {
            var key = Convert.ToBase64String(slot.SlotId);
            var shortId = Convert.ToHexStringLower(slot.SlotId)[..8];
            if (YubiKeySlotBlob.IsYubiKeyBlob(slot.HwBlob))
            {
                if (TryDecodeBlob(slot.HwBlob, out var blob))
                    result.Add(new(key, PostureName(blob.RequiresTouch), $"YubiKey {blob.Serial} (slot {shortId})"));
            }
            else if (yubiKeyVault && pair is not null
                     && (ownSlotId is null ? slot == firstMachine : slot.SlotId.AsSpan().SequenceEqual(ownSlotId)))
            {
                result.Add(new(key, PostureName(config.RequiresTouch), $"{pair} (slot {shortId})"));
            }
        }
        return result;
    }

    private static byte[]? TryBase64(string value)
    {
        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static bool TryDecodeBlob(byte[]? hwBlob, out YubiKeySlotBlob blob)
    {
        blob = null!;
        if (!YubiKeySlotBlob.IsYubiKeyBlob(hwBlob))
            return false;
        try
        {
            blob = YubiKeySlotBlob.Decode(hwBlob!);
            return true;
        }
        catch (TswapException)
        {
            return false;
        }
    }

    /// <summary>
    /// <paramref name="config"/> with the current posture of its YubiKey slots recorded as
    /// acknowledged: all of them, or only those whose key is in <paramref name="onlyKeys"/> (a slot
    /// just explained). Entries for other slots are kept.
    /// </summary>
    public static Config Acknowledge(Config config, IReadOnlyCollection<string>? onlyKeys = null)
    {
        var acknowledged = config.AcknowledgedTouch is null
            ? new Dictionary<string, string>()
            : new Dictionary<string, string>(config.AcknowledgedTouch);
        foreach (var slot in Current(config).Where(s => onlyKeys is null || onlyKeys.Contains(s.Key)))
            acknowledged[slot.Key] = slot.Posture;
        return config with { AcknowledgedTouch = acknowledged };
    }

    /// <summary>
    /// The slots whose posture differs from what was acknowledged. A slot never acknowledged counts
    /// only when it needs no touch or its posture is unknown: a touch-required key leaves nothing to
    /// decide.
    /// </summary>
    public static List<(SlotPosture Slot, string? Was)> Changed(Config config)
    {
        List<(SlotPosture, string?)> changed = [];
        foreach (var slot in Current(config))
        {
            var was = config.AcknowledgedTouch?.GetValueOrDefault(slot.Key);
            if (was == slot.Posture || (was is null && slot.Posture == Touch))
                continue;
            changed.Add((slot, was));
        }
        return changed;
    }

    /// <summary>
    /// The everyday-command notice: one line on stderr, only for postures that changed since they
    /// were last acknowledged (see <see cref="Changed"/>); nothing otherwise.
    /// </summary>
    public static void NoticeIfChanged(IConsole console, Config config)
    {
        var changed = Changed(config);
        if (changed.Count == 0)
            return;
        // Fix round 1 (MiMo): a slot never acknowledged here hasn't "changed"; say which case it is.
        var parts = changed.Select(c => c.Was is null
            ? $"{c.Slot.Label}: {Words(c.Slot.Posture)}"
            : $"{c.Slot.Label}: {Words(c.Slot.Posture)} (was {Words(c.Was)})");
        var what = changed.All(c => c.Was is null) ? "not acknowledged on this machine"
            : changed.All(c => c.Was is not null) ? "changed since last acknowledged"
            : "changed or not acknowledged on this machine";
        console.Error.WriteLine(
            $"tswap: YubiKey touch setting {what}: {string.Join("; ", parts)}. " +
            "See 'tswap slots', then run 'tswap slots --ack'.");
    }

    /// <summary>
    /// Explains a key's touch posture once, on stderr, where it is chosen (enrolment, migrate):
    /// what it means and how to change it. "Couldn't check" is said as such, with the fix.
    /// </summary>
    public static void ExplainTouch(IConsole console, string keyLabel, bool? requiresTouch)
    {
        var e = console.Error;
        switch (requiresTouch)
        {
            case true:
                console.SetForeground(ConsoleColor.Green);
                e.WriteLine($"✓ {keyLabel}: touch required (recommended). Every unlock needs a press of the key.");
                console.ResetColor();
                break;
            case false:
                console.SetForeground(ConsoleColor.Yellow);
                e.WriteLine($"⚠ {keyLabel}: no touch required, so any process running as you can unlock the vault while the key is plugged in.");
                e.WriteLine("  That can be deliberate (an always-on machine). To require a touch instead, reprogram the key");
                e.WriteLine("  (ykman otp chalresp --generate --touch 2) and enroll it again. 'tswap slots' shows each key's setting.");
                console.ResetColor();
                break;
            default:
                e.WriteLine($"{keyLabel}: Couldn't check the touch setting (ykman didn't report whether the key asked for a touch).");
                e.WriteLine("  Fix: install yubikey-manager 5 or later (ykman on PATH) and enroll the key again; until then");
                e.WriteLine("  'tswap slots' shows it as unknown, and if it needs no touch, any process running as you can use it.");
                break;
        }
    }

    /// <summary>
    /// Explains a posture already recorded in a slot (or a classic vault), where it is reviewed
    /// (migrate). Unlike <see cref="ExplainTouch"/> at enrolment, an unknown posture here wasn't
    /// checked when the key was enrolled; it says so instead of "couldn't check".
    /// </summary>
    public static void ExplainRecordedTouch(IConsole console, string keyLabel, string posture)
    {
        if (posture != Unknown)
        {
            ExplainTouch(console, keyLabel, posture == Touch);
            return;
        }
        var e = console.Error;
        e.WriteLine($"{keyLabel}: touch setting unknown (it wasn't checked when the key was enrolled). If it needs no touch,");
        e.WriteLine("  any process running as you can unlock the vault while the key is plugged in. To record it, enroll the");
        e.WriteLine("  key again with yubikey-manager 5 or later on PATH. 'tswap slots' shows each key's setting.");
    }

    /// <summary>
    /// Explains a classic vault's touch posture (both keys) once, on stderr; nothing for a
    /// touch-required vault or a non-YubiKey backend. Used where the posture is reviewed (migrate).
    /// </summary>
    public static void WarnIfNoTouch(IConsole console, Config config)
    {
        if (config.Backend is not (null or HardwareBackend.YubiKey))
            return;
        if (config.RequiresTouch == true)
            return;
        var label = config.YubiKeySerials is { Count: > 0 } ? $"YubiKeys {string.Join(", ", config.YubiKeySerials)}" : "This vault's YubiKeys";
        ExplainTouch(console, label, config.RequiresTouch);
    }
}
