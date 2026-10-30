using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;

namespace TswapCli;

/// <summary>
/// Enrolls one plugged-in YubiKey as a one-key keyring slot (brief T4 decisions 1 and 2): picks
/// the key, records its touch policy, draws a fresh challenge and salt
/// (<see cref="YubiKeySlotBlob.Create"/>) and derives the slot's <c>KEK_slot</c> from the key's
/// response (<see cref="YubiKeySlotKek"/>). Shared by <c>init --keyring</c>, <c>slot add
/// --yubikey</c> and <c>slot request</c>, so all three build the same slot.
/// </summary>
internal static class YubiKeySlotEnrollment
{
    /// <summary>
    /// Enrolls a key for the slot <paramref name="slotId"/>. Keys whose serials are in
    /// <paramref name="alreadyEnrolled"/> are never picked; when every plugged-in key is one of
    /// them, this fails with an actionable error. With several eligible keys plugged in, the
    /// usual serial prompt decides. The key is challenged <b>twice</b> with the slot's challenge and
    /// the responses compared in constant time (security review of T4): a key that answers the
    /// same challenge differently would make a slot that never opens, so it is refused before
    /// anything is written. The caller zeroes the returned <c>KEK_slot</c> after use.
    /// </summary>
    public static (YubiKeySlotBlob Blob, byte[] KekSlot) Enroll(
        CommandContext ctx, byte[] slotId, IReadOnlyCollection<int>? alreadyEnrolled = null)
    {
        var c = ctx.Console;
        var pluggedIn = ctx.YubiKeys.ListSerials();
        if (pluggedIn.Count == 0)
            throw new TswapException("No YubiKey detected. Please insert YubiKey.");

        var eligible = pluggedIn.Where(s => alreadyEnrolled?.Contains(s) != true).ToList();
        if (eligible.Count == 0)
            throw new TswapException(
                $"Every plugged-in YubiKey ({string.Join(", ", pluggedIn)}) already has a slot in this vault. " +
                "Plug in a YubiKey that has no slot yet; each key needs only one slot.");

        return EnrollSerial(ctx, slotId, ctx.ChooseSerialAmong(eligible));
    }

    /// <summary>
    /// Enrolls the plugged-in key <paramref name="serial"/> for the slot <paramref name="slotId"/>
    /// (brief T6: <c>migrate --to-records</c> gives each key of a plain XOR vault its own slot),
    /// with the same double challenge as <see cref="Enroll"/>.
    /// </summary>
    public static (YubiKeySlotBlob Blob, byte[] KekSlot) EnrollSerial(CommandContext ctx, byte[] slotId, int serial)
    {
        var c = ctx.Console;
        c.Out.WriteLine($"\nEnrolling YubiKey {serial} (touch it each time it flashes; it is asked twice)...");
        // Brief T7 item 5: the posture is whether the first challenge asked for a touch (ykman can't
        // read a slot's touch setting); a service that can't tell falls back to its own detection.
        var probe = YubiKeySlotBlob.Create(serial, requiresTouch: null);
        var answer = ctx.YubiKeys.ChallengeReportingTouch(serial, probe.ChallengeString);
        var blob = probe.WithRequiresTouch(answer.AskedForTouch ?? ctx.YubiKeys.DetectTouchRequirement(serial));
        var first = answer.Response;
        var second = ctx.YubiKeys.Challenge(serial, blob.ChallengeString);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(first, second))
                throw new TswapException(
                    $"YubiKey {serial} answered the same challenge differently; it can't be used as a slot. " +
                    "Check that its slot 2 is configured for HMAC-SHA1 challenge-response, or use another key.");
            return (blob, YubiKeySlotKek.Derive(first, blob.Salt, slotId));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
    }

    /// <summary>
    /// The touch posture of a key just enrolled, explained once on stderr (brief T7 item 5): this is
    /// where it is chosen. The caller acknowledges it in config (<see cref="SecurityWarnings.Acknowledge"/>).
    /// </summary>
    public static void PrintTouchPolicy(IConsole c, YubiKeySlotBlob blob)
        => SecurityWarnings.ExplainTouch(c, $"YubiKey {blob.Serial}", blob.RequiresTouch);
}
