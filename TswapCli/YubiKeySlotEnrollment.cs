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
        var requiresTouch = ctx.YubiKeys.DetectTouchRequirement(serial);
        var blob = YubiKeySlotBlob.Create(serial, requiresTouch);
        var first = ctx.YubiKeys.Challenge(serial, blob.ChallengeString);
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

    /// <summary>The touch-policy lines printed after enrolling a key.</summary>
    public static void PrintTouchPolicy(IConsole c, YubiKeySlotBlob blob)
    {
        switch (blob.RequiresTouch)
        {
            case true:
                c.SetForeground(ConsoleColor.Green);
                c.Out.WriteLine("✓ Touch requirement: ENABLED (recommended)");
                c.ResetColor();
                break;
            case false:
                c.SetForeground(ConsoleColor.Yellow);
                c.Out.WriteLine("⚠️  Touch requirement: DISABLED");
                c.Out.WriteLine("\nSECURITY NOTICE: this YubiKey is configured without a button press");
                c.Out.WriteLine("requirement. Any process with access to the inserted key can unlock the vault.");
                c.ResetColor();
                break;
            default:
                c.Out.WriteLine("Touch requirement: unknown (detection failed)");
                break;
        }
    }
}
