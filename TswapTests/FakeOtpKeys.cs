using System.Security.Cryptography;
using TswapCore.Vault;

namespace TswapTests;

/// <summary>
/// The device seam's fake (YubiKey SDK stage 1, task 2): drives <see cref="SdkYubiKeyService"/> without hardware.
/// Every challenge and program call is recorded. It can be told which keys are present (and over which transports),
/// which are busy, which have slot 2 empty, which ask for a touch, and how a program call ends.
/// </summary>
internal sealed class FakeOtpKeys : IOtpKeys
{
    /// <summary>The keys <see cref="Find"/> reports, in this order.</summary>
    public List<OtpKeyInfo> Keys { get; } = [];

    /// <summary>Serials whose challenge, slot read and program call fail with <see cref="OtpFailure.Busy"/>.</summary>
    public HashSet<int> Busy { get; } = [];

    /// <summary>Serials whose slot 2 is empty: a challenge fails with <see cref="OtpFailure.Slot2Empty"/>.</summary>
    public HashSet<int> Slot2Empty { get; } = [];

    /// <summary>Serials whose challenge calls <c>onTouchRequested</c> before answering.</summary>
    public HashSet<int> AsksForTouch { get; } = [];

    /// <summary>Per serial: the kind <see cref="ProgramSlot2"/> fails with (absent: success).</summary>
    public Dictionary<int, OtpFailure> ProgramOutcome { get; } = [];

    /// <summary>What the read-only probe of the raw keyboard interfaces finds (default: none listed).</summary>
    public List<KeyboardInterfaceState> Interfaces { get; } = [];

    /// <summary>The probe itself fails (the SDK's HID listing threw).</summary>
    public bool ProbeFails { get; init; }

    /// <summary>Every challenge: the serial and the exact 64 bytes received (a copy).</summary>
    public List<(int Serial, byte[] Challenge)> Challenges { get; } = [];

    /// <summary>Every program call: the serial and whether touch was asked for.</summary>
    public List<(int Serial, bool RequireTouch)> Programs { get; } = [];

    /// <summary>Adds a key reachable over the keyboard interface.</summary>
    public FakeOtpKeys WithKey(int? serial, string transports = "HidKeyboard, HidFido, SmartCard")
    {
        Keys.Add(new OtpKeyInfo(serial, KeyboardReachable: true, transports));
        return this;
    }

    /// <summary>Adds a key the OS hides from the keyboard interface (seen over FIDO only by default).</summary>
    public FakeOtpKeys WithHiddenKey(int? serial, string transports = "HidFido")
    {
        Keys.Add(new OtpKeyInfo(serial, KeyboardReachable: false, transports));
        return this;
    }

    /// <summary>The secret the fake answers with for a serial (deterministic).</summary>
    public static byte[] SecretFor(int serial) => SHA1.HashData(BitConverter.GetBytes(serial));

    public IReadOnlyList<OtpKeyInfo> Find() => Keys.ToList();

    public OtpChallengeResult Challenge(int serial, ReadOnlySpan<byte> challenge64, Action onTouchRequested)
    {
        Challenges.Add((serial, challenge64.ToArray()));
        if (Busy.Contains(serial))
            throw new OtpKeysException(OtpFailure.Busy, serial, "the key did not accept the command");
        if (Slot2Empty.Contains(serial))
            throw new OtpKeysException(OtpFailure.Slot2Empty, serial, "slot 2 is empty");
        var touched = AsksForTouch.Contains(serial);
        if (touched)
            onTouchRequested();
        return new OtpChallengeResult(HMACSHA1.HashData(SecretFor(serial), challenge64), touched);
    }

    public Slot2State Slot2(int serial)
    {
        if (Busy.Contains(serial))
            throw new OtpKeysException(OtpFailure.Busy, serial, "the key did not accept the command");
        return Slot2Empty.Contains(serial) ? Slot2State.Empty : Slot2State.Configured;
    }

    public IReadOnlyList<KeyboardInterfaceState> ProbeKeyboardInterfaces() =>
        ProbeFails ? throw new OtpKeysException(OtpFailure.Other, null, "fake probe failure") : Interfaces.ToList();

    public void ProgramSlot2(int serial, bool requireTouch)
    {
        Programs.Add((serial, requireTouch));
        if (ProgramOutcome.TryGetValue(serial, out var kind))
            throw new OtpKeysException(kind, serial, $"fake {kind}");
        Slot2Empty.Remove(serial);
    }
}
