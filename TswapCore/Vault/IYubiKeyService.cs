namespace TswapCore.Vault;

/// <summary>
/// Hardware abstraction for YubiKey operations. The production implementation
/// (<see cref="SdkYubiKeyService"/>) talks to the keys through Yubico's .NET SDK
/// (<see cref="YkmanYubiKeyService"/>, the ykman one, goes in stage 1's task 3); tests substitute
/// <see cref="TestKeyYubiKeyService"/>. No UI here — serial selection prompts and
/// touch warnings are the CLI layer's job.
/// </summary>
public interface IYubiKeyService
{
    /// <summary>
    /// True when this implementation simulates hardware (test mode). Commands that
    /// offer hardware-entropy paths fall back to system RNG when set.
    /// </summary>
    bool IsSimulated { get; }

    /// <summary>Serial numbers of currently connected YubiKeys.</summary>
    IReadOnlyList<int> ListSerials();

    /// <summary>
    /// HMAC-SHA1 challenge-response against slot 2 of the given YubiKey.
    /// The challenge string is padded to 64 bytes before hex-encoding.
    /// </summary>
    byte[] Challenge(int serial, string challenge);

    /// <summary>
    /// Whether slot 2 of the given YubiKey requires a button press.
    /// Returns null if detection fails.
    /// </summary>
    bool? DetectTouchRequirement(int serial);

    /// <summary>
    /// <see cref="Challenge"/>, also reporting whether the key asked for a touch before it answered
    /// (brief T7 item 5): how the touch posture is detected at enrolment. Null when this service
    /// can't tell.
    /// </summary>
    YubiKeyResponse ChallengeReportingTouch(int serial, string challenge) => new(Challenge(serial, challenge), null);

    /// <summary>
    /// Every key plugged in, also those whose OTP interface can't be reached (they are reported, never an error):
    /// what <c>tswap yubikey setup</c> lists and chooses from. The default (for test doubles that predate it):
    /// <see cref="ListSerials"/>, each reachable over the keyboard interface.
    /// </summary>
    IReadOnlyList<YubiKeyInfo> FindKeys() => ListSerials().Select(s => new YubiKeyInfo(s, true, "HidKeyboard")).ToList();

    /// <summary>Whether slot 2 of the given key holds any configuration.</summary>
    Slot2State GetSlot2State(int serial) => throw new NotSupportedException($"{GetType().Name} can't read a YubiKey's slot 2");

    /// <summary>
    /// Programs slot 2 of the given key for HMAC-SHA1 challenge-response (a fresh secret; touch per
    /// <paramref name="requireTouch"/>) and checks that it answers. A failure after writing started is a
    /// <see cref="YubiKeyProgramException"/> carrying its <see cref="OtpFailure"/> kind.
    /// </summary>
    void ProgramSlot2(int serial, bool requireTouch) => throw new NotSupportedException($"{GetType().Name} can't program a YubiKey");
}

/// <summary>Whether a key's slot 2 holds any configuration (of any kind: challenge-response, OTP, static password).</summary>
public enum Slot2State { Empty, Configured }

/// <summary>
/// One plugged-in key: its serial (null when it can't be read), whether its OTP interface is reachable over the
/// keyboard interface, and the transports it was found on, as text (for example <c>HidKeyboard, HidFido, SmartCard</c>).
/// </summary>
public sealed record YubiKeyInfo(int? Serial, bool KeyboardReachable, string Transports);

/// <summary>A challenge's response, and whether the key asked for a touch first (null: unknown).</summary>
public sealed record YubiKeyResponse(byte[] Response, bool? AskedForTouch);
