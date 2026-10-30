namespace TswapCore.Vault;

/// <summary>
/// Hardware abstraction for YubiKey operations. The production implementation
/// (<see cref="YkmanYubiKeyService"/>) shells out to the ykman CLI; tests substitute
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
}

/// <summary>A challenge's response, and whether the key asked for a touch first (null: unknown).</summary>
public sealed record YubiKeyResponse(byte[] Response, bool? AskedForTouch);
