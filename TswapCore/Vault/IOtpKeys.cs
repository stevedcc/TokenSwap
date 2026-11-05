namespace TswapCore.Vault;

/// <summary>
/// The device seam under <see cref="SdkYubiKeyService"/> (YubiKey SDK stage 1): the few things tswap asks of a
/// YubiKey's OTP application. <see cref="YubicoOtpKeys"/> is the one real implementation (Yubico's .NET SDK); the
/// unit tests drive a fake. Keys are addressed by serial; nothing here picks among several keys. Failures are
/// <see cref="OtpKeysException"/>s.
/// </summary>
internal interface IOtpKeys
{
    /// <summary>Every physical key the SDK sees, on any transport, in the SDK's order.</summary>
    IReadOnlyList<OtpKeyInfo> Find();

    /// <summary>
    /// HMAC-SHA1 challenge-response on slot 2: <paramref name="challenge64"/> goes to the key as it is (64 bytes).
    /// <paramref name="onTouchRequested"/> is called when the key asks for a touch. The caller zeroes
    /// <see cref="OtpChallengeResult.Response"/> after use.
    /// </summary>
    OtpChallengeResult Challenge(int serial, ReadOnlySpan<byte> challenge64, Action onTouchRequested);

    /// <summary>Whether slot 2 holds any configuration.</summary>
    Slot2State Slot2(int serial);

    /// <summary>
    /// Programs slot 2 for HMAC-SHA1 challenge-response with a fresh secret, and proves it: returns only when the slot
    /// answered a verify challenge correctly (and with the touch setting asked for). Otherwise throws
    /// <see cref="OtpKeysException"/> with <see cref="OtpFailure.ProgramFailed"/>, <see cref="OtpFailure.VerifyWrong"/>
    /// or <see cref="OtpFailure.VerifyNoAnswer"/> (or, before anything was written, the kind of the failure).
    /// </summary>
    void ProgramSlot2(int serial, bool requireTouch);

    /// <summary>
    /// A read-only look at every YubiKey keyboard interface the OS lists, for a key <see cref="Find"/> saw only on other
    /// transports: busy (a command in progress), hidden (can't be opened) or idle. Never writes to a key. Throws
    /// <see cref="OtpKeysException"/> when the interfaces can't be listed.
    /// </summary>
    IReadOnlyList<KeyboardInterfaceState> ProbeKeyboardInterfaces();
}

/// <summary>One keyboard interface, as the read-only probe found it.</summary>
internal enum KeyboardInterfaceState
{
    /// <summary>Opened; its status shows no command in progress.</summary>
    Idle,
    /// <summary>Opened; its status shows a command in progress (another program, e.g. waiting for a touch).</summary>
    Busy,
    /// <summary>The OS refused to open it (no udev rule, no Input Monitoring, access denied).</summary>
    Unopenable,
    /// <summary>Opened, but its status couldn't be read.</summary>
    Unreadable,
}

/// <summary>
/// One physical key: its serial (null when it can't be read), whether the OTP application is reachable over the
/// keyboard interface (the only transport on which a USB key answers HMAC challenge-response), and the transports the
/// SDK found it on, as text (for example <c>HidKeyboard, HidFido, SmartCard</c>).
/// </summary>
internal sealed record OtpKeyInfo(int? Serial, bool KeyboardReachable, string Transports);

/// <summary>A challenge's response and whether the key asked for a touch first. The caller zeroes the response.</summary>
internal sealed record OtpChallengeResult(byte[] Response, bool TouchRequested);

/// <summary>What went wrong at the device seam.</summary>
public enum OtpFailure
{
    /// <summary>Another process is using the key.</summary>
    Busy,
    /// <summary>Slot 2 holds no configuration.</summary>
    Slot2Empty,
    /// <summary>The key's OTP interface can't be reached (the OS hides or refuses it).</summary>
    NotReachable,
    /// <summary>Programming slot 2 failed: the slot may be empty or half-written.</summary>
    ProgramFailed,
    /// <summary>Slot 2 was programmed, but its answer (or its touch setting) is not what was asked for.</summary>
    VerifyWrong,
    /// <summary>Slot 2 was programmed, but it didn't answer the verify challenge (including a touch timeout).</summary>
    VerifyNoAnswer,
    /// <summary>
    /// The key didn't take or answer the command in time: busy with another program, or slot 2 holds a configuration
    /// that doesn't answer HMAC challenges.
    /// </summary>
    NoAnswer,
    /// <summary>Anything else; the SDK's message is passed through.</summary>
    Other,
}

/// <summary>A failure at the device seam: its kind, the key's serial when known, and the SDK's own message.</summary>
internal sealed class OtpKeysException(OtpFailure kind, int? serial, string detail) : Exception(detail)
{
    public OtpFailure Kind { get; } = kind;
    public int? Serial { get; } = serial;
    public string Detail { get; } = detail;
}
