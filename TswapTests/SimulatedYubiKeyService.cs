using System.Security.Cryptography;
using System.Text;
using TswapCore.Vault;

namespace TswapTests;

/// <summary>
/// A simulated set of YubiKeys for tests (brief T4 item 1): each serial has its own HMAC-SHA1
/// secret, and <see cref="Challenge"/> computes a real HMAC-SHA1 over the challenge exactly as
/// <see cref="YkmanYubiKeyService"/> sends it to the key (UTF-8, zero-padded or truncated to 64
/// bytes). Which keys are "plugged in" is configurable and can change during a test, so a test
/// can unplug key A and plug in key B between two commands.
///
/// <para>Unlike <see cref="TestKeyYubiKeyService"/> (every challenge answers with the same bytes)
/// this one answers differently per key and per challenge, so a test can tell which key and which
/// challenge a derivation used. <see cref="IsSimulated"/> is false on purpose: the commands then
/// take their real-hardware paths (for example <c>create</c>'s YubiKey entropy) instead of the
/// test-key shortcuts.</para>
/// </summary>
public sealed class SimulatedYubiKeyService : IYubiKeyService
{
    private readonly Dictionary<int, byte[]> _secrets;
    private readonly Dictionary<int, bool?> _touch;

    /// <param name="secrets">Each key's serial and its 20-byte HMAC-SHA1 secret.</param>
    /// <param name="pluggedIn">Serials plugged in at the start (default: all of them).</param>
    public SimulatedYubiKeyService(IReadOnlyDictionary<int, byte[]> secrets, IEnumerable<int>? pluggedIn = null)
    {
        _secrets = secrets.ToDictionary(kv => kv.Key, kv => (byte[])kv.Value.Clone());
        _touch = secrets.Keys.ToDictionary(s => s, _ => (bool?)true);
        PluggedIn = (pluggedIn ?? secrets.Keys).ToList();
    }

    /// <summary>A key per serial with a secret derived from the serial (deterministic).</summary>
    public static SimulatedYubiKeyService WithKeys(params int[] serials) =>
        new(serials.ToDictionary(s => s, SecretFor));

    /// <summary>The deterministic secret <see cref="WithKeys"/> gives a serial.</summary>
    public static byte[] SecretFor(int serial) =>
        SHA1.HashData(Encoding.UTF8.GetBytes($"simulated-yubikey-{serial}"));

    /// <summary>Serials currently plugged in, in the order <see cref="ListSerials"/> reports them.</summary>
    public List<int> PluggedIn { get; set; }

    /// <summary>Every challenge answered so far: (serial, challenge string).</summary>
    public List<(int Serial, string Challenge)> Challenges { get; } = [];

    /// <summary>Brief T7 item 4: plugged-in serials that don't answer a challenge (busy, or a touch that timed out).</summary>
    public HashSet<int> NotAnswering { get; } = [];

    /// <summary>
    /// Guided init: serials whose challenge fails with this message (a key ykman can't reach, e.g. macOS
    /// blocking its OTP interface, or one unplugged after the listing), before anything is recorded.
    /// </summary>
    public Dictionary<int, string> FailWith { get; } = [];

    /// <summary>
    /// Guided init: called with the serial at the start of every <see cref="Challenge"/>, so a test can
    /// change the world while init waits for a key (fill the vault folder, write a config).
    /// </summary>
    public Action<int>? OnChallenge { get; set; }

    public bool IsSimulated => false;

    public void SetTouch(int serial, bool? requiresTouch) => _touch[serial] = requiresTouch;

    /// <summary>Guided init: called at the start of every <see cref="ListSerials"/> (what was on screen by then).</summary>
    public Action? OnListSerials { get; set; }

    public IReadOnlyList<int> ListSerials()
    {
        OnListSerials?.Invoke();
        return PluggedIn.Where(s => !Hidden.Contains(s)).ToList();
    }

    /// <summary>
    /// YubiKey SDK stage 1: serials the OS hides from the keyboard interface (seen over FIDO only). They are left out
    /// of <see cref="ListSerials"/> and reported by <see cref="FindKeys"/> as not reachable, plugged in or not.
    /// </summary>
    public HashSet<int> Hidden { get; set; } = [];

    /// <summary>Stage 1: a serial's transports as <see cref="FindKeys"/> reports them (default by reachability).</summary>
    public Dictionary<int, string> Transports { get; } = [];

    /// <summary>Stage 1: slot 2's state per serial (default <see cref="Slot2State.Configured"/>).</summary>
    public Dictionary<int, Slot2State> Slot2States { get; } = [];

    /// <summary>Stage 1: per serial, the kind <see cref="ProgramSlot2"/> fails with (absent: success).</summary>
    public Dictionary<int, OtpFailure> ProgramOutcome { get; } = [];

    /// <summary>Stage 1: every <see cref="ProgramSlot2"/> call, also failed ones: (serial, touch asked for).</summary>
    public List<(int Serial, bool RequireTouch)> Programmed { get; } = [];

    /// <summary>Plugged-in keys (reachable unless hidden), then hidden keys that aren't plugged in.</summary>
    public IReadOnlyList<YubiKeyInfo> FindKeys()
    {
        OnListSerials?.Invoke();
        var keys = PluggedIn.Select(s => Info(s, !Hidden.Contains(s))).ToList();
        keys.AddRange(Hidden.Where(s => !PluggedIn.Contains(s)).Select(s => Info(s, false)));
        return keys;
    }

    private YubiKeyInfo Info(int serial, bool reachable) =>
        new(serial, reachable, Transports.GetValueOrDefault(serial) ?? (reachable ? "HidKeyboard, HidFido" : "HidFido"));

    public Slot2State GetSlot2State(int serial)
    {
        if (!PluggedIn.Contains(serial))
            throw new TswapCore.TswapException($"YubiKey {serial} is not plugged in.");
        return Slot2States.GetValueOrDefault(serial, Slot2State.Configured);
    }

    /// <summary>
    /// Records the call; with a <see cref="ProgramOutcome"/> for the serial, fails with that kind; otherwise slot 2
    /// gets a fresh secret and the touch flag.
    /// </summary>
    public void ProgramSlot2(int serial, bool requireTouch)
    {
        if (!PluggedIn.Contains(serial))
            throw new TswapCore.TswapException($"YubiKey {serial} is not plugged in.");
        Programmed.Add((serial, requireTouch));
        if (ProgramOutcome.TryGetValue(serial, out var kind))
            throw new YubiKeyProgramException(kind, serial);
        _secrets[serial] = RandomNumberGenerator.GetBytes(20);
        _touch[serial] = requireTouch;
        Slot2States[serial] = Slot2State.Configured;
    }

    public byte[] Challenge(int serial, string challenge)
    {
        OnChallenge?.Invoke(serial);
        if (FailWith.TryGetValue(serial, out var failure))
            throw new TswapCore.TswapException(failure);
        if (!PluggedIn.Contains(serial) || !_secrets.TryGetValue(serial, out var secret))
            throw new TswapCore.TswapException($"ykman failed: device {serial} not found");

        if (Slot2States.GetValueOrDefault(serial, Slot2State.Configured) == Slot2State.Empty)
            throw new TswapCore.TswapException($"Slot 2 of YubiKey {serial} isn't set up for challenge-response; run `tswap yubikey setup`.");

        Challenges.Add((serial, challenge)); // asked, even when it doesn't answer
        if (NotAnswering.Contains(serial))
            throw new TswapCore.TswapException($"ykman failed: timed out waiting for YubiKey {serial}");
        var padded = new byte[64];
        var input = Encoding.UTF8.GetBytes(challenge);
        Array.Copy(input, padded, Math.Min(input.Length, 64));
        return HMACSHA1.HashData(secret, padded);
    }

    /// <summary>
    /// Brief T7 item 5: false makes <see cref="DetectTouchRequirement"/> return null, like real
    /// <c>ykman otp info</c>, which can't read a slot's touch setting.
    /// </summary>
    public bool DetectionWorks { get; set; } = true;

    public bool? DetectTouchRequirement(int serial) => DetectionWorks ? _touch.GetValueOrDefault(serial) : null;

    /// <summary>
    /// Brief T7 item 5: the "asked for touch" flag is the key's touch setting (<see cref="SetTouch"/>),
    /// as ykman prints "Touch your YubiKey..." exactly when the key waits for one.
    /// </summary>
    public YubiKeyResponse ChallengeReportingTouch(int serial, string challenge)
        => new(Challenge(serial, challenge), _touch.GetValueOrDefault(serial));
}
