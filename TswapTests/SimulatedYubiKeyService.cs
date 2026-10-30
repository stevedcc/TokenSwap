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

    public bool IsSimulated => false;

    public void SetTouch(int serial, bool? requiresTouch) => _touch[serial] = requiresTouch;

    public IReadOnlyList<int> ListSerials() => PluggedIn.ToList();

    public byte[] Challenge(int serial, string challenge)
    {
        if (!PluggedIn.Contains(serial) || !_secrets.TryGetValue(serial, out var secret))
            throw new TswapCore.TswapException($"ykman failed: device {serial} not found");

        Challenges.Add((serial, challenge));
        var padded = new byte[64];
        var input = Encoding.UTF8.GetBytes(challenge);
        Array.Copy(input, padded, Math.Min(input.Length, 64));
        return HMACSHA1.HashData(secret, padded);
    }

    public bool? DetectTouchRequirement(int serial) => _touch.GetValueOrDefault(serial);
}
