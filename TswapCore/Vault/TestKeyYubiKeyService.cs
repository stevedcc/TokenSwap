namespace TswapCore.Vault;

/// <summary>
/// Simulated <see cref="IYubiKeyService"/> for tests (TSWAP_TEST_KEY). Mirrors the
/// historical test-mode behaviour: one synthetic serial is "connected", and every
/// challenge answers with the first 20 bytes of the test key (a fake HMAC-SHA1
/// response). Vault unlock in test mode does not go through challenge-response at
/// all — see <see cref="VaultUnlocker"/>'s override key.
/// </summary>
public sealed class TestKeyYubiKeyService(byte[] testKey) : IYubiKeyService
{
    /// <summary>Synthetic serials used by test-mode init (matches historical config).</summary>
    public const int Serial1 = 99999999;
    public const int Serial2 = 99999998;

    public bool IsSimulated => true;

    public IReadOnlyList<int> ListSerials() => [Serial1];

    public byte[] Challenge(int serial, string challenge) => testKey[..20];

    public bool? DetectTouchRequirement(int serial) => null;

    /// <summary>The one synthetic key, reachable over the keyboard interface.</summary>
    public IReadOnlyList<YubiKeyInfo> FindKeys() => [new YubiKeyInfo(Serial1, true, "HidKeyboard")];

    public Slot2State GetSlot2State(int serial) => Slot2State.Configured;

    public void ProgramSlot2(int serial, bool requireTouch) =>
        throw new TswapException("Test mode (TSWAP_TEST_KEY) can't program a YubiKey.");
}
