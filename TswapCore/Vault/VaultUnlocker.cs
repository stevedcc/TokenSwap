namespace TswapCore.Vault;

/// <summary>
/// Derives the vault master key from a connected YubiKey plus the config's XOR share.
/// Pure logic over <see cref="IYubiKeyService"/> — serial selection UI is supplied by
/// the caller as a callback (only invoked when more than one YubiKey is connected).
///
/// When <paramref name="overrideKey"/> is set (test mode), unlock returns it directly
/// without touching hardware or the config — test vaults are encrypted with the test
/// key itself, not a derived key.
/// </summary>
public sealed class VaultUnlocker(IYubiKeyService yubiKeys, byte[]? overrideKey = null)
{
    /// <summary>The challenge used by configs created before vault-unique challenges.</summary>
    public const string LegacyChallenge = "tswap-unlock";

    /// <summary>
    /// Unlocks the vault and returns the 32-byte master key.
    /// </summary>
    /// <param name="config">Vault configuration (serials + XOR share).</param>
    /// <param name="chooseSerial">
    /// Called with the connected serials when more than one YubiKey is present;
    /// returns the serial to use. Never called for zero or one connected key.
    /// </param>
    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
    {
        if (overrideKey != null)
            return overrideKey; // Test mode: bypass YubiKey entirely — the test key is the master key

        var serial = SelectConnectedSerial(chooseSerial);

        if (!config.YubiKeySerials.Contains(serial))
            throw new TswapException($"YubiKey {serial} not authorized. Expected: {string.Join(", ", config.YubiKeySerials)}");

        // Challenge current YubiKey using the vault-unique challenge (falls back to the
        // legacy fixed challenge for configs created before this feature was added).
        var k_current = yubiKeys.Challenge(serial, config.UnlockChallenge ?? LegacyChallenge);

        // Reconstruct other key via XOR
        var xorShare = Convert.FromHexString(config.RedundancyXor);
        var k_other = Crypto.XorBytes(k_current, xorShare);

        // Determine order (use serials to ensure consistent ordering)
        byte[] k1, k2;
        if (serial == config.YubiKeySerials[0])
        {
            k1 = k_current;
            k2 = k_other;
        }
        else
        {
            k1 = k_other;
            k2 = k_current;
        }

        return Crypto.DeriveKey(k1, k2);
    }

    /// <summary>
    /// Resolves which connected YubiKey to use: errors when none are connected,
    /// returns the single key directly, or defers to the callback for multiple.
    /// Also used by commands that need a specific connected key (init, create's
    /// hardware-entropy path) rather than a vault unlock.
    /// </summary>
    public int SelectConnectedSerial(Func<IReadOnlyList<int>, int> chooseSerial, int? requiredSerial = null)
    {
        if (overrideKey != null)
            return requiredSerial ?? TestKeyYubiKeyService.Serial1;

        var serials = yubiKeys.ListSerials();

        if (serials.Count == 0)
            throw new TswapException("No YubiKey detected. Please insert YubiKey.");

        if (requiredSerial.HasValue)
        {
            if (!serials.Contains(requiredSerial.Value))
                throw new TswapException($"YubiKey with serial {requiredSerial} not found.");
            return requiredSerial.Value;
        }

        if (serials.Count > 1)
            return chooseSerial(serials);

        return serials[0];
    }
}
