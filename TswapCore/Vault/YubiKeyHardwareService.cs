namespace TswapCore.Vault;

/// <summary>
/// The YubiKey <see cref="IHardwareKeyService"/>: derives the vault master key from a
/// connected YubiKey plus the config's XOR share (the 1-of-2 redundancy scheme — either
/// enrolled key reconstructs the other from a non-secret public share). Wraps the
/// low-level <see cref="IYubiKeyService"/> ykman driver and owns the challenge/XOR/PBKDF2
/// logic that used to live inline in <see cref="VaultUnlocker"/>.
///
/// When <paramref name="overrideKey"/> is set (test mode) unlock returns it directly
/// without touching hardware — test vaults are encrypted with the test key itself, not a
/// derived key.
/// </summary>
public sealed class YubiKeyHardwareService(IYubiKeyService yubiKeys, byte[]? overrideKey = null)
    : IHardwareKeyService
{
    /// <summary>The challenge used by configs created before vault-unique challenges.</summary>
    public const string LegacyChallenge = "tswap-unlock";

    public HardwareBackend Backend => HardwareBackend.YubiKey;
    public bool IsSimulated => yubiKeys.IsSimulated;

    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial)
    {
        if (overrideKey != null)
            return overrideKey; // Test mode: bypass YubiKey entirely — the test key is the master key

        // The XOR-redundancy scheme requires exactly two enrolled keys; a corrupted or
        // hand-edited config would otherwise surface as an opaque index-out-of-range.
        if (config.YubiKeySerials is not { Count: 2 })
            throw new TswapException(
                $"Config is corrupted: expected exactly 2 YubiKey serials, found {config.YubiKeySerials?.Count ?? 0}. " +
                "Restore config.json from backup or re-run 'tswap init'.");

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
        {
            var chosen = chooseSerial(serials);
            // Guard against a callback returning something that isn't connected —
            // later hardware calls would otherwise fail in confusing ways.
            if (!serials.Contains(chosen))
                throw new TswapException($"Selected YubiKey serial {chosen} is not among the connected keys ({string.Join(", ", serials)}).");
            return chosen;
        }

        return serials[0];
    }
}
