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
        => Unlock(config, YubiKeySelection.FromChooser(chooseSerial));

    /// <summary>
    /// Unlocks a classic XOR vault (brief T7 item 4): either enrolled key works with the share, so
    /// of the plugged-in enrolled keys <paramref name="selection"/> decides; unattended, the first
    /// that answers wins (the vault has one touch posture for both keys, so the order is the
    /// plugged-in order).
    /// </summary>
    public byte[] Unlock(Config config, YubiKeySelection selection)
    {
        if (overrideKey is not null)
            return overrideKey; // Test mode: bypass YubiKey entirely — the test key is the master key

        // The XOR-redundancy scheme requires exactly two enrolled keys; a corrupted or
        // hand-edited config would otherwise surface as an opaque index-out-of-range.
        if (config.YubiKeySerials is not { Count: 2 })
            throw new TswapException(
                $"Config is corrupted: expected exactly 2 YubiKey serials, found {config.YubiKeySerials?.Count ?? 0}. " +
                "Restore config.json from backup or re-run 'tswap init'.");

        var connected = yubiKeys.ListSerials();
        if (connected.Count == 0)
            throw new TswapException("No YubiKey detected. Please insert YubiKey.");

        var enrolled = connected.Where(config.YubiKeySerials.Contains).Distinct().ToList();
        if (enrolled.Count == 0 && selection.Serial is null)
            throw new TswapException(connected.Count == 1
                ? $"YubiKey {connected[0]} not authorized. Expected: {string.Join(", ", config.YubiKeySerials)}"
                : $"None of the plugged-in YubiKeys ({string.Join(", ", connected)}) is authorized. Expected: {string.Join(", ", config.YubiKeySerials)}");

        var order = selection.Order(enrolled, enrolled.Select(_ => config.RequiresTouch).ToList(), connected);
        var failures = new List<string>();
        foreach (var serial in order)
        {
            byte[] k_current;
            try
            {
                // Challenge current YubiKey using the vault-unique challenge (falls back to the
                // legacy fixed challenge for configs created before this feature was added).
                k_current = yubiKeys.Challenge(serial, config.UnlockChallenge ?? LegacyChallenge);
            }
            catch (TswapException ex) when (order.Count > 1)
            {
                failures.Add($"{serial}: {ex.Message}");
                continue; // unattended: busy, or a touch that timed out; try the next key
            }
            return DeriveMasterKey(config, serial, k_current);
        }
        throw new TswapException(
            $"None of the plugged-in YubiKeys ({string.Join(", ", order)}) answered: {string.Join("; ", failures)}");
    }

    private static byte[] DeriveMasterKey(Config config, int serial, byte[] k_current)
    {
        // Reconstruct other key via XOR
        var xorShare = Convert.FromHexString(config.RedundancyXor ?? "");
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

        // Null means this config predates per-vault salts (or never opted in) and must keep
        // deriving via the legacy hardcoded Crypto.MasterKeySalt constant — see Config.MasterKeySalt.
        var salt = config.MasterKeySalt is not null ? Convert.FromBase64String(config.MasterKeySalt) : null;
        return Crypto.DeriveKey(k1, k2, salt);
    }

    /// <summary>
    /// Resolves which connected YubiKey to use: errors when none are connected,
    /// returns the single key directly, or defers to the callback for multiple.
    /// Also used by commands that need a specific connected key (init, create's
    /// hardware-entropy path) rather than a vault unlock.
    /// </summary>
    public int SelectConnectedSerial(Func<IReadOnlyList<int>, int> chooseSerial, int? requiredSerial = null)
    {
        if (overrideKey is not null)
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
