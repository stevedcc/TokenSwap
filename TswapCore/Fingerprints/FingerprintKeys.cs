using System.Buffers.Binary;
using System.Security.Cryptography;
using TswapCore.Keyring;

namespace TswapCore.Fingerprints;

/// <summary>
/// Brief T16-S1: the two fingerprint keys of one vault, <c>K_fp</c> (the HMAC key) and the
/// rolling-hash base derived from <c>K_roll</c>. Both derive from <c>K_v</c>
/// (<see cref="RecordKeyDerivation.DeriveFingerprintKey"/>,
/// <see cref="RecordKeyDerivation.DeriveRollingHashSeed"/>), so fingerprints are useless without
/// the vault key; disposing zeroes both, as the store zeroes every other key it derives.
/// </summary>
public sealed class FingerprintKeys : IDisposable
{
    private readonly byte[] _fingerprintKey;
    private ulong _rollingBase;
    private bool _disposed;

    private FingerprintKeys(byte[] fingerprintKey, ulong rollingBase)
    {
        _fingerprintKey = fingerprintKey;
        _rollingBase = rollingBase;
    }

    /// <summary>
    /// Derives both keys from <paramref name="vaultKey"/>. The base is
    /// <c>2 + (u64_le(seed) mod (p − 3))</c>, i.e. in [2, p−2]: 0 and 1 would make the hash ignore
    /// position, and p−1 (≡ −1) would alternate signs.
    /// </summary>
    public static FingerprintKeys Derive(byte[] vaultKey)
    {
        var seed = RecordKeyDerivation.DeriveRollingHashSeed(vaultKey);
        try
        {
            var rollingBase = 2 + BinaryPrimitives.ReadUInt64LittleEndian(seed) % (RollingHash.Modulus - 3);
            return new FingerprintKeys(RecordKeyDerivation.DeriveFingerprintKey(vaultKey), rollingBase);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary><c>K_fp</c>, 32 bytes.</summary>
    internal ReadOnlySpan<byte> FingerprintKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _fingerprintKey;
        }
    }

    /// <summary>The rolling-hash base <c>b</c>.</summary>
    internal ulong RollingBase
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _rollingBase;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_fingerprintKey);
        _rollingBase = 0;
        _disposed = true;
    }
}
