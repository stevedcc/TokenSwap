using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace TswapCore.Keyring;

/// <summary>
/// Per-record key derivation (issue #113b): <c>HKDF(K_v, salt = recordId || writeCounter)</c>.
///
/// Splitting one vault into N independently-rewritten files (one per secret, see
/// <see cref="FilenameHasher"/>) vastly enlarges the AES-GCM nonce-uniqueness surface versus the
/// old single-blob format's one-fresh-nonce-per-save: N files rewritten independently and
/// concurrently across machines, all under one key, makes nonce collision a real risk — and GCM
/// nonce reuse under one key is catastrophic (loses both confidentiality and forgeability, for
/// every record under that key, not just the colliding pair). Deriving a distinct key per
/// record instead bounds each key to exactly one (record, write) pair, so even a nonce
/// collision across two different records is a collision between independent keys, not a
/// classic GCM nonce-reuse break. It also makes <c>K_v</c> rotation (v1) cleaner, since
/// rotating the root key is one derivation-input change rather than a re-encrypt tied to nonce
/// bookkeeping.
/// </summary>
public static class RecordKeyDerivation
{
    /// <summary>
    /// Domain-separation label for the HKDF "info" parameter, so this derivation can never
    /// collide with some other future use of <c>K_v</c> in an HKDF call over the same
    /// (recordId, writeCounter) input space.
    /// </summary>
    private static readonly byte[] Info = Encoding.UTF8.GetBytes("tswap-record-key-v1");

    /// <summary>Derived key length in bytes (AES-256).</summary>
    public const int KeyLength = 32;

    /// <summary>
    /// Derives the AES-256-GCM key for one record write. <paramref name="recordId"/> must be
    /// the raw (non-hex) <see cref="KeyringFormat.RecordIdSize"/>-byte identifier — the same
    /// bytes used as the filename hash (see <see cref="FilenameHasher"/>) — and
    /// <paramref name="writeCounter"/> the write that is about to be (or was) encrypted.
    /// </summary>
    public static byte[] Derive(byte[] vaultKey, byte[] recordId, ulong writeCounter)
    {
        if (vaultKey.Length != KeyLength)
            throw new ArgumentException($"vaultKey must be {KeyLength} bytes", nameof(vaultKey));
        if (recordId.Length != KeyringFormat.RecordIdSize)
            throw new ArgumentException($"recordId must be {KeyringFormat.RecordIdSize} bytes", nameof(recordId));

        var salt = new byte[recordId.Length + sizeof(ulong)];
        recordId.CopyTo(salt, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(salt.AsSpan(recordId.Length), writeCounter);

        return HKDF.DeriveKey(HashAlgorithmName.SHA256, vaultKey, KeyLength, salt: salt, info: Info);
    }

    /// <summary>
    /// Brief T6 decision 3: the record store's per-record key,
    /// <c>HKDF(K_v, salt = recordId || HLC physical (8, LE) || HLC logical (4, LE) || origin id (16))</c>,
    /// with this type's info label. The ordering stamp of the write replaces the plain write counter,
    /// and the origin id is part of it, so two machines writing the same record at the same HLC still
    /// encrypt under different keys.
    /// </summary>
    public static byte[] Derive(byte[] vaultKey, byte[] recordId, Stamp write)
    {
        if (vaultKey.Length != KeyLength)
            throw new ArgumentException($"vaultKey must be {KeyLength} bytes", nameof(vaultKey));
        if (recordId.Length != KeyringFormat.RecordIdSize)
            throw new ArgumentException($"recordId must be {KeyringFormat.RecordIdSize} bytes", nameof(recordId));

        var salt = new byte[recordId.Length + 8 + 4 + KeyringFormat.OriginIdSize];
        recordId.CopyTo(salt, 0);
        BinaryPrimitives.WriteInt64LittleEndian(salt.AsSpan(recordId.Length, 8), write.Hlc.PhysicalMs);
        BinaryPrimitives.WriteUInt32LittleEndian(salt.AsSpan(recordId.Length + 8, 4), write.Hlc.Logical);
        write.Origin.CopyTo(salt, recordId.Length + 12);

        return HKDF.DeriveKey(HashAlgorithmName.SHA256, vaultKey, KeyLength, salt: salt, info: Info);
    }

    private static readonly byte[] NamesInfo = Encoding.UTF8.GetBytes("tswap-record-names-v1");

    /// <summary>
    /// Brief T6 decision 3: <c>K_names</c>, the filename-HMAC key, is derived from <c>K_v</c>
    /// (<c>HKDF(K_v, info = "tswap-record-names-v1")</c>, no salt). Settled for v0, where
    /// <c>K_v</c> never rotates; #126 revisits it before rotation exists.
    /// </summary>
    public static byte[] DeriveNamesKey(byte[] vaultKey)
    {
        if (vaultKey.Length != KeyLength)
            throw new ArgumentException($"vaultKey must be {KeyLength} bytes", nameof(vaultKey));
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, vaultKey, FilenameHasher.KeyLength, salt: null, info: NamesInfo);
    }
}
