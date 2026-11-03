using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TswapCore.VaultPassword;

/// <summary>
/// The vault's <c>vault-password</c> file (brief T17 ruling 2), in the shared vault folder. Fixed binary,
/// 130 bytes:
/// <code>
/// magic "TSVP" | version 1 | vaultId 16 | kdf 1 (1 = Argon2id) | memoryKiB 4 LE | timeCost 4 LE
///   | parallelism 4 LE | salt 32 | verifier 32 | keyCheck 32
/// header   = magic through salt (66 bytes)
/// verifier = HMAC-SHA256(HKDF-SHA256(K_v, 32, info "tswap-vault-password-verifier-v1"), header || stretched)
/// keyCheck = HMAC-SHA256(HKDF-SHA256(K_v, 32, info "tswap-vault-key-check-v1"), header)
/// </code>
/// The salt and parameters are in the clear (a joining machine needs them before it has <c>K_v</c>).
/// Neither MAC can be computed without <c>K_v</c>, so the file adds no guessing target for whoever lacks
/// it. <see cref="Verifies"/> checks a password (it needs both <c>K_v</c> and the stretched bytes);
/// <see cref="KeyMatches"/> checks a vault key alone, which is how a client checks the agent's answer.
/// </summary>
public sealed record VaultPasswordFile(byte[] VaultId, VaultPasswordParams Params, byte[] Salt, byte[] Verifier, byte[] KeyCheck)
{
    public const byte CurrentVersion = 1;
    public const byte KdfArgon2id = 1;
    public const int VaultIdSize = 16;
    public const int MacSize = 32;
    public const int HeaderSize = 4 + 1 + VaultIdSize + 1 + 4 + 4 + 4 + VaultPasswordKdf.SaltSize; // 66
    public const int EncodedSize = HeaderSize + MacSize + MacSize;                                  // 130

    /// <summary>"TSVP": TokenSwap vault password.</summary>
    public static ReadOnlySpan<byte> Magic => "TSVP"u8;

    private static ReadOnlySpan<byte> VerifierInfo => "tswap-vault-password-verifier-v1"u8;
    private static ReadOnlySpan<byte> KeyCheckInfo => "tswap-vault-key-check-v1"u8;

    /// <summary>A new file for the vault <paramref name="vaultId"/> whose key is <paramref name="vaultKey"/>.</summary>
    public static VaultPasswordFile Create(byte[] vaultKey, byte[] vaultId, StretchedPassword stretched, byte[] salt, VaultPasswordParams p)
    {
        if (vaultId.Length != VaultIdSize)
            throw new ArgumentException($"The vault id must be {VaultIdSize} bytes", nameof(vaultId));
        if (salt.Length != VaultPasswordKdf.SaltSize)
            throw new ArgumentException($"The salt must be {VaultPasswordKdf.SaltSize} bytes", nameof(salt));
        if (p.OutOfBounds() is { } bad)
            throw new ArgumentException($"Argon2id parameters out of bounds: {bad}", nameof(p));

        var header = EncodeHeader(vaultId, p, salt);
        return new VaultPasswordFile(
            (byte[])vaultId.Clone(), p, (byte[])salt.Clone(),
            ComputeVerifier(vaultKey, header, stretched),
            ComputeKeyCheck(vaultKey, header));
    }

    /// <summary>True when <paramref name="stretched"/> is this vault's password, given its key.</summary>
    public bool Verifies(byte[] vaultKey, StretchedPassword stretched)
    {
        var expected = ComputeVerifier(vaultKey, EncodeHeader(VaultId, Params, Salt), stretched);
        return CryptographicOperations.FixedTimeEquals(expected, Verifier);
    }

    /// <summary>True when <paramref name="vaultKey"/> is this vault's key (no password needed).</summary>
    public bool KeyMatches(byte[] vaultKey)
    {
        var expected = ComputeKeyCheck(vaultKey, EncodeHeader(VaultId, Params, Salt));
        return CryptographicOperations.FixedTimeEquals(expected, KeyCheck);
    }

    public byte[] Encode()
    {
        var bytes = new byte[EncodedSize];
        EncodeHeader(VaultId, Params, Salt).CopyTo(bytes, 0);
        Verifier.CopyTo(bytes, HeaderSize);
        KeyCheck.CopyTo(bytes, HeaderSize + MacSize);
        return bytes;
    }

    /// <summary>
    /// Decodes strictly: exact length, known magic, version and KDF, parameters within ruling 1's bounds,
    /// and the vault id <paramref name="expectedVaultId"/> (the keyring's).
    /// </summary>
    public static VaultPasswordFile Decode(byte[] bytes, byte[] expectedVaultId)
    {
        if (bytes.Length != EncodedSize)
            throw Malformed($"wrong length ({bytes.Length} bytes, expected {EncodedSize})");
        if (!bytes.AsSpan(0, 4).SequenceEqual(Magic))
            throw Malformed("wrong magic");
        if (bytes[4] != CurrentVersion)
            throw Malformed($"unknown version {bytes[4]} (this build reads version {CurrentVersion})");
        var vaultId = bytes.AsSpan(5, VaultIdSize).ToArray();
        if (bytes[21] != KdfArgon2id)
            throw Malformed($"unknown KDF {bytes[21]}");
        var p = new VaultPasswordParams(
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(22, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(26, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(30, 4)));
        if (p.OutOfBounds() is { } bad)
            throw Malformed(bad);
        if (!CryptographicOperations.FixedTimeEquals(vaultId, expectedVaultId))
            throw Malformed("its vault id is not this vault's");

        return new VaultPasswordFile(
            vaultId, p,
            bytes.AsSpan(34, VaultPasswordKdf.SaltSize).ToArray(),
            bytes.AsSpan(HeaderSize, MacSize).ToArray(),
            bytes.AsSpan(HeaderSize + MacSize, MacSize).ToArray());
    }

    private static TswapException Malformed(string what) => new($"The vault folder's vault-password file is unusable: {what}.");

    private static byte[] EncodeHeader(byte[] vaultId, VaultPasswordParams p, byte[] salt)
    {
        var header = new byte[HeaderSize];
        var span = header.AsSpan();
        Magic.CopyTo(span);
        span[4] = CurrentVersion;
        vaultId.CopyTo(span.Slice(5, VaultIdSize));
        span[21] = KdfArgon2id;
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(22, 4), p.MemoryKiB);
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(26, 4), p.TimeCost);
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(30, 4), p.Parallelism);
        salt.CopyTo(span.Slice(34, VaultPasswordKdf.SaltSize));
        return header;
    }

    private static byte[] ComputeVerifier(byte[] vaultKey, byte[] header, StretchedPassword stretched)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, vaultKey, 32, salt: [], info: VerifierInfo.ToArray());
        var input = new byte[header.Length + StretchedPassword.Size];
        try
        {
            header.CopyTo(input, 0);
            stretched.CopyTo(input.AsSpan(header.Length));
            return HMACSHA256.HashData(key, input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] ComputeKeyCheck(byte[] vaultKey, byte[] header)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, vaultKey, 32, salt: [], info: KeyCheckInfo.ToArray());
        try
        {
            return HMACSHA256.HashData(key, header);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
