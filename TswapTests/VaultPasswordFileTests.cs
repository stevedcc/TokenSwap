using System.Buffers.Binary;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 1, ruling 2: the fixed-binary <c>vault-password</c> file (salt, Argon2id
/// parameters, the verifier and the key check).
/// </summary>
public class VaultPasswordFileTests
{
    private static readonly byte[] VaultKey = Enumerable.Range(10, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] VaultId = Enumerable.Range(60, 16).Select(i => (byte)i).ToArray();
    private static readonly byte[] Salt = Enumerable.Range(90, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Stretched = Enumerable.Range(150, 32).Select(i => (byte)i).ToArray();

    private static VaultPasswordFile Create(VaultPasswordParams? p = null)
    {
        using var stretched = StretchedPassword.FromBytes(Stretched);
        return VaultPasswordFile.Create(VaultKey, VaultId, stretched, Salt, p ?? VaultPasswordParams.Default);
    }

    private static bool Verifies(VaultPasswordFile file, byte[] stretchedBytes, byte[]? vaultKey = null)
    {
        using var stretched = StretchedPassword.FromBytes(stretchedBytes);
        return file.Verifies(vaultKey ?? VaultKey, stretched);
    }

    [Fact]
    public void Encode_Is130Bytes_WithTheRulingLayout()
    {
        var file = Create(new VaultPasswordParams(65536, 3, 1));
        var bytes = file.Encode();

        Assert.Equal(130, bytes.Length);
        Assert.Equal("TSVP"u8.ToArray(), bytes[0..4]);
        Assert.Equal(1, bytes[4]);
        Assert.Equal(VaultId, bytes[5..21]);
        Assert.Equal(1, bytes[21]);
        Assert.Equal(65536, BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(22, 4)));
        Assert.Equal(3, BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(26, 4)));
        Assert.Equal(1, BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(30, 4)));
        Assert.Equal(Salt, bytes[34..66]);
        Assert.Equal(file.Verifier, bytes[66..98]);
        Assert.Equal(file.KeyCheck, bytes[98..130]);

        // The two MACs are the ruling's formulas over the header (bytes 0..65).
        var header = bytes[0..66];
        var verifierKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, VaultKey, 32, info: "tswap-vault-password-verifier-v1"u8.ToArray());
        Assert.Equal(HMACSHA256.HashData(verifierKey, header.Concat(Stretched).ToArray()), file.Verifier);
        var keyCheckKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, VaultKey, 32, info: "tswap-vault-key-check-v1"u8.ToArray());
        Assert.Equal(HMACSHA256.HashData(keyCheckKey, header), file.KeyCheck);

        var decoded = VaultPasswordFile.Decode(bytes, VaultId);
        Assert.Equal(file.Params, decoded.Params);
        Assert.Equal(bytes, decoded.Encode());
    }

    [Fact]
    public void Verifies_TrueForTheRightPassword_FalseForOneFlippedBit()
    {
        var file = Create();
        Assert.True(Verifies(file, Stretched));

        for (var bit = 0; bit < 8; bit++)
        {
            var flipped = (byte[])Stretched.Clone();
            flipped[31] ^= (byte)(1 << bit);
            Assert.False(Verifies(file, flipped));
        }
        // With the wrong vault key, even the right password doesn't verify.
        var otherKey = (byte[])VaultKey.Clone();
        otherKey[0] ^= 1;
        Assert.False(Verifies(file, Stretched, otherKey));
    }

    [Fact]
    public void Verifier_BindsSaltAndParams()
    {
        var bytes = Create(new VaultPasswordParams(65536, 3, 1)).Encode();
        Assert.True(Verifies(VaultPasswordFile.Decode(bytes, VaultId), Stretched));

        var saltChanged = (byte[])bytes.Clone();
        saltChanged[34] ^= 0x01;
        Assert.False(Verifies(VaultPasswordFile.Decode(saltChanged, VaultId), Stretched));

        var timeCostChanged = (byte[])bytes.Clone();
        BinaryPrimitives.WriteInt32LittleEndian(timeCostChanged.AsSpan(26, 4), 2);
        Assert.False(Verifies(VaultPasswordFile.Decode(timeCostChanged, VaultId), Stretched));
    }

    [Fact]
    public void KeyMatches_TrueForK_v_FalseForAnotherKey()
    {
        var file = Create();
        Assert.True(file.KeyMatches(VaultKey));

        var otherKey = (byte[])VaultKey.Clone();
        otherKey[31] ^= 0x80;
        Assert.False(file.KeyMatches(otherKey));
        Assert.False(file.KeyMatches(RandomNumberGenerator.GetBytes(32)));
    }

    public static TheoryData<string, string> RefusalCases() => new()
    {
        { "length 129", "length" },
        { "length 131", "length" },
        { "magic TSVQ", "magic" },
        { "version 2", "version" },
        { "kdf 2", "KDF" },
        { "m 19455", "memory" },
        { "m 262145", "memory" },
        { "t 0", "time cost" },
        { "t 9", "time cost" },
        { "p 0", "parallelism" },
        { "p 5", "parallelism" },
        { "other vault id", "vault id" },
    };

    [Theory]
    [MemberData(nameof(RefusalCases))]
    public void Decode_Refuses(string mutation, string field)
    {
        var bytes = Create().Encode();
        var expectedVaultId = VaultId;
        switch (mutation)
        {
            case "length 129": bytes = bytes[..129]; break;
            case "length 131": bytes = [.. bytes, 0]; break;
            case "magic TSVQ": bytes[3] = (byte)'Q'; break;
            case "version 2": bytes[4] = 2; break;
            case "kdf 2": bytes[21] = 2; break;
            case "m 19455": BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(22, 4), 19455); break;
            case "m 262145": BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(22, 4), 262145); break;
            case "t 0": BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(26, 4), 0); break;
            case "t 9": BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(26, 4), 9); break;
            case "p 0": BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(30, 4), 0); break;
            case "p 5": BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(30, 4), 5); break;
            case "other vault id":
                expectedVaultId = (byte[])VaultId.Clone();
                expectedVaultId[15] ^= 1;
                break;
            default: throw new InvalidOperationException(mutation);
        }

        var ex = Assert.Throws<TswapException>(() => VaultPasswordFile.Decode(bytes, expectedVaultId));
        Assert.Contains(field, ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("vault-password", ex.Message);
    }

    [Fact]
    public void Decode_AcceptsTheMaximum()
    {
        var bytes = Create(new VaultPasswordParams(262144, 8, 4)).Encode();
        var decoded = VaultPasswordFile.Decode(bytes, VaultId);
        Assert.Equal(new VaultPasswordParams(262144, 8, 4), decoded.Params);
        Assert.True(Verifies(decoded, Stretched));
    }

    [Fact]
    public void Decode_AcceptsTheMinimum()
    {
        var bytes = Create(new VaultPasswordParams(19456, 1, 1)).Encode();
        Assert.Equal(new VaultPasswordParams(19456, 1, 1), VaultPasswordFile.Decode(bytes, VaultId).Params);
    }

    [Fact]
    public void NothingInTheFile_EqualsStretchedOrK_v()
    {
        var bytes = Create().Encode();

        // 8-byte windows (review T17 p4 MiMo M6: 16 let an 8-byte leak through).
        const int Window = 8;
        foreach (var secret in new[] { Stretched, VaultKey })
        {
            for (var s = 0; s + Window <= secret.Length; s++)
            {
                var window = secret.AsSpan(s, Window);
                for (var f = 0; f + Window <= bytes.Length; f++)
                    Assert.False(bytes.AsSpan(f, Window).SequenceEqual(window),
                        $"file bytes {f}..{f + Window - 1} equal a secret window at {s}");
            }
        }
    }

    [Fact]
    public void Unavailable_IsATswapException()
    {
        TswapException ex = new VaultPasswordUnavailableException("no terminal");
        Assert.Equal("no terminal", ex.Message);
    }
}
