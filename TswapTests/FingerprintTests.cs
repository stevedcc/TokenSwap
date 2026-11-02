using System.Security.Cryptography;
using System.Text;
using TswapCore.Fingerprints;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 2: the keyed fingerprint primitives. <c>K_fp</c> and the rolling-hash base
/// derive from <c>K_v</c> by HKDF with their own labels, so they are independent of the record and
/// names keys; a fingerprint set is computed from the same decoded string redaction matches.
/// </summary>
public class FingerprintTests
{
    private static byte[] RandomKey() => RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void Keys_AreDistinctFromEachOtherAndFromRecordKeys()
    {
        var vaultKey = RandomKey();
        using var keys = FingerprintKeys.Derive(vaultKey);
        var fp = keys.FingerprintKey.ToArray();
        var names = RecordKeyDerivation.DeriveNamesKey(vaultKey);
        var record = RecordKeyDerivation.Derive(vaultKey, new byte[KeyringFormat.RecordIdSize],
            new Stamp(new Hlc(1, 0), new byte[KeyringFormat.OriginIdSize]));
        var rollSeed = RecordKeyDerivation.DeriveRollingHashSeed(vaultKey);

        Assert.Equal(32, fp.Length);
        Assert.NotEqual(fp, names);
        Assert.NotEqual(fp, record);
        Assert.NotEqual(names, record);
        Assert.NotEqual(fp.AsSpan(0, 8).ToArray(), rollSeed);
        Assert.NotEqual(names.AsSpan(0, 8).ToArray(), rollSeed);
        Assert.InRange(keys.RollingBase, 2UL, RollingHash.Modulus - 2);
    }

    [Fact]
    public void Keys_RollingBase_IsTheSeedMappedIntoTwoToPMinusTwo()
    {
        var vaultKey = RandomKey();
        using var keys = FingerprintKeys.Derive(vaultKey);
        var seed = BitConverter.ToUInt64(RecordKeyDerivation.DeriveRollingHashSeed(vaultKey));
        if (!BitConverter.IsLittleEndian) seed = System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(seed);
        Assert.Equal(2 + seed % (RollingHash.Modulus - 3), keys.RollingBase);
    }

    [Fact]
    public void Keys_Dispose_ZeroesTheKeyAndRefusesUse()
    {
        var keys = FingerprintKeys.Derive(RandomKey());
        keys.Dispose();
        Assert.Throws<ObjectDisposedException>(() => keys.FingerprintKey.ToArray());
        Assert.Throws<ObjectDisposedException>(() => keys.RollingBase);
    }

    [Fact]
    public void Compute_IsDeterministicPerVaultKey_AndDiffersAcrossVaultKeys()
    {
        var value = Encoding.UTF8.GetBytes("correct horse battery staple");
        var keyA = RandomKey();
        using var a1 = FingerprintKeys.Derive(keyA);
        using var a2 = FingerprintKeys.Derive(keyA);
        using var b = FingerprintKeys.Derive(RandomKey());

        var setA1 = Fingerprinter.Compute(value, a1);
        var setA2 = Fingerprinter.Compute(value, a2);
        var setB = Fingerprinter.Compute(value, b);

        Assert.Equal(setA1, setA2);
        Assert.NotEqual(setA1, setB);
        Assert.Equal(SecretVariants.For("correct horse battery staple").Select(v => (v.Kind, v.Text.Length)),
            setA1.Entries.Select(e => (e.Kind, e.Length)));
        for (var i = 0; i < setA1.Entries.Count; i++)
        {
            Assert.Equal(16, setA1.Entries[i].Hmac.Length);
            Assert.NotEqual(setA1.Entries[i].Hmac, setB.Entries[i].Hmac);
            Assert.NotEqual(setA1.Entries[i].RollingHash, setB.Entries[i].RollingHash);
        }
    }

    [Fact]
    public void Compute_EntryIsTheTruncatedHmacAndRollingHashOfTheVariant()
    {
        using var keys = FingerprintKeys.Derive(RandomKey());
        var set = Fingerprinter.Compute(Encoding.UTF8.GetBytes("a b"), keys);
        var stripped = set.Entries.Single(e => e.Kind == VariantKind.WhitespaceStripped);

        var expectedHmac = HMACSHA256.HashData(keys.FingerprintKey.ToArray(), Encoding.UTF8.GetBytes("ab"))[..16];
        Assert.Equal(expectedHmac, stripped.Hmac);
        Assert.Equal(2, stripped.Length);
        Assert.Equal(RollingHash.Of("ab", keys.RollingBase), stripped.RollingHash);
        // "ab" = 'a'·b + 'b' (mod p), the definition written out.
        var b = (UInt128)keys.RollingBase;
        Assert.Equal((ulong)(('a' * b + 'b') % RollingHash.Modulus), stripped.RollingHash);
    }

    [Fact]
    public void Compute_EmptyValue_HasZeroEntries()
    {
        using var keys = FingerprintKeys.Derive(RandomKey());
        var set = Fingerprinter.Compute([], keys);
        Assert.Equal(1, set.VariantSetVersion);
        Assert.Empty(set.Entries);
    }

    [Fact]
    public void Compute_InvalidUtf8Value_UsesTheDecodedString()
    {
        using var keys = FingerprintKeys.Derive(RandomKey());
        var fromBytes = Fingerprinter.Compute([0x66, 0xFF, 0x6F], keys);
        var fromString = Fingerprinter.Compute(Encoding.UTF8.GetBytes("f�o"), keys);
        Assert.Equal(fromString, fromBytes);
        Assert.Equal(3, fromBytes.Entries[0].Length);
    }

    [Fact]
    public void ToString_PrintsNoFingerprintMaterial()
    {
        using var keys = FingerprintKeys.Derive(RandomKey());
        var set = Fingerprinter.Compute(Encoding.UTF8.GetBytes("hunter2"), keys);
        var entry = set.Entries[0];
        Assert.Equal("Plain", entry.ToString());
        var text = set.ToString();
        Assert.DoesNotContain(entry.RollingHash.ToString(), text);
        Assert.DoesNotContain(Convert.ToHexString(entry.Hmac), text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(entry.Length.ToString() + ",", text);
    }

    [Fact]
    public void Entries_HaveValueEquality()
    {
        var a = new FingerprintEntry(VariantKind.Base64, 4, 99, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        var b = new FingerprintEntry(VariantKind.Base64, 4, 99, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        var c = b with { Hmac = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17] };
        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.NotEqual(a, c);
        Assert.Equal(new FingerprintSet(1, [a]), new FingerprintSet(1, [b]));
        Assert.NotEqual(new FingerprintSet(1, [a]), new FingerprintSet(1, [c]));
        Assert.NotEqual(new FingerprintSet(1, [a]), new FingerprintSet(2, [a]));
    }

    [Fact]
    public void RollingHash_SlidingUpdate_EqualsDirectHash()
    {
        var random = new Random(2_16);
        var text = new string(Enumerable.Range(0, 300).Select(_ => (char)random.Next(0, 0x10000)).ToArray());
        using var keys = FingerprintKeys.Derive(RandomKey());
        var b = keys.RollingBase;
        for (var length = 1; length <= 40; length++)
        {
            var top = RollingHash.Power(b, length - 1);
            var hash = RollingHash.Of(text.AsSpan(0, length), b);
            for (var start = 0; ; start++)
            {
                Assert.Equal(RollingHash.Of(text.AsSpan(start, length), b), hash);
                if (start + length >= text.Length) break;
                hash = RollingHash.Slide(hash, text[start], text[start + length], b, top);
            }
        }
    }

    [Fact]
    public void RollingHash_MatchesTheDefinitionWithBigIntegers()
    {
        var random = new Random(3_16);
        for (var round = 0; round < 50; round++)
        {
            var b = 2 + (ulong)random.NextInt64() % (RollingHash.Modulus - 3);
            var text = new string(Enumerable.Range(0, random.Next(1, 60)).Select(_ => (char)random.Next(0, 0x10000)).ToArray());
            System.Numerics.BigInteger expected = 0;
            for (var i = 0; i < text.Length; i++)
                expected += text[i] * System.Numerics.BigInteger.ModPow(b, text.Length - 1 - i, RollingHash.Modulus);
            expected %= RollingHash.Modulus;
            Assert.Equal((ulong)expected, RollingHash.Of(text, b));
        }
    }
}
