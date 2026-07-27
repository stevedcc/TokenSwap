using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Golden-value tests for the per-record key derivation (issue #113b):
/// <c>HKDF-SHA256(K_v, salt = recordId || writeCounter(LE64), info = "tswap-record-key-v1")</c>.
///
/// The expected hex below was independently computed with OpenSSL's HKDF KDF (<c>openssl kdf
/// -keylen 32 -kdfopt digest:SHA256 -kdfopt hexkey:&lt;ikm&gt; -kdfopt hexsalt:&lt;salt&gt;
/// -kdfopt hexinfo:&lt;info&gt; HKDF</c>), not merely captured from this code's own output —
/// this pins both the algorithm (standard RFC 5869 HKDF) and this format's specific
/// salt/info encoding convention (recordId immediately followed by the 8-byte little-endian
/// write counter; the fixed "tswap-record-key-v1" domain-separation info string) against an
/// independent implementation.
/// </summary>
public class RecordKeyDerivationTests
{
    private static readonly byte[] VaultKey = Convert.FromHexString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    private static readonly byte[] RecordId = Convert.FromHexString("0101010101010101010101010101010101010101010101010101010101010101");

    [Fact]
    public void Derive_MatchesIndependentlyComputedHkdf()
    {
        var key = RecordKeyDerivation.Derive(VaultKey, RecordId, writeCounter: 7);

        Assert.Equal("18ff83e2b3390eef6c1d5fc49f40ab6e5cf4d7e4108027749d253bcfde2e74c1", Convert.ToHexStringLower(key));
    }

    [Fact]
    public void Derive_Returns32Bytes()
    {
        var key = RecordKeyDerivation.Derive(VaultKey, RecordId, writeCounter: 0);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void Derive_Deterministic()
    {
        var a = RecordKeyDerivation.Derive(VaultKey, RecordId, writeCounter: 42);
        var b = RecordKeyDerivation.Derive(VaultKey, RecordId, writeCounter: 42);

        Assert.Equal(a, b);
    }

    [Fact]
    public void Derive_DifferentWriteCountersDifferentKeys()
    {
        // The core nonce-uniqueness-surface mitigation (issue #113b): rewriting the same
        // secret must not reuse the same AES-GCM key.
        var a = RecordKeyDerivation.Derive(VaultKey, RecordId, writeCounter: 1);
        var b = RecordKeyDerivation.Derive(VaultKey, RecordId, writeCounter: 2);

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Derive_DifferentRecordIdsDifferentKeys()
    {
        var otherRecordId = Convert.FromHexString("0202020202020202020202020202020202020202020202020202020202020202");

        var a = RecordKeyDerivation.Derive(VaultKey, RecordId, writeCounter: 1);
        var b = RecordKeyDerivation.Derive(VaultKey, otherRecordId, writeCounter: 1);

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Derive_DifferentVaultKeysDifferentKeys()
    {
        var otherVaultKey = Convert.FromHexString("3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120");

        var a = RecordKeyDerivation.Derive(VaultKey, RecordId, writeCounter: 1);
        var b = RecordKeyDerivation.Derive(otherVaultKey, RecordId, writeCounter: 1);

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Derive_WrongVaultKeyLengthThrows()
    {
        Assert.Throws<ArgumentException>(() => RecordKeyDerivation.Derive(new byte[16], RecordId, writeCounter: 0));
    }

    [Fact]
    public void Derive_WrongRecordIdLengthThrows()
    {
        Assert.Throws<ArgumentException>(() => RecordKeyDerivation.Derive(VaultKey, new byte[10], writeCounter: 0));
    }
}
