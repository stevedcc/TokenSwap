using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Tests for the recovery slot's wrap/unwrap construction (issue #120): ephemeral X25519 ECDH +
/// HKDF-SHA256 (<see cref="RecoverySlotKek"/>) feeding the existing
/// <see cref="SlotPayloadWrap"/> AEAD layer. Same round-trip + tamper rigor
/// <c>SlotPayloadWrapTests</c> already applies to the machine-slot wrap, applied here to the
/// recovery-slot wrap.
/// </summary>
public class RecoverySlotWrapTests
{
    private static readonly byte[] VaultId = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
    private static readonly byte[] SlotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
    private const byte FormatVersion = KeyringFormat.KeyringFormatVersion;
    private const byte K = 1;

    [Fact]
    public void WrapUnwrap_RoundTrips()
    {
        var vaultKey = RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var recoveryKeyPair = SlotKeyPair.Generate();

        var (ephemeralPublicKey, wrapped) = RecoverySlotWrap.Wrap(
            vaultKey, recoveryKeyPair.PublicKey, FormatVersion, VaultId, K, SlotId);

        var recovered = RecoverySlotWrap.Unwrap(
            wrapped, ephemeralPublicKey, recoveryKeyPair.PrivateKey, FormatVersion, VaultId, K, SlotId);

        Assert.Equal(vaultKey, recovered);
    }

    [Fact]
    public void Wrap_ProducesEphemeralKeyDifferentFromRecoveryKeyPair()
    {
        // The stored public key must be the fresh, per-wrap ephemeral key (discarded private
        // half), never the long-lived recovery keypair's own public key.
        var vaultKey = RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var recoveryKeyPair = SlotKeyPair.Generate();

        var (ephemeralPublicKey, _) = RecoverySlotWrap.Wrap(
            vaultKey, recoveryKeyPair.PublicKey, FormatVersion, VaultId, K, SlotId);

        Assert.NotEqual(recoveryKeyPair.PublicKey, ephemeralPublicKey);
    }

    [Fact]
    public void Wrap_EachCallGeneratesFreshEphemeralKeyAndDifferentCiphertext()
    {
        var vaultKey = RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var recoveryKeyPair = SlotKeyPair.Generate();

        var (ephemeral1, wrapped1) = RecoverySlotWrap.Wrap(vaultKey, recoveryKeyPair.PublicKey, FormatVersion, VaultId, K, SlotId);
        var (ephemeral2, wrapped2) = RecoverySlotWrap.Wrap(vaultKey, recoveryKeyPair.PublicKey, FormatVersion, VaultId, K, SlotId);

        Assert.NotEqual(ephemeral1, ephemeral2);
        Assert.NotEqual(wrapped1, wrapped2);

        // Both must still independently recover the same K_v.
        Assert.Equal(vaultKey, RecoverySlotWrap.Unwrap(wrapped1, ephemeral1, recoveryKeyPair.PrivateKey, FormatVersion, VaultId, K, SlotId));
        Assert.Equal(vaultKey, RecoverySlotWrap.Unwrap(wrapped2, ephemeral2, recoveryKeyPair.PrivateKey, FormatVersion, VaultId, K, SlotId));
    }

    [Fact]
    public void Unwrap_WrongRecoveryPrivateKey_FailsCleanlyWithTswapException()
    {
        var vaultKey = RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var recoveryKeyPair = SlotKeyPair.Generate();
        var wrongKeyPair = SlotKeyPair.Generate(); // a different, still-validly-clamped keypair

        var (ephemeralPublicKey, wrapped) = RecoverySlotWrap.Wrap(
            vaultKey, recoveryKeyPair.PublicKey, FormatVersion, VaultId, K, SlotId);

        var ex = Assert.Throws<TswapException>(() => RecoverySlotWrap.Unwrap(
            wrapped, ephemeralPublicKey, wrongKeyPair.PrivateKey, FormatVersion, VaultId, K, SlotId));
        Assert.Contains("authentication", ex.Message);
    }

    [Fact]
    public void Unwrap_TamperedCiphertext_FailsCleanlyWithTswapException()
    {
        var vaultKey = RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var recoveryKeyPair = SlotKeyPair.Generate();

        var (ephemeralPublicKey, wrapped) = RecoverySlotWrap.Wrap(
            vaultKey, recoveryKeyPair.PublicKey, FormatVersion, VaultId, K, SlotId);
        wrapped[^1] ^= 0xFF;

        var ex = Assert.Throws<TswapException>(() => RecoverySlotWrap.Unwrap(
            wrapped, ephemeralPublicKey, recoveryKeyPair.PrivateKey, FormatVersion, VaultId, K, SlotId));
        Assert.Contains("authentication", ex.Message);
    }

    [Fact]
    public void Unwrap_TamperedEphemeralPublicKey_FailsCleanlyWithTswapException()
    {
        // The ephemeral public key feeds both the ECDH and the HKDF salt — corrupting it after
        // the fact must fail the same way any other tampering does, not silently derive a
        // different-but-plausible KEK.
        var vaultKey = RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var recoveryKeyPair = SlotKeyPair.Generate();

        var (ephemeralPublicKey, wrapped) = RecoverySlotWrap.Wrap(
            vaultKey, recoveryKeyPair.PublicKey, FormatVersion, VaultId, K, SlotId);
        var tamperedEphemeral = (byte[])ephemeralPublicKey.Clone();
        tamperedEphemeral[0] ^= 0xFF;

        Assert.Throws<TswapException>(() => RecoverySlotWrap.Unwrap(
            wrapped, tamperedEphemeral, recoveryKeyPair.PrivateKey, FormatVersion, VaultId, K, SlotId));
    }

    [Fact]
    public void Unwrap_TamperedAadBoundSlotId_FailsCleanlyWithTswapException()
    {
        var vaultKey = RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var recoveryKeyPair = SlotKeyPair.Generate();
        var otherSlotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);

        var (ephemeralPublicKey, wrapped) = RecoverySlotWrap.Wrap(
            vaultKey, recoveryKeyPair.PublicKey, FormatVersion, VaultId, K, SlotId);

        var ex = Assert.Throws<TswapException>(() => RecoverySlotWrap.Unwrap(
            wrapped, ephemeralPublicKey, recoveryKeyPair.PrivateKey, FormatVersion, VaultId, K, otherSlotId));
        Assert.Contains("authentication", ex.Message);
    }

    [Fact]
    public void Wrap_WrongVaultKeyLength_ThrowsArgumentException()
    {
        var recoveryKeyPair = SlotKeyPair.Generate();

        Assert.Throws<ArgumentException>(() => RecoverySlotWrap.Wrap(
            new byte[16], recoveryKeyPair.PublicKey, FormatVersion, VaultId, K, SlotId));
    }
}
