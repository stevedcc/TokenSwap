using System.Security.Cryptography;
using System.Text;
using TswapCore.Vault;

namespace TswapCore.Broker;

/// <summary>A failed vault unlock (counted by <see cref="BrokerUnlockGuard"/>).</summary>
public sealed class BrokerUnlockException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>A route's secret that is missing or can't be a header value (not an unlock failure; never counted).</summary>
public sealed class BrokerSecretException(string message) : Exception(message);

/// <summary>
/// One route's secret as bytes (UTF-8), zeroed on <see cref="Dispose"/>. The broker disposes it as
/// soon as the request is done with it.
/// </summary>
public sealed class BrokerSecret(byte[] value) : IDisposable
{
    private byte[]? _value = value;

    /// <summary>The value; throws after <see cref="Dispose"/>.</summary>
    public ReadOnlySpan<byte> Value => _value ?? throw new ObjectDisposedException(nameof(BrokerSecret));

    public void Dispose()
    {
        if (_value is { } v)
            CryptographicOperations.ZeroMemory(v);
        _value = null;
    }
}

/// <summary>Where <c>serve</c> gets a route's secret: a fresh vault unlock per call (decision 1).</summary>
public interface IBrokerSecretSource
{
    /// <summary>
    /// Unlocks the vault and returns <paramref name="secretName"/>'s value. Blocking (an unlock takes
    /// about 2 s on the router's TPM); the broker serialises calls. Throws
    /// <see cref="BrokerUnlockException"/> when the unlock fails, <see cref="BrokerSecretException"/>
    /// when the secret is missing or unusable.
    /// </summary>
    BrokerSecret Read(string secretName);
}

/// <summary>
/// The real source: every call loads the config, unlocks the vault with the hardware (no prompt;
/// the router's TPM unseals unattended), decrypts the database, takes only the route's secret, and
/// zeroes the vault key. The rest of the database is dropped at once.
/// </summary>
public sealed class VaultBrokerSecretSource(IVaultStore store, VaultUnlocker unlocker) : IBrokerSecretSource
{
    public BrokerSecret Read(string secretName)
    {
        byte[] key;
        SecretsDb db;
        try
        {
            var config = store.LoadConfig();
            key = unlocker.Unlock(config, _ => throw new TswapException(
                "Several YubiKeys are plugged in; 'tswap broker serve' can't ask which one to use."));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            throw new BrokerUnlockException($"vault unlock failed: {ex.Message}", ex);
        }
        try
        {
            db = store.LoadSecrets(key);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            throw new BrokerUnlockException($"vault could not be decrypted: {ex.Message}", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        if (!db.Secrets.TryGetValue(secretName, out var secret))
            throw new BrokerSecretException($"secret '{secretName}' is not in the vault");
        if (secret.Value.AsSpan().IndexOfAny('\r', '\n', '\0') >= 0)
            throw new BrokerSecretException($"secret '{secretName}' contains CR, LF or NUL and can't be sent in a header");
        return new BrokerSecret(Encoding.UTF8.GetBytes(secret.Value));
    }
}
