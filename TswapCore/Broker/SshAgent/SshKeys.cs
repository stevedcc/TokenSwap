using System.Security.Cryptography;
using TswapCore.Vault;

namespace TswapCore.Broker.SshAgent;

/// <summary>The key types the agent signs with (brief T10 decision 3).</summary>
public enum SshKeyType { Ed25519, EcdsaP256, EcdsaP384, EcdsaP521, Rsa }

/// <summary>A key that can't be used: unparsable, encrypted, inconsistent, unsupported or too small.</summary>
public sealed class SshKeyException(string message) : TswapException(message);

/// <summary>
/// One configured key that can't be loaded (brief T17 ruling 14: a deferred load names it as
/// <c>ssh key '&lt;name&gt;' can't be loaded: &lt;reason&gt;</c>). <see cref="Exception.Message"/> is the text
/// <c>serve</c> has always stopped with; <see cref="SshAgentKeyLoader.Load"/> itself still throws a plain
/// <see cref="TswapException"/> with it.
/// </summary>
public sealed class SshKeyLoadException(string keyName, string reason, string message) : TswapException(message)
{
    public string KeyName { get; } = keyName;
    public string Reason { get; } = reason;
}

/// <summary>
/// A password broker's ssh keys (brief T17 ruling 14): empty while locked, loaded after the first
/// successful <c>broker unlock</c> (<see cref="SshAgentKeyLoader.Load"/>), emptied at every return to locked.
/// </summary>
public sealed class DeferredSshKeys
{
    private static readonly IReadOnlyDictionary<string, SshAgentKey> None = new Dictionary<string, SshAgentKey>();
    private volatile IReadOnlyDictionary<string, SshAgentKey> _current = None;

    /// <summary>The keys the agent endpoint lists and signs with now.</summary>
    public IReadOnlyDictionary<string, SshAgentKey> Current => _current;

    /// <summary>Loads every configured key (one unlock each); a key that can't be loaded throws <see cref="SshKeyLoadException"/> and nothing is kept.</summary>
    public void Load(BrokerPolicy policy, ISshKeySource source)
    {
        SshAgentKeyLoader.Validate(policy);
        _current = SshAgentKeyLoader.LoadValidated(policy, source);
    }

    public void Unload() => _current = None;
}

/// <summary>A sign request refused by the signing layer; the message is a fixed reason word for the log.</summary>
public sealed class SshSignRefusedException(string reason) : Exception(reason);

/// <summary>
/// Where a key's private key comes from: a fresh vault unlock per call (brief T10 decision 5). Blocking;
/// the agent serialises calls with the broker's other unlocks. The caller zeroes the returned bytes.
/// Throws <see cref="BrokerUnlockException"/> when the unlock fails and
/// <see cref="BrokerSecretException"/> when the secret is missing or unreadable.
/// </summary>
public interface ISshKeySource
{
    byte[] ReadKey(string secretName);
}

/// <summary>
/// The real source: every call loads the config, unlocks the vault with the hardware (no prompt),
/// decrypts <b>only that key's record</b> (<see cref="RecordVaultStore.ReadSecretValue"/>) and zeroes
/// the vault key at once. Like <see cref="VaultBrokerSecretSource"/>, without its header-value check
/// (a PEM key has line breaks).
/// </summary>
/// <remarks>Brief T17: <paramref name="password"/> is a password broker's held password, null for a password-free one; no unlock asks an agent.</remarks>
public sealed class VaultSshKeySource(RecordVaultStore store, VaultUnlocker unlocker, TswapCore.VaultPassword.VaultPasswordProvider? password = null) : ISshKeySource
{
    public byte[] ReadKey(string secretName)
    {
        byte[] key;
        try
        {
            var config = store.LoadConfig();
            key = unlocker.Unlock(config, BrokerPasswordProof.NoChoice, BrokerPasswordProof.SourcesFor(password));
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or BrokerLockedException))
        {
            throw new BrokerUnlockException($"vault unlock failed: {ex.Message}", ex);
        }
        byte[]? value;
        try
        {
            value = store.ReadSecretValue(secretName, key);
        }
        catch (TswapException ex)
        {
            throw new BrokerSecretException($"secret '{secretName}': {ex.Message}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        return value ?? throw new BrokerSecretException($"secret '{secretName}' is not in the vault");
    }
}

/// <summary>
/// Loads every configured key once at <c>serve</c> start (brief T10 decision 3): one unlock and one
/// record per key, the public key derived and kept, the private bytes zeroed. Fails fast: a key that
/// can't be loaded stops serve with an error naming it; it is never left out.
/// </summary>
public static class SshAgentKeyLoader
{
    public static Dictionary<string, SshAgentKey> Load(BrokerPolicy policy, ISshKeySource source)
    {
        Validate(policy);
        try
        {
            return LoadValidated(policy, source);
        }
        catch (SshKeyLoadException ex)
        {
            throw new TswapException(ex.Message); // serve's start: the text it has always stopped with
        }
    }

    /// <summary>
    /// The checks that need no unlock (brief T17: a password broker runs them at <c>serve</c> start, and
    /// loads the keys only after its first <c>broker unlock</c>).
    /// </summary>
    public static void Validate(BrokerPolicy policy)
    {
        // Checked before any unlock (fix round 1): a socket lists at most as many keys as an identities
        // answer carries, and no two keys share a secret (the first name would silently win at sign time).
        foreach (var socket in policy.Sockets.Values.OrderBy(s => s.Name, StringComparer.Ordinal))
            if (socket.SshKeys.Count > SshAgentProtocol.MaxIdentities)
                throw new TswapException($"Socket '{socket.Name}' lists {socket.SshKeys.Count} ssh keys; at most {SshAgentProtocol.MaxIdentities} are allowed.");
        Dictionary<string, string> bySecret = [with(StringComparer.Ordinal)];
        foreach (var config in policy.SshKeys.Values.OrderBy(k => k.Name, StringComparer.Ordinal))
            if (!bySecret.TryAdd(config.SecretName, config.Name))
                throw new TswapException($"Ssh keys '{bySecret[config.SecretName]}' and '{config.Name}' use the same secret '{config.SecretName}'; each key needs its own.");
    }

    /// <summary>
    /// <see cref="Load"/> after <see cref="Validate"/>, for a password broker's deferred load (brief T17): a
    /// key that can't be loaded throws <see cref="SshKeyLoadException"/>, which names it.
    /// </summary>
    internal static Dictionary<string, SshAgentKey> LoadValidated(BrokerPolicy policy, ISshKeySource source)
    {
        Dictionary<string, SshAgentKey> keys = [with(StringComparer.Ordinal)];
        foreach (var config in policy.SshKeys.Values.OrderBy(k => k.Name, StringComparer.Ordinal))
        {
            var what = $"Ssh key '{config.Name}' (secret '{config.SecretName}')";
            byte[] secret;
            try
            {
                secret = source.ReadKey(config.SecretName);
            }
            catch (BrokerUnlockException ex)
            {
                throw new SshKeyLoadException(config.Name, $"the vault can't be unlocked to derive its public key ({ex.Message})",
                    $"{what}: the vault can't be unlocked to derive its public key ({ex.Message}).");
            }
            catch (BrokerSecretException ex)
            {
                throw new SshKeyLoadException(config.Name, ex.Message, $"{what}: {ex.Message}.");
            }
            try
            {
                using var key = SshPrivateKey.Parse(secret);
                if (keys.Values.FirstOrDefault(k => k.PublicBlob.AsSpan().SequenceEqual(key.PublicBlob)) is { } twin)
                    throw new SshKeyLoadException(config.Name, $"it holds the same private key as '{twin.Name}'",
                        $"Ssh keys '{twin.Name}' and '{config.Name}' hold the same private key; list it once (with every host it may sign in to).");
                keys[config.Name] = new SshAgentKey(config.Name, config.SecretName, key.PublicBlob);
            }
            catch (SshKeyException ex)
            {
                throw new SshKeyLoadException(config.Name, ex.Message, $"{what} can't be used: {ex.Message}");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
        return keys;
    }
}

/// <summary>
/// The signing layer (brief T10 decision 5): checks the flags first (no unlock for a refusal), then
/// one fresh unlock reading only the key's record, parses it, checks it is still the key loaded at
/// start, signs, and zeroes and disposes everything.
/// </summary>
public static class SshKeySigner
{
    /// <summary>
    /// Why <paramref name="flags"/> don't fit a key of <paramref name="type"/>, or null (wire doc
    /// section 5): Ed25519 and ECDSA need 0; RSA exactly <c>RSA_SHA2_256</c> or <c>RSA_SHA2_512</c>
    /// (no flag is SHA-1, refused; both, the reserved bit or any unknown bit are refused).
    /// </summary>
    public static string? FlagsRefusal(SshKeyType type, uint flags) => type switch
    {
        SshKeyType.Rsa => flags is SshAgentProtocol.RsaSha2_256 or SshAgentProtocol.RsaSha2_512 ? null : flags == 0 ? "rsa-sha1" : "flags",
        _ => flags == 0 ? null : "flags",
    };

    /// <summary>The signature (and userauth) algorithm name a key and valid flags call for.</summary>
    public static string AlgorithmName(SshKeyType type, uint flags) => type switch
    {
        SshKeyType.Rsa => flags == SshAgentProtocol.RsaSha2_512 ? "rsa-sha2-512" : "rsa-sha2-256",
        _ => SshPublicKey.KeyTypeName(type),
    };

    /// <summary>Signs <paramref name="data"/> with a fresh unlock; returns the signature blob (wire doc section 8).</summary>
    public static byte[] Sign(ISshKeySource source, SshAgentKey key, ReadOnlySpan<byte> data, uint flags)
    {
        if (FlagsRefusal(key.Type, flags) is { } refused)
            throw new SshSignRefusedException(refused);
        var secret = source.ReadKey(key.SecretName);
        try
        {
            using var privateKey = SshPrivateKey.Parse(secret);
            // The vault's secret may have been replaced since serve started: never sign with a key
            // other than the one this identity advertised.
            if (!privateKey.PublicBlob.AsSpan().SequenceEqual(key.PublicBlob))
                throw new SshSignRefusedException("key-changed");
            return privateKey.Sign(data, flags);
        }
        catch (SshKeyException)
        {
            throw new SshSignRefusedException("key-unusable");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}
