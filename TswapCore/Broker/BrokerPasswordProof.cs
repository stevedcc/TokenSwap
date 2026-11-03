using System.Security.Cryptography;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;

namespace TswapCore.Broker;

/// <summary>
/// How a broker unlocks (brief T17 rulings 13 and 14): never through an agent, always with the hardware
/// and, for a password slot, with the password it holds or is being handed.
/// </summary>
public static class BrokerPasswordProof
{
    /// <summary>An unlock selection that never asks (serve has no terminal).</summary>
    public static YubiKeySelection NoChoice { get; } = YubiKeySelection.FromChooser(_ => throw new TswapException(
        "Several YubiKeys are plugged in; 'tswap broker serve' can't ask which one to use."));

    /// <summary>
    /// The sources of every unlock <c>serve</c> makes for a request (a route's secret, an ssh key): no agent
    /// (ruling 13: a broker's behaviour never depends on whether an agent runs), and
    /// <paramref name="password"/> as the password, or none for a password-free broker.
    /// </summary>
    public static UnlockSources SourcesFor(VaultPasswordProvider? password) => new(AskAgent: null, Prompt: password);

    /// <summary>
    /// <c>broker unlock</c>'s proof (ruling 14): one real unlock through this machine's password slots only
    /// (<see cref="VaultUnlocker.UnlockWithPasswordSlots"/>: never a password-free slot, an agent or a prompt)
    /// with <paramref name="candidate"/>, then the vault's <c>vault-password</c> verifier, which needs both
    /// the key and the password. Returns <c>K_v</c>; the caller zeroes it. A wrong password fails at the
    /// hardware (ruling 18's texts); a password the hardware accepts but the verifier refuses is
    /// <see cref="VaultPasswordMessages.VerifierMismatch"/> (<see cref="VaultPasswordRefusal.FileMismatch"/>).
    /// </summary>
    public static byte[] Prove(RecordVaultStore store, VaultUnlocker unlocker, StretchedPassword candidate)
    {
        var config = store.LoadConfig();
        var key = unlocker.UnlockWithPasswordSlots(config, NoChoice, candidate);
        try
        {
            var vaultId = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring
                ?? throw new TswapException("This vault has no keyring; a broker with a vault password needs one."))).VaultId;
            VaultPasswordFile? read;
            try
            {
                read = store.ReadVaultPassword(vaultId);
            }
            catch (TswapException ex) when (ex is not VaultPasswordUnavailableException)
            {
                // Conflicting copies, a file of another vault, a malformed file: the configuration, never a
                // wrong password (the control server doesn't count it).
                throw new VaultPasswordUnavailableException(ex.Message);
            }
            var file = read ?? throw new VaultPasswordUnavailableException(VaultPasswordMessages.MissingFile);
            if (!file.Verifies(key, candidate))
                // The hardware proved the password: the file (or this slot) is out of step, not a guess.
                throw new VaultPasswordRefusedException(VaultPasswordMessages.VerifierMismatch, VaultPasswordRefusal.FileMismatch);
            return key;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
    }
}
