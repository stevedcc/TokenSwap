using TswapCore.VaultPassword;

namespace TswapCore.Vault;

/// <summary>
/// Where <see cref="VaultUnlocker.Unlock(Config, YubiKeySelection, UnlockSources)"/> may turn when no
/// password-free slot opens the vault (brief T17 ruling 13).
/// </summary>
/// <param name="AskAgent">
/// Pass 2: asks a running <c>tswap agent</c> for the vault key. Returns a <c>K_v</c> already checked
/// against the <c>vault-password</c> file's key check (ruling 9), or null when the agent can't be used
/// (not running, unusable answer). It throws <see cref="AgentUnlockFailedException"/> when the agent
/// answered that its own hardware unlock failed (pass 3 then runs and the error names both), and any
/// other <see cref="TswapException"/> to refuse outright (a key that fails the check).
/// </param>
/// <param name="Prompt">Pass 3: the stretched password, asked for once per unlock.</param>
public sealed record UnlockSources(Func<byte[]?>? AskAgent, VaultPasswordProvider? Prompt)
{
    /// <summary>No agent and no prompt: a slot that needs the password can't be opened.</summary>
    public static UnlockSources None { get; } = new(null, null);
}

/// <summary>
/// Thrown by <see cref="UnlockSources.AskAgent"/> when the agent answered that its hardware unlock failed
/// (agent status <c>3</c>, ruling 8). The message is the agent's; the unlocker goes on to pass 3 and,
/// if that fails too, adds <c>The tswap agent could not unlock either: &lt;message&gt;.</c>
/// </summary>
public sealed class AgentUnlockFailedException(string message) : TswapException(message);

/// <summary>
/// How this machine's own slot of a vault classifies (brief T17 ruling 3), with its id8 and, for
/// <see cref="Keyring.SlotPasswordKind.NeedsNewerTswap"/> and <see cref="Keyring.SlotPasswordKind.Corrupt"/>,
/// ruling 3's text without the slot id (<see cref="VaultUnlocker.OwnSlotPassword"/>).
/// </summary>
public sealed record OwnSlotStanding(Keyring.SlotPasswordKind Kind, string? SlotId8, string? Error);
