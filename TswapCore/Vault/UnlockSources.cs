using TswapCore.Vault.Fido2;
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
    /// <summary>
    /// YubiKey SDK stage 1, task 4b: this machine's remembered slots (<see cref="RememberedYubiKeySlots"/>), or null for
    /// none. With it, each key's remembered slot is tried first, and the one-key slot that opened the vault is remembered.
    /// </summary>
    public RememberedYubiKeySlots? Remembered { get; init; }

    /// <summary>
    /// Final review, round 2: when set, the one-key slot that opened the vault is handed here (vault id, serial, slot
    /// id) instead of being written to <see cref="Remembered"/>, so a caller that may still abort (re-enrolment)
    /// writes the hint only once it has written its own change.
    /// </summary>
    public Action<byte[], int, byte[]>? RememberLater { get; init; }

    /// <summary>
    /// FIDO2 plan, task 7: pass 4's PIN source (the terminal's, <c>Fido2PinPrompt.For</c>), or null when there is no
    /// terminal: then the FIDO2 slots are skipped (no key call, no dialog) and the error says why.
    /// </summary>
    public Fido2Pin? Fido2Pin { get; init; }

    /// <summary>
    /// FIDO2 plan, task 7: where pass 4 says its touch line before the key operation (the device layer has no touch
    /// callback); stderr in the CLI. Null says nothing.
    /// </summary>
    public Action<string>? Fido2Notice { get; init; }

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
