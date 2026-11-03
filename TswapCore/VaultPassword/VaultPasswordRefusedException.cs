namespace TswapCore.VaultPassword;

/// <summary>
/// The hardware or the key derivation refused a slot because of its vault password (brief T17 rulings 3
/// and 18): a wrong password, a lockout, or a stripped password header. The unlocker passes it on
/// unchanged, without the "another machine's slot" hint, because the slot does belong here.
/// </summary>
public sealed class VaultPasswordRefusedException(string message) : TswapException(message);

/// <summary>The fixed user-facing texts of brief T17 rulings 3, 13 and 18.</summary>
public static class VaultPasswordMessages
{
    /// <summary>Ruling 13: a password slot, no usable agent and no terminal.</summary>
    public const string NoTerminal =
        "This vault's slot on this machine needs the vault password. Start the agent ('tswap agent start') or run this command in a terminal.";

    /// <summary>Ruling 18: a YubiKey slot (or the simulated backend) that fails to unwrap with the password supplied.</summary>
    public const string WrongPasswordKdf = "Wrong vault password (or this slot's key changed).";

    /// <summary>Ruling 3: the hardware object needs a password but the blob's header was removed.</summary>
    public const string StrippedHeader =
        "This slot's hardware object needs a password, but its blob doesn't say so: restore config.json from backup, or upgrade tswap.";

    /// <summary>Ruling 13: pass 2's agent failure, appended after the pass 3 failure.</summary>
    public static string AgentAlsoFailed(string agentMessage) =>
        $"The tswap agent could not unlock either: {agentMessage.TrimEnd('.')}.";
}
