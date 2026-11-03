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

    /// <summary>Task 5: a password slot, but the vault folder has no <c>vault-password</c> file to stretch with.</summary>
    public const string MissingFile =
        "This vault's slot needs the vault password, but the vault folder has no vault-password file. If it is synced, wait for the sync; otherwise restore it from a backup of the folder.";

    /// <summary>Ruling 13: pass 2's agent failure, appended after the pass 3 failure.</summary>
    public static string AgentAlsoFailed(string agentMessage) =>
        $"The tswap agent could not unlock either: {agentMessage.TrimEnd('.')}.";

    /// <summary>Ruling 18: the TPM (Linux <c>TPM_RC_AUTH_FAIL</c>, Windows <c>NTE_PERM</c>) refused the supplied password.</summary>
    public const string WrongPasswordTpm =
        "Wrong vault password. The TPM counts failed attempts and locks out for a while after several.";

    /// <summary>Ruling 18: Linux <c>TPM_RC_LOCKOUT</c> (0x921).</summary>
    public const string TpmLockoutLinux =
        "The TPM is in dictionary-attack lockout after failed password attempts; wait and try again.";

    /// <summary>Ruling 18: Windows 0x80090031 or 0x80290409.</summary>
    public const string TpmLockoutWindows =
        "Windows has locked TPM use for this user after too many wrong passwords (by default for up to 8 hours, or until an administrator resets the TPM lockout). Slots on this machine without a vault password may be blocked meanwhile too.";

    /// <summary>Ruling 18: Windows <c>NTE_SILENT_CONTEXT</c> on a Password-classified slot (tswap always sets the auth there).</summary>
    public const string WindowsSilentContextBug =
        "tswap opened a password-protected TPM key without its password (a tswap bug; please report it).";

    /// <summary>Ruling 18: the Secure Enclave shim's wrong-credential code (-7).</summary>
    public const string WrongPasswordSecureEnclave = "Wrong vault password (or this slot was made on another Mac).";

    /// <summary>
    /// Ruling 3: what the legacy parsers (<c>Tpm2ToolsInterop</c>, <c>PlatformCryptoProviderInterop</c>,
    /// <c>AppleSecureEnclaveInterop</c>) say when they are handed an unsplit <c>TSTP</c>/<c>TSSE</c> blob.
    /// </summary>
    public static string LegacyParserNeedsNewerTswap(int version) =>
        $"This slot needs the vault password and a newer tswap (blob version {version} or unknown flags); upgrade tswap.";
}
