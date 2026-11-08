using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using TswapCore.Vault.Interop;

namespace TswapCore.Vault;

/// <summary>
/// Brief T17 ruling 17 (Linux): whether this TPM's lockout authorisation is empty, read from
/// <c>tpm2_getcap properties-variable</c>'s <c>lockoutAuthSet</c>. With an empty one, anyone who can use the
/// TPM can reset its failed-password counter and keep guessing, so a TPM password-slot enrolment prints
/// <see cref="EmptyLockoutAuthWarning"/> once. A failed probe is silent (null): no warning, no error.
/// Windows manages the lockout authorisation itself and has no such probe.
/// </summary>
[SupportedOSPlatform("linux")]
public static partial class TpmLockoutProbe
{
    /// <summary>Ruling 17's warning text, printed once per TPM password-slot enrolment when the probe says true.</summary>
    public const string EmptyLockoutAuthWarning =
        "Warning: this TPM's lockout password is empty, so anyone who can use the TPM can reset its failed-password counter and keep guessing the vault password. Setting one (as root: tpm2_changeauth -c lockout) affects every program that uses this TPM.";

    /// <summary>True when <c>lockoutAuthSet</c> is 0, false when it is 1, null when the probe failed.</summary>
    public static bool? IsLockoutAuthEmpty()
    {
        try
        {
            var (exitCode, stdout, _) = Tpm2ToolsInterop.Run("tpm2_getcap", "properties-variable");
            if (exitCode != 0)
                return null;
            var match = LockoutAuthSet().Match(stdout);
            return match.Success ? match.Groups["v"].Value == "0" : null;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Advisory only (ruling 17): tpm2-tools missing, a broken pipe, anything else, never an error.
            return null;
        }
    }

    [GeneratedRegex(@"^\s*lockoutAuthSet:\s*(?<v>[01])\s*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LockoutAuthSet();
}
