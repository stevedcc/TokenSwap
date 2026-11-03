using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Vault;
using TswapCore.VaultPassword;

namespace TswapCli;

/// <summary>
/// Brief T17 ruling 15: choosing the vault password when a slot is made (<c>init</c>, <c>slot add
/// --yubikey</c>, <c>slot request</c>, <c>recover</c>). <c>--password</c> or <c>--no-password</c>; with neither,
/// tswap asks on a terminal and otherwise makes the slot without one, saying so in one line. The first
/// password slot of a vault asks for the password twice and creates the <c>vault-password</c> file; a later
/// one asks once and checks it against the file's verifier with <c>K_v</c>.
/// </summary>
internal static class VaultPasswordChoice
{
    public const string PasswordFlag = "--password";
    public const string NoPasswordFlag = "--no-password";

    /// <summary>Ruling 15: a password shorter than this many characters gets a warning, never a refusal.</summary>
    public const int ShortPasswordWarningLength = 12;

    public const string Question = "Add a vault password? (yes/no, default no): ";

    /// <summary>The one line an unattended enrolment (neither flag, no terminal) prints.</summary>
    public const string NoPasswordLine = "No vault password for this slot (pass --password to add one).";

    public const string WrongPasswordText =
        "That is not this vault's password (every slot with a password uses the same one).";

    public const string ShortPasswordWarning =
        "Warning: this vault password is shorter than 12 characters; a longer one is much harder to guess.";

    public const string RepeatMismatchText = "The two vault passwords differ. Nothing was changed.";

    public const string YubiKeyLine =
        "For this slot the password is mixed into the key, not checked by the hardware: someone holding the plugged-in key can guess it offline, so make it long.";

    public const string SecureEnclaveLine =
        "The Secure Enclave checks the password: this slot is useless off this Mac and without it. It does not limit how fast someone on this Mac can guess, so make it long.";

    public const string VersionLine = "Every machine that opens this vault's password slots needs tswap 0.2.0 or newer.";

    /// <summary>Ruling 17: printed for a Windows TPM password slot.</summary>
    public const string WindowsLockoutLine =
        "Windows locks TPM use after about 4 wrong passwords, for up to 8 hours; run 'tswap agent start' to avoid retyping it.";

    public const string NeedsRecordVaultText =
        "A vault password needs a record vault: its vault folder holds the vault-password file.";

    /// <summary>Test seam (ruling 17): whether this is Windows, for the TPM lockout line.</summary>
    internal static Func<bool> IsWindows = OperatingSystem.IsWindows;

    /// <summary>Test seam (ruling 17): whether this is Linux, for the TPM lockout probe.</summary>
    internal static Func<bool> IsLinux = OperatingSystem.IsLinux;

    /// <summary>
    /// Test seam (ruling 17, Linux): the TPM lockout probe. Null: <see cref="TpmLockoutProbe.IsLockoutAuthEmpty"/>,
    /// except in test mode (<c>TSWAP_TEST_KEY</c>), whose simulated TPM is not the machine's.
    /// </summary>
    internal static Func<bool?>? ProbeLockout;

    /// <summary>
    /// Takes <c>--password</c> / <c>--no-password</c> out of <paramref name="args"/>: null for neither. Both,
    /// or either one twice, is a usage error.
    /// </summary>
    public static (string[] Remaining, bool? Password) Split(string[] args, string usage)
    {
        var yes = args.Count(a => a == PasswordFlag);
        var no = args.Count(a => a == NoPasswordFlag);
        if (yes + no > 1)
            throw new UsageException(usage);
        var rest = args.Where(a => a is not (PasswordFlag or NoPasswordFlag)).ToArray();
        return (rest, yes == 1 ? true : no == 1 ? false : null);
    }

    /// <summary>The usage text fragment for the two flags.</summary>
    public const string Flags = "[--password|--no-password]";

    /// <summary>
    /// Whether the new slot gets the vault password (ruling 15): the flag; with neither, the answer to
    /// <see cref="Question"/> on a terminal (after the explanation), or no password and
    /// <see cref="NoPasswordLine"/> without one. Test mode (<c>TSWAP_TEST_KEY</c>) asks nothing, as its
    /// enrolments never have (a test's stdin may never close). With a password, the backend's own line
    /// and the version line are printed when the explanation wasn't, and the Windows TPM lockout line.
    /// </summary>
    public static bool Decide(CommandContext ctx, bool? flag, HardwareBackend backend)
    {
        var c = ctx.Console;
        bool chosen;
        if (flag is { } given)
        {
            chosen = given;
            if (chosen)
                PrintBackendLines(c, backend);
        }
        else if (!c.IsInputRedirected && ctx.TestKey is null)
        {
            c.Out.WriteLine();
            c.Out.WriteLine("Add a vault password to this slot? Then every unlock needs it, or a running agent that holds it in memory.");
            c.Out.WriteLine($"Without one, anyone who can use this machine's {HardwareName(backend)} as you can open the vault.");
            PrintBackendLines(c, backend);
            c.Out.Write(Question);
            chosen = c.ReadLine()?.Trim().ToLowerInvariant() is "yes" or "y";
        }
        else
        {
            c.Error.WriteLine(NoPasswordLine);
            chosen = false;
        }
        if (chosen)
            PrintTpmLockoutNotice(ctx, backend);
        return chosen;
    }

    /// <summary>
    /// Ruling 17, once per TPM password-slot enrolment: on Windows, <see cref="WindowsLockoutLine"/>; on Linux,
    /// <see cref="TpmLockoutProbe.EmptyLockoutAuthWarning"/> on stderr when the probe says the TPM's lockout
    /// password is empty, nothing when it is set or the probe failed. Nothing for any other backend.
    /// </summary>
    public static void PrintTpmLockoutNotice(CommandContext ctx, HardwareBackend backend)
    {
        if (backend != HardwareBackend.Tpm)
            return;
        if (IsWindows())
        {
            ctx.Console.Out.WriteLine(WindowsLockoutLine);
            return;
        }
        if (!IsLinux())
            return;
        var empty = ProbeLockout is { } probe ? probe()
            : ctx.TestKey is null && OperatingSystem.IsLinux() ? TpmLockoutProbe.IsLockoutAuthEmpty()
            : null;
        if (empty == true)
#pragma warning disable CA1416 // a const string, compiled in: no Linux-only API runs here
            ctx.Console.Error.WriteLine(TpmLockoutProbe.EmptyLockoutAuthWarning);
#pragma warning restore CA1416
    }

    private static void PrintBackendLines(IConsole c, HardwareBackend backend)
    {
        if (backend == HardwareBackend.YubiKey)
            c.Out.WriteLine(YubiKeyLine);
        else if (backend == HardwareBackend.SecureEnclave)
            c.Out.WriteLine(SecureEnclaveLine);
        c.Out.WriteLine(VersionLine);
    }

    internal static string HardwareName(HardwareBackend backend) => backend switch
    {
        HardwareBackend.Tpm => "TPM",
        HardwareBackend.SecureEnclave => "Secure Enclave",
        _ => "YubiKey",
    };

    /// <summary>
    /// The first password slot of a vault (ruling 15): asks for a new password twice, warns when it is short,
    /// refuses an empty one (a usage error naming <c>--no-password</c>) and two that differ, stretches it with a
    /// fresh salt and the default parameters, and builds the <c>vault-password</c> file for
    /// <paramref name="vaultKey"/> and <paramref name="vaultId"/>. The caller writes the file.
    /// </summary>
    public static (StretchedPassword Stretched, VaultPasswordFile File) CreateNew(
        CommandContext ctx, byte[] vaultKey, byte[] vaultId, string command)
    {
        var c = ctx.Console;
        c.Error.Write("New vault password: ");
        var first = c.ReadPassword(c.Error);
        if (first.Length == 0)
            throw new UsageException($"{ctx.Prefix} {command} {PasswordFlag} needs a non-empty vault password, or use {NoPasswordFlag} for a slot without one");
        c.Error.Write("Repeat the vault password: ");
        var second = c.ReadPassword(c.Error);
        if (!string.Equals(first.Normalize(NormalizationForm.FormC), second.Normalize(NormalizationForm.FormC), StringComparison.Ordinal))
            throw new TswapException(RepeatMismatchText);
        WarnIfShort(c, first);

        var salt = RandomNumberGenerator.GetBytes(VaultPasswordKdf.SaltSize);
        var p = VaultPasswordParams.Default;
        var stretched = VaultPasswordKdf.Stretch(first, salt, p, c.Error);
        try
        {
            return (stretched, VaultPasswordFile.Create(vaultKey, vaultId, stretched, salt, p));
        }
        catch
        {
            stretched.Dispose();
            throw;
        }
    }

    /// <summary>
    /// A later password slot (ruling 15): asks for the vault password once and checks it against
    /// <paramref name="file"/>'s verifier with <paramref name="vaultKey"/>; a mismatch refuses with
    /// <see cref="WrongPasswordText"/>.
    /// </summary>
    public static StretchedPassword AskExisting(CommandContext ctx, VaultPasswordFile file, byte[] vaultKey)
    {
        var stretched = AskUnverified(ctx, file);
        if (file.Verifies(vaultKey, stretched))
            return stretched;
        stretched.Dispose();
        throw new TswapException(WrongPasswordText);
    }

    /// <summary>
    /// Asks for the vault password once and stretches it with <paramref name="file"/>'s salt and parameters,
    /// without checking it (<c>slot request</c> has no <c>K_v</c> to check it with). Refuses an empty one.
    /// </summary>
    public static StretchedPassword AskUnverified(CommandContext ctx, VaultPasswordFile file)
    {
        var c = ctx.Console;
        c.Error.Write(TerminalPasswordProvider.PromptText);
        var password = c.ReadPassword(c.Error);
        if (password.Length == 0)
            throw new TswapException($"An empty vault password can't be this vault's password. Run the command again, or use {NoPasswordFlag}.");
        return VaultPasswordKdf.Stretch(password, file.Salt, file.Params, c.Error);
    }

    private static void WarnIfShort(IConsole c, string password)
    {
        if (password.Normalize(NormalizationForm.FormC).EnumerateRunes().Count() < ShortPasswordWarningLength)
            c.Error.WriteLine(ShortPasswordWarning);
    }

    /// <summary>
    /// Ruling 15 for a slot added to an existing vault (<c>slot add</c>, <c>recover</c>): <see cref="Decide"/>,
    /// then, with a password, <see cref="AskExisting"/> when <paramref name="store"/>'s folder has a
    /// <c>vault-password</c> file, else <see cref="CreateNew"/>. Null when no password was chosen.
    ///
    /// <para>Deviation from the brief's signature (which returns the stretched password and writes the file
    /// itself): a new file is returned in <see cref="Resolved.NewFile"/>, and the caller writes it with
    /// <see cref="Resolved.WriteNewFile"/> only once the hardware enrolment has succeeded, just before it
    /// saves the keyring. A failed enrolment then leaves no file behind.</para>
    /// </summary>
    public static Resolved? Resolve(CommandContext ctx, bool? flag, HardwareBackend backend, RecordVaultStore? store, byte[] vaultKey, byte[] vaultId, string command)
    {
        if (flag == true && store is null)
            throw new TswapException(NeedsRecordVaultText);
        if (store is null || !Decide(ctx, flag, backend))
            return null;
        if (store.ReadVaultPassword(vaultId) is { } existing)
            return new Resolved(AskExisting(ctx, existing, vaultKey), null);
        var (stretched, file) = CreateNew(ctx, vaultKey, vaultId, command);
        return new Resolved(stretched, file);
    }

    /// <summary>What <see cref="Resolve"/> chose: the stretched password, and the new file when this is the vault's first password slot.</summary>
    internal sealed class Resolved(StretchedPassword stretched, VaultPasswordFile? newFile) : IDisposable
    {
        public StretchedPassword Stretched { get; } = stretched;
        public VaultPasswordFile? NewFile { get; } = newFile;

        /// <summary>Writes <see cref="NewFile"/> (when there is one) into <paramref name="store"/>'s vault folder.</summary>
        public void WriteNewFile(RecordVaultStore store)
        {
            if (NewFile is not null)
                store.WriteVaultPassword(NewFile);
        }

        public void Dispose() => Stretched.Dispose();
    }
}
