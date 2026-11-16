using System.Security.Principal;
using TswapCore;
using TswapCore.Broker;
using TswapCore.Fields;

namespace TswapCli;

/// <summary>
/// #311, spec guard rail 3: who made a field change, as far as tswap can know. A history, not an authentication:
/// the user name is reliable on this machine only, and <c>--by</c> is self-asserted.
/// </summary>
public static class FieldWhoSource
{
    /// <summary>The longest <c>--by</c> label, in characters.</summary>
    public const int MaxByLength = 64;

    /// <summary>The who-record of a change made now by this process; <paramref name="by"/> is the optional <c>--by</c> label.</summary>
    public static FieldWho Current(CommandContext ctx, string? by)
    {
        var label = by is null ? null : ValidateBy(by);
        var origin = (ctx.Storage as RecordVaultStore ?? throw new TswapException("This command needs a record vault.")).ShortOriginId();
        var user = ctx.UserLookup is { } lookup ? lookup() : SystemUser();
        return new FieldWho(origin, user,
            Elevated: ctx.SudoBypass || (ctx.ElevationLookup is { } elevation ? elevation() : Environment.IsPrivilegedProcess),
            Terminal: !ctx.Console.IsInputRedirected, label);
    }

    /// <summary>Validates the label and returns it in the form that is stored (NFC, as a field value is).</summary>
    private static string ValidateBy(string by)
    {
        var label = FieldRules.NormaliseValue(by);
        // The label's own cap first: the value rules' cap (4096) is a field's.
        if (label.EnumerateRunes().Count() > MaxByLength)
            throw new TswapException($"--by: a label is at most {MaxByLength} characters.");
        if (FieldRules.ValidateValue(label, FieldRules.ValueSubject.Label) is { } refusal)
            throw new TswapException("--by: " + refusal);
        if (label.Contains('\n'))
            throw new TswapException("--by: a label is one line (it contains a line feed).");
        return label;
    }

    private static string? SystemUser() => OperatingSystem.IsWindows()
        ? ResolveUser(Environment.GetEnvironmentVariable, Environment.IsPrivilegedProcess, 0, _ => null, _ => null, WindowsIdentity.GetCurrent().Name)
        : ResolveUser(Environment.GetEnvironmentVariable, Environment.IsPrivilegedProcess, new UnixOwnership().EffectiveUid,
            name => UnixPasswd.Lookup(name), BrokerNative.NameOf, windowsName: null);

    /// <summary>
    /// The user name for the record. <paramref name="windowsName"/> (the account, <c>DOMAIN\user</c>) wins when set.
    /// Otherwise, elevated under sudo: <c>SUDO_USER</c>, but only when <c>SUDO_UID</c> matches that user's uid in
    /// the password database (<see cref="CliEnvironment.CheckInvokingUser"/>, the rule the config folder uses; a mismatch or root falls back to the effective
    /// user rather than failing a history write); else the effective user's name.
    /// </summary>
    internal static string? ResolveUser(Func<string, string?> getEnv, bool elevated, uint effectiveUid,
        Func<string, UnixPasswdEntry?> lookupUser, Func<uint, string?> nameOf, string? windowsName)
    {
        if (windowsName is not null)
            return windowsName;
        if (elevated && getEnv("SUDO_USER") is { Length: > 0 } sudoUser
            && CliEnvironment.CheckInvokingUser(sudoUser, getEnv("SUDO_UID"), lookupUser, out _) is not null)
            return sudoUser;
        return nameOf(effectiveUid);
    }
}
