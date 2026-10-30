using TswapCore;

namespace TswapCli;

/// <summary>
/// Brief T11 decision 1: every command that creates a Secure Enclave key (<c>init</c>,
/// <c>slot request</c>, <c>recover</c>) needs exactly one of <c>--with-touch</c> or
/// <c>--no-touch</c> next to <c>--secure-enclave</c>, in any order. The flag is the owner's
/// decision: no default, no config setting, no prompt. Parsed before anything is read, prompted
/// for or written, and before the sudo check.
/// </summary>
internal static class SecureEnclaveTouchChoice
{
    public const string WithTouch = "--with-touch";
    public const string NoTouch = "--no-touch";
    public const string SecureEnclave = "--secure-enclave";

    /// <summary>For usage strings: <c>--secure-enclave --with-touch|--no-touch</c>.</summary>
    public const string Flags = $"{SecureEnclave} {WithTouch}|{NoTouch}";

    private const string WhatEachDoes =
        $"{SecureEnclave} needs exactly one of {WithTouch} (every unlock asks for Touch ID or the login password) " +
        $"or {NoTouch} (unlocks with no prompt at all; read the warning it prints). " +
        $"Neither goes without {SecureEnclave}.";

    /// <summary>
    /// Takes the touch flags out of <paramref name="args"/>. Returns the rest and the choice:
    /// true (<c>--with-touch</c>), false (<c>--no-touch</c>), or null when
    /// <c>--secure-enclave</c> isn't among the rest. Throws a <see cref="UsageException"/>
    /// (<paramref name="usage"/> plus what each flag does) for <c>--secure-enclave</c> with
    /// neither, both, either one twice, or either one without <c>--secure-enclave</c>.
    /// </summary>
    public static (string[] Remaining, bool? RequirePresence) Split(string[] args, string usage)
    {
        var withTouch = args.Count(a => a == WithTouch);
        var noTouch = args.Count(a => a == NoTouch);
        var rest = args.Where(a => a is not (WithTouch or NoTouch)).ToArray();
        var secureEnclave = rest.Contains(SecureEnclave);

        var valid = secureEnclave
            ? withTouch + noTouch == 1
            : withTouch + noTouch == 0;
        if (!valid)
            throw new UsageException($"{usage}\n{WhatEachDoes}");
        return (rest, secureEnclave ? withTouch == 1 : null);
    }

    /// <summary>
    /// The warning for <c>--no-touch</c> (decision 7), on stderr, as soon as the flags are
    /// validated. Not a prompt: the flag is the decision. Three claims: (a) no Touch ID or password;
    /// (b) anything that runs code here and reads the config, any account including root, unlocks
    /// silently; (c) the slot can't be changed or removed, only a new vault drops it.
    /// </summary>
    public static void WarnIfNoTouch(IConsole c, bool? requirePresence)
    {
        if (requirePresence != false)
            return;
        c.SetForeground(ConsoleColor.Yellow);
        c.Error.WriteLine($"WARNING ({NoTouch}): this Mac's Secure Enclave slot will unlock the vault without Touch ID or a password.");
        c.Error.WriteLine("  The key still never leaves the Secure Enclave and works only on this Mac, but anything that");
        c.Error.WriteLine("  can run code on this Mac and read this vault's config, from any account, including root, can");
        c.Error.WriteLine("  unlock the vault without you noticing. The config file's permissions are what keep other");
        c.Error.WriteLine("  accounts out.");
        c.Error.WriteLine("  This slot can't be changed or removed later: the only way to drop it is");
        c.Error.WriteLine("  a new vault and moving the secrets over.");
        c.ResetColor();
    }

    /// <summary>The completion summary's posture line (decision 7).</summary>
    public static string Summary(bool requirePresence) => requirePresence
        ? "Secure Enclave slot: touch (Touch ID or password on every unlock)"
        : "Secure Enclave slot: no touch (unlocks without Touch ID or password)";
}
