using TswapCore;

namespace TswapCli;

/// <summary>
/// Brief T21 (#314): the warning a command prints on stderr after storing a value shorter than
/// <see cref="Validation.ShortValueLength"/>. It names the secret and the reason only, never the value
/// or its length (owner decision 5, as for <c>add</c>'s whitespace warning), and never refuses.
/// </summary>
internal static class ValueWarnings
{
    public static string ShortValue(string name) =>
        $"Warning: the value of '{name}' is shorter than {Validation.ShortValueLength} characters. 'run', 'redact' and " +
        "'tocomment' match a value wherever it appears, also inside longer words and numbers, so a short value gets " +
        "hidden in unrelated output and gives itself away. If it isn't a secret (a username, a port, a setting), it " +
        "doesn't belong in tswap.";

    /// <summary>Writes <see cref="ShortValue"/> to stderr when <paramref name="value"/> is short.</summary>
    public static void WarnIfShort(CommandContext ctx, string name, string value)
    {
        if (Validation.IsShortValue(value))
            ctx.Console.Error.WriteLine(ShortValue(name));
    }
}
