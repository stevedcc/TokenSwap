using TswapCore;

namespace TswapCli;

/// <summary>
/// Brief T21 (#314): the warning a command prints on stderr after storing a value shorter than
/// <see cref="Validation.ShortValueLength"/>. Since brief T30 <c>run</c>, <c>redact</c> and <c>tocomment</c>
/// hide such a value only where it stands as a whole word or number, so a secret that short can show
/// unmasked inside a longer one; a non-secret belongs in a field. It names the secret and the reason only,
/// never the value or its length (owner decision 5, as for <c>add</c>'s whitespace warning), and never refuses.
/// </summary>
internal static class ValueWarnings
{
    public static string ShortValue(string name) =>
        $"Warning: the value of '{name}' is shorter than {Validation.ShortValueLength} characters. 'run', 'redact' and " +
        "'tocomment' hide a value this short only where it stands as a whole word or number, not inside a longer one, " +
        "so a secret this short can show unmasked there. If it isn't a secret (a username, a port, a setting), store it " +
        "as a field of the secret it belongs to.";

    /// <summary>Writes <see cref="ShortValue"/> to stderr when <paramref name="value"/> is short.</summary>
    public static void WarnIfShort(CommandContext ctx, string name, string value)
    {
        if (Validation.IsShortValue(value))
            ctx.Console.Error.WriteLine(ShortValue(name));
    }
}
