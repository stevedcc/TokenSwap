using System.Text.RegularExpressions;
using Xunit;

namespace TswapTests;

/// <summary>
/// The leak checks the YubiKey test classes run over a command's output (final review item 8, round 2: one copy, used
/// by <see cref="YubiKeyReenrolTests"/> and <see cref="YubiKeySetupTests"/>, self-tested in <see cref="KeyMaterialTests"/>).
/// </summary>
internal static partial class KeyMaterial
{
    /// <summary>
    /// No key-like token in <paramref name="output"/>. Each whitespace-delimited token is first trimmed of leading and
    /// trailing punctuation (<c>.,;:!?()[]{}"'</c> and backtick; a closed set: <c>=</c> is kept, so base64 padding
    /// survives, and <c>&lt;</c>, <c>&gt;</c> and <c>*</c> are not trimmed, so a key printed as <c>&lt;0123…EF&gt;</c>
    /// or <c>**…**</c> is outside this check), then checked:
    /// <list type="bullet">
    /// <item>as it is: no run of 32 or more hex characters, or 24 or more base64 characters, as the whole token;</item>
    /// <item>each <c>/</c> or <c>\</c> segment, trimmed the same way and otherwise as it is, never degrouped (so a
    /// hyphenated folder name isn't taken for a grouped secret), for every token;</item>
    /// <item>a token that is not a path (a path starts with <c>/</c>, <c>~</c> or a drive letter, or its last
    /// <c>/</c> segment holds a <c>.</c>): once more with <c>-</c> and <c>:</c> stripped, as a whole (a secret printed
    /// in groups, base64 with <c>/</c> included).</item>
    /// </list>
    /// And no run of hex groups separated by <c>-</c>, <c>:</c> or spaces adding up to 32 or more hex characters.
    /// </summary>
    public static void AssertNone(string output)
    {
        foreach (var printed in output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            var token = TrimPunctuation(printed);
            Assert.True(!LooksLikeKey(token), $"key-like token in the output: {printed}");
            foreach (var segment in token.Split('/', '\\'))
                Assert.True(!LooksLikeKey(TrimPunctuation(segment)), $"key-like path segment in the output: {printed}");
            if (!IsPathShaped(token))
            {
                var joined = token.Replace("-", "").Replace(":", "");
                Assert.True(!LooksLikeKey(joined), $"grouped key-like token in the output: {printed}");
            }
        }
        foreach (Match run in SeparatedHexRun().Matches(output))
            Assert.True(SeparatorChars().Replace(run.Value, "").Length < 32, $"grouped hex in the output: {run.Value}");
    }

    /// <summary>A value typed on stdin (the recovery key, the vault password) is never printed; then <see cref="AssertNone"/>.</summary>
    public static void AssertNotEchoed(string output, params string[] typed)
    {
        foreach (var value in typed)
            Assert.False(output.Contains(value, StringComparison.Ordinal), "a typed secret appears in the output");
        AssertNone(output);
    }

    /// <summary>The closed trim set of <see cref="AssertNone"/> (#258): sentence and bracket punctuation, not <c>=</c>.</summary>
    private static readonly char[] Punctuation = ['.', ',', ';', ':', '!', '?', '(', ')', '[', ']', '{', '}', '"', '\'', '`'];

    private static string TrimPunctuation(string text) => text.Trim(Punctuation);

    private static bool LooksLikeKey(string text) => HexToken().IsMatch(text) || Base64Token().IsMatch(text);

    private static bool IsPathShaped(string token)
    {
        var t = token.TrimStart('(', '"', '\'', '`');
        if (t.StartsWith('/') || t.StartsWith('~') || DriveRoot().IsMatch(t))
            return true;
        var slash = t.LastIndexOf('/');
        return slash >= 0 && t[(slash + 1)..].Contains('.');
    }

    [GeneratedRegex(@"^[A-Za-z]:[\\/]")]
    private static partial Regex DriveRoot();

    [GeneratedRegex("[0-9A-Fa-f]+(?:[-: ]+[0-9A-Fa-f]+)+")]
    private static partial Regex SeparatedHexRun();

    [GeneratedRegex("[-: ]")]
    private static partial Regex SeparatorChars();

    [GeneratedRegex("^[0-9A-Fa-f]{32,}$")]
    private static partial Regex HexToken();

    [GeneratedRegex("^[A-Za-z0-9+/]{24,}={0,2}$")]
    private static partial Regex Base64Token();
}
