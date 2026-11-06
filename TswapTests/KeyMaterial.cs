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
    /// No key-like token in <paramref name="output"/>. Each whitespace-delimited token is checked:
    /// <list type="bullet">
    /// <item>as it is: no run of 32 or more hex characters, or 24 or more base64 characters, as the whole token;</item>
    /// <item>a path (it starts with <c>/</c>, <c>~</c> or a drive letter, or its last <c>/</c> segment holds a
    /// <c>.</c>): each <c>/</c> segment as it is, so a hyphenated folder name isn't taken for a grouped secret;</item>
    /// <item>any other token: once more with <c>-</c> and <c>:</c> stripped, as a whole (a secret printed in groups,
    /// base64 with <c>/</c> included).</item>
    /// </list>
    /// And no run of hex groups separated by <c>-</c>, <c>:</c> or spaces adding up to 32 or more hex characters.
    /// </summary>
    public static void AssertNone(string output)
    {
        foreach (var token in output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            Assert.True(!LooksLikeKey(token), $"key-like token in the output: {token}");
            if (IsPathShaped(token))
            {
                foreach (var segment in token.Split('/', '\\'))
                    Assert.True(!LooksLikeKey(segment), $"key-like path segment in the output: {token}");
            }
            else
            {
                var joined = token.Replace("-", "").Replace(":", "");
                Assert.True(!LooksLikeKey(joined), $"grouped key-like token in the output: {token}");
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
