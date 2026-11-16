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
    /// The test process's own temp folder (<see cref="Path.GetTempPath"/>) is read as <c>/tmp</c> first: it is never a
    /// key (#345), and everything after it is checked as above.
    /// </summary>
    public static void AssertNone(string output) => AssertNone(output, Path.GetTempPath());

    /// <summary>
    /// <see cref="AssertNone(string)"/> with the test run's temp folder given: <paramref name="tempRoot"/> is the
    /// tests' own folder, never a key, so it is read as <c>/tmp</c> (#345: a macOS runner's per-user temp folder,
    /// <c>/var/folders/&lt;2&gt;/&lt;30 random characters&gt;/T</c>, can read as base64). What follows it is checked as usual.
    /// Only a multi-part path counts (a separator after its first character, once trailing ones are trimmed): a root
    /// such as <c>C:</c> or <c>q2</c> could occur inside a key, and replacing it there could hide the key.
    /// </summary>
    internal static void AssertNone(string output, string tempRoot)
    {
        var root = tempRoot.TrimEnd('/', '\\');
        if (root.IndexOfAny(['/', '\\'], Math.Min(1, root.Length)) > 0)
            output = output.Replace(root, "/tmp", StringComparison.Ordinal);
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
