using System.Text;
using System.Text.RegularExpressions;
using TswapCli;

namespace TswapTests.Docs;

/// <summary>
/// Generates the per-command block of <c>docs/commands.md</c> from <see cref="CommandRegistry.All"/> and writes it
/// between the page's markers (docs restructure D3). <c>TSWAP_REGENERATE_DOCS=1</c> on a run of
/// <c>CommandReferenceIsCurrent</c> rewrites the page through <see cref="Rewrite"/>.
/// </summary>
internal static partial class CommandReference
{
    public const string BeginMarker = "<!-- BEGIN GENERATED: commands (TswapTests/Docs/CommandReference.cs) -->";
    public const string EndMarker = "<!-- END GENERATED: commands -->";

    /// <summary>
    /// The text between the markers: per command in registry order, a <c>### name</c> heading, a fenced block with
    /// <c>[sudo ]tswap HelpUsage</c>, and the Description line. LF line endings.
    /// </summary>
    public static string Generate()
    {
        var sb = new StringBuilder("\n");
        foreach (var command in CommandRegistry.All)
        {
            sb.Append("\n### ").Append(command.Name).Append("\n\n");
            sb.Append("```\n").Append(command.RequiresSudo ? "sudo " : "").Append("tswap ").Append(command.HelpUsage).Append("\n```\n\n");
            sb.Append(EscapeText(command.Description)).Append('\n');
        }
        return sb.Append('\n').ToString();
    }

    /// <summary>
    /// A Description as Markdown text: the characters Markdown would read as markup (<c>&lt;dir&gt;</c> as an HTML
    /// tag, <c>*</c> and <c>_</c> as emphasis, brackets as a link) get a backslash, so the page shows the help text.
    /// </summary>
    public static string EscapeText(string text) => MarkupCharacter().Replace(text, @"\$0");

    [GeneratedRegex(@"[\\`*_\[\]<>]")]
    private static partial Regex MarkupCharacter();

    /// <summary>The text between the two markers of <paramref name="page"/> (LF line endings); throws when a marker is missing or repeated.</summary>
    public static string ReadBlock(string page)
    {
        var (start, end) = Markers(page);
        return page[start..end];
    }

    private static (int Start, int End) Markers(string text)
    {
        var begin = Only(text, BeginMarker);
        var end = Only(text, EndMarker);
        if (end < begin)
            throw new InvalidOperationException($"'{EndMarker}' comes before '{BeginMarker}'.");
        return (begin + BeginMarker.Length, end);

        static int Only(string text, string marker)
        {
            var first = text.IndexOf(marker, StringComparison.Ordinal);
            if (first < 0)
                throw new InvalidOperationException($"The marker '{marker}' is missing.");
            if (text.IndexOf(marker, first + marker.Length, StringComparison.Ordinal) >= 0)
                throw new InvalidOperationException($"The marker '{marker}' appears more than once.");
            return first;
        }
    }

    /// <summary>
    /// Replaces the block of the file at <paramref name="path"/> with <see cref="Generate"/>, writing LF line endings
    /// through a temp file beside it and a rename (<paramref name="move"/>, for tests: the rename). The temp file is
    /// deleted when anything fails; a missing or repeated marker throws before anything is written.
    /// </summary>
    public static void Rewrite(string path, Action<string, string>? move = null)
    {
        var text = MarkdownLinks.ReadText(path);
        var (start, end) = Markers(text);
        var updated = text[..start] + Generate() + text[end..];

        var temp = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(path))!, "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp");
        try
        {
            File.WriteAllText(temp, updated, new UTF8Encoding(false));
            (move ?? ((from, to) => File.Move(from, to, overwrite: true)))(temp, path);
        }
        finally
        {
            if (File.Exists(temp))
                File.Delete(temp);
        }
    }

    // ------------------------------------------------------------------ subcommands

    /// <summary>The subcommands named in <paramref name="command"/>'s HelpUsage.</summary>
    public static IReadOnlyList<string> Subcommands(ICliCommand command) => Subcommands(command.Name, command.HelpUsage);

    /// <summary>
    /// The subcommands of a usage line in either shape: <c>name &lt;a|b|c&gt; ...</c> (the group after the name, split on
    /// <c>|</c>), or <c>name a ... | name b ...</c> (top-level alternatives; in each, the first word after the name once
    /// <c>[...]</c>, <c>&lt;...&gt;</c> and <c>(...)</c> fragments are removed and options skipped). An alternative that does
    /// not start with the name (an option's other spelling) names none.
    /// </summary>
    public static IReadOnlyList<string> Subcommands(string name, string helpUsage)
    {
        var rest = helpUsage.StartsWith(name + " ", StringComparison.Ordinal) ? helpUsage[(name.Length + 1)..].TrimStart() : helpUsage;
        if (rest.StartsWith('<'))
        {
            var close = Matching(rest, 0);
            return rest[1..close].Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        }

        var flat = RemoveGroups(helpUsage);
        var found = new List<string>();
        foreach (var alternative in flat.Split('|'))
        {
            var words = alternative.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (words.Length < 2 || words[0] != name)
                continue;
            var sub = words.Skip(1).FirstOrDefault(w => !w.StartsWith('-'));
            if (sub is not null && !found.Contains(sub))
                found.Add(sub);
        }
        return found;
    }

    private static string RemoveGroups(string text)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] is '[' or '<' or '(')
            {
                i = Matching(text, i);
                sb.Append(' ');
            }
            else
                sb.Append(text[i]);
        }
        return sb.ToString();
    }

    /// <summary>The index of the bracket closing the one at <paramref name="open"/> (nesting of all three kinds counted).</summary>
    private static int Matching(string text, int open)
    {
        var depth = 0;
        for (var i = open; i < text.Length; i++)
        {
            if (text[i] is '[' or '<' or '(') depth++;
            else if (text[i] is ']' or '>' or ')' && --depth == 0) return i;
        }
        throw new InvalidOperationException($"Unbalanced brackets in usage: {text}");
    }

    // ------------------------------------------------------------------ environment variables

    [GeneratedRegex(@"\b(?:GetEnvironmentVariable|getEnv|getEnvironmentVariable)\s*\(\s*(?:""(?<literal>[A-Za-z0-9_]+)""|(?<ident>[A-Za-z_][\w.]*))\s*\)")]
    private static partial Regex EnvironmentRead();

    [GeneratedRegex(@"\bconst\s+string\s+(?<name>[A-Za-z_]\w*)\s*=\s*""(?<value>[^""]*)""")]
    private static partial Regex ConstString();

    [GeneratedRegex(@"^(?:TSWAP|XDG)_[A-Z0-9_]+$")]
    private static partial Regex DocumentedName();

    /// <summary>
    /// The <c>TSWAP_*</c> and <c>XDG_*</c> names the given C# sources read: string literals passed to
    /// <c>GetEnvironmentVariable</c> or to the <c>getEnv</c> seam, and <c>const string</c> fields passed so.
    /// Comments don't count. Sorted, distinct.
    /// </summary>
    public static IReadOnlyList<string> EnvironmentVariablesRead(IEnumerable<string> sources)
    {
        var code = sources.Select(StripComments).ToList();
        var consts = code.SelectMany(c => ConstString().Matches(c))
            .GroupBy(m => m.Groups["name"].Value)
            .ToDictionary(g => g.Key, g => g.Select(m => m.Groups["value"].Value).ToList());
        var names = new SortedSet<string>(StringComparer.Ordinal);
        foreach (Match m in code.SelectMany(c => EnvironmentRead().Matches(c)))
        {
            var values = m.Groups["literal"].Success
                ? [m.Groups["literal"].Value]
                : consts.GetValueOrDefault(m.Groups["ident"].Value.Split('.')[^1]) ?? [];
            foreach (var v in values.Where(v => DocumentedName().IsMatch(v)))
                names.Add(v);
        }
        return names.ToList();
    }

    /// <summary>C# source with its comments blanked out; string and char literals (regular, verbatim, raw) are kept.</summary>
    internal static string StripComments(string source)
    {
        var sb = new StringBuilder(source.Length);
        var i = 0;
        while (i < source.Length)
        {
            var c = source[i];
            var next = i + 1 < source.Length ? source[i + 1] : '\0';
            if (c == '/' && next == '/')
            {
                while (i < source.Length && source[i] != '\n') i++;
                continue;
            }
            if (c == '/' && next == '*')
            {
                var close = source.IndexOf("*/", i + 2, StringComparison.Ordinal);
                var stop = close < 0 ? source.Length : close + 2;
                for (; i < stop; i++) if (source[i] == '\n') sb.Append('\n');
                continue;
            }
            if (c == '"' && source.AsSpan(i).StartsWith("\"\"\""))
            {
                var quotes = 0;
                while (i + quotes < source.Length && source[i + quotes] == '"') quotes++;
                var fence = new string('"', quotes);
                var close = source.IndexOf(fence, i + quotes, StringComparison.Ordinal);
                var stop = close < 0 ? source.Length : close + quotes;
                sb.Append(source, i, stop - i);
                i = stop;
                continue;
            }
            if (c == '"' || c == '\'')
            {
                var verbatim = i > 0 && (source[i - 1] == '@' || i > 1 && source[i - 2] == '@' && source[i - 1] == '$');
                var start = i++;
                while (i < source.Length)
                {
                    if (!verbatim && source[i] == '\\') { i += 2; continue; }
                    if (source[i] == c)
                    {
                        if (verbatim && i + 1 < source.Length && source[i + 1] == c) { i += 2; continue; }
                        i++;
                        break;
                    }
                    if (!verbatim && source[i] == '\n') break;
                    i++;
                }
                sb.Append(source, start, Math.Min(i, source.Length) - start);
                continue;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString();
    }
}
