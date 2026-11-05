using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace TswapTests.Docs;

/// <summary>Where an anchor comes from: a heading, or an explicit <c>&lt;a id&gt;</c> / <c>&lt;a name&gt;</c>.</summary>
internal enum AnchorKind { Heading, Explicit }

/// <summary>One anchor of a Markdown file. <see cref="InMovedSections"/> marks one inside a "Moved sections" <c>&lt;details&gt;</c> block (a redirect).</summary>
internal sealed record Anchor(string Id, AnchorKind Kind, bool InMovedSections, int Line);

/// <summary>
/// Reads Markdown the way GitHub renders it, as far as the docs guards need: heading slugs, explicit anchors and links.
/// Code (fenced, indented, inline) and HTML comments never count.
/// </summary>
internal static partial class MarkdownLinks
{
    public static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "TokenSwap.slnx"))) return dir.FullName;
        }
        throw new InvalidOperationException("TokenSwap.slnx not found above " + AppContext.BaseDirectory);
    }

    /// <summary>Reads a file with CRLF normalised to LF.</summary>
    public static string ReadText(string path) => File.ReadAllText(path).Replace("\r\n", "\n").Replace('\r', '\n');

    /// <summary>Repo-relative paths (forward slashes) of every Markdown file git tracks or would track.</summary>
    public static IReadOnlyList<string> AllMarkdown()
    {
        var psi = new ProcessStartInfo("git")
        {
            WorkingDirectory = RepoRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in new[] { "-c", "core.quotepath=off", "ls-files", "--cached", "--others", "--exclude-standard", "--", "*.md" })
            psi.ArgumentList.Add(arg);
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0) throw new InvalidOperationException("git ls-files failed: " + stderr);
        return stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(IsNotScratch)
            .Distinct()
            .Order(StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>The files the link guards read: everything but the history under docs/superpowers and docs/briefs.</summary>
    public static IReadOnlyList<string> CheckedMarkdown() =>
        AllMarkdown().Where(p => !p.StartsWith("docs/superpowers/", StringComparison.Ordinal)
                              && !p.StartsWith("docs/briefs/", StringComparison.Ordinal)).ToList();

    /// <summary>False for the SDD workspace, other worktrees, build output and scratch notes.</summary>
    public static bool IsNotScratch(string repoRelativePath)
    {
        var segments = repoRelativePath.Split('/');
        var name = segments[^1];
        if (name.StartsWith("wip-", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
            return false;
        return !segments[..^1].Any(s => s is ".superpowers" or ".worktrees" or "bin" or "obj");
    }

    // ---- live lines: the Markdown with code and comments blanked, one entry per source line ----

    [GeneratedRegex(@"^[ \t>]*")]
    private static partial Regex BlockquotePrefix();
    [GeneratedRegex(@"^[ \t]*(?:>[ \t]*)*(?:(?:[-*+]|\d+[.)])[ \t]+)?(`{3,}|~{3,})")]
    private static partial Regex FenceOpen();
    [GeneratedRegex(@"^\s*([-*+]|\d+[.)])(\s|$)")]
    private static partial Regex ListMarker();

    /// <summary>
    /// The text of each line with fenced code, indented code blocks and HTML comments removed (the line count is kept).
    /// </summary>
    internal static string[] LiveLines(string markdown)
    {
        var lines = markdown.Replace("\r\n", "\n").Split('\n');
        var live = new string[lines.Length];
        char fenceChar = '\0';
        var fenceLen = 0;
        var inComment = false;
        var prevBlank = true;
        var inList = false;

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];

            if (fenceChar != '\0')
            {
                var t = BlockquotePrefix().Replace(line, "").Trim();
                if (t.Length >= fenceLen && t.All(c => c == fenceChar)) fenceChar = '\0';
                live[i] = "";
                prevBlank = false;
                continue;
            }

            if (!inComment)
            {
                var m = FenceOpen().Match(line);
                var indentedCode = (line.StartsWith("    ", StringComparison.Ordinal) || line.StartsWith('\t')) && prevBlank && !inList;
                if (m.Success && !indentedCode)
                {
                    fenceChar = m.Groups[1].Value[0];
                    fenceLen = m.Groups[1].Value.Length;
                    live[i] = "";
                    prevBlank = false;
                    continue;
                }
            }

            // HTML comments, possibly across lines.
            var sb = new StringBuilder();
            var pos = 0;
            while (pos < line.Length)
            {
                if (inComment)
                {
                    var end = line.IndexOf("-->", pos, StringComparison.Ordinal);
                    if (end < 0) { pos = line.Length; break; }
                    pos = end + 3;
                    inComment = false;
                }
                else
                {
                    var start = line.IndexOf("<!--", pos, StringComparison.Ordinal);
                    if (start < 0) { sb.Append(line, pos, line.Length - pos); pos = line.Length; break; }
                    sb.Append(line, pos, start - pos);
                    pos = start + 4;
                    inComment = true;
                }
            }
            var text = sb.ToString();
            var blank = text.Trim().Length == 0;

            // Indented code: 4+ spaces (or a tab) after a blank line, outside a list.
            var indented = line.StartsWith("    ", StringComparison.Ordinal) || line.StartsWith('\t');
            if (!blank && indented && prevBlank && !inList)
            {
                live[i] = "";
                continue; // prevBlank stays true: the block goes on
            }

            if (!blank)
            {
                if (ListMarker().IsMatch(text)) inList = true;
                else if (!indented && prevBlank) inList = false;
            }
            live[i] = text;
            prevBlank = line.Trim().Length == 0; // a comment-only line is not blank
        }
        return live;
    }

    // ---- anchors ----

    [GeneratedRegex(@"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$")]
    private static partial Regex AtxHeading();
    [GeneratedRegex(@"[ \t]+#+$")]
    private static partial Regex ClosingHashes();
    [GeneratedRegex(@"<a\s[^>]*?\b(?:id|name)\s*=\s*""([^""]+)""", RegexOptions.IgnoreCase)]
    private static partial Regex ExplicitAnchor();
    [GeneratedRegex(@"!?\[([^\]]*)\]\([^)]*\)")]
    private static partial Regex InlineLinkText();
    [GeneratedRegex(@"<[^>]+>")]
    private static partial Regex HtmlTag();

    /// <summary>GitHub's heading slug, before duplicates get <c>-1</c>, <c>-2</c>.</summary>
    internal static string BaseSlug(string headingText)
    {
        var text = InlineLinkText().Replace(headingText, "$1");
        text = HtmlTag().Replace(text, "");
        text = OutsideCodeSpans(text, t => UnderscoreEmphasis().Replace(t, "$2")); // _em_ and __strong__; TSWAP_CONFIG_DIR and `_code_` keep their underscores
        text = WebUtility.HtmlDecode(text).Replace("`", "").Replace("*", "").Trim().ToLowerInvariant();
        var sb = new StringBuilder();
        foreach (var rune in text.EnumerateRunes())
        {
            if (rune.Value == ' ') sb.Append('-');
            else if (rune.Value is '-' or '_' || Rune.IsLetterOrDigit(rune) || IsMark(rune)) sb.Append(rune.ToString());
        }
        return sb.ToString();
    }

    /// <summary>
    /// Underscore emphasis as GitHub renders it (markup removed from the slug): a run of one or two
    /// <c>_</c> not inside a word, opening before and closing after a non-space. Intraword underscores
    /// (<c>snake_case</c>) are literal and stay.
    /// </summary>
    [GeneratedRegex(@"(?<![\p{L}\p{N}_])(_{1,2})(?=\S)(.+?)(?<=\S)\1(?![\p{L}\p{N}_])")]
    private static partial Regex UnderscoreEmphasis();

    /// <summary>Applies <paramref name="transform"/> to the text between inline code spans, never inside one.</summary>
    private static string OutsideCodeSpans(string text, Func<string, string> transform)
    {
        var sb = new StringBuilder();
        var at = 0;
        foreach (Match m in CodeSpan().Matches(text))
        {
            sb.Append(transform(text[at..m.Index])).Append(m.Value);
            at = m.Index + m.Length;
        }
        return sb.Append(transform(text[at..])).ToString();
    }

    private static bool IsMark(Rune r) => Rune.GetUnicodeCategory(r) is System.Globalization.UnicodeCategory.NonSpacingMark
        or System.Globalization.UnicodeCategory.SpacingCombiningMark or System.Globalization.UnicodeCategory.EnclosingMark;

    [GeneratedRegex(@"<details\b|</details\s*>|<summary\b[^>]*>.*?</summary\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex DetailsTags();

    /// <summary>Every anchor of the file in document order: heading slugs and explicit ids.</summary>
    public static IReadOnlyList<Anchor> AnchorsDetailed(string markdown)
    {
        var live = LiveLines(markdown);
        var masked = MaskCodeSpans(string.Join('\n', live)); // code spans per paragraph
        var lineStarts = new int[live.Length];
        for (int i = 0, off = 0; i < live.Length; i++) { lineStarts[i] = off; off += live[i].Length + 1; }
        int LineOf(int offset)
        {
            var idx = Array.BinarySearch(lineStarts, offset);
            return (idx >= 0 ? idx : ~idx - 1) + 1;
        }

        // "Moved sections" blocks as offset intervals; a <summary> may span lines.
        var moved = new List<(int Start, int End)>();
        var stack = new Stack<(int Start, bool Moved)>();
        foreach (Match tag in DetailsTags().Matches(masked))
        {
            if (tag.Value.StartsWith("</details", StringComparison.OrdinalIgnoreCase))
            {
                if (stack.Count == 0) continue;
                var top = stack.Pop();
                if (top.Moved) moved.Add((top.Start, tag.Index));
            }
            else if (tag.Value.StartsWith("<details", StringComparison.OrdinalIgnoreCase)) stack.Push((tag.Index, false));
            else if (stack.Count > 0 && Regex.IsMatch(tag.Value, @"Moved\s+sections", RegexOptions.IgnoreCase))
            {
                var top = stack.Pop();
                stack.Push((top.Start, true));
            }
        }
        foreach (var open in stack.Where(o => o.Moved)) moved.Add((open.Start, masked.Length));
        bool InMoved(int offset) => moved.Any(r => offset >= r.Start && offset < r.End);

        var found = new List<(int Offset, Anchor Anchor)>();
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < live.Length; i++)
        {
            var h = AtxHeading().Match(live[i]);
            if (!h.Success) continue;
            var text = ClosingHashes().Replace(h.Groups[2].Value, "");
            if (text.StartsWith('#') && text.All(c => c == '#')) text = "";
            var baseSlug = BaseSlug(text);
            var candidate = baseSlug;
            while (seen.Contains(candidate))
            {
                counts[baseSlug] = counts.GetValueOrDefault(baseSlug) + 1;
                candidate = baseSlug + "-" + counts[baseSlug];
            }
            seen.Add(candidate);
            found.Add((lineStarts[i], new Anchor(candidate, AnchorKind.Heading, InMoved(lineStarts[i]), i + 1)));
        }

        foreach (Match a in ExplicitAnchor().Matches(masked))
            found.Add((a.Index, new Anchor(a.Groups[1].Value, AnchorKind.Explicit, InMoved(a.Index), LineOf(a.Index))));

        return found.OrderBy(f => f.Offset).Select(f => f.Anchor).ToList();
    }

    /// <summary>Heading slugs and explicit ids, in document order.</summary>
    public static IReadOnlyList<string> Anchors(string markdown) => AnchorsDetailed(markdown).Select(a => a.Id).ToList();

    /// <summary>True when the file has a setext heading (a paragraph line underlined with <c>=</c> or <c>-</c>).</summary>
    public static IReadOnlyList<int> SetextHeadingLines(string markdown)
    {
        var live = LiveLines(markdown);
        var hits = new List<int>();
        for (var i = 1; i < live.Length; i++)
        {
            if (!Regex.IsMatch(live[i], @"^ {0,3}(=+|-+)[ \t]*$")) continue;
            var prev = live[i - 1];
            if (prev.Trim().Length == 0) continue; // a thematic break
            if (AtxHeading().IsMatch(prev) || ListMarker().IsMatch(prev) || prev.TrimStart().StartsWith('>')
                || prev.Contains('|') || Regex.IsMatch(prev, @"^ {0,3}(=+|-+)[ \t]*$")) continue;
            hits.Add(i + 1);
        }
        return hits;
    }

    // ---- links ----

    [GeneratedRegex(@"(?<!\\)\[(?<text>(?:[^\[\]]|\[[^\]]*\])*)\]\(\s*(?<target><[^>\n]*>|[^\s)]+)(?:\s+(?:""[^""]*""|'[^']*'))?\s*\)")]
    private static partial Regex InlineLink();
    [GeneratedRegex(@"^ {0,3}\[([^\]^][^\]]*)\]:[ \t]*<?([^\s>]+)>?", RegexOptions.Multiline)]
    private static partial Regex ReferenceDefinition();
    [GeneratedRegex(@"\b(?:href|src)\s*=\s*(?:""([^""]*)""|'([^']*)')", RegexOptions.IgnoreCase)]
    private static partial Regex HrefAttribute();

    [GeneratedRegex(@"(\n[ \t]*\n)")]
    private static partial Regex ParagraphBreak();

    /// <summary>
    /// Replaces every inline code span with spaces (newlines kept). A span cannot cross a blank line,
    /// so each paragraph is masked on its own: a stray backtick hides nothing outside its paragraph.
    /// </summary>
    internal static string MaskCodeSpans(string text)
    {
        var parts = ParagraphBreak().Split(text); // separators are kept at the odd indexes
        for (var i = 0; i < parts.Length; i += 2)
            parts[i] = CodeSpan().Replace(parts[i], m => Regex.Replace(m.Value, @"[^\n]", " "));
        return string.Concat(parts);
    }

    [GeneratedRegex(@"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)", RegexOptions.Singleline)]
    private static partial Regex CodeSpan();

    /// <summary>
    /// Every link target of the file with its 1-based line: inline and image links (an image inside a
    /// link's text too), reference definitions and <c>href</c> and <c>src</c> attributes, outside code and
    /// comments.
    /// </summary>
    public static IReadOnlyList<(int Line, string Target)> Links(string markdown)
    {
        var live = LiveLines(markdown);
        var text = MaskCodeSpans(string.Join('\n', live));
        var links = new List<(int Line, string Target)>();

        int LineOf(int offset)
        {
            var n = 1;
            for (var i = 0; i < offset; i++) if (text[i] == '\n') n++;
            return n;
        }

        foreach (Match m in InlineLink().Matches(text))
        {
            links.Add((LineOf(m.Groups["target"].Index), Unwrap(m.Groups["target"].Value)));
            // An image inside the link's text (the badge shape [![alt](img.png)](page.md)) is a link too.
            var inner = m.Groups["text"];
            foreach (Match n in InlineLink().Matches(inner.Value))
                links.Add((LineOf(inner.Index + n.Groups["target"].Index), Unwrap(n.Groups["target"].Value)));
        }
        foreach (Match m in ReferenceDefinition().Matches(text))
            links.Add((LineOf(m.Groups[2].Index), m.Groups[2].Value));
        foreach (Match m in HrefAttribute().Matches(text))
            { var g = m.Groups[1].Success ? m.Groups[1] : m.Groups[2]; links.Add((LineOf(g.Index), g.Value)); }

        return links.Where(l => l.Target.Length > 0).OrderBy(l => l.Line).ToList();
    }

    private static string Unwrap(string target) =>
        target.StartsWith('<') && target.EndsWith('>') ? target[1..^1] : target;

    // ---- resolving ----

    [GeneratedRegex(@"^[a-zA-Z][a-zA-Z0-9+.\-]*:")]
    private static partial Regex HasScheme();

    public static bool IsExternal(string target) => HasScheme().IsMatch(target) || target.StartsWith("//", StringComparison.Ordinal);

    /// <summary>
    /// Resolves a relative link from a repo-relative file to a repo-relative path, comparing every segment
    /// case-sensitively against the directory listing. Returns null when it does not exist (or leaves the repo).
    /// </summary>
    public static (string Path, bool IsDirectory)? ResolveExisting(string root, string fromFile, string pathPart)
    {
        pathPart = Uri.UnescapeDataString(pathPart);
        var segments = new List<string>();
        if (!pathPart.StartsWith('/'))
            segments.AddRange(fromFile.Split('/')[..^1]);
        foreach (var seg in pathPart.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (seg == ".") continue;
            if (seg == "..")
            {
                if (segments.Count == 0) return null;
                segments.RemoveAt(segments.Count - 1);
            }
            else segments.Add(seg);
        }

        var current = root;
        var isDir = true;
        foreach (var seg in segments)
        {
            if (!isDir) return null;
            var match = Directory.EnumerateFileSystemEntries(current)
                .FirstOrDefault(e => string.Equals(System.IO.Path.GetFileName(e), seg, StringComparison.Ordinal));
            if (match == null) return null;
            current = match;
            isDir = Directory.Exists(match);
        }
        return (string.Join('/', segments), isDir);
    }
}
