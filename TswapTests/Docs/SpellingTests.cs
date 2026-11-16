using System.Text.RegularExpressions;
using Xunit;

namespace TswapTests.Docs;

/// <summary>
/// Brief T33 (#254): tswap is written in British English. These guards read every text file git tracks, apart
/// from the historical records (<c>docs/briefs/</c>, <c>docs/superpowers/</c>, <c>docs/release-notes/</c>) and
/// the allowlist itself, and fail on a US form. A line that must keep one (a released anchor, a name another
/// tool owns, the US synonym of <c>slot enrol</c>) is listed in <c>TswapTests/Docs/us-spellings-allowed.txt</c>
/// as <c>path&lt;TAB&gt;exact line text&lt;TAB&gt;reason</c>; an edited line falls out of the list.
/// </summary>
public partial class SpellingTests
{
    private static readonly string Root = MarkdownLinks.RepoRoot();

    private const string AllowlistPath = "TswapTests/Docs/us-spellings-allowed.txt";

    private static readonly string[] RecordFolders = ["docs/briefs/", "docs/superpowers/", "docs/release-notes/"];

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".md", ".sh", ".ps1", ".yml", ".yaml", ".json", ".json5", ".txt", ".te", ".fc", ".service",
        ".socket", ".xml", ".csproj", ".slnx", ".c", ".h", ".swift", ".py", ".cil", ".html",
    };

    /// <summary>The US forms of the enrol family: <c>enrol</c> plus a second <c>l</c>, unless <c>ed</c> or <c>ing</c> follows.</summary>
    [GeneratedRegex("[Ee][Nn][Rr][Oo][Ll][Ll](?![Ee][Dd]|[Ii][Nn][Gg])")]
    internal static partial Regex UsEnrolForm();

    /// <summary>One line of a scanned file: repo-relative path, 1-based line number, the line's text.</summary>
    private sealed record ScannedLine(string Path, int Number, string Text);

    /// <summary>One allowlist entry: the path, the trimmed line text, and why it may keep its US form.</summary>
    private sealed record AllowedLine(string Path, string Text, string Reason);

    /// <summary>A name starting with '.' (<c>.gitignore</c>) counts as having no extension.</summary>
    internal static bool IsScannedText(string repoRelativePath)
    {
        var name = repoRelativePath.Split('/')[^1];
        var dot = name.LastIndexOf('.');
        return dot <= 0 || TextExtensions.Contains(name[dot..]);
    }

    internal static bool IsInScope(string repoRelativePath) =>
        repoRelativePath != AllowlistPath
        && !RecordFolders.Any(f => repoRelativePath.StartsWith(f, StringComparison.Ordinal))
        && IsScannedText(repoRelativePath);

    private static IEnumerable<ScannedLine> ScannedLines()
    {
        foreach (var path in MarkdownLinks.AllTracked().Where(IsInScope))
        {
            var full = Path.Combine(Root, path);
            if (!File.Exists(full)) continue; // deleted in the working tree, not yet staged
            var lines = MarkdownLinks.ReadText(full).Split('\n');
            for (var i = 0; i < lines.Length; i++)
                yield return new ScannedLine(path, i + 1, lines[i]);
        }
    }

    private static List<AllowedLine> Allowlist()
    {
        List<AllowedLine> entries = [];
        var lines = MarkdownLinks.ReadText(Path.Combine(Root, AllowlistPath)).Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Trim().Length == 0 || line.StartsWith('#')) continue;
            var first = line.IndexOf('\t');
            var last = line.LastIndexOf('\t');
            if (first < 0 || last == first)
                throw new InvalidOperationException($"{AllowlistPath}:{i + 1}: not 'path<TAB>line text<TAB>reason': {line}");
            entries.Add(new AllowedLine(line[..first], line[(first + 1)..last].Trim(), line[(last + 1)..].Trim()));
        }
        return entries;
    }

    private static bool IsAllowed(List<AllowedLine> allowlist, ScannedLine line)
    {
        var text = line.Text.Trim();
        return allowlist.Any(e => e.Path == line.Path && e.Text == text);
    }

    private static List<string> Offenders(Func<string, bool> hasUsForm)
    {
        var allowlist = Allowlist();
        return ScannedLines()
            .Where(l => hasUsForm(l.Text) && !IsAllowed(allowlist, l))
            .Select(l => $"{l.Path}:{l.Number}: {l.Text.Trim()}")
            .ToList();
    }

    [Fact]
    public void NoUsEnrolSpellings_InTrackedText()
    {
        var offenders = Offenders(UsEnrolForm().IsMatch);
        Assert.True(offenders.Count == 0,
            $"{offenders.Count} lines with a US form of enrol (British: enrol, enrols, enrolment, enrolments; " +
            $"or add the line to {AllowlistPath} with a reason):\n" + string.Join('\n', offenders));
    }

    [Fact]
    public void UsSpellingAllowlist_HasNoStaleEntries()
    {
        var lines = ScannedLines()
            .Select(l => (l.Path, Text: l.Text.Trim()))
            .ToHashSet();
        var stale = Allowlist()
            .Where(e => !lines.Contains((e.Path, e.Text)))
            .Select(e => $"{e.Path}\t{e.Text}\t{e.Reason}")
            .ToList();
        Assert.True(stale.Count == 0, $"{AllowlistPath} entries that match no line any more:\n" + string.Join('\n', stale));
    }

    [Fact]
    public void ScannedFiles_CoverTheTextTypes_AndSkipTheRecords()
    {
        Assert.True(IsScannedText(".gitignore"));
        Assert.True(IsScannedText("LICENSE"));
        Assert.True(IsScannedText("TswapCli/Native/pcsc-loader.c"));
        Assert.False(IsScannedText("docs/images/logo.png"));
        Assert.False(IsInScope("docs/briefs/t33-british-spelling.md"));
        Assert.False(IsInScope("docs/superpowers/plan.md"));
        Assert.False(IsInScope("docs/release-notes/v0.3.0.md"));
        Assert.False(IsInScope(AllowlistPath));
        Assert.True(IsInScope("docs/commands.md"));

        // The pattern: the US forms, in any case, and not the forms both spellings share.
        // (Built from parts, so this file holds no US form itself.)
        Assert.Matches(UsEnrolForm(), "Enrol" + "l");
        Assert.Matches(UsEnrolForm(), "SlotEnrol" + "lment");
        Assert.Matches(UsEnrolForm(), "ENROL" + "LS");
        Assert.DoesNotMatch(UsEnrolForm(), "enrolled");
        Assert.DoesNotMatch(UsEnrolForm(), "Enrolling");
        Assert.DoesNotMatch(UsEnrolForm(), "enrolment");
    }
}
