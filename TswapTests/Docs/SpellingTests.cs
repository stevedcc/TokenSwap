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

    /// <summary>
    /// Brief T33 task 2 and T40: the US forms tswap has used or is likely to use, not every US spelling; the list is
    /// deliberate and grows when a review finds a new one. The words are lowercase whole words (case-sensitive, a
    /// word boundary each side), built from stems and suffixes so that no US word appears whole in this file.
    /// PascalCase names (a framework's or tswap's own) never match, nor does a capitalised word starting a sentence
    /// (<see cref="CasedUsForm"/> guards those).
    /// <para>The <c>-ize</c> endings are a valid British (Oxford) spelling too; the owner chose <c>-ise</c> for tswap.</para>
    /// </summary>
    private static readonly (string Stem, string[] Suffixes)[] OtherUsWords =
    [
        ("behavi", ["or", "ors", "oral", "orally"]),
        ("col", ["or", "ors", "ored", "oring"]),
        ("hon", ["or", "ors", "ored", "oring"]),
        ("fav", ["or", "ors", "ored", "oring", "orite", "orites"]),
        ("neighb", ["or", "ors", "oring", "orhood", "orhoods"]),
        ("rum", ["or", "ors", "ored"]),
        ("endeav", ["or", "ors", "ored", "oring"]),
        ("cent", ["er", "ers", "ered", "ering"]),
        ("lit", ["er", "ers"]),
        ("gr", ["ay"]),
        ("cancel", ["ed", "ing"]),
        ("defen", ["se", "ses"]),
        ("offen", ["se", "ses"]),
        ("judg", ["ment", "ments"]),
        ("acknowledg", ["ment", "ments"]),
        ("fulfil", ["l", "ls", "lment"]),
        ("travel", ["ed", "ing"]),
        ("label", ["ed", "ing"]),
        ("model", ["ed", "ing"]),
        ("analy", ["ze", "zes", "zed", "zing", "zer", "zers"]),
        .. new[]
        {
            "recogn", "organ", "author", "final", "normal", "initial", "summar", "minim", "maxim", "custom",
            "priorit", "synchron", "optim", "serial", "deserial", "sanit", "material", "util", "real", "standard",
            "special", "general", "local", "visual", "emphas", "random", "canonical", "token", "stabil", "categor",
            "character", "modern", "item", "memor", "legitim", "penal", "apolog", "digit", "notar", "personal",
            "unrecogn", "reinitial", "parallel",
        }.Select(stem => (stem, new[] { "ize", "izes", "ized", "izing", "ization", "izations", "izer", "izers" })),
    ];

    internal static readonly Regex OtherUsForm = new(
        @"\b(?:" + string.Join('|', OtherUsWords.Select(w => w.Stem + "(?:" + string.Join('|', w.Suffixes) + ")")) + @")\b",
        RegexOptions.CultureInvariant);

    /// <summary>
    /// Capitalised and ALL-CAPS forms (#352): a sentence start, a heading, a banner. Code is left alone: a word after
    /// a <c>.</c> or before <c>(</c> or <c>&lt;</c>. The <c>Authoriz…</c> forms are not matched at all: <c>Authorization</c>
    /// is the HTTP header name (RFC 9110), which other software owns; the lowercase forms stay guarded.
    /// Built from <see cref="OtherUsWords"/>, so a family added there is guarded in every case at once.
    /// </summary>
    internal static readonly Regex CasedUsForm = new(
        @"(?<!\.)\b(?:" + string.Join('|', OtherUsWords.Where(w => w.Stem != "author").SelectMany(w => w.Suffixes.Select(
            suffix => Capitalised(w.Stem + suffix) + "|" + (w.Stem + suffix).ToUpperInvariant()))) + @")\b(?![(<])",
        RegexOptions.CultureInvariant);

    private static string Capitalised(string word) => char.ToUpperInvariant(word[0]) + word[1..];

    [Fact]
    public void NoOtherUsSpellings_InProse()
    {
        var offenders = Offenders(OtherUsForm.IsMatch);
        Assert.True(offenders.Count == 0,
            $"{offenders.Count} lines with a US spelling (British: -our, centre, grey, cancelled, -ise, analyse, defence, " +
            $"acknowledgement, fulfil, travelled, labelled, modelled, neighbour, rumour, endeavour, litre, judgement; or add the line to {AllowlistPath} with a reason):\n" +
            string.Join('\n', offenders));
    }

    [Fact]
    public void NoUsSpellings_CapitalisedOrAllCaps()
    {
        var offenders = Offenders(CasedUsForm.IsMatch);
        Assert.True(offenders.Count == 0,
            $"{offenders.Count} lines with a capitalised or ALL-CAPS US spelling (British: -our, centre, grey, cancelled, " +
            $"-ise, analyse, defence, acknowledgement, fulfil, travelled, labelled, modelled, neighbour, rumour, endeavour, " +
            $"litre, judgement; or add the line to {AllowlistPath} with a reason):\n" + string.Join('\n', offenders));
    }

    [Fact]
    public void CasedUsForm_MatchesProseNotCode()
    {
        // (Built from parts, so this file holds no US word itself.)
        Assert.Matches(CasedUsForm, "Serial" + "izes the config");
        Assert.Matches(CasedUsForm, "✓ INITIAL" + "IZATION COMPLETE");
        Assert.Matches(CasedUsForm, "### Code Organ" + "ization");
        Assert.Matches(CasedUsForm, "Hon" + "ored here");
        Assert.Matches(CasedUsForm, "NEIGHB" + "OR");
        Assert.DoesNotMatch(CasedUsForm, "JsonSerializer." + "Serial" + "ize(x)");
        Assert.DoesNotMatch(CasedUsForm, "System.Text.Json." + "Serial" + "ization;");
        Assert.DoesNotMatch(CasedUsForm, "Normal" + "ize(record)");
        Assert.DoesNotMatch(CasedUsForm, "Deserial" + "ize<T>");
        Assert.DoesNotMatch(CasedUsForm, "Author" + "ization: Bearer x");
        Assert.DoesNotMatch(CasedUsForm, "Proxy-Author" + "ization");
        Assert.DoesNotMatch(CasedUsForm, "AUTHORIZ" + "ATION");
        Assert.DoesNotMatch(CasedUsForm, "Serialises, Initialisation, INITIALISATION, Honoured");
        Assert.DoesNotMatch(CasedUsForm, "serial" + "izes");
    }

    [Fact]
    public void OtherUsForm_MatchesLowercaseWholeWordsOnly()
    {
        // (Built from parts, so this file holds no US word itself.)
        Assert.Matches(OtherUsForm, "a " + "behavi" + "or change");
        Assert.Matches(OtherUsForm, "it was " + "normal" + "ized");
        Assert.Matches(OtherUsForm, "the " + "gr" + "ay key");
        Assert.Matches(OtherUsForm, "hon" + "ored");
        Assert.Matches(OtherUsForm, "neighb" + "or");
        Assert.Matches(OtherUsForm, "rum" + "or");
        Assert.Matches(OtherUsForm, "endeav" + "or");
        Assert.Matches(OtherUsForm, "lit" + "ers");
        Assert.Matches(OtherUsForm, "defen" + "ses");
        Assert.Matches(OtherUsForm, "judg" + "ment");
        Assert.Matches(OtherUsForm, "col" + "oring");
        Assert.Matches(OtherUsForm, "cent" + "ering");
        Assert.DoesNotMatch(OtherUsForm, "Json" + "Serial" + "izer");
        Assert.DoesNotMatch(OtherUsForm, "Operation" + "Cancel" + "edException");
        Assert.DoesNotMatch(OtherUsForm, "Console" + "Col" + "or");
        Assert.DoesNotMatch(OtherUsForm, "Behavi" + "or starts a sentence");
        Assert.DoesNotMatch(OtherUsForm, "the size, not a " + "size" + "d prize");
        Assert.DoesNotMatch(OtherUsForm, "cancelled, normalised, behaviour, colour, centre, grey, analysed");
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
