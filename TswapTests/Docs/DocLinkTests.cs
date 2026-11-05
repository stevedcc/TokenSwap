using Xunit;

namespace TswapTests.Docs;

/// <summary>
/// Guards for the docs restructure (#244): every relative link in the repo's Markdown resolves, every
/// anchor the docs used to have still resolves, and nothing links to a redirect.
/// </summary>
public class DocLinkTests
{
    private static readonly string Root = MarkdownLinks.RepoRoot();

    private static string Read(string repoRelative) => MarkdownLinks.ReadText(Path.Combine(Root, repoRelative));

    private static IReadOnlyList<string> AnchorsOf(string repoRelative) => MarkdownLinks.Anchors(Read(repoRelative));

    private static string[] ReadList(string name) =>
        MarkdownLinks.ReadText(Path.Combine(Root, "TswapTests", "Docs", name))
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static readonly string[] DesignFiles = ["MULTI_MACHINE_KEYING.md", "HARDWARE_BACKENDS.md"];

    [Fact]
    public void GuardFileSet_ExcludesScratch()
    {
        var all = MarkdownLinks.AllMarkdown();
        Assert.NotEmpty(all);
        Assert.DoesNotContain(all, p => p.StartsWith(".superpowers/") || p.Contains("/.superpowers/"));
        Assert.DoesNotContain(all, p => p.StartsWith(".worktrees/") || p.Contains("/.worktrees/"));
        Assert.DoesNotContain(all, p => Path.GetFileName(p).StartsWith("wip-", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(all, p => p.Split('/').Any(s => s is "bin" or "obj"));

        // The filter itself, on paths that may not exist on this machine.
        Assert.False(MarkdownLinks.IsNotScratch(".superpowers/sdd/x/task-1-brief.md"));
        Assert.False(MarkdownLinks.IsNotScratch(".worktrees/dr/README.md"));
        Assert.False(MarkdownLinks.IsNotScratch("docs/wip-notes.md"));
        Assert.True(MarkdownLinks.IsNotScratch("docs/BROKER.md"));
    }

    [Fact]
    public void NoSetextHeadings()
    {
        var offenders = new List<string>();
        foreach (var file in MarkdownLinks.CheckedMarkdown())
            foreach (var line in MarkdownLinks.SetextHeadingLines(Read(file)))
                offenders.Add($"{file}:{line}");
        Assert.True(offenders.Count == 0, "setext headings (use '#' headings):\n" + string.Join('\n', offenders));

        // The detector does fire on a real one.
        Assert.Equal([2], MarkdownLinks.SetextHeadingLines("Title\n=====\n\ntext\n\n---\n"));
        Assert.Equal([2], MarkdownLinks.SetextHeadingLines("Title\n-----\n"));
    }

    [Fact]
    public void Links_IgnoreInlineCode()
    {
        var md = "See `docs/x.md#y` and `[a](x)` and ``[b](y) with ` inside``.\n"
               + "A real [one](docs/real.md#frag) and ![img](pic.png) and <a href=\"h.md\">h</a>.\n"
               + "A [multi-line\nlink](two.md) and [ref] later.\n\n"
               + "```\n[fenced](nope.md)\n```\n\n"
               + "<!-- [comment](nope2.md) -->\n\n"
               + "[ref]: refdoc.md#r\n";
        Assert.Equal(
            [(2, "docs/real.md#frag"), (2, "pic.png"), (2, "h.md"), (4, "two.md"), (12, "refdoc.md#r")],
            MarkdownLinks.Links(md));
    }

    [Fact]
    public void Links_StrayBacktickDoesNotHideLaterParagraphs()
    {
        Assert.Equal([(3, "a.md")], MarkdownLinks.Links("A stray ` backtick.\n\nNext [real](a.md) and `code` here.\n"));
    }

    [Fact]
    public void Links_CodeSpanWrappingLinesInOneParagraphIsMasked()
    {
        Assert.Equal([(2, "ok.md")], MarkdownLinks.Links("text `wrapped\n[x](hidden.md)` end [ok](ok.md)\n"));
        Assert.DoesNotContain(MarkdownLinks.AnchorsDetailed("text `wrapped\n<a id=\"hidden\"></a>` end\n"), a => a.Kind == AnchorKind.Explicit);
    }

    [Fact]
    public void Links_FencesInBlockquotesAndListItemsAreCode()
    {
        var md = "> ```\n> [q](hidden1.md)\n> ```\n\n- ```\n  [l](hidden2.md)\n  ```\n\n[ok](ok.md)\n";
        Assert.Equal([(9, "ok.md")], MarkdownLinks.Links(md));
    }

    [Fact]
    public void Links_IndentedFenceMarkerIsIndentedCodeNotAFence()
    {
        Assert.Equal([(5, "real.md")], MarkdownLinks.Links("para\n\n    ```\n\n[real](real.md)\n\n    ```\n"));
    }

    [Fact]
    public void MovedSections_RunFromTheHeadingToTheNextHeadingOfTheSameOrHigherLevel()
    {
        var md = "# T\n\n## Moved sections\n\n<a id=\"old\"></a>\n\n### Sub\n\n<a id=\"sub-old\"></a>\n\n## Next\n\n<a id=\"after\"></a>\n";
        var anchors = MarkdownLinks.AnchorsDetailed(md);
        Assert.Equal(["t", "moved-sections", "old", "sub", "sub-old", "next", "after"], anchors.Select(a => a.Id));
        Assert.Equal([false, false, true, true, true, false, false], anchors.Select(a => a.InMovedSections));
    }

    [Fact]
    public void MovedSections_AreNeverCollapsed()
    {
        // Firefox doesn't open a closed <details> for a link into it: an old link landed on a
        // collapsed block at the foot of the README (owner check after PR #248).
        var collapsed = MarkdownLinks.CheckedMarkdown()
            .Where(f => System.Text.RegularExpressions.Regex.IsMatch(Read(f),
                @"<summary\b[^>]*>\s*Moved\s+sections", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            .ToList();
        Assert.True(collapsed.Count == 0, "Moved sections inside <details> in: " + string.Join(", ", collapsed));
    }

    [Fact]
    public void Links_SingleQuotedHrefIsRead()
    {
        Assert.Equal([(1, "s.md"), (1, "d.md")], MarkdownLinks.Links("<a href='s.md'>s</a> <a href=\"d.md\">d</a>\n"));
    }

    [Fact]
    public void Links_ImageInsideLinkTextAndImgSrcAreRead()
    {
        // The badge shape: the image's own target is a link too, and so is a raw <img src>.
        Assert.Equal([(1, "docs/setup.md"), (1, "img/badge.png"), (2, "img/raw.png")],
            MarkdownLinks.Links("[![badge](img/badge.png)](docs/setup.md)\n<img src=\"img/raw.png\" alt=\"x\">\n"));
    }

    [Theory]
    [InlineData("The _vault_ password", "the-vault-password")]
    [InlineData("__Strong__ and *em*", "strong-and-em")]
    [InlineData("TSWAP_CONFIG_DIR and snake_case", "tswap_config_dir-and-snake_case")]
    [InlineData("Using `_private_` names", "using-_private_-names")]
    [InlineData("_Emphasis around `code` here_", "emphasis-around-code-here")]
    [InlineData("Use ``_x_`` here", "use-_x_-here")]
    [InlineData("Threat Model & Non-Goals", "threat-model--non-goals")]
    [InlineData("Setting up: the guided `tswap init`", "setting-up-the-guided-tswap-init")]
    [InlineData("Install (compiled binary — recommended)", "install-compiled-binary--recommended")]
    [InlineData("Burn & rotate: a [link](x.md) <b>bold</b>", "burn--rotate-a-link-bold")]
    public void Slug_FollowsGitHubRules(string heading, string expected)
    {
        Assert.Equal([expected], MarkdownLinks.Anchors($"## {heading}\n"));
        Assert.Equal([expected], MarkdownLinks.Anchors($"## {heading} ##\n"));
    }

    [Fact]
    public void Slug_DuplicatesAndFencesAndClosingHashes()
    {
        Assert.Equal(["setup", "setup-1", "setup-2"], MarkdownLinks.Anchors("## Setup\n\n### Setup\n\n## Setup ##\n"));
        Assert.Equal(["real"], MarkdownLinks.Anchors("```bash\n# comment\n```\n~~~\n# also\n~~~\n    # indented code\n\n<!--\n# commented\n-->\n## Real\n"));
        Assert.Equal(["a"], MarkdownLinks.Anchors("# A\r\n"));
    }

    [Fact]
    public void ExplicitAnchors_AreRecordedWithMovedSectionsFlag()
    {
        var md = "# Title\n\n<a id=\"live\"></a>\n\n"
               + "<details><summary>Other</summary><a id=\"inside-other\"></a></details>\n\n`<a id=\"in-code\">`\n\n"
               + "## Moved sections\n\n<a id=\"old-one\"></a> <a name=\"old-two\"></a>\n";
        var anchors = MarkdownLinks.AnchorsDetailed(md);
        Assert.Equal(["title", "live", "inside-other", "moved-sections", "old-one", "old-two"], anchors.Select(a => a.Id));
        Assert.Equal([false, false, false, false, true, true], anchors.Select(a => a.InMovedSections));
        Assert.All(anchors.Where(a => a.Id is "live" or "inside-other" or "old-one" or "old-two"), a => Assert.Equal(AnchorKind.Explicit, a.Kind));
    }

    /// <summary>Broken links of the checked files as <c>file:line → target</c>.</summary>
    private static List<string> BrokenLinks()
    {
        var anchorCache = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        IReadOnlyList<string> AnchorsCached(string file) =>
            anchorCache.TryGetValue(file, out var a) ? a : anchorCache[file] = AnchorsOf(file);

        var broken = new List<string>();
        foreach (var file in MarkdownLinks.CheckedMarkdown())
        {
            foreach (var (line, target) in MarkdownLinks.Links(Read(file)))
            {
                if (MarkdownLinks.IsExternal(target)) continue;
                var hash = target.IndexOf('#');
                var pathPart = hash < 0 ? target : target[..hash];
                var anchor = hash < 0 ? null : Uri.UnescapeDataString(target[(hash + 1)..]);
                var query = pathPart.IndexOf('?');
                if (query >= 0) pathPart = pathPart[..query];

                string resolved;
                var isDirectory = false;
                if (pathPart.Length == 0) resolved = file;
                else
                {
                    var r = MarkdownLinks.ResolveExisting(Root, file, pathPart);
                    if (r == null) { broken.Add($"{file}:{line} → {target}"); continue; }
                    (resolved, isDirectory) = r.Value;
                }

                if (string.IsNullOrEmpty(anchor) || isDirectory || !resolved.EndsWith(".md", StringComparison.Ordinal)) continue;
                if (!AnchorsCached(resolved).Contains(anchor, StringComparer.Ordinal))
                    broken.Add($"{file}:{line} → {target} (no such anchor in {resolved})");
            }
        }
        return broken;
    }

    [Fact]
    public void EveryRelativeLinkResolves()
    {
        var broken = BrokenLinks();
        Assert.True(broken.Count == 0, "broken links:\n" + string.Join('\n', broken));
    }

    [Fact]
    public void OldReadmeAnchorsStillResolve()
    {
        // An emptied or truncated fixture would pass vacuously.
        foreach (var list in new[] { "old-readme-anchors.txt", "old-broker-anchors.txt", "old-design-anchors.txt" })
            Assert.NotEmpty(ReadList(list));
        Assert.All(ReadList("old-design-anchors.txt"), e => Assert.Contains(DesignFiles, f => e.StartsWith(f + "#", StringComparison.Ordinal)));
        foreach (var file in DesignFiles)
            Assert.Contains(ReadList("old-design-anchors.txt"), e => e.StartsWith(file + "#", StringComparison.Ordinal));
        AssertContainsAll("README.md", ReadList("old-readme-anchors.txt"), AnchorsOf("README.md"));
        AssertContainsAll("docs/BROKER.md", ReadList("old-broker-anchors.txt"), AnchorsOf("docs/BROKER.md"));
        foreach (var file in DesignFiles)
        {
            var wanted = ReadList("old-design-anchors.txt").Where(e => e.StartsWith(file + "#", StringComparison.Ordinal))
                .Select(e => e[(file.Length + 1)..]);
            AssertContainsAll(file, wanted, AnchorsOf(file));
        }
    }

    private static void AssertContainsAll(string file, IEnumerable<string> wanted, IReadOnlyList<string> actual)
    {
        var missing = wanted.Except(actual, StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0, $"{file} lost anchors:\n" + string.Join('\n', missing));
    }

    [Fact]
    public void NoInRepoLinkToRedirectAnchor()
    {
        var offenders = new List<string>();
        var cache = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        HashSet<string> RedirectOnly(string file)
        {
            if (cache.TryGetValue(file, out var set)) return set;
            var all = MarkdownLinks.AnchorsDetailed(Read(file));
            var live = all.Where(a => !a.InMovedSections).Select(a => a.Id).ToHashSet(StringComparer.Ordinal);
            return cache[file] = all.Where(a => a.InMovedSections && !live.Contains(a.Id))
                .Select(a => a.Id).ToHashSet(StringComparer.Ordinal);
        }

        foreach (var file in MarkdownLinks.CheckedMarkdown())
        {
            // Released release notes are never edited; landing on a redirect is what redirects are for.
            if (file.StartsWith("docs/release-notes/", StringComparison.Ordinal)) continue;
            foreach (var (line, target) in MarkdownLinks.Links(Read(file)))
            {
                if (MarkdownLinks.IsExternal(target)) continue;
                var hash = target.IndexOf('#');
                if (hash < 0) continue;
                var pathPart = target[..hash];
                var resolved = file;
                if (pathPart.Length > 0)
                {
                    var r = MarkdownLinks.ResolveExisting(Root, file, pathPart);
                    if (r == null || r.Value.IsDirectory || !r.Value.Path.EndsWith(".md", StringComparison.Ordinal)) continue;
                    resolved = r.Value.Path;
                }
                if (RedirectOnly(resolved).Contains(Uri.UnescapeDataString(target[(hash + 1)..]), StringComparer.Ordinal))
                    offenders.Add($"{file}:{line} → {target}");
            }
        }
        Assert.True(offenders.Count == 0, "links to redirect-only anchors (link the new home):\n" + string.Join('\n', offenders));
    }

    /// <summary>Explicit ids that equal a heading slug or another explicit id of the same file.</summary>
    internal static IReadOnlyList<string> DuplicateIds(string markdown)
    {
        var anchors = MarkdownLinks.AnchorsDetailed(markdown);
        var dups = new List<string>();
        foreach (var e in anchors.Where(a => a.Kind == AnchorKind.Explicit))
        {
            var others = anchors.Count(a => a.Id == e.Id);
            if (others > 1) dups.Add($"{e.Id} (line {e.Line})");
        }
        return dups;
    }

    [Fact]
    public void NoDuplicateIds()
    {
        var offenders = new List<string>();
        foreach (var file in MarkdownLinks.CheckedMarkdown())
            offenders.AddRange(DuplicateIds(Read(file)).Select(d => $"{file}: {d}"));
        Assert.True(offenders.Count == 0, "explicit ids that collide:\n" + string.Join('\n', offenders));

        // The check fires on both kinds of collision.
        Assert.NotEmpty(DuplicateIds("## Setup\n\n<a id=\"setup\"></a>\n"));
        Assert.NotEmpty(DuplicateIds("<a id=\"x\"></a>\n<a name=\"x\"></a>\n"));
        Assert.Empty(DuplicateIds("## Setup\n\n<a id=\"setup-old\"></a>\n"));
    }

    [Fact]
    public void ReadmeStaysShort()
    {
        // The redirect table under "## Moved sections" (the end of the file) doesn't count.
        var lines = Read("README.md").Split('\n');
        var moved = Array.FindIndex(lines, l => System.Text.RegularExpressions.Regex.IsMatch(l, @"^#{1,6}\s+Moved sections\s*$"));
        var counted = moved < 0 ? lines.Length : moved;
        Assert.True(counted <= 300, $"README.md has {counted} lines before its Moved sections (limit 300)");
    }

    [Fact]
    public void GuardFilesExist()
    {
        foreach (var f in new[] { "MULTI_MACHINE_KEYING.md", "HARDWARE_BACKENDS.md", "docs/BROKER.md" })
            Assert.True(File.Exists(Path.Combine(Root, f)), f + " is missing");

        var broker = MarkdownLinks.AnchorsDetailed(Read("docs/BROKER.md"));
        // The broker's log line names these headings; they are frozen, and must be live headings, not redirect ids.
        foreach (var id in new[] { "selinux", "redaction-confirms-whole-guesses" })
            Assert.True(broker.Any(a => a.Id == id && a.Kind == AnchorKind.Heading && !a.InMovedSections),
                $"docs/BROKER.md has no live heading '{id}'");
        // Old links to the two "Setup" headings (redirect rows after Task 4).
        foreach (var id in new[] { "setup", "setup-1" })
            Assert.Contains(broker, a => a.Id == id);
    }
}
