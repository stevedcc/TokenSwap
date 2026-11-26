using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using TswapTests.Docs;
using Xunit;

namespace TswapTests.Build;

/// <summary>
/// Brief T57 (#420): every NuGet package is pinned by version and content hash. Each project has a
/// <c>packages.lock.json</c>; <c>Directory.Build.props</c> turns the lock files on, locks every restore on CI
/// (<c>CI=true</c>) and lists the runtime identifiers release.yml ships, so the lock files hold a section for each;
/// <c>global.json</c> names the exact SDK (its ILCompiler packages are in the lock files); and no workflow caches the
/// packages folder, points restore at another one, or unlocks restore, since a pre-extracted package is trusted through
/// its stored hash and a cache would defeat the check. File reads only: the file list is
/// <see cref="MarkdownLinks.AllTracked"/> (its <c>git ls-files</c> is the only process these tests start), no network.
/// The workflow scan is plain text, so some spellings remain a residual risk: shell quoting
/// (<c>Restore''LockedMode</c>), quoted YAML keys (<c>"HOME": x</c>), and PowerShell forms it has no row for (it has
/// rows for <c>Remove-Item env:CI</c>, its aliases and <c>SetEnvironmentVariable('CI', …)</c>).
/// </summary>
public partial class DependencyPinningTests
{
    private static readonly string Root = MarkdownLinks.RepoRoot();
    private static readonly IReadOnlyList<string> Files = MarkdownLinks.AllTracked();

    private const string PropsPath = "Directory.Build.props";
    private const string ReleaseWorkflowPath = ".github/workflows/release.yml";

    private const string RegenerateHint =
        "Regenerate the lock files on Linux x64 with the SDK global.json names: delete every obj/ folder, run "
        + "`dotnet restore TokenSwap.slnx --force-evaluate` and commit the changed packages.lock.json files with the "
        + "project or props change (AGENTS.md, \"Building and Running\").";

    private static string Read(string repoRelativePath) => MarkdownLinks.ReadText(Path.Combine(Root, repoRelativePath));

    private static IEnumerable<string> Projects() => Files.Where(f => f.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase));

    private static string LockFileOf(string project) =>
        (Path.GetDirectoryName(project) is { Length: > 0 } dir ? dir.Replace('\\', '/') + "/" : "") + "packages.lock.json";

    // ---- 1 ----

    [Fact]
    public void EveryProject_HasALockFile()
    {
        var projects = Projects().ToList();
        Assert.NotEmpty(projects);
        var missing = projects.Where(p => !Files.Contains(LockFileOf(p), StringComparer.Ordinal)).ToList();
        Assert.True(missing.Count == 0,
            $"These projects have no packages.lock.json beside them: {string.Join(", ", missing)}. Every project "
            + "restores with a lock file (RestorePackagesWithLockFile in Directory.Build.props). " + RegenerateHint);
    }

    // ---- 2 ----

    /// <summary>The only properties <c>Directory.Build.props</c> may set: one each, in one PropertyGroup.</summary>
    private static readonly string[] PropsProperties = ["RestorePackagesWithLockFile", "RestoreLockedMode", "RuntimeIdentifiers"];

    /// <summary>Properties no project file may set: they move, unlock or bypass the lock files or the packages folder.</summary>
    private static readonly string[] ProjectForbidden =
    [
        "RestoreLockedMode", "RestorePackagesWithLockFile", "RestoreForceEvaluate", "RuntimeIdentifiers",
        "NuGetLockFilePath", "RestorePackagesPath", "RestoreFallbackFolders",
    ];

    /// <summary>A condition as MSBuild reads it: no whitespace, either quote, any case.</summary>
    internal static string NormaliseCondition(string condition) =>
        new string(condition.Where(c => !char.IsWhiteSpace(c)).ToArray()).Replace('"', '\'').ToLowerInvariant();

    private static XElement PropsPropertyGroup()
    {
        Assert.True(Files.Contains(PropsPath, StringComparer.Ordinal),
            $"{PropsPath} is missing at the repository root: it turns the lock files on for every project (brief T57).");
        var project = XDocument.Parse(Read(PropsPath)).Root!;
        Assert.Equal("Project", project.Name.LocalName);
        var children = project.Elements().ToList();
        Assert.True(children.Count == 1 && children[0].Name.LocalName == "PropertyGroup" && !children[0].HasAttributes,
            $"{PropsPath} holds exactly one PropertyGroup without a condition and nothing else (no item, Import or target); "
            + $"found: {string.Join(", ", children.Select(c => c.Name.LocalName))}. Put any other setting in the project file it belongs to.");
        return children[0];
    }

    [Fact]
    public void DirectoryBuildProps_LocksRestoreOnCi()
    {
        var group = PropsPropertyGroup();
        var properties = group.Elements().ToList();
        var names = properties.Select(p => p.Name.LocalName).ToList();
        Assert.True(names.Order(StringComparer.Ordinal).SequenceEqual(PropsProperties.Order(StringComparer.Ordinal)),
            $"{PropsPath} sets exactly {string.Join(", ", PropsProperties)}, each once; found: {string.Join(", ", names)}. "
            + "Any other property belongs in the project file that needs it.");

        var withLockFile = properties.Single(p => p.Name.LocalName == "RestorePackagesWithLockFile");
        Assert.True(withLockFile.Attribute("Condition") is null && withLockFile.Value.Trim() == "true",
            $"{PropsPath}: RestorePackagesWithLockFile must be `true`, without a condition, so every restore writes and reads packages.lock.json.");

        var lockedMode = properties.Single(p => p.Name.LocalName == "RestoreLockedMode");
        var condition = (string?)lockedMode.Attribute("Condition");
        Assert.True(lockedMode.Value.Trim() == "true" && condition is not null
                    && NormaliseCondition(condition) == NormaliseCondition("'$(CI)' == 'true'"),
            $"{PropsPath}: RestoreLockedMode must be `true` under exactly the condition '$(CI)' == 'true' (found value "
            + $"'{lockedMode.Value.Trim()}', condition '{condition}'): every CI restore is locked, a local one may update the lock files.");

        var rids = properties.Single(p => p.Name.LocalName == "RuntimeIdentifiers");
        Assert.True(rids.Attribute("Condition") is null,
            $"{PropsPath}: RuntimeIdentifiers takes no condition; every host must resolve the same runtime sections.");

        var otherBuildFiles = Files.Where(f => f != PropsPath
            && (f.EndsWith(".props", StringComparison.OrdinalIgnoreCase)
                || f.EndsWith(".targets", StringComparison.OrdinalIgnoreCase)
                || f.EndsWith(".rsp", StringComparison.OrdinalIgnoreCase))).ToList();
        Assert.True(otherBuildFiles.Count == 0,
            $"Only the root {PropsPath} may be an MSBuild props, targets or response file (MSBuild reads Directory.Build.* "
            + $"and Directory.Build.rsp on its own, and a project can import any .props); found: {string.Join(", ", otherBuildFiles)}. "
            + "Put the setting in the project file or in the root props file.");

        var nugetConfigs = Files.Where(f => f.Split('/')[^1].Equals("nuget.config", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.True(nugetConfigs.Count == 0,
            $"No nuget.config may be in the repository (it can move the packages folder or add fallback folders, whose "
            + $"packages restore trusts by their stored hash); found: {string.Join(", ", nugetConfigs)}.");

        foreach (var project in Projects())
        {
            var text = Read(project);
            var hits = ProjectForbidden.Where(name => Regex.IsMatch(text, $@"\b{name}\b", RegexOptions.IgnoreCase)).ToList();
            Assert.True(hits.Count == 0,
                $"{project} mentions {string.Join(", ", hits)}: restore and lock-file settings live in {PropsPath} only, "
                + "so no project can unlock, move or bypass its lock file.");
        }
    }

    // ---- 3 ----

    private static List<string> ListedRuntimes()
    {
        var rids = PropsPropertyGroup().Elements().Single(p => p.Name.LocalName == "RuntimeIdentifiers").Value;
        return rids.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }

    [GeneratedRegex(@"^\s*(?:-\s*)?rid:\s*['""]?(?<rid>[a-z0-9]+(?:-[a-z0-9]+)+)['""]?\s*(?:#.*)?$")]
    private static partial Regex MatrixRid();

    [GeneratedRegex(@"(?<![\w-])(?:--runtime(?:\s+|=)|-r\s+)['""]?(?<rid>[a-z0-9]+(?:-[a-z0-9]+)+)(?![\w-])")]
    private static partial Regex RuntimeArgument();

    /// <summary>The RIDs a workflow publishes: the <c>build</c> job's matrix <c>rid:</c> values plus every RID-shaped <c>--runtime</c> / <c>-r</c> argument.</summary>
    internal static SortedSet<string> PublishedRuntimes(string workflow)
    {
        var rids = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var line in JobLines(workflow, "build"))
        {
            var m = MatrixRid().Match(line);
            if (m.Success) rids.Add(m.Groups["rid"].Value);
        }
        foreach (Match m in RuntimeArgument().Matches(workflow)) rids.Add(m.Groups["rid"].Value);
        return rids;
    }

    [Fact]
    public void PublishedRuntimes_ReadsTheBuildMatrixAndRuntimeArguments()
    {
        const string sample = """
            jobs:
              test:
                strategy:
                  matrix:
                    include:
                      - rid: osx-x64
              build:
                strategy:
                  matrix:
                    include:
                      - rid: linux-x64
                        os: ubuntu-24.04
                steps:
                  - run: dotnet publish TswapCli/TswapCli.csproj --runtime ${{ matrix.rid }}
                  - run: dotnet publish TswapCli/TswapCli.csproj --runtime osx-arm64
                  - run: dotnet restore TswapCli/TswapCli.csproj -r win-x64
                  - run: while IFS= read -r file; do echo "$file"; done
            """;
        Assert.Equal(["linux-x64", "osx-arm64", "win-x64"], PublishedRuntimes(sample));
    }

    [Fact]
    public void RuntimeIdentifiers_CoverEveryReleasedRuntime()
    {
        var listed = ListedRuntimes();
        var published = PublishedRuntimes(Read(ReleaseWorkflowPath));
        Assert.NotEmpty(published);
        Assert.True(new SortedSet<string>(listed, StringComparer.Ordinal).SetEquals(published),
            $"RuntimeIdentifiers in {PropsPath} ({string.Join(";", listed)}) must be the runtimes {ReleaseWorkflowPath} publishes "
            + $"({string.Join(";", published)}): a runtime the lock files don't cover fails the locked restore of its release leg. "
            + "Change both files together, then: " + RegenerateHint);
        var ordinal = listed.Order(StringComparer.Ordinal).ToList();
        Assert.True(listed.SequenceEqual(ordinal) && listed.Distinct().Count() == listed.Count,
            $"RuntimeIdentifiers in {PropsPath} must be in ordinal order without repeats ({string.Join(";", ordinal)}), so the "
            + "props file and the lock files stay stable against regeneration and review churn.");
    }

    // ---- 4 ----

    [Fact]
    public void LockFiles_RecordExactlyTheListedRuntimes()
    {
        var listed = ListedRuntimes();
        foreach (var project in Projects())
        {
            var lockFile = LockFileOf(project);
            if (!Files.Contains(lockFile, StringComparer.Ordinal)) continue; // EveryProject_HasALockFile says so
            var tfm = XDocument.Parse(Read(project)).Descendants().Single(e => e.Name.LocalName == "TargetFramework").Value.Trim();
            var expected = new SortedSet<string>(listed.Select(rid => $"{tfm}/{rid}").Append(tfm), StringComparer.Ordinal);

            using var json = JsonDocument.Parse(Read(lockFile));
            var sections = new SortedSet<string>(
                json.RootElement.GetProperty("dependencies").EnumerateObject().Select(p => p.Name), StringComparer.Ordinal);
            Assert.True(sections.SetEquals(expected),
                $"{lockFile} has the sections {string.Join(", ", sections)}, expected {string.Join(", ", expected)} "
                + $"(the target framework plus one per RuntimeIdentifiers entry in {PropsPath}). An extra section means the "
                + "restore ran on a host that isn't listed: discard that change. " + RegenerateHint);
        }
    }

    // ---- 5 ----

    [GeneratedRegex(@"^11\.0\.1\d\d$")]
    private static partial Regex SdkBand();

    [Fact]
    public void GlobalJson_PinsTheExactSdk()
    {
        using var json = JsonDocument.Parse(Read("global.json"),
            new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        var sdk = json.RootElement.GetProperty("sdk");
        var rollForward = sdk.TryGetProperty("rollForward", out var rf) ? rf.GetString() : null;
        Assert.True(rollForward == "disable",
            $"global.json: sdk.rollForward must be \"disable\" (found \"{rollForward}\"): the lock files record the SDK's own "
            + "ILCompiler and ILLink packages, so a newer SDK patch would rewrite them locally and fail CI's locked restore.");
        var version = sdk.GetProperty("version").GetString();
        Assert.True(version is not null && SdkBand().IsMatch(version),
            $"global.json: sdk.version must be an exact 11.0.1xx SDK (pattern {SdkBand()}; found \"{version}\"). The pattern "
            + "encodes the 11.0.1xx band, as Renovate's global.json patch automerge rule does: a band move updates both.");
    }

    // ---- 6 ----

    /// <summary>One forbidden form under <c>.github/</c>: a name, a finder over a whole file, a sample it must hit and one it must not.</summary>
    public sealed record ForbiddenForm(string Name, string Why, Func<string, IEnumerable<int>> Find, string Hit, string? Miss)
    {
        public override string ToString() => Name;
    }

    /// <summary>1-based numbers of the lines matching <paramref name="pattern"/>.</summary>
    private static IEnumerable<int> LinesMatching(string text, Regex pattern) =>
        text.Split('\n').Select((line, i) => (line, i)).Where(x => pattern.IsMatch(x.line)).Select(x => x.i + 1);

    /// <summary>An assignment of <paramref name="name"/> (a YAML key, <c>NAME=</c>, <c>-p:NAME=</c>, <c>/p:NAME=</c>) to anything but <c>true</c>.</summary>
    private static IEnumerable<int> AssignedOtherThanTrue(string text, string name)
    {
        var assignment = new Regex($@"(?<![\w.-]){Regex.Escape(name)}\s*(?:=|:(?!:))\s*(?<v>'[^']*'|""[^""]*""|[^\s;,}}#]*)", RegexOptions.IgnoreCase);
        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            foreach (Match m in assignment.Matches(lines[i]))
            {
                var value = m.Groups["v"].Value.Trim('\'', '"').Trim();
                if (!value.Equals("true", StringComparison.OrdinalIgnoreCase)) { yield return i + 1; break; }
            }
        }
    }

    /// <summary>Any assignment of <paramref name="name"/> (a YAML key or <c>NAME=</c> in a command), whatever the value.</summary>
    private static IEnumerable<int> Assigned(string text, string name) =>
        LinesMatching(text, new Regex($@"(?<![\w.$-]){Regex.Escape(name)}\s*(?:=|:(?!:))", RegexOptions.IgnoreCase));

    [GeneratedRegex(@"(?<![\w-])(?:unset\b[^;|&\n]*?(?<![\w-])CI|env\b[^;|&\n]*?(?:-u\s*|--unset[=\s]\s*)CI)(?![\w-])", RegexOptions.IgnoreCase)]
    private static partial Regex CiRemoval();

    [GeneratedRegex(@"(?<![\w-])(?:(?:Remove-Item|ri|rm|del|erase|rmdir|rd)\b[^;|&\n]*?(?<![\w-])['""]?env:\\?CI|SetEnvironmentVariable\s*\(\s*(?:name\s*:\s*)?['""]CI['""])(?![\w-])", RegexOptions.IgnoreCase)]
    private static partial Regex CiRemovalPowerShell();

    /// <summary>PowerShell lines that remove <c>CI</c>: <c>Remove-Item env:CI</c> (or an alias), <c>[Environment]::SetEnvironmentVariable('CI', …)</c>.</summary>
    private static IEnumerable<int> RemovesCiPowerShell(string text) => LinesMatching(text, CiRemovalPowerShell());

    /// <summary>Lines that remove <c>CI</c> from the environment: <c>unset … CI</c>, <c>env -u CI</c>, <c>env --unset=CI</c>.</summary>
    private static IEnumerable<int> RemovesCi(string text) => LinesMatching(text, CiRemoval());

    private const string HomeWhy =
        "HOME, USERPROFILE, APPDATA and LOCALAPPDATA decide where NuGet's user-level config, caches and packages folder "
        + "are, so moving them can point restore at a pre-extracted folder whose packages it trusts by their stored hash";

    private const string CliHomeWhy =
        "DOTNET_CLI_HOME moves the .NET CLI's profile root; forbidden fail closed, since no workflow needs it";

    private const string XdgWhy =
        "XDG_CONFIG_HOME, XDG_DATA_HOME and XDG_CACHE_HOME move the per-user config, data and cache folders on Linux and "
        + "macOS, where NuGet keeps its caches; forbidden fail closed, since no workflow needs them";

    private static IEnumerable<int> Token(string text, string token) =>
        LinesMatching(text, new Regex($@"(?<![\w-]){Regex.Escape(token)}(?![\w-])", RegexOptions.IgnoreCase));

    [GeneratedRegex(@"^(?<indent>\s*)-\s")]
    private static partial Regex SequenceItem();

    [GeneratedRegex(@"^\s*cache[\w-]*\s*:")]
    private static partial Regex CacheKey();

    /// <summary>Lines of a YAML sequence item (a step) that uses <c>actions/setup-dotnet</c> and sets a <c>cache</c> key.</summary>
    private static IEnumerable<int> SetupDotnetCache(string text)
    {
        var lines = text.Split('\n');
        for (var start = 0; start < lines.Length; start++)
        {
            var item = SequenceItem().Match(lines[start]);
            if (!item.Success) continue;
            var indent = item.Groups["indent"].Length;
            var end = start + 1;
            while (end < lines.Length && (lines[end].Trim().Length == 0 || lines[end].Length - lines[end].TrimStart().Length > indent)) end++;
            var step = lines[start..end];
            if (!step.Any(l => l.Contains("actions/setup-dotnet", StringComparison.OrdinalIgnoreCase))) continue;
            for (var i = 0; i < step.Length; i++)
            {
                var keyText = i == 0 ? step[0][(item.Length)..] : step[i];
                if (CacheKey().IsMatch(keyText)) yield return start + i + 1;
            }
        }
    }

    [GeneratedRegex(@"^(?<key>[A-Za-z0-9_-]+):")]
    private static partial Regex TopLevelKey();

    [GeneratedRegex(@"^  (?<key>[A-Za-z0-9_-]+):")]
    private static partial Regex JobKey();

    /// <summary>
    /// For each line, the job it belongs to: between a job's key (two spaces under <c>jobs:</c>) and the next key at
    /// that indentation (or the next top-level key); null outside every job.
    /// </summary>
    internal static string?[] JobOfEachLine(string workflow)
    {
        var lines = workflow.Split('\n');
        var jobs = new string?[lines.Length];
        var inJobs = false;
        string? job = null;
        for (var i = 0; i < lines.Length; i++)
        {
            var top = TopLevelKey().Match(lines[i]);
            if (top.Success) { inJobs = top.Groups["key"].Value == "jobs"; job = null; }
            else if (inJobs && JobKey().Match(lines[i]) is { Success: true } jobKey) job = jobKey.Groups["key"].Value;
            jobs[i] = job;
        }
        return jobs;
    }

    private static IEnumerable<string> JobLines(string workflow, string job)
    {
        var lines = workflow.Split('\n');
        var jobs = JobOfEachLine(workflow);
        return lines.Where((_, i) => jobs[i] == job);
    }

    private static IEnumerable<int> ForceEvaluateOutsideLockFilesJob(string text)
    {
        var jobs = JobOfEachLine(text);
        return Token(text, "--force-evaluate").Where(line => jobs[line - 1] != "lock-files");
    }

    private const string PackagesFolderWhy =
        "restore trusts a package already in a packages folder through its stored hash, so pointing restore at another "
        + "folder, a fallback folder or a cache defeats the content-hash check";

    public static readonly IReadOnlyList<ForbiddenForm> ForbiddenForms =
    [
        new("actions/cache", "neither workflow caches anything; a cached packages folder or obj/ defeats the hash check",
            t => Token(t, "actions/cache"), "      - uses: actions/cache@v4", "      - uses: actions/cachet@v1"),
        new("setup-dotnet cache:", "setup-dotnet's cache restores the packages folder from an earlier run",
            SetupDotnetCache,
            "      - uses: actions/setup-dotnet@v4\n        with:\n          global-json-file: global.json\n          cache: true\n",
            "      - uses: actions/setup-dotnet@v4\n        with:\n          global-json-file: global.json\n      - uses: actions/setup-node@v4\n        with:\n          cache: npm\n"),
        new("RestoreForceEvaluate", "a forced re-resolve rewrites the lock files instead of checking them",
            t => Token(t, "RestoreForceEvaluate"), "run: dotnet restore -p:RestoreForceEvaluate=true", "run: dotnet restore -p:NoRestoreForceEvaluate=1"),
        new("--locked-mode", "locked mode comes from Directory.Build.props on CI; a workflow managing it by hand is a smell",
            t => Token(t, "--locked-mode"), "run: dotnet restore --locked-mode", "run: tool --locked-modes; cargo install --locked --git https://example.invalid/x"),
        new("NuGetLockFilePath", "the lock file lives beside its project, where the guard tests read it",
            t => Token(t, "NuGetLockFilePath"), "run: dotnet restore -p:NuGetLockFilePath=other.json", "run: echo NuGetLockFilePaths"),
        new("--lock-file-path", "the lock file lives beside its project, where the guard tests read it",
            t => Token(t, "--lock-file-path"), "run: dotnet restore --lock-file-path other.json", "run: tool --lock-file-paths"),
        new("NUGET_PACKAGES", PackagesFolderWhy, t => Token(t, "NUGET_PACKAGES"), "  NUGET_PACKAGES: /tmp/pkgs", "  NUGET_PACKAGES_X: 1"),
        new("NUGET_FALLBACK_PACKAGES", PackagesFolderWhy, t => Token(t, "NUGET_FALLBACK_PACKAGES"), "  NUGET_FALLBACK_PACKAGES: /opt/pkgs", "  NUGET_FALLBACK_PACKAGES_X: 1"),
        new(".nuget/packages", PackagesFolderWhy, t => Token(t, ".nuget/packages"), "          path: ~/.nuget/packages", "          path: docs/x.nuget/packages-list.txt"),
        new("http-cache", PackagesFolderWhy, t => Token(t, "http-cache"), "run: dotnet nuget locals http-cache --list", "run: dotnet restore --no-http-cache"),
        new("v3-cache", PackagesFolderWhy, t => Token(t, "v3-cache"), "          path: ~/.local/share/NuGet/v3-cache", "          path: v3-cached"),
        new("--packages", PackagesFolderWhy, t => Token(t, "--packages"), "run: dotnet restore --packages ./pkgs", "run: tool --packagesDirectory ./x"),
        new("RestorePackagesPath", PackagesFolderWhy, t => Token(t, "RestorePackagesPath"), "run: dotnet build -p:RestorePackagesPath=./pkgs", "run: echo MyRestorePackagesPath"),
        new("RestoreFallbackFolders", PackagesFolderWhy, t => Token(t, "RestoreFallbackFolders"), "run: dotnet build -p:RestoreFallbackFolders=/opt/pkgs", "run: dotnet build -p:RestoreFallbackFoldersExcludes=/opt/pkgs"),
        new("NUGET_HTTP_CACHE_PATH", PackagesFolderWhy, t => Token(t, "NUGET_HTTP_CACHE_PATH"), "  NUGET_HTTP_CACHE_PATH: /tmp/http", "  NUGET_HTTP_CACHE_PATH_X: 1"),
        new("globalPackagesFolder", PackagesFolderWhy, t => Token(t, "globalPackagesFolder"), "run: dotnet nuget config set globalPackagesFolder ./pkgs", "run: echo globalPackagesFolders"),
        new("--configfile", "a NuGet config file can move the packages folder or add fallback folders",
            t => Token(t, "--configfile"), "run: dotnet restore --configfile ./ci.nuget.config", "run: tool --configfiles"),
        new("--force-evaluate outside lock-files", "only the lock-files job re-resolves (and then diffs the lock files); anywhere else it rewrites them instead of checking",
            ForceEvaluateOutsideLockFilesJob,
            "jobs:\n  build-test-publish:\n    steps:\n      - run: dotnet build TokenSwap.slnx --force-evaluate\n",
            "jobs:\n  lock-files:\n    steps:\n      - run: dotnet restore TokenSwap.slnx --force-evaluate\n  build:\n    steps:\n      - run: tool --force-evaluated\n"),
        new("RestoreLockedMode not true", "every CI restore is locked (Directory.Build.props)",
            t => AssignedOtherThanTrue(t, "RestoreLockedMode"), "run: dotnet build -p:RestoreLockedMode=false", "run: dotnet build -p:RestoreLockedMode='true' -p:MyRestoreLockedMode=false"),
        new("RestorePackagesWithLockFile not true", "every restore writes and reads the lock files (Directory.Build.props)",
            t => AssignedOtherThanTrue(t, "RestorePackagesWithLockFile"), "run: dotnet build -p:RestorePackagesWithLockFile=false",
            "run: dotnet build -p:RestorePackagesWithLockFile=True -p:MyRestorePackagesWithLockFile=false"),
        new("RestorePackagesWithLockFile not true (YAML key)", "every restore writes and reads the lock files (Directory.Build.props)",
            t => AssignedOtherThanTrue(t, "RestorePackagesWithLockFile"), "        env:\n          RestorePackagesWithLockFile: false\n",
            "        env:\n          RestorePackagesWithLockFile: 'true'\n"),
        new("unset CI", "removing CI turns the locked restore off (Directory.Build.props locks it when CI is true)",
            RemovesCi, "run: unset FOO CI; dotnet restore TokenSwap.slnx", "run: unset CI_REQUIRE_BWRAP; echo CI\nrun: xunset CI"),
        new("env -u CI", "removing CI turns the locked restore off (Directory.Build.props locks it when CI is true)",
            RemovesCi, "run: env -u CI dotnet restore TokenSwap.slnx\nrun: env --unset=CI dotnet build",
            "run: env -u CI_REQUIRE_BWRAP dotnet test\nrun: env --unset=CI_REQUIRE_SE dotnet test\nrun: penv -u CI"),
        new("PowerShell removes CI", "removing CI turns the locked restore off (Directory.Build.props locks it when CI is true)",
            RemovesCiPowerShell,
            "run: Remove-Item -Force env:CI",
            "run: Remove-Item env:CI_REQUIRE_SE; xdel env:CI; Remove-Item ./CI\nrun: [Environment]::SetEnvironmentVariable('CI_X', $null)"),
        new("HOME assigned", HomeWhy, t => Assigned(t, "HOME"), "        env:\n          HOME: /opt/prefilled\nrun: HOME=/tmp dotnet restore",
            "run: echo \"$HOME/.config\"; TSWAP_HOME=/x; echo ${HOME}; cfg.HOME=x; tool --set-HOME=x\n          XDG_CONFIG_HOME_X: 1"),
        new("USERPROFILE assigned", HomeWhy, t => Assigned(t, "USERPROFILE"), "        env:\n          USERPROFILE: D:\\prefilled",
            "run: echo \"$env:USERPROFILE\"; MY_USERPROFILE=x"),
        new("APPDATA assigned", HomeWhy, t => Assigned(t, "APPDATA"), "run: APPDATA=/tmp/appdata dotnet restore",
            "run: echo $APPDATA; MYAPPDATA=x; APPDATA_DIR=x"),
        new("LOCALAPPDATA assigned", HomeWhy, t => Assigned(t, "LOCALAPPDATA"), "        env:\n          LOCALAPPDATA: D:\\prefilled",
            "run: echo $LOCALAPPDATA; MYLOCALAPPDATA=x; LOCALAPPDATA_X=1"),
        new("DOTNET_CLI_HOME assigned", CliHomeWhy, t => Assigned(t, "DOTNET_CLI_HOME"), "run: DOTNET_CLI_HOME=/tmp/clihome dotnet restore",
            "run: echo $DOTNET_CLI_HOME; MY_DOTNET_CLI_HOME=x; DOTNET_CLI_HOME_X=1"),
        new("XDG_CONFIG_HOME assigned", XdgWhy, t => Assigned(t, "XDG_CONFIG_HOME"), "        env:\n          XDG_CONFIG_HOME: /opt/prefilled",
            "run: echo $XDG_CONFIG_HOME; MY_XDG_CONFIG_HOME=x; XDG_CONFIG_HOME_X=1"),
        new("XDG_DATA_HOME assigned", XdgWhy, t => Assigned(t, "XDG_DATA_HOME"), "run: XDG_DATA_HOME=/tmp/data dotnet restore",
            "run: echo $XDG_DATA_HOME; MY_XDG_DATA_HOME=x; XDG_DATA_HOME_X=1"),
        new("XDG_CACHE_HOME assigned", XdgWhy, t => Assigned(t, "XDG_CACHE_HOME"), "        env:\n          XDG_CACHE_HOME: /opt/prefilled",
            "run: echo $XDG_CACHE_HOME; MY_XDG_CACHE_HOME=x; XDG_CACHE_HOME_X=1"),
        new("CI not true (YAML key)", "Directory.Build.props locks restore when CI is true; GitHub sets CI=true for every step",
            t => AssignedOtherThanTrue(t, "CI"), "        env:\n          CI: false\n", "          CI_REQUIRE_BWRAP: '1'\nname: CI\n          CI: True\n"),
        new("CI not true (-p:)", "Directory.Build.props locks restore when CI is true; GitHub sets CI=true for every step",
            t => AssignedOtherThanTrue(t, "CI"), "run: dotnet build -p:CI=false", "  # release.yml's bump-version job dispatches CI on its PR's branch\n  # ci.yml builds and packs\nrun: dotnet build /p:CI=true"),
        new("CI not true (command)", "Directory.Build.props locks restore when CI is true; GitHub sets CI=true for every step",
            t => AssignedOtherThanTrue(t, "CI"), "run: CI= dotnet restore TokenSwap.slnx", "run: CI=true dotnet restore TokenSwap.slnx"),
        new("CI not true (PowerShell)", "Directory.Build.props locks restore when CI is true; GitHub sets CI=true for every step",
            t => AssignedOtherThanTrue(t, "CI"), "run: $env:CI = $null", "run: $env:CI = 'true'; $env:CI_REQUIRE_SE = $null"),
    ];

    public static TheoryData<string> ForbiddenFormRows() => new(ForbiddenForms.Select(f => f.Name));

    [Theory]
    [MemberData(nameof(ForbiddenFormRows))]
    public void ForbiddenForm_IsFoundInItsSample_AndNotInItsNearMiss(string name)
    {
        var form = ForbiddenForms.Single(f => f.Name == name);
        Assert.True(form.Find(form.Hit).Any(), $"The '{form.Name}' scan finds nothing in its sample:\n{form.Hit}");
        if (form.Miss is not null)
            Assert.True(!form.Find(form.Miss).Any(), $"The '{form.Name}' scan hits its near miss:\n{form.Miss}");
    }

    /// <summary>Each PowerShell way of removing <c>CI</c> the scan knows, one line each (the row's sample shows one).</summary>
    [Theory]
    [InlineData("Remove-Item env:CI")]
    [InlineData("Remove-Item -Force env:CI")]
    [InlineData("Remove-Item -Path:env:CI")]
    [InlineData("Remove-Item -p env:CI")]
    [InlineData("Remove-Item -Path 'env:CI'")]
    [InlineData("Remove-Item -LiteralPath env:CI")]
    [InlineData("ri env:CI")]
    [InlineData("rm env:CI")]
    [InlineData("del Env:\\CI")]
    [InlineData("erase env:CI")]
    [InlineData("rmdir env:CI")]
    [InlineData("rd env:CI")]
    [InlineData("[Environment]::SetEnvironmentVariable('CI', $null)")]
    [InlineData("[Environment]::SetEnvironmentVariable(name: 'CI', $null)")]
    public void PowerShellCiRemoval_FindsEachForm(string line) =>
        Assert.True(RemovesCiPowerShell("run: " + line).Any(), $"The PowerShell CI-removal scan misses: {line}");

    [Fact]
    public void Workflows_NeverCacheOrUnlockNuGet()
    {
        var githubFiles = Files.Where(f => f.StartsWith(".github/", StringComparison.Ordinal)).ToList();
        Assert.Contains(".github/workflows/ci.yml", githubFiles);
        var hits = (from file in githubFiles
                    let text = Read(file)
                    from form in ForbiddenForms
                    from line in form.Find(text)
                    select $"{file}:{line}: {form.Name} ({form.Why})").ToList();
        Assert.True(hits.Count == 0,
            "Found forms under .github/ that cache, move or unlock NuGet restore (the scan is plain text: comments count too). "
            + "Remove them; the lock files are checked only by a locked restore into an empty packages folder:\n"
            + string.Join("\n", hits));
    }
}
