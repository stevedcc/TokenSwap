using System.Text.RegularExpressions;
using System.Xml.Linq;
using TswapTests.Docs;
using Xunit;

namespace TswapTests.Build;

/// <summary>
/// Brief T58 Task 5: trim and AOT warnings fail the Release publish. <c>TswapCli/TswapCli.csproj</c> sets
/// <c>TrimmerSingleWarn</c> false unconditionally (a package's warnings listed per member, not one IL2104) and
/// <c>IlcTreatWarningsAsErrors</c> true for Release only (the Debug publish has one known IL2026 in Yubico.YubiKey). No
/// project file and no workflow may undo either or silence the warnings another way. File reads only
/// (<see cref="MarkdownLinks.AllTracked"/>); each forbidden form has a positive row proving the scan finds it.
/// </summary>
public partial class AotWarningTests
{
    private static readonly string Root = MarkdownLinks.RepoRoot();
    private const string CliProject = "TswapCli/TswapCli.csproj";

    private static string Read(string path) => MarkdownLinks.ReadText(Path.Combine(Root, path));

    private static IEnumerable<string> ProjectFiles() =>
        MarkdownLinks.AllTracked().Where(f => f.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)
                                             || f.EndsWith(".props", StringComparison.OrdinalIgnoreCase)
                                             || f.EndsWith(".targets", StringComparison.OrdinalIgnoreCase));

    private static IEnumerable<string> WorkflowFiles() =>
        MarkdownLinks.AllTracked().Where(f => f.StartsWith(".github/workflows/", StringComparison.Ordinal));

    [Fact]
    public void TswapCli_SetsBothSettings_OneUnconditional_OneForReleaseOnly()
    {
        var project = XDocument.Parse(Read(CliProject)).Root!;
        var properties = project.Elements().Where(e => e.Name.LocalName == "PropertyGroup")
            .SelectMany(g => g.Elements().Select(p => (Group: g, Property: p))).ToList();

        var single = properties.Where(p => p.Property.Name.LocalName == "TrimmerSingleWarn").ToList();
        Assert.True(single.Count == 1 && single[0].Property.Value.Trim() == "false"
                    && single[0].Group.Attribute("Condition") is null && single[0].Property.Attribute("Condition") is null,
            $"{CliProject} sets <TrimmerSingleWarn>false</TrimmerSingleWarn> once, in a PropertyGroup without a condition.");

        var asErrors = properties.Where(p => p.Property.Name.LocalName == "IlcTreatWarningsAsErrors").ToList();
        Assert.True(asErrors.Count == 1 && asErrors[0].Property.Value.Trim() == "true" && asErrors[0].Property.Attribute("Condition") is null
                    && (string?)asErrors[0].Group.Attribute("Condition") is { } condition
                    && DependencyPinningTests.NormaliseCondition(condition) == DependencyPinningTests.NormaliseCondition("'$(Configuration)' == 'Release'"),
            $"{CliProject} sets <IlcTreatWarningsAsErrors>true</IlcTreatWarningsAsErrors> once, in a PropertyGroup with exactly " +
            "the condition '$(Configuration)' == 'Release'.");
    }

    // An MSBuild property element: <Name ...>value</Name>, names ignoring case as MSBuild reads them.
    [GeneratedRegex(@"<\s*IlcTreatWarningsAsErrors\b[^>]*>\s*false\s*<", RegexOptions.IgnoreCase)]
    private static partial Regex ProjectIlcFalse();

    [GeneratedRegex(@"<\s*TrimmerSingleWarn\b[^>]*>\s*true\s*<", RegexOptions.IgnoreCase)]
    private static partial Regex ProjectSingleWarnTrue();

    [GeneratedRegex(@"<\s*SuppressTrimAnalysisWarnings\b[^>]*>\s*true\s*<", RegexOptions.IgnoreCase)]
    private static partial Regex ProjectSuppressTrim();

    [GeneratedRegex(@"<\s*SuppressAotAnalysisWarnings\b[^>]*>\s*true\s*<", RegexOptions.IgnoreCase)]
    private static partial Regex ProjectSuppressAot();

    [GeneratedRegex(@"<\s*(?:NoWarn|WarningsNotAsErrors)\b[^>]*>[^<]*\bIL[23]\d{3}", RegexOptions.IgnoreCase)]
    private static partial Regex ProjectNoWarnIl();

    // A property passed to dotnet/msbuild in a workflow: -p:, /p:, --property:, -property: (several joined by ';').
    private const string PropertySwitch = @"(?:-p:|/p:|--property:|-property:)[^\s]*?";

    [GeneratedRegex(PropertySwitch + @"\bIlcTreatWarningsAsErrors\s*=\s*[""']?false", RegexOptions.IgnoreCase)]
    private static partial Regex WorkflowIlcFalse();

    [GeneratedRegex(PropertySwitch + @"\bTrimmerSingleWarn\s*=\s*[""']?true", RegexOptions.IgnoreCase)]
    private static partial Regex WorkflowSingleWarnTrue();

    [GeneratedRegex(PropertySwitch + @"\bSuppressTrimAnalysisWarnings\s*=\s*[""']?true", RegexOptions.IgnoreCase)]
    private static partial Regex WorkflowSuppressTrim();

    [GeneratedRegex(PropertySwitch + @"\bSuppressAotAnalysisWarnings\s*=\s*[""']?true", RegexOptions.IgnoreCase)]
    private static partial Regex WorkflowSuppressAot();

    [GeneratedRegex(PropertySwitch + @"\b(?:NoWarn|WarningsNotAsErrors)\s*=[^\s]*IL[23]\d{3}", RegexOptions.IgnoreCase)]
    private static partial Regex WorkflowNoWarnIl();

    // MSBuild also reads environment variables as properties: an env: entry in a workflow.
    [GeneratedRegex(@"^\s*(?:IlcTreatWarningsAsErrors\s*:\s*[""']?false|(?:TrimmerSingleWarn|SuppressTrimAnalysisWarnings|SuppressAotAnalysisWarnings)\s*:\s*[""']?true|(?:NoWarn|WarningsNotAsErrors)\s*:.*\bIL[23]\d{3})",
        RegexOptions.IgnoreCase | RegexOptions.Multiline)]
    private static partial Regex WorkflowEnvironment();

    private static readonly (string Form, Regex Scan)[] ProjectForms =
    [
        ("IlcTreatWarningsAsErrors false", ProjectIlcFalse()), ("TrimmerSingleWarn true", ProjectSingleWarnTrue()),
        ("SuppressTrimAnalysisWarnings true", ProjectSuppressTrim()), ("SuppressAotAnalysisWarnings true", ProjectSuppressAot()),
        ("NoWarn/WarningsNotAsErrors with an IL2/IL3 code", ProjectNoWarnIl()),
    ];

    private static readonly (string Form, Regex Scan)[] WorkflowForms =
    [
        ("-p:IlcTreatWarningsAsErrors=false", WorkflowIlcFalse()), ("-p:TrimmerSingleWarn=true", WorkflowSingleWarnTrue()),
        ("-p:SuppressTrimAnalysisWarnings=true", WorkflowSuppressTrim()), ("-p:SuppressAotAnalysisWarnings=true", WorkflowSuppressAot()),
        ("-p:NoWarn/WarningsNotAsErrors with an IL2/IL3 code", WorkflowNoWarnIl()), ("an environment variable", WorkflowEnvironment()),
    ];

    [Fact]
    public void NoProjectFile_UndoesOrSilencesTrimAndAotWarnings()
    {
        var projects = ProjectFiles().ToList();
        Assert.Contains(CliProject, projects);
        var found = projects.SelectMany(p => ProjectForms.Where(f => f.Scan.IsMatch(Read(p))).Select(f => $"{p}: {f.Form}")).ToList();
        Assert.True(found.Count == 0, $"Trim and AOT warnings must stay visible and fail the Release publish (brief T58): {string.Join("; ", found)}");
    }

    [Fact]
    public void NoWorkflow_PassesASettingThatUndoesOrSilencesThem()
    {
        var workflows = WorkflowFiles().ToList();
        Assert.Contains(".github/workflows/release.yml", workflows);
        var found = workflows.SelectMany(w => WorkflowForms.Where(f => f.Scan.IsMatch(Read(w))).Select(f => $"{w}: {f.Form}")).ToList();
        Assert.True(found.Count == 0, $"No workflow may switch the trim and AOT warnings off (brief T58): {string.Join("; ", found)}");
    }

    [Theory]
    [InlineData(0, "<IlcTreatWarningsAsErrors>false</IlcTreatWarningsAsErrors>")]
    [InlineData(0, "<ilctreatwarningsaserrors Condition=\"'$(Configuration)' == 'Debug'\"> false </ilctreatwarningsaserrors>")]
    [InlineData(1, "<TrimmerSingleWarn>true</TrimmerSingleWarn>")]
    [InlineData(2, "<SuppressTrimAnalysisWarnings>true</SuppressTrimAnalysisWarnings>")]
    [InlineData(3, "<SuppressAotAnalysisWarnings>true</SuppressAotAnalysisWarnings>")]
    [InlineData(4, "<NoWarn>$(NoWarn);IL2026</NoWarn>")]
    [InlineData(4, "<WarningsNotAsErrors>CS1591;IL3050</WarningsNotAsErrors>")]
    public void ProjectScan_FindsEachForbiddenForm(int form, string sample) => Assert.Matches(ProjectForms[form].Scan, sample);

    [Theory]
    [InlineData("<IlcTreatWarningsAsErrors>true</IlcTreatWarningsAsErrors>")]
    [InlineData("<TrimmerSingleWarn>false</TrimmerSingleWarn>")]
    [InlineData("<NoWarn>$(NoWarn);CS1591</NoWarn>")]
    public void ProjectScan_LeavesTheAllowedSettingsAlone(string sample) => Assert.All(ProjectForms, f => Assert.DoesNotMatch(f.Scan, sample));

    [Theory]
    [InlineData(0, "dotnet publish TswapCli/TswapCli.csproj -c Release -p:IlcTreatWarningsAsErrors=false")]
    [InlineData(0, "dotnet publish x /p:Foo=1;IlcTreatWarningsAsErrors=false")]
    [InlineData(1, "dotnet publish x --property:TrimmerSingleWarn=true")]
    [InlineData(2, "dotnet publish x -p:SuppressTrimAnalysisWarnings=true")]
    [InlineData(3, "dotnet publish x -p:SuppressAotAnalysisWarnings=true")]
    [InlineData(4, "dotnet publish x -p:NoWarn=IL2104")]
    [InlineData(4, "dotnet publish x \"-p:WarningsNotAsErrors=IL3050\"")]
    [InlineData(5, "        env:\n          IlcTreatWarningsAsErrors: false")]
    [InlineData(5, "  NoWarn: 'IL2026'")]
    public void WorkflowScan_FindsEachForbiddenForm(int form, string sample) => Assert.Matches(WorkflowForms[form].Scan, sample);
}
