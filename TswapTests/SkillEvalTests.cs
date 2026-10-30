using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T7 item 7: the skill eval (<c>evals/skill/run.sh</c>) with its fake agent. Per scenario, the
/// fake's passing variant passes and every failing variant fails on exactly the rule it breaks; the
/// expectations are worked out here from the scenario's rules, independently of the Python generator.
/// And the isolation check aborts the run when a real tswap is reachable in the sandbox.
/// Linux only (bubblewrap); without <c>bwrap</c> the tests say so and return.
/// </summary>
public class SkillEvalTests(ITestOutputHelper output)
{
    private static readonly string RepoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
    private static readonly string EvalRoot = Path.Combine(RepoRoot, "evals", "skill");

    public static TheoryData<string> Scenarios()
    {
        var data = new TheoryData<string>();
        foreach (var file in Directory.GetFiles(Path.Combine(EvalRoot, "scenarios"), "*.json").Order())
            data.Add(Path.GetFileNameWithoutExtension(file));
        return data;
    }

    private bool CanRun()
    {
        if (!OperatingSystem.IsLinux())
            return false; // the eval is Linux-only (until #181: reported as Passed elsewhere)
        if (File.Exists("/usr/bin/bwrap") || File.Exists("/bin/bwrap"))
            return true;
        output.WriteLine("SKIPPED: bubblewrap (bwrap) is not installed, so the skill eval can't run here.");
        return false;
    }

    private static (int Exit, string Out) RunEval(IEnumerable<string> arguments, Action<ProcessStartInfo>? configure = null)
    {
        var psi = new ProcessStartInfo(Path.Combine(EvalRoot, "run.sh"))
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in arguments)
            psi.ArgumentList.Add(a);
        configure?.Invoke(psi);
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(TimeSpan.FromMinutes(5)), "run.sh did not finish");
        return (process.ExitCode, stdout.Result + stderr.Result);
    }

    /// <summary>The fake agent's variants and the rule ids each must break, from the scenario's rules.</summary>
    private static Dictionary<string, string[]> ExpectedVariants(string scenario)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(EvalRoot, "scenarios", scenario + ".json")));
        var rules = doc.RootElement.GetProperty("rules");
        var must = rules.GetProperty("must").EnumerateArray().ToList();
        var never = rules.TryGetProperty("never", out var n) ? n.EnumerateArray().ToList() : [];
        var says = rules.TryGetProperty("says", out var s) ? s.EnumerateArray().ToList() : [];
        var expected = new Dictionary<string, string[]>
        {
            ["pass"] = [],
            ["nothing"] = [.. must.Select((_, i) => $"must[{i}]"), .. says.Select((_, i) => $"says[{i}]")],
            ["direct-sudo"] = ["never[sudo]"],
            // Fix round 1: a record written to the log channel by anything but a shim.
            ["forge-log"] = ["forged_log"],
        };
        var covered = new List<string>();
        for (var i = 0; i < must.Count; i++)
        {
            covered.Add($"must[{i}]");
            if (must[i].TryGetProperty("example", out var example) && example.ValueKind == JsonValueKind.String)
            {
                expected[$"skip-must-{i}"] = [.. covered];
                covered.Clear();
            }
            if (must[i].TryGetProperty("first", out var first) && first.GetBoolean())
                expected[$"not-first-must-{i}"] = [$"must[{i}]"];
        }
        for (var i = 0; i < never.Count; i++)
            expected[$"never-{i}"] = [$"never[{i}]"];
        if (rules.TryGetProperty("no_marker_in_files", out _))
        {
            expected["leak-file"] = ["no_marker_in_files"];
            expected["leak-home"] = ["no_marker_in_files"]; // fix round 1: HOME and /eval/state are scanned too
            expected["leak-state"] = ["no_marker_in_files"];
        }
        for (var i = 0; i < says.Count; i++)
            expected[$"says-{i}"] = [$"says[{i}]"];
        return expected;
    }

    [Fact]
    public void ThereAreAtLeastEightScenarios_EachWithAMustRule()
    {
        var scenarios = Directory.GetFiles(Path.Combine(EvalRoot, "scenarios"), "*.json").Select(Path.GetFileNameWithoutExtension).ToList();

        Assert.True(scenarios.Count >= 8, string.Join(", ", scenarios));
        foreach (var scenario in scenarios)
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(EvalRoot, "scenarios", scenario + ".json")));
            Assert.True(doc.RootElement.GetProperty("rules").GetProperty("must").GetArrayLength() > 0, scenario);
        }
    }

    [Theory]
    [MemberData(nameof(Scenarios))]
    public void FakeAgent_PassVariantPasses_EveryOtherVariantFailsOnTheRuleItBreaks(string scenario)
    {
        if (!CanRun())
            return;
        var expected = ExpectedVariants(scenario);

        var (exit, stdout) = RunEval(["--agent", "fake", "--skill", "off", "--scenario", scenario, "--fake-variant", "all"]);

        output.WriteLine(stdout);
        Assert.True(exit is 0 or 1, $"run.sh exit {exit}:\n{stdout}");
        var lines = stdout.Split('\n').Where(l => l.StartsWith("PASS ") || l.StartsWith("FAIL ")).ToList();
        var seen = new Dictionary<string, (string Status, string[] Broken)>();
        foreach (var line in lines)
        {
            var label = line.Split(' ')[1].TrimEnd(':');
            var variant = label[(label.IndexOf('/') + 1)..];
            var broken = Regex.Match(line, @"\[broken: ((?:[a-z_]+(?:\[\w+\])?)(?:,[a-z_]+(?:\[\w+\])?)*)\]") is { Success: true } m ? m.Groups[1].Value.Split(',') : [];
            seen[variant] = (line[..4], broken);
        }
        Assert.Equal(expected.Keys.Order(), seen.Keys.Order());
        foreach (var (variant, rules) in expected)
        {
            var (status, broken) = seen[variant];
            if (rules.Length == 0)
                Assert.True(status == "PASS", $"{scenario}/{variant} should pass:\n{stdout}");
            else
            {
                Assert.True(status == "FAIL", $"{scenario}/{variant} should fail:\n{stdout}");
                Assert.True(rules.Order().SequenceEqual(broken.Order()),
                    $"{scenario}/{variant} should break exactly [{string.Join(",", rules)}], broke [{string.Join(",", broken)}]");
            }
        }
    }

    // A real tswap reachable in the sandbox (here: a stand-in on the runner's PATH, leaked into the
    // sandbox at the same path) makes the isolation check abort before any agent runs.
    [Fact]
    public void IsolationCheck_AbortsWhenARealTswapIsReachable()
    {
        if (!CanRun())
            return;
        var dir = Path.Combine(Path.GetTempPath(), "tswap-eval-leak-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            var realTswap = Path.Combine(dir, "tswap");
            File.WriteAllText(realTswap, "#!/bin/sh\necho 'a real tswap'\n");
            if (!OperatingSystem.IsWindows()) // always true here (CanRun is Linux-only); for the analyzer
                File.SetUnixFileMode(realTswap, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            var (exit, stdout) = RunEval(["--agent", "fake", "--skill", "off", "--scenario", "01-secret-in-log"], psi =>
            {
                psi.Environment["PATH"] = dir + ":" + Environment.GetEnvironmentVariable("PATH");
                psi.Environment["EVAL_TEST_EXTRA_RO_BIND"] = $"{realTswap}:{realTswap}";
            });

            output.WriteLine(stdout);
            Assert.Equal(2, exit);
            Assert.Contains("ABORT 01-secret-in-log/pass: isolation check failed", stdout);
            Assert.Contains($"the host's tswap ({realTswap}) is reachable", stdout);
            Assert.DoesNotContain("PASS ", stdout);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    // Without the leak, the same run passes the isolation check: the abort above is the leak's doing.
    [Fact]
    public void IsolationCheck_PassesWithTheShimsOnly()
    {
        if (!CanRun())
            return;

        var (exit, stdout) = RunEval(["--agent", "fake", "--skill", "off", "--scenario", "01-secret-in-log"]);

        Assert.True(exit == 0, stdout);
        Assert.Contains("PASS 01-secret-in-log/pass", stdout);
    }
}
