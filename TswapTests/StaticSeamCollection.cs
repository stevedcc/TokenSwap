using System.Text.Json;
using Xunit;

namespace TswapTests;

/// <summary>
/// Review T17 p4 B1 (and p1 M4/M7, p5 assumption 1): the brief T17 test classes that set process-wide
/// static seams (<c>StretchedPassword.BeforeFreeObserver</c>, <c>VaultPasswordChoice</c>'s platform
/// seams, <c>SimulatedHardwareService.ObserveCalls</c>, the agent and broker observers) and count
/// what they see. A collection with parallelization disabled runs alone, after every parallel one,
/// so no other class can dispose a password or reach a seam while these count, whatever the runner
/// configuration says.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class StaticSeamCollection
{
    public const string Name = "Static test seams (T17)";
}

/// <summary>
/// The whole assembly runs one collection at a time (<c>xunit.runner.json</c>): many older classes set
/// static seams too. This keeps that setting from being dropped unnoticed.
/// </summary>
public class TestRunnerConfigTests
{
    [Fact]
    public void RunnerConfig_RunsCollectionsOneAtATime()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "xunit.runner.json");
        using var config = JsonDocument.Parse(File.ReadAllText(path));

        Assert.False(config.RootElement.GetProperty("parallelizeTestCollections").GetBoolean());
        Assert.Equal(1, config.RootElement.GetProperty("maxParallelThreads").GetInt32());
    }
}
