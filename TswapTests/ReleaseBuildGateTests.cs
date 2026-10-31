using System.Diagnostics;
using System.Reflection;
using System.Runtime.Loader;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Proves the simulated hardware backend (and the YubiKey test key with it) cannot be selected
/// in a Release build (issue #153, brief T2 item 2). The selection is
/// <c>HardwareServices.UnlockBackends(testKey, scope)</c> / <c>Enrollment(backend, testKey, scope)</c>, which
/// pick <see cref="SimulatedHardwareService"/> only for a non-null test key; the test key comes
/// only from <c>HardwareServices.ReadTestKey</c>. This test builds <c>TswapCli</c> in Release,
/// loads that assembly into its own load context and calls its <c>ReadTestKey</c> with
/// <c>TSWAP_TEST_KEY</c> set to a valid key: the Release build must return null.
///
/// <para>Category E2E: it spawns a <c>dotnet build</c> (seconds, not milliseconds), like the
/// other subprocess tests.</para>
/// </summary>
[Trait("Category", "E2E")]
public class ReleaseBuildGateTests
{
    private const string ValidTestKeyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    [Fact]
    public void ReleaseBuild_IgnoresTswapTestKey_SoSimulatedHardwareCannotBeSelected()
    {
        var releaseAssemblyPath = BuildTswapCli("Release");
        var context = new IsolatedContext(releaseAssemblyPath);
        try
        {
            var assembly = context.LoadFromAssemblyPath(releaseAssemblyPath);
            var hardwareServices = assembly.GetType("TswapCli.HardwareServices", throwOnError: true)!;

            var readTestKey = hardwareServices.GetMethod("ReadTestKey", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)!;
            Func<string, string?> environment = name => name == "TSWAP_TEST_KEY" ? ValidTestKeyHex : null;
            var testKey = readTestKey.Invoke(null, [environment]);

            Assert.Null(testKey);

            // And with no test key, the Release composition registers no simulated backend. (Brief
            // T12: the second argument is the Secure Enclave's owner scope; building the backends
            // never calls it, so null is enough here. The Secure Enclave on macOS is now a decorator,
            // which hides the inner type's name: IsSimulated is checked as well.)
            var unlockBackends = hardwareServices.GetMethod("UnlockBackends", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)!;
            var backends = ((System.Collections.IEnumerable)unlockBackends.Invoke(null, [null, null])!).Cast<object>().ToList();
            Assert.DoesNotContain(backends, b => b.GetType().Name == nameof(SimulatedHardwareService));
            Assert.DoesNotContain(backends, b => (bool)b.GetType().GetProperty("IsSimulated")!.GetValue(b)!);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Builds TswapCli in <paramref name="configuration"/> and returns the managed assembly path.
    /// Uses the SDK running this test (DOTNET_HOST_PATH, set by <c>dotnet test</c>) rather than
    /// whatever <c>dotnet</c> is first on PATH.
    /// </summary>
    private static string BuildTswapCli(string configuration)
    {
        var repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        var project = Path.Combine(repoRoot, "TswapCli", "TswapCli.csproj");
        // Build first, then ask for TargetPath: '-getProperty' on its own only evaluates the
        // project and does not run the build.
        RunDotnet(repoRoot, ["build", project, "-c", configuration]);
        var stdout = RunDotnet(repoRoot, ["msbuild", project, $"-p:Configuration={configuration}", "-getProperty:TargetPath"]);

        var targetPath = stdout.Trim();
        Assert.True(File.Exists(targetPath), $"Built assembly not found: '{targetPath}'");
        Assert.Contains($"{Path.DirectorySeparatorChar}{configuration}{Path.DirectorySeparatorChar}", targetPath);
        return targetPath;
    }

    private static string RunDotnet(string workingDirectory, string[] arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host ? host : "dotnet",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory,
        };
        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);

        using var process = Process.Start(psi)!;
        var stderrTask = process.StandardError.ReadToEndAsync();
        var stdout = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        var stderr = stderrTask.Result;
        Assert.True(process.ExitCode == 0, $"dotnet {string.Join(' ', arguments)} failed (exit {process.ExitCode}):\n{stdout}\n{stderr}");
        return stdout;
    }

    /// <summary>Loads the Release TswapCli and its Release dependencies side by side with the Debug ones.</summary>
    private sealed class IsolatedContext(string mainAssemblyPath) : AssemblyLoadContext("tswap-release-gate", isCollectible: true)
    {
        private readonly AssemblyDependencyResolver _resolver = new(mainAssemblyPath);

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            var path = _resolver.ResolveAssemblyToPath(assemblyName);
            return path != null ? LoadFromAssemblyPath(path) : null;
        }
    }
}
