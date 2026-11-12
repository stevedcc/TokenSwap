using TswapCore.Vault.Fido2.Libfido2;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T19, item 1: the binding against the real libfido2, unprivileged: it loads, every symbol resolves,
/// <c>fido_init</c> runs, and <c>fido_dev_info_manifest</c> succeeds with a count of zero or more. It lists devices but
/// opens none: no PIN, no credential, no touch. Without libfido2 installed it says so and returns, except when
/// <c>CI_REQUIRE_LIBFIDO2=1</c> (the Linux and macOS CI legs): then it fails, as <c>CI_REQUIRE_BWRAP</c> does.
/// </summary>
public class Libfido2SmokeTests(ITestOutputHelper output)
{
    [Fact]
    public void RealLibrary_LoadsAndListsDevices()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            output.WriteLine("SKIPPED: libfido2 is never loaded on this OS.");
            return;
        }

        var loader = Libfido2Loader.ForThisProcess(privileged: false);
        var status = loader.TryLoad();
        if (status == Libfido2Status.NotInstalled)
        {
            if (Environment.GetEnvironmentVariable("CI_REQUIRE_LIBFIDO2") == "1")
                Assert.Fail("CI_REQUIRE_LIBFIDO2=1 but libfido2 isn't installed");
            output.WriteLine("SKIPPED: libfido2 isn't installed.");
            return;
        }

        Assert.Equal(Libfido2Status.Loaded, status);
        var fido = loader.Library!;
        const nuint capacity = 64;
        var list = fido.DevInfoNew(capacity);
        Assert.NotEqual(0, list);
        try
        {
            var result = fido.DevInfoManifest(list, capacity, out var found);

            Assert.Equal(Libfido2Errors.Ok, result);
            Assert.InRange(found, 0u, capacity);
            output.WriteLine($"libfido2 at {loader.LoadedPath}: {found} device(s) listed");
        }
        finally
        {
            fido.DevInfoFree(list, capacity);
        }
    }
}
