using TswapCore;
using TswapCore.Vault.Interop;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T14 item 5: <c>libtswapse.dylib</c> is loaded only through the shim's
/// <c>NativeLibrary.SetDllImportResolver</c> registration, which pins it to
/// <see cref="AppContext.BaseDirectory"/> and turns a missing file into the install hint. The macOS
/// round trip can't see a bypass (.NET's default probing also finds the app folder), so this checks
/// the resolver where the dylib is absent: on Linux and Windows the shim must still throw the
/// install-hint <see cref="TswapException"/>, never the runtime's <see cref="DllNotFoundException"/>.
/// Where the dylib sits beside the test binary (macOS builds) the resolver loads it, so there is
/// nothing to check and the test returns.
/// </summary>
public class SecureEnclaveResolverTests
{
    [Fact]
    public void WithNoDylibBesideTheBinary_TheShimThrowsTheInstallHint_NotDllNotFound()
    {
        var dylib = Path.Combine(AppContext.BaseDirectory, "libtswapse.dylib");
        if (File.Exists(dylib))
            return;

        // CA1416: the shim is macOS-only on purpose; here its resolver is what is under test.
#pragma warning disable CA1416
        var ex = Assert.Throws<TswapException>(() => AppleSecureEnclaveInterop.IsAvailable());
#pragma warning restore CA1416

        Assert.Contains($"tswap's Secure Enclave support library is missing ({dylib} not found)", ex.Message);
        Assert.Contains("run 'tswap installscript'", ex.Message);
    }

    /// <summary>
    /// Issue #238: the macOS release archive now carries the dylib next to <c>tswap</c>, so a portable copy (no
    /// install, no sudo) works when the whole archive is unpacked; the hint names that route before the install script.
    /// </summary>
    [Fact]
    public void WithNoDylibBesideTheBinary_TheHintSaysToKeepItNextToTswap()
    {
        var dylib = Path.Combine(AppContext.BaseDirectory, "libtswapse.dylib");
        if (File.Exists(dylib))
            return;

#pragma warning disable CA1416
        var ex = Assert.Throws<TswapException>(() => AppleSecureEnclaveInterop.IsAvailable());
#pragma warning restore CA1416

        Assert.Contains("Keep libtswapse.dylib in the same folder as tswap: the macOS release archive has both, so unpack all of it.", ex.Message);
    }

    /// <summary>
    /// Issue #240: from v0.3.0 both files are signed with the hardened runtime, so library validation refuses a dylib
    /// from another build (an old v0.2 one, a self-built copy): dyld's reason ("different Team IDs") is kept and the
    /// message says the two files must come from one release.
    /// </summary>
    [Fact]
    public void ADylibThatWontLoad_KeepsDyldsReasonAndSaysToPairTheFiles()
    {
        const string reason = "dlopen(/opt/tswap/libtswapse.dylib, 0x0001): tried: '/opt/tswap/libtswapse.dylib' (code signature in <...> " +
                              "'/opt/tswap/libtswapse.dylib' not valid for use in process: mapping process and mapped file (non-platform) have different Team IDs)";

#pragma warning disable CA1416
        var message = AppleSecureEnclaveInterop.LoadFailureMessage("/opt/tswap/libtswapse.dylib", reason);
#pragma warning restore CA1416

        Assert.StartsWith("tswap's Secure Enclave support library /opt/tswap/libtswapse.dylib could not be loaded: ", message);
        Assert.Contains(reason, message);
        Assert.Contains("tswap and libtswapse.dylib must come from the same release (from v0.3.0 they are signed together): " +
                        "reinstall the package, or replace both from one archive.", message);
    }
}
