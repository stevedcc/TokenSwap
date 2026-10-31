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
}
