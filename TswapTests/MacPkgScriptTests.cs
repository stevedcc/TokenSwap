using System.Text.RegularExpressions;
using Xunit;

namespace TswapTests;

/// <summary>
/// The macOS release's build inputs (issues #240 and #265): the Secure Enclave shim's deployment target and signing in
/// <c>TswapCore.csproj</c>. The shim is signed inside the MSBuild target, before it is embedded into <c>tswap</c> for
/// <c>installscript</c>; signing the publish folder afterwards would leave the embedded copy unsigned.
/// </summary>
public partial class MacPkgScriptTests
{
    private static string RepoFile(params string[] parts) =>
        Path.GetFullPath(Path.Combine([AppContext.BaseDirectory, "..", "..", "..", "..", .. parts]));

    private static string Csproj => File.ReadAllText(RepoFile("TswapCore", "TswapCore.csproj"));

    /// <summary>The value of <c>SecureEnclaveShimMinOS</c> in the csproj; the property must be defined exactly once.</summary>
    internal static string ShimMinOs()
    {
        var definitions = ShimMinOsProperty().Matches(Csproj);
        Assert.Single(definitions);
        return definitions[0].Groups[1].Value;
    }

    [Fact]
    public void Csproj_ShimTarget_SignsBeforeOptionsAndSetsTheTarget()
    {
        Assert.Matches(@"^\d+\.\d+$", ShimMinOs());

        var exec = Regex.Matches(Csproj, @"<Exec\b[^>]*?\sCommand=""([^""]*)""").Select(m => m.Groups[1].Value).ToList();
        var swiftc = Assert.Single(exec, command => command.StartsWith("swiftc ", StringComparison.Ordinal));
        // The arch comes from the build host (an Intel Mac developer build keeps a loadable dylib); the minimum is one property.
        Assert.Matches(@"-target \S+-apple-macos\$\(SecureEnclaveShimMinOS\)(\s|$)", swiftc);

        var codesign = Assert.Single(exec, command => command.StartsWith("codesign ", StringComparison.Ordinal));
        // --keychain only when TswapMacSignKeychain is set: the csproj builds it into _ShimSignKeychainArgument.
        var keychain = Regex.Match(codesign, @"--keychain|\$\(_ShimSignKeychainArgument\)").Index;
        var sign = codesign.IndexOf("--sign ", StringComparison.Ordinal);
        var options = codesign.IndexOf("--options runtime", StringComparison.Ordinal);
        Assert.True(sign >= 0 && options > sign, $"--sign must come before --options runtime: {codesign}");
        Assert.True(keychain > 0 && keychain < sign, $"--keychain must come before --sign: {codesign}");
        Assert.Contains("--timestamp", codesign);
        Assert.Contains("--identifier dev.crawford.tswap.libtswapse", codesign);
        Assert.DoesNotContain("--entitlements", codesign);
        Assert.DoesNotContain("--deep", codesign);
    }

    [GeneratedRegex(@"<SecureEnclaveShimMinOS>([^<]*)</SecureEnclaveShimMinOS>")]
    private static partial Regex ShimMinOsProperty();
}
