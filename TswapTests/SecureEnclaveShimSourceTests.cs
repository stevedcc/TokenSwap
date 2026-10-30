using System.Text.RegularExpressions;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T11 item 2: the Swift shim only compiles on macOS, so this reads its source on every OS
/// and checks the C ABI the C# side declares (the reflection test in
/// <see cref="SecureEnclaveTouchChoiceTests"/> covers the C# half): <c>tswap_se_wrap_v2</c> is
/// <c>tswap_se_wrap</c>'s six parameters plus <c>requirePresence: Int32</c>, and the six-parameter
/// <c>tswap_se_wrap</c> is still exported.
/// </summary>
public class SecureEnclaveShimSourceTests
{
    private static readonly string RepoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));

    private static readonly string Source = File.ReadAllText(
        Path.Combine(RepoRoot, "TswapCore", "Vault", "Interop", "swift", "TswapSecureEnclave.swift"));

    /// <summary>The parameter types (labels stripped) of the function exported as <paramref name="symbol"/>.</summary>
    private static (string Name, string Type)[] ExportedParameters(string symbol)
    {
        var match = Regex.Match(Source,
            $@"@_cdecl\(""{Regex.Escape(symbol)}""\)\s*public func {Regex.Escape(symbol)}\((?<params>[^)]*)\)\s*->\s*Int32");
        Assert.True(match.Success, $"{symbol} is not exported with @_cdecl as a function returning Int32");
        return match.Groups["params"].Value
            .Split(',')
            .Select(p => p.Trim())
            .Select(p =>
            {
                var colon = p.IndexOf(':');
                var name = p[..colon].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries).Last();
                return (name, Regex.Replace(p[(colon + 1)..], @"\s+", ""));
            })
            .ToArray();
    }

    [Fact]
    public void WrapV2_IsWrapsSixParametersPlusRequirePresence()
    {
        var wrap = ExportedParameters("tswap_se_wrap");
        var wrapV2 = ExportedParameters("tswap_se_wrap_v2");

        Assert.Equal(6, wrap.Length);
        Assert.Equal(7, wrapV2.Length);
        Assert.Equal(wrap.Select(p => p.Type), wrapV2[..6].Select(p => p.Type));
        Assert.Equal(("requirePresence", "Int32"), wrapV2[6]);
    }

    [Fact]
    public void Wrap_KeepsItsSixParameterSignature() =>
        Assert.Equal(
            ["UnsafePointer<UInt8>", "Int32", "UnsafeMutablePointer<UInt8>", "UnsafeMutablePointer<Int32>",
             "UnsafeMutablePointer<UInt8>", "UnsafeMutablePointer<Int32>"],
            ExportedParameters("tswap_se_wrap").Select(p => p.Type));

    [Fact]
    public void WrapV2_ReturnsTheCodesTheCSideMaps()
    {
        // The new codes the C# gives their own messages (SecureEnclaveReturnCodes).
        var body = Source[Source.IndexOf("@_cdecl(\"tswap_se_wrap_v2\")", StringComparison.Ordinal)..];
        body = body[..body.IndexOf("@_cdecl(", 1, StringComparison.Ordinal)];
        Assert.Contains("return -4", body);
        Assert.Contains("return -5", body);
        Assert.DoesNotContain(")!", body); // the guard replaces the force-unwrap
    }
}
