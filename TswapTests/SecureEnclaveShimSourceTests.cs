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

/// <summary>
/// Brief T17 task 13: the shim's two password entry points (ruling 19), read from the Swift source on every
/// OS. CI's macOS job compiles the shim and runs <see cref="SecureEnclavePasswordRoundTripTests"/> against it.
/// </summary>
public class SecureEnclaveShimPasswordSourceTests
{
    private static readonly string RepoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));

    private static readonly string Source = File.ReadAllText(
        Path.Combine(RepoRoot, "TswapCore", "Vault", "Interop", "swift", "TswapSecureEnclave.swift"));

    /// <summary>The source from <c>@_cdecl("<paramref name="symbol"/>")</c> to the next <c>@_cdecl</c> or the end.</summary>
    private static string Body(string symbol)
    {
        var start = Source.IndexOf($"@_cdecl(\"{symbol}\")", StringComparison.Ordinal);
        Assert.True(start >= 0, $"{symbol} is not exported");
        var next = Source.IndexOf("@_cdecl(", start + 1, StringComparison.Ordinal);
        return next < 0 ? Source[start..] : Source[start..next];
    }

    private static string[] ParameterTypes(string symbol)
    {
        var match = Regex.Match(Source,
            $@"@_cdecl\(""{Regex.Escape(symbol)}""\)\s*public func {Regex.Escape(symbol)}\((?<params>[^)]*)\)\s*->\s*Int32");
        Assert.True(match.Success, $"{symbol} is not exported with @_cdecl as a function returning Int32");
        return match.Groups["params"].Value.Split(',')
            .Select(p => Regex.Replace(p[(p.IndexOf(':') + 1)..], @"\s+", ""))
            .ToArray();
    }

    /// <summary>The source with every <c>//</c> comment removed, so prose can't satisfy or trip a check.</summary>
    private static string Code(string text) => Regex.Replace(text, @"//[^\n]*", "");

    [Fact]
    public void WrapV3_IsWrapV2PlusACredential()
    {
        Assert.Equal(
            ["UnsafePointer<UInt8>", "Int32", "UnsafeMutablePointer<UInt8>", "UnsafeMutablePointer<Int32>",
             "UnsafeMutablePointer<UInt8>", "UnsafeMutablePointer<Int32>", "Int32", "UnsafePointer<UInt8>", "Int32"],
            ParameterTypes("tswap_se_wrap_v3"));
    }

    [Fact]
    public void UnwrapV2_IsUnwrapWithACredentialBeforeTheOutput()
    {
        Assert.Equal(
            ["UnsafePointer<UInt8>", "Int32", "UnsafePointer<UInt8>", "Int32", "UnsafePointer<UInt8>", "Int32",
             "UnsafeMutablePointer<UInt8>", "UnsafeMutablePointer<Int32>"],
            ParameterTypes("tswap_se_unwrap_v2"));
    }

    [Fact]
    public void WrapV3_PinsTheFlags()
    {
        var body = Code(Body("tswap_se_wrap_v3"));
        Assert.Contains("case 1: flags = [.privateKeyUsage, .userPresence, .applicationPassword]", body);
        Assert.Contains("case 0: flags = [.privateKeyUsage, .applicationPassword]", body);
        Assert.Contains("compactRepresentable: false, accessControl: access, authenticationContext: context", body);
        Assert.Contains("context.interactionNotAllowed = requirePresence != 1", body);
    }

    [Fact]
    public void UnwrapV2_RestoresUnderAContextWithTheCredential_NoDialogFirst()
    {
        var body = Code(Body("tswap_se_unwrap_v2"));
        Assert.Contains("dataRepresentation: blobData, authenticationContext: context", body);
        Assert.Contains("context.interactionNotAllowed = !interactionAllowed", body);
        Assert.Contains("try agree(interactionAllowed: false)", body);
        // The interactive retry happens only after LAError notInteractive.
        var retry = body.IndexOf("agree(interactionAllowed: true)", StringComparison.Ordinal);
        var guardNotInteractive = body.IndexOf("LAError.Code.notInteractive.rawValue", StringComparison.Ordinal);
        Assert.True(guardNotInteractive >= 0 && guardNotInteractive < retry);
    }

    [Theory]
    [InlineData("tswap_se_wrap_v3")]
    [InlineData("tswap_se_unwrap_v2")]
    public void TheCredentialLength_IsCheckedBeforeTheEnclave(string symbol)
    {
        var body = Code(Body(symbol));
        var check = body.IndexOf("guard credentialLen == credentialLength else { return -6 }", StringComparison.Ordinal);
        Assert.True(check >= 0);
        Assert.True(check < body.IndexOf("LAContext()", StringComparison.Ordinal));
        Assert.True(check < body.IndexOf("SecureEnclave.P256", StringComparison.Ordinal));
    }

    [Fact]
    public void UnwrapV2_ReturnsTheNewCodes()
    {
        var body = Code(Body("tswap_se_unwrap_v2"));
        Assert.Contains("return -6", body);
        Assert.Contains("return -7", body);
        Assert.Contains("-8", body);
    }

    [Fact]
    public void TheCredential_AppearsOnlyInTheNewEntryPoints_AndNothingShowsUi()
    {
        var code = Code(Source);
        var newEntryPoints = Code(Body("tswap_se_wrap_v3")) + Code(Body("tswap_se_unwrap_v2"));
        Assert.Equal(Count(code, "setCredential"), Count(newEntryPoints, "setCredential"));
        Assert.Equal(Count(code, ".applicationPassword"), Count(newEntryPoints, ".applicationPassword"));
        Assert.True(Count(newEntryPoints, ".applicationPassword") >= 4);
        Assert.DoesNotContain("evaluatePolicy", code);
        // The old entry points are untouched: no credential and no LocalAuthentication context in them.
        foreach (var old in new[] { "tswap_se_wrap", "tswap_se_wrap_v2", "tswap_se_unwrap" })
            Assert.DoesNotContain("LAContext", Code(Body(old)));
    }

    // T17 fix round 2: the legacy unwrap without interaction, for a slot recorded as made without presence.

    [Fact]
    public void UnwrapNoInteraction_HasTheOldUnwrapsParameters() =>
        Assert.Equal(ParameterTypes("tswap_se_unwrap"), ParameterTypes("tswap_se_unwrap_no_interaction"));

    [Fact]
    public void UnwrapNoInteraction_AllowsNoInteraction_AndTakesNoCredential()
    {
        var body = Code(Body("tswap_se_unwrap_no_interaction"));
        Assert.Contains("context.interactionNotAllowed = true", body);
        Assert.Contains("dataRepresentation: blobData, authenticationContext: context", body);
        Assert.Equal(1, Count(body, "interactionNotAllowed")); // set once, never back to false
        Assert.Equal(1, Count(body, "LAContext()"));           // one context: no interactive retry
        Assert.DoesNotContain("setCredential", body);
        Assert.DoesNotContain(".applicationPassword", body);
        Assert.Contains("-8", body);
    }

    private static int Count(string text, string what) => Regex.Matches(text, Regex.Escape(what)).Count;
}
