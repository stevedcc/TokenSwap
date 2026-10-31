using System.Text;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T12 decision 3: every Secure Enclave service is built by one factory
/// (<c>TswapCli/HardwareServices.cs</c>), which always wraps it in the owner scope. This scan of the
/// non-test sources fails when the service type or the Swift shim is named in code anywhere else,
/// so a later direct construction fails here instead of silently skipping the owner switch under sudo.
/// Comments and string literals don't count. Fix round 1 (MiMo 3): a simulated Secure Enclave
/// (<c>new SimulatedHardwareService(HardwareBackend.SecureEnclave, ...)</c>) built outside the factory
/// fails it too.
/// <para><b>What it can't see</b> (a tripwire for the realistic regression, not a proof): code in
/// interpolated-string holes (stripped with the literal); a type named through reflection from a
/// string (<c>Type.GetType("...SecureEnclaveHardwareService")</c>); Unicode escapes in identifiers;
/// source generators and other assemblies; a simulated Secure Enclave built with a backend variable;
/// and an unwrapped construction inside the allowed files themselves, which the factory tests in
/// <c>SecureEnclaveOwnerScopeTests</c> catch through the factory's entry points instead.</para>
/// </summary>
public class SecureEnclaveFactoryScanTests
{
    private const string Service = "SecureEnclaveHardwareService";
    private const string Shim = "AppleSecureEnclaveInterop";

    private static readonly Dictionary<string, string[]> AllowedFiles = new()
    {
        [Service] = ["TswapCli/HardwareServices.cs", "TswapCore/Vault/SecureEnclaveHardwareService.cs"],
        [Shim] = ["TswapCore/Vault/SecureEnclaveHardwareService.cs", "TswapCore/Vault/Interop/AppleSecureEnclaveInterop.cs"],
    };

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "TokenSwap.slnx")))
                return dir.FullName;
        throw new InvalidOperationException("TokenSwap.slnx not found above " + AppContext.BaseDirectory);
    }

    private static IEnumerable<string> NonTestSources(string root) =>
        Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(root, f).Replace('\\', '/'))
            .Where(f => !f.StartsWith("TswapTests/", StringComparison.Ordinal))
            .Where(f => !f.Split('/').Any(part => part is "bin" or "obj"));

    [Theory]
    [InlineData(Service)]
    [InlineData(Shim)]
    public void TheSecureEnclaveServiceAndShim_AreNamedInCodeOnlyByTheFactoryAndTheServiceItself(string name)
    {
        var root = RepoRoot();
        var sources = NonTestSources(root).ToList();
        Assert.Contains("TswapCli/HardwareServices.cs", sources); // the scan sees the sources at all

        var offenders = sources
            .Where(f => !AllowedFiles[name].Contains(f))
            .Where(f => NamesInCode(File.ReadAllText(Path.Combine(root, f)), name))
            .ToList();

        Assert.Empty(offenders);
    }

    private const string SimulatedSecureEnclave = "newSimulatedHardwareService(HardwareBackend.SecureEnclave";

    [Fact]
    public void ASimulatedSecureEnclave_IsBuiltInCodeOnlyByTheFactory()
    {
        var root = RepoRoot();

        var offenders = NonTestSources(root)
            .Where(f => f != "TswapCli/HardwareServices.cs")
            .Where(f => BuildsSimulatedSecureEnclave(File.ReadAllText(Path.Combine(root, f))))
            .ToList();

        Assert.Empty(offenders);
        Assert.True(BuildsSimulatedSecureEnclave(File.ReadAllText(Path.Combine(root, "TswapCli/HardwareServices.cs")))); // the control
    }

    [Theory]
    [InlineData("var s = new SimulatedHardwareService(HardwareBackend.SecureEnclave, key);", true)]
    [InlineData("var s = new SimulatedHardwareService( HardwareBackend.SecureEnclave,\n key, false);", true)]
    [InlineData("var s = new SimulatedHardwareService(HardwareBackend.Tpm, key);", false)]
    [InlineData("// new SimulatedHardwareService(HardwareBackend.SecureEnclave, key)", false)]
    public void TheScanner_SeesASimulatedSecureEnclaveConstruction(string source, bool expected) =>
        Assert.Equal(expected, BuildsSimulatedSecureEnclave(source));

    /// <summary>True when code (not comments or literals) builds a simulated Secure Enclave, whitespace ignored.</summary>
    private static bool BuildsSimulatedSecureEnclave(string source) =>
        string.Concat(StripCommentsAndLiterals(source).Where(c => !char.IsWhiteSpace(c))).Contains(SimulatedSecureEnclave, StringComparison.Ordinal);

    // Round 2 (GLM N1): the real UnixOwnership.ActAs can't be made to fail without root (as a normal
    // user its first call, setgroups, fails with EPERM, and restoring the groups then fails too, which
    // is Environment.FailFast: it would kill the test host). So this pins its throws in the source:
    // every throw in ActAs is the hard-stop type, none is the base TswapException.
    [Fact]
    public void TheRealActAs_ThrowsOnlyOwnerSwitchException()
    {
        var source = StripCommentsAndLiterals(File.ReadAllText(Path.Combine(RepoRoot(), "TswapCore/FileOwnership.cs")));
        var start = source.IndexOf("public unsafe IDisposable ActAs(", StringComparison.Ordinal);
        var end = source.IndexOf("private sealed class Identity", start, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start, "UnixOwnership.ActAs not found");
        var body = source[start..end];

        Assert.Equal(2, body.Split("throw new OwnerSwitchException(").Length - 1);
        Assert.DoesNotContain("throw new TswapException(", body);
    }

    [Fact]
    public void TheFactory_StillBuildsTheService_SoTheScanWatchesTheRightName()
    {
        var factory = File.ReadAllText(Path.Combine(RepoRoot(), "TswapCli/HardwareServices.cs"));

        Assert.True(NamesInCode(factory, "new " + Service + "("));
    }

    [Theory]
    [InlineData("var s = new SecureEnclaveHardwareService(true);", true)]
    [InlineData("SecureEnclaveHardwareService s = new(true);", true)]
    [InlineData("var b = AppleSecureEnclaveInterop.Unwrap(x);", true)]
    [InlineData("var u = \"http://x\"; var s = new SecureEnclaveHardwareService();", true)]
    [InlineData("// new SecureEnclaveHardwareService()", false)]
    [InlineData("/// <see cref=\"SecureEnclaveHardwareService\"/>", false)]
    [InlineData("/* AppleSecureEnclaveInterop.Wrap */ var a = 1;", false)]
    [InlineData("var s = \"SecureEnclaveHardwareService\";", false)]
    [InlineData("var s = @\"a \"\" SecureEnclaveHardwareService\";", false)]
    [InlineData("var s = \"\"\"\n SecureEnclaveHardwareService \"\n\"\"\";", false)]
    [InlineData("var c = '\"'; var s = new SecureEnclaveHardwareService();", true)]
    [InlineData("var s = $\"\"\"\n SecureEnclaveHardwareService \"\n\"\"\";", false)]
    public void TheScanner_SeesCode_NotCommentsOrStrings(string source, bool expected)
    {
        var name = source.Contains(Shim) ? Shim : Service;

        Assert.Equal(expected, NamesInCode(source, name));
    }

    /// <summary>True when <paramref name="name"/> occurs in <paramref name="source"/> outside comments and literals.</summary>
    private static bool NamesInCode(string source, string name) => StripCommentsAndLiterals(source).Contains(name, StringComparison.Ordinal);

    /// <summary>
    /// <paramref name="source"/> with comments, string literals (regular, verbatim, raw, and the text of
    /// interpolated ones) and character literals replaced by spaces.
    /// </summary>
    private static string StripCommentsAndLiterals(string source)
    {
        var code = new StringBuilder(source.Length);
        var i = 0;
        while (i < source.Length)
        {
            var c = source[i];
            var next = i + 1 < source.Length ? source[i + 1] : '\0';
            if (c == '/' && next == '/')
            {
                while (i < source.Length && source[i] != '\n') i++;
            }
            else if (c == '/' && next == '*')
            {
                var end = source.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = end < 0 ? source.Length : end + 2;
            }
            else if ((c == '"' || (c is '@' or '$' && LiteralStart(source, i, out _))) && RawStart(source, i, out var rawQuote))
            {
                i = rawQuote;
                var quotes = 0;
                while (i < source.Length && source[i] == '"') { quotes++; i++; }
                var closing = new string('"', quotes);
                var end = source.IndexOf(closing, i, StringComparison.Ordinal);
                i = end < 0 ? source.Length : end + quotes;
            }
            else if (c == '"' || (c is '@' or '$' && LiteralStart(source, i, out _)))
            {
                var verbatim = false;
                while (source[i] != '"') { verbatim |= source[i] == '@'; i++; }
                i++; // opening quote
                while (i < source.Length)
                {
                    if (verbatim && source[i] == '"' && i + 1 < source.Length && source[i + 1] == '"') { i += 2; continue; }
                    if (!verbatim && source[i] == '\\') { i += 2; continue; }
                    if (source[i] == '"') { i++; break; }
                    i++;
                }
            }
            else if (c == '\'')
            {
                i++;
                while (i < source.Length && source[i] != '\'')
                    i += source[i] == '\\' ? 2 : 1;
                i++;
            }
            else
            {
                code.Append(c);
                i++;
                continue;
            }
            code.Append(' ');
        }
        return code.ToString();
    }

    /// <summary>A raw string literal (<c>\"\"\"</c>, optionally after <c>$</c> prefixes) at <paramref name="i"/>.</summary>
    private static bool RawStart(string source, int i, out int quote)
    {
        quote = i;
        while (quote < source.Length && source[quote] == '$') quote++;
        return source.AsSpan(quote).StartsWith("\"\"\"");
    }

    /// <summary>A <c>@"</c>, <c>$"</c>, <c>$@"</c> or <c>@$"</c> prefix at <paramref name="i"/>.</summary>
    private static bool LiteralStart(string source, int i, out int quote)
    {
        quote = i;
        while (quote < source.Length && source[quote] is '@' or '$' && quote - i < 2) quote++;
        return quote < source.Length && source[quote] == '"';
    }
}
