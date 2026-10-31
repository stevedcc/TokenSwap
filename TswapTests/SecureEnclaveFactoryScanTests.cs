using System.Text;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T12 decision 3: every Secure Enclave service is built by one factory
/// (<c>TswapCli/HardwareServices.cs</c>), which always wraps it in the owner scope. This scan of the
/// non-test sources fails when the service type or the Swift shim is named in code anywhere else,
/// so a later direct construction fails here instead of silently skipping the owner switch under sudo.
/// Comments and string literals don't count.
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
