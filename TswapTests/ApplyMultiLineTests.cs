using System.Text;
using System.Text.Json;
using RedactingPty;
using TswapCli;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T20 (#315), tasks 1-3: a multi-line value (a PEM, a JSON document) filled through a
/// <c># tswap:</c> marker is written as an escaped double-quoted string, so YAML and JSON read it back
/// byte for byte. There is no YAML library here (and none is added): the quoted part is decoded by
/// <see cref="DoubleQuotedTestDecoder"/>, which knows only the escapes tswap writes.
/// </summary>
public sealed class ApplyMultiLineTests
{
    private const string Pem = "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----";

    // (value, its double-quoted escaping): every expectation written out by hand.
    private static readonly Dictionary<string, (string Value, string Escaped)> Cases = new()
    {
        ["pem-trailing-lf"] = (Pem + "\n", @"-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----\n"),
        ["pem"] = (Pem, @"-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----"),
        ["pem-crlf"] = (Pem.Replace("\n", "\r\n"), @"-----BEGIN KEY-----\r\nAAAA\r\nBBBB\r\n-----END KEY-----"),
        ["tab"] = ("a\tb", @"a\tb"),
        ["quote-backslash"] = ("quote \" and back \\ slash", @"quote \"" and back \\ slash"),
        ["backslash-letter"] = (@"C:\new\table", @"C:\\new\\table"),
        ["json"] = ("{\n  \"a\": \"b\",\n  \"c\": 1\n}", @"{\n  \""a\"": \""b\"",\n  \""c\"": 1\n}"),
        ["u0001-u007f"] = ("x\u0001y\u007Fz", @"x\u0001y\u007Fz"),
        ["u2028"] = ("a\u2028b", @"a\u2028b"),
    };

    public static TheoryData<string> CaseNames => [.. Cases.Keys];

    private static SecretsDb Db(string value) => new(new Dictionary<string, Secret>
    {
        ["x"] = new Secret(value, TestTime.Fixed, TestTime.Fixed, null, null),
    });

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void DoubleQuoted_TopLevelYaml_EscapedAndDecodesToTheValue(string name)
    {
        var (value, escaped) = Cases[name];

        var result = Apply.ApplySecrets("key: \"\"  # tswap: x", Db(value));

        Assert.Equal($"key: \"{escaped}\"  # tswap: x", result);
        Assert.Equal(value, DoubleQuotedTestDecoder.Decode(QuotedPart(result, "key: \"")));
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void DoubleQuoted_NestedYaml_EscapedAndDecodesToTheValue(string name)
    {
        var (value, escaped) = Cases[name];

        var result = Apply.ApplySecrets("a:\n  key: \"\"  # tswap: x", Db(value));

        var lines = result.Split('\n');
        Assert.Equal(2, lines.Length);
        Assert.Equal("a:", lines[0]);
        Assert.Equal($"  key: \"{escaped}\"  # tswap: x", lines[1]);
        Assert.Equal(value, DoubleQuotedTestDecoder.Decode(QuotedPart(lines[1], "  key: \"")));
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void DoubleQuoted_JsonIsh_EscapedAndDecodesToTheValue(string name)
    {
        var (value, escaped) = Cases[name];

        var result = Apply.ApplySecrets("\"k\": \"\"  # tswap: x", Db(value));

        Assert.Equal($"\"k\": \"{escaped}\"  # tswap: x", result);
        Assert.Equal(value, DoubleQuotedTestDecoder.Decode(QuotedPart(result, "\"k\": \"")));
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void DoubleQuoted_JsonIsh_SystemTextJsonReadsTheValue(string name)
    {
        var (value, _) = Cases[name];

        var result = Apply.ApplySecrets("\"k\": \"\"  # tswap: x", Db(value));

        var literal = "\"" + QuotedPart(result, "\"k\": \"") + "\"";
        Assert.Equal(value, JsonSerializer.Deserialize<string>(literal));
    }

    [Fact]
    public void DoubleQuoted_ReportsTheEscapedWrittenForm()
    {
        var (value, escaped) = Cases["pem"];

        var (_, applied) = Apply.ApplySecretsReporting("key: \"\"  # tswap: x", Db(value), null);

        var row = Assert.Single(applied);
        Assert.Equal("x", row.Name);
        Assert.Equal(value, row.Raw);
        Assert.Equal([escaped], row.WrittenForms);
    }

    // ------------------------------------------------------------------ task 2: single quotes

    [Fact]
    public void SingleQuoted_PemBecomesDoubleQuotedAndEscaped()
    {
        var (value, escaped) = Cases["pem"];

        var (content, applied) = Apply.ApplySecretsReporting("tls:\n  key: ''  # tswap: x", Db(value), null);

        Assert.Equal($"tls:\n  key: \"{escaped}\"  # tswap: x", content);
        Assert.Equal(value, DoubleQuotedTestDecoder.Decode(QuotedPart(content.Split('\n')[1], "  key: \"")));
        var row = Assert.Single(applied);
        Assert.Equal([escaped], row.WrittenForms);
    }

    [Fact]
    public void SingleQuoted_ControlCharacterKeepsTheSeparatorWhitespace()
    {
        var result = Apply.ApplySecrets("key: ''# tswap: x\nother: ''\t# tswap: x", Db("a\tb"));

        Assert.Equal("key: \"a\\tb\" # tswap: x\nother: \"a\\tb\"\t# tswap: x", result);
    }

    [Fact]
    public void SingleQuoted_PlainValueStaysSingleQuoted()
    {
        var (content, applied) = Apply.ApplySecretsReporting("key: ''  # tswap: x", Db("it's plain"), null);

        Assert.Equal("key: 'it''s plain'  # tswap: x", content);
        Assert.Equal(["it''s plain"], Assert.Single(applied).WrittenForms);
    }

    /// <summary>The text between <paramref name="start"/> and the closing quote before the marker.</summary>
    internal static string QuotedPart(string line, string start)
    {
        Assert.StartsWith(start, line);
        var end = line.LastIndexOf("\"  # tswap:", StringComparison.Ordinal);
        Assert.True(end >= start.Length, line);
        return line[start.Length..end];
    }
}

/// <summary>
/// Brief T20: a test-only decoder for the escapes tswap writes in a double-quoted scalar
/// (<c>\\ \" \n \r \t \uXXXX</c>), which YAML double quotes and JSON strings both decode the same way.
/// Anything else after a backslash, a raw control character or a raw line break fails the test.
/// </summary>
internal static class DoubleQuotedTestDecoder
{
    public static string Decode(string quoted)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < quoted.Length; i++)
        {
            var c = quoted[i];
            Assert.False(c < ' ' || c == '\u007F' || c is '\u0085' or '\u2028' or '\u2029',
                $"raw control character U+{(int)c:X4} at {i} in the quoted part");
            Assert.False(c == '"', $"unescaped quote at {i} in the quoted part");
            if (c != '\\')
            {
                sb.Append(c);
                continue;
            }
            Assert.True(i + 1 < quoted.Length, "a backslash ends the quoted part");
            var e = quoted[++i];
            switch (e)
            {
                case '\\': sb.Append('\\'); break;
                case '"': sb.Append('"'); break;
                case 'n': sb.Append('\n'); break;
                case 'r': sb.Append('\r'); break;
                case 't': sb.Append('\t'); break;
                case 'u':
                    Assert.True(i + 4 < quoted.Length, "a short \\u escape");
                    var hex = quoted.Substring(i + 1, 4);
                    Assert.Matches("^[0-9A-F]{4}$", hex);
                    sb.Append((char)Convert.ToInt32(hex, 16));
                    i += 4;
                    break;
                default:
                    Assert.Fail($"unknown escape \\{e} at {i - 1}");
                    break;
            }
        }
        return sb.ToString();
    }
}

/// <summary>
/// Brief T20, tasks 1 and 3 through <c>run … {{@file}}</c>: the child gets a copy whose filled line is a
/// single line holding the escaped form, and a refused <c>KEY=</c> line starts no child and leaves no copy.
/// In process, with the PTY runner and the private folder's roots faked (as <see cref="RunFileTokenTests"/> does).
/// </summary>
public sealed class ApplyMultiLineRunTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _configDir;
    private readonly string _work;
    private readonly string _xdg;
    private readonly string _tmpRoot;
    private readonly byte[] _testKey =
        Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
    private readonly CapturingPty _pty = new();
    private readonly FilledFilesEnvironment _env;

    internal const string Pem = "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEw\nggE9AgEAAkEAq7BFUpkGp3+Gz8XxKE0VYg9N\n-----END PRIVATE KEY-----";
    internal const string PemEscaped = @"-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEw\nggE9AgEAAkEAq7BFUpkGp3+Gz8XxKE0VYg9N\n-----END PRIVATE KEY-----";

    public ApplyMultiLineRunTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "tswap-applyml-test-" + Guid.NewGuid().ToString("N")[..8]);
        _configDir = Path.Combine(_tempDir, "config");
        _work = Path.Combine(_tempDir, "work");
        _xdg = Path.Combine(_tempDir, "xdg");
        _tmpRoot = Path.Combine(_tempDir, "tmp");
        foreach (var dir in new[] { _configDir, _work, _xdg, _tmpRoot })
            Directory.CreateDirectory(dir);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(_xdg, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        _env = FilledFilesEnvironment.FromSystem() with
        {
            XdgRuntimeDir = _xdg,
            TempRoot = _tmpRoot,
            CurrentDirectory = _work,
            RegisterSignals = _ => new Nothing(),
            SignalChildren = _ => 0,
        };

        Assert.Equal(0, Run("init", "--yubikey").Exit);
        Ingest("pem", Pem);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private sealed class Nothing : IDisposable
    {
        public void Dispose() { }
    }

    /// <summary>Records how often a child started and what it read from its copy; prints nothing.</summary>
    private sealed class CapturingPty : IPtyRunner
    {
        public Action<string[]>? During { get; set; }
        public int Starts { get; private set; }

        public int Run(string[] argv, IReadOnlyList<StreamReplacement> replacements) =>
            Run(argv, replacements, new RedactionOptions());

        public int Run(string[] argv, IReadOnlyList<StreamReplacement> replacements, RedactionOptions options)
        {
            Starts++;
            During?.Invoke(argv);
            return 0;
        }
    }

    private (int Exit, string Out, string Err) Run(params string[] args)
    {
        var console = new FakeConsole();
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _configDir, Verbose = false, CommandArgs = args };
        var storage = VaultStores.Open(_configDir, warnings: console.Error);
        var yubiKeys = new TestKeyYubiKeyService(_testKey);
        var unlocker = new VaultUnlocker(yubiKeys, overrideKey: _testKey);
        var ctx = new CommandContext(console, env, storage, yubiKeys, unlocker, _testKey, SudoBypass: true)
        {
            PtyRunner = () => _pty,
            FilledFilesEnvironment = _env,
        };
        var exit = CliRunner.Run(ctx, env.CommandArgs);
        return (exit, console.OutText, console.ErrorText);
    }

    private void Ingest(string name, string value)
    {
        var (exit, _, err) = RunWithStdin(value, "ingest", name);
        Assert.True(exit == 0, err);
    }

    private (int Exit, string Out, string Err) RunWithStdin(string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _configDir, Verbose = false, CommandArgs = args };
        var yubiKeys = new TestKeyYubiKeyService(_testKey);
        var ctx = new CommandContext(console, env, VaultStores.Open(_configDir, warnings: console.Error), yubiKeys,
            new VaultUnlocker(yubiKeys, overrideKey: _testKey), _testKey, SudoBypass: true);
        var exit = CliRunner.Run(ctx, env.CommandArgs);
        return (exit, console.OutText, console.ErrorText);
    }

    private void WriteFile(string relative, string content) => File.WriteAllText(Path.Combine(_work, relative), content);

    private string CopyPath(string[] argv) =>
        argv.Single(a => a.StartsWith(_xdg, StringComparison.Ordinal) || a.StartsWith(_tmpRoot, StringComparison.Ordinal));

    private IEnumerable<string> FilesUnderRunRoots() =>
        new[] { _xdg, _tmpRoot }.SelectMany(root => Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories));

    [Fact]
    public void RunFileToken_MultiLineValue_FilledLineIsOneLineWithTheEscapedForm()
    {
        WriteFile("values.yaml", "tls:\n  key: \"\"  # tswap: pem\n  name: app\n");
        string? copy = null;
        _pty.During = argv => copy = File.ReadAllText(CopyPath(argv));

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal($"tls:\n  key: \"{PemEscaped}\"  # tswap: pem\n  name: app\n", copy);
        var line = copy!.Split('\n')[1];
        Assert.Equal(Pem, DoubleQuotedTestDecoder.Decode(ApplyMultiLineTests.QuotedPart(line, "  key: \"")));
    }
}
