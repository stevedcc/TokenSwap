using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using RedactingPty;
using TswapCli;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using TswapCore.Vault;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Issue #251, task 1: <c>run</c> learns the <c>{{@path}}</c> file token. tswap fills the file's
/// <c># tswap:</c> markers into a private, user-only folder, hands the child that copy's path and
/// redacts every form of every value it wrote from the child's output. In-process: the PTY runner is
/// faked through <see cref="CommandContext.PtyRunner"/> (it streams the "child's" output through the
/// real <see cref="StreamRedactor"/>, as every RedactingPty runner does), and the private folder's
/// seams (names, stat, euid, signals, cleanup steps) through <see cref="FilledFilesEnvironment"/>.
/// </summary>
public sealed class RunFileTokenTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly string _tempDir;
    private readonly string _configDir;
    private readonly string _work;
    private readonly string _xdg;
    private readonly string _tmpRoot;
    private readonly byte[] _testKey =
        Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
    private readonly FakePty _pty = new();
    private readonly List<CleanupStep> _cleanup = [];
    private readonly Dictionary<string, byte[]> _onDiskAtZeroing = [];
    private readonly List<int> _forwarded = [];
    private readonly ManualResetEventSlim _forwardedEvent = new();
    private Action<int>? _signalHandler;
    private FilledFilesEnvironment _env;

    private const string Value = "s3cr3t-db-value-123";

    public RunFileTokenTests(ITestOutputHelper output)
    {
        _output = output;
        _tempDir = Path.Combine(Path.GetTempPath(), "tswap-runfile-test-" + Guid.NewGuid().ToString("N")[..8]);
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
            RegisterSignals = handler =>
            {
                _signalHandler = handler;
                return new Unregister(() => _signalHandler = null);
            },
            SignalChildren = signal =>
            {
                lock (_forwarded)
                    _forwarded.Add(signal);
                _forwardedEvent.Set();
                return 1;
            },
            Recorder = step =>
            {
                if (step.Kind == CleanupKind.Zeroed)
                    _onDiskAtZeroing[step.Path] = File.ReadAllBytes(step.Path);
                _cleanup.Add(step);
            },
        };

        Assert.Equal(0, Run("init", "--yubikey").Exit);
        Ingest("db-pw", Value);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private sealed class Unregister(Action action) : IDisposable
    {
        public void Dispose() => action();
    }

    /// <summary>
    /// A stand-in for RedactingPty's runners: records argv, runs <see cref="During"/> while "the child
    /// runs", and streams the child's output (<see cref="Child"/>) through <see cref="StreamRedactor"/>
    /// in chunks of <see cref="ChunkSize"/> characters, with <c>\n</c> turned into <c>\r\n</c> first
    /// when <see cref="CrLf"/> is set (a PTY's output translation).
    /// </summary>
    private sealed class FakePty : IPtyRunner
    {
        public Func<string[], string> Child { get; set; } = _ => "";
        public Action<string[]>? During { get; set; }
        public int ExitCode { get; set; }
        public int ChunkSize { get; set; } = 4096;
        public bool CrLf { get; set; }
        public string[]? Argv { get; private set; }
        public int Starts { get; private set; }
        public StringBuilder Output { get; } = new();

        public int Run(string[] argv, IReadOnlyList<StreamReplacement> replacements)
        {
            Starts++;
            Argv = argv;
            During?.Invoke(argv);
            var raw = Child(argv);
            if (CrLf)
                raw = raw.Replace("\r\n", "\n").Replace("\n", "\r\n");
            var redactor = new StreamRedactor(replacements);
            for (var i = 0; i < raw.Length; i += ChunkSize)
                Output.Append(redactor.ProcessChunk(raw.Substring(i, Math.Min(ChunkSize, raw.Length - i))));
            Output.Append(redactor.Flush());
            return ExitCode;
        }
    }

    private (int Exit, string Out, string Err) Run(params string[] args)
    {
        var console = new FakeConsole();
        var (verbose, commandArgs) = CliEnvironment.SplitGlobalFlags(args);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _configDir, Verbose = verbose, CommandArgs = commandArgs };
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
        var console = new FakeConsole(value);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _configDir, Verbose = false, CommandArgs = ["ingest", name] };
        var storage = VaultStores.Open(_configDir, warnings: console.Error);
        var yubiKeys = new TestKeyYubiKeyService(_testKey);
        var ctx = new CommandContext(console, env, storage, yubiKeys, new VaultUnlocker(yubiKeys, overrideKey: _testKey), _testKey, SudoBypass: true);
        Assert.True(CliRunner.Run(ctx, env.CommandArgs) == 0, console.ErrorText);
    }

    // The vault as a command sees it (the same unlock as Run's context).
    private SecretsDb Db()
    {
        var console = new FakeConsole();
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _configDir, Verbose = false, CommandArgs = [] };
        var yubiKeys = new TestKeyYubiKeyService(_testKey);
        var ctx = new CommandContext(console, env, VaultStores.Open(_configDir), yubiKeys,
            new VaultUnlocker(yubiKeys, overrideKey: _testKey), _testKey, SudoBypass: true);
        return ctx.LoadSecrets(ctx.Unlock(ctx.Storage.LoadConfig()));
    }

    private string WriteFile(string relative, string content)
    {
        var path = Path.Combine(_work, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private const string ValuesYaml = "db:\n  password: \"\"  # tswap: db-pw\n  user: app\n";

    private IEnumerable<string> RunFolders() =>
        new[] { _xdg, _tmpRoot }.SelectMany(root => Directory.EnumerateDirectories(root, "tswap-run-*"));

    private IEnumerable<string> CopyPaths(string[] argv) =>
        argv.Where(a => a.StartsWith(_xdg, StringComparison.Ordinal) || a.StartsWith(_tmpRoot, StringComparison.Ordinal));

    private string CopyPath(string[] argv) => CopyPaths(argv).Single();

    /// <summary>The copy's run folder: <c>&lt;root&gt;/tswap-run-…/&lt;n&gt;/&lt;file&gt;</c>.</summary>
    private static string RunFolderOf(string copy) => Path.GetDirectoryName(Path.GetDirectoryName(copy)!)!;

    private static string Base64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
    private static string Base64Url(string s) => Base64(s).Replace('+', '-').Replace('/', '_');

    // ------------------------------------------------------------------ the filled copy

    [Fact]
    public void RunFileToken_ChildGetsTheFilledFile()
    {
        WriteFile("values.yaml", ValuesYaml);
        string? seen = null;
        _pty.During = argv => seen = File.ReadAllText(CopyPath(argv));

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["helm", "template", "-f"], _pty.Argv![..3]);
        Assert.True(Path.IsPathRooted(_pty.Argv[3]), _pty.Argv[3]);
        Assert.Equal("values.yaml", Path.GetFileName(_pty.Argv[3]));
        Assert.Equal(Apply.ApplySecrets(ValuesYaml, Db()), seen);
        Assert.Contains(Value, seen);
    }

    [Fact]
    public void RunFileToken_ChildOutputIsRedacted()
    {
        WriteFile("values.yaml", ValuesYaml);
        _pty.Child = argv => File.ReadAllText(CopyPath(argv));

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        var output = _pty.Output.ToString();
        Assert.Contains("password: \"[REDACTED: db-pw]\"", output);
        Assert.DoesNotContain(Value, output);
    }

    [Fact]
    public void RunFileToken_EscapedValueIsRedacted()
    {
        const string value = "pa\"ss\\word-xyz";
        const string escaped = "pa\\\"ss\\\\word-xyz";
        Ingest("esc", value);
        WriteFile("values.yaml", "password: \"\"  # tswap: esc\n");
        string? copy = null;
        _pty.Child = argv => (copy = File.ReadAllText(CopyPath(argv))) + "\nraw: " + value + "\n";

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Contains(escaped, copy); // the file really holds the escaped form
        var output = _pty.Output.ToString();
        Assert.DoesNotContain(escaped, output);
        Assert.DoesNotContain(value, output);
        Assert.Contains("[REDACTED: esc]", output);
    }

    [Fact]
    public void RunFileToken_SingleQuotedAndDoubleQuotedFormsRedacted()
    {
        const string value = "a\"b'c\\d-secret";
        const string doubleQuoted = "a\\\"b'c\\\\d-secret";
        const string singleQuoted = "a\"b''c\\d-secret";
        Ingest("quoted", value);
        WriteFile("values.yaml", "p1: \"\"  # tswap: quoted\np2: ''  # tswap: quoted\n");
        string? copy = null;
        _pty.Child = argv => (copy = File.ReadAllText(CopyPath(argv))) + "\nraw: " + value + "\n";

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Contains(doubleQuoted, copy);
        Assert.Contains(singleQuoted, copy);
        var output = _pty.Output.ToString();
        Assert.DoesNotContain(value, output);
        Assert.DoesNotContain(doubleQuoted, output);
        Assert.DoesNotContain(singleQuoted, output);
        Assert.Contains("p1: \"[REDACTED: quoted]\"", output);
        Assert.Contains("p2: '[REDACTED: quoted]'", output);
    }

    [Fact]
    public void RunFileToken_Base64OfValueRedacted()
    {
        // '>' and '?' give '+' and '/' in base64, and the length gives padding, so all four forms differ.
        const string value = "db>>pass??word~~1";
        Ingest("b64", value);
        Assert.Contains("=", Base64(value));
        Assert.NotEqual(Base64(value), Base64Url(value));
        WriteFile("values.yaml", "password: \"\"  # tswap: b64\n");
        _pty.Child = _ => $"data:\n  a: {Base64(value)}\n  b: {Base64(value).TrimEnd('=')}\n  c: {Base64Url(value)}\n  d: {Base64Url(value).TrimEnd('=')}\n";

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        var output = _pty.Output.ToString();
        foreach (var form in new[] { Base64(value), Base64(value).TrimEnd('='), Base64Url(value), Base64Url(value).TrimEnd('=') })
            Assert.DoesNotContain(form, output);
        foreach (var key in new[] { "a", "b", "c", "d" })
            Assert.Contains($"  {key}: [REDACTED: b64]", output);
    }

    [Fact]
    public void Run_NameToken_Base64Redacted()
    {
        const string value = "db>>pass??word~~1";
        Ingest("b64", value);
        _pty.Child = _ => $"a: {Base64(value)}\nb: {Base64(value).TrimEnd('=')}\nc: {Base64Url(value)}\nd: {Base64Url(value).TrimEnd('=')}\n";

        var (exit, _, err) = Run("run", "mytool", "--password={{b64}}");

        Assert.True(exit == 0, err);
        var output = _pty.Output.ToString();
        foreach (var form in new[] { Base64(value), Base64(value).TrimEnd('='), Base64Url(value), Base64Url(value).TrimEnd('=') })
            Assert.DoesNotContain(form, output);
        foreach (var key in new[] { "a", "b", "c", "d" })
            Assert.Contains($"{key}: [REDACTED: b64]", output);
    }

    [Fact]
    public void RunFileToken_MultiLineValueRedacted()
    {
        const string body1 = "MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEwggE9AgEAAkEAq7BFUpkGp3";
        const string body2 = "+Gz8XxKE0VYg9NdOzSgEsdrVbOdCD1wb1Z3Q3aDdYXr8Zg3vIfLQ==";
        const string value = "-----BEGIN PRIVATE KEY-----\n" + body1 + "\n" + body2 + "\n-----END PRIVATE KEY-----";
        Ingest("pem", value);
        WriteFile("values.yaml", "key: \"\"  # tswap: pem\n");
        var crlfValue = value.Replace("\n", "\r\n");
        _pty.CrLf = true;
        _pty.ChunkSize = 7; // every form straddles several relay chunks
        _pty.Child = argv => File.ReadAllText(CopyPath(argv)) + "\nb64: " + Base64(crlfValue) + "\nraw: " + value + "\n";

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        var output = _pty.Output.ToString();
        Assert.DoesNotContain(body1, output);
        Assert.DoesNotContain(body2, output);
        Assert.DoesNotContain(Base64(crlfValue)[..40], output);
        Assert.Contains("key: \"[REDACTED: pem]\"", output);
        Assert.Contains("b64: [REDACTED: pem]", output);
        Assert.Contains("raw: [REDACTED: pem]", output);
    }

    [Fact]
    public void RunFileToken_BurnedValueWarns()
    {
        WriteFile("values.yaml", ValuesYaml);
        Assert.Equal(0, Run("burn", "db-pw", "seen in a log").Exit);

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.Equal(0, exit);
        Assert.Contains("Warning: Secret 'db-pw' is burned (line 2)", err);
    }

    [Fact]
    public void RunFileToken_VerboseLineMasksFileTokens()
    {
        WriteFile("values.yaml", ValuesYaml);

        var (exit, stdout, err) = Run("-v", "run", "helm", "template", "-f", "{{@values.yaml}}", "--set", "pw={{db-pw}}");

        Assert.True(exit == 0, err);
        Assert.Contains("Executing: helm template -f ******** --set pw=********", stdout);
        Assert.Contains("Found files: values.yaml", stdout);
        Assert.DoesNotContain("tswap-run-", stdout);
    }

    // ------------------------------------------------------------------ the private folder

    [Fact]
    public void RunFileToken_FolderIsPrivate()
    {
        if (OperatingSystem.IsWindows())
        {
            _output.WriteLine("SKIPPED: Unix modes and owners; Windows has RunFileToken_WindowsFolderAclIsCurrentUserOnly.");
            return;
        }
        WriteFile("values.yaml", ValuesYaml);
        var euid = new UnixOwnership().EffectiveUid;
        (BrokerNative.EntryType, UnixFileMode, uint)? folder = null, sub = null, file = null;
        string? copy = null;
        _pty.During = argv =>
        {
            copy = CopyPath(argv);
            folder = BrokerNative.LStat(RunFolderOf(copy));
            sub = BrokerNative.LStat(Path.GetDirectoryName(copy)!);
            file = BrokerNative.LStat(copy);
        };

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        const UnixFileMode rwx = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Assert.Equal((BrokerNative.EntryType.Directory, rwx, euid), folder);
        Assert.Equal((BrokerNative.EntryType.Directory, rwx, euid), sub);
        Assert.Equal((BrokerNative.EntryType.Regular, UnixFileMode.UserRead | UnixFileMode.UserWrite, euid), file);
        Assert.StartsWith(Path.Combine(_xdg, "tswap-run-"), copy);
        Assert.Matches("^tswap-run-[0-9a-f]{16}$", Path.GetFileName(RunFolderOf(copy!)));
    }

    [Fact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")] // the ACL calls; elsewhere it returns at once
    public void RunFileToken_WindowsFolderAclIsCurrentUserOnly()
    {
        if (!OperatingSystem.IsWindows())
        {
            _output.WriteLine("SKIPPED: Windows ACLs; Unix has RunFileToken_FolderIsPrivate (it runs on CI's windows-latest leg).");
            return;
        }
        WriteFile("values.yaml", ValuesYaml);
        bool? isProtected = null;
        List<(string Sid, AccessControlType Type)> rules = [];
        _pty.During = argv =>
        {
            var security = new DirectoryInfo(RunFolderOf(CopyPath(argv))).GetAccessControl();
            isProtected = security.AreAccessRulesProtected;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                rules.Add((rule.IdentityReference.Value, rule.AccessControlType));
        };

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        Assert.True(isProtected, "inheritance from the parent must be removed");
        var me = WindowsIdentity.GetCurrent().User!.Value;
        Assert.NotEmpty(rules);
        Assert.All(rules, r => Assert.Equal((me, AccessControlType.Allow), r));
    }

    [Fact]
    public void RunFileToken_FolderRemovedAfterSuccess() => FolderRemovedAndZeroed(childExit: 0);

    [Fact]
    public void RunFileToken_ChildFails_FolderRemoved() => FolderRemovedAndZeroed(childExit: 3);

    private void FolderRemovedAndZeroed(int childExit)
    {
        WriteFile("values.yaml", ValuesYaml);
        WriteFile("other.yaml", "token: \"\"  # tswap: db-pw\n");
        List<(string Path, long Length)> copies = [];
        _pty.During = argv => copies.AddRange(CopyPaths(argv).Select(p => (p, new FileInfo(p).Length)));
        _pty.ExitCode = childExit;

        var (exit, _, _) = Run("run", "helm", "template", "-f", "{{@values.yaml}}", "-f", "{{@other.yaml}}");

        Assert.Equal(childExit, exit);
        Assert.Empty(RunFolders());
        Assert.Equal(2, copies.Count);
        foreach (var (path, length) in copies)
        {
            Assert.True(length > 0);
            var zeroed = _cleanup.FindIndex(s => s.Kind == CleanupKind.Zeroed && s.Path == path);
            var deleted = _cleanup.FindIndex(s => s.Kind == CleanupKind.Deleted && s.Path == path);
            Assert.True(zeroed >= 0 && deleted > zeroed, $"{path}: zeroed at {zeroed}, deleted at {deleted}");
            Assert.Equal(length, _cleanup[zeroed].Length);
            Assert.Equal(new byte[length], _onDiskAtZeroing[path]);
            Assert.False(File.Exists(path));
        }
    }

    [Fact]
    public void RunFileToken_StaleFolders_Swept()
    {
        var old = Path.Combine(_tmpRoot, "tswap-run-0123456789abcdef");
        var fresh = Path.Combine(_tmpRoot, "tswap-run-fedcba9876543210");
        foreach (var dir in new[] { old, fresh })
        {
            MakeRunFolder(dir);
            File.WriteAllText(Path.Combine(dir, "1", "values.yaml"), "left over");
        }
        Directory.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddHours(-2));
        Directory.SetLastWriteTimeUtc(fresh, DateTime.UtcNow.AddMinutes(-30));
        WriteFile("values.yaml", ValuesYaml);
        bool? oldGoneAtChildStart = null;
        _pty.During = _ => oldGoneAtChildStart = !Directory.Exists(old);

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        Assert.True(oldGoneAtChildStart, "the stale folder is swept when run starts");
        Assert.True(Directory.Exists(fresh), "a folder younger than an hour is kept");
        Assert.Equal("left over", File.ReadAllText(Path.Combine(fresh, "1", "values.yaml")));
    }

    [Fact]
    public void RunFileToken_SweepSkipsLiveFolder()
    {
        List<IDisposable> locks = [];
        try
        {
            foreach (var root in new[] { _xdg, _tmpRoot })
            {
                foreach (var name in new[] { "tswap-run-1111111111111111", "tswap-run-2222222222222222" })
                {
                    var dir = Path.Combine(root, name);
                    MakeRunFolder(dir);
                    File.WriteAllText(Path.Combine(dir, "1", "values.yaml"), "left over");
                    File.WriteAllText(Path.Combine(dir, ".lock"), "");
                }
                locks.Add(HoldLock(Path.Combine(root, "tswap-run-1111111111111111", ".lock")));
                foreach (var name in new[] { "tswap-run-1111111111111111", "tswap-run-2222222222222222" })
                    Directory.SetLastWriteTimeUtc(Path.Combine(root, name), DateTime.UtcNow.AddHours(-2));
            }
            WriteFile("values.yaml", ValuesYaml);

            var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

            Assert.True(exit == 0, err);
            foreach (var root in new[] { _xdg, _tmpRoot })
            {
                Assert.True(File.Exists(Path.Combine(root, "tswap-run-1111111111111111", "1", "values.yaml")), $"live folder in {root} kept");
                Assert.False(Directory.Exists(Path.Combine(root, "tswap-run-2222222222222222")), $"dead folder in {root} removed");
            }
        }
        finally
        {
            foreach (var l in locks)
                l.Dispose();
        }
    }

    // A run folder as tswap makes it (mode 0700 on Unix: the sweep touches no other), with subfolder 1.
    private static void MakeRunFolder(string dir)
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(Path.Combine(dir, "1"));
            return;
        }
        const UnixFileMode rwx = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Directory.CreateDirectory(dir, rwx);
        Directory.CreateDirectory(Path.Combine(dir, "1"), rwx);
    }

    private static IDisposable HoldLock(string path)
    {
        if (OperatingSystem.IsWindows())
            return new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var stream = UnixLockFile.TryTake(path, out var held);
        Assert.False(held);
        return stream!;
    }

    [Fact]
    public void RunFileToken_PrecreatedFolderOrSymlinkRefused()
    {
        WriteFile("values.yaml", ValuesYaml);
        var taken = Path.Combine(_xdg, "tswap-run-aaaaaaaaaaaaaaaa");
        Directory.CreateDirectory(taken);
        Queue<string> names = new(["tswap-run-aaaaaaaaaaaaaaaa", "tswap-run-bbbbbbbbbbbbbbbb"]);
        _env = _env with { NewFolderName = () => names.Dequeue() };
        string? copy = null;
        _pty.During = argv => copy = CopyPath(argv);

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Equal(Path.Combine(_xdg, "tswap-run-bbbbbbbbbbbbbbbb"), RunFolderOf(copy!));
        Assert.Empty(Directory.EnumerateFileSystemEntries(taken));

        if (OperatingSystem.IsWindows())
        {
            _output.WriteLine("SKIPPED (the rest): symlinks and the Unix stat seam.");
            return;
        }

        // A symlink at the first name is never written through.
        var target = Path.Combine(_tempDir, "target");
        Directory.CreateDirectory(target);
        Directory.CreateSymbolicLink(Path.Combine(_xdg, "tswap-run-cccccccccccccccc"), target);
        names = new(["tswap-run-cccccccccccccccc", "tswap-run-dddddddddddddddd"]);
        (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");
        Assert.True(exit == 0, err);
        Assert.Equal(Path.Combine(_xdg, "tswap-run-dddddddddddddddd"), RunFolderOf(copy!));
        Assert.Empty(Directory.EnumerateFileSystemEntries(target));

        // A group-writable or foreign-owned $XDG_RUNTIME_DIR falls back to the temp root.
        var euid = new UnixOwnership().EffectiveUid;
        foreach (var (mode, uid) in new[]
                 {
                     (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupWrite, euid),
                     (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, euid + 1),
                 })
        {
            _env = _env with
            {
                NewFolderName = FilledFilesEnvironment.FromSystem().NewFolderName,
                Stat = path => path == _xdg ? (BrokerNative.EntryType.Directory, mode, uid) : BrokerNative.LStat(path),
            };
            (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");
            Assert.True(exit == 0, err);
            Assert.Equal(_tmpRoot, Path.GetDirectoryName(RunFolderOf(copy!)));
        }
    }

    // ------------------------------------------------------------------ paths

    [Fact]
    public void RunFileToken_PathForms()
    {
        WriteFile("values.yaml", ValuesYaml);
        WriteFile("my values.yaml", "token: \"\"  # tswap: db-pw\n");
        Directory.CreateDirectory(Path.Combine(_work, "sub"));
        _env = _env with { CurrentDirectory = Path.Combine(_work, "sub") };
        Dictionary<string, string> contents = [];
        _pty.During = argv =>
        {
            foreach (var p in CopyPaths(argv))
                contents[p] = File.ReadAllText(p);
        };

        var (exit, _, err) = Run("run", "helm", "template",
            "-f", "{{@../values.yaml}}", "-f", "{{@../my values.yaml}}", "-f", "{{@../sub/../values.yaml}}", "--set", "pw={{db-pw}}");

        Assert.True(exit == 0, err);
        var argv = _pty.Argv!;
        Assert.Equal(argv[3], argv[7]); // the same file twice: one copy
        Assert.NotEqual(argv[3], argv[5]);
        Assert.Equal("my values.yaml", Path.GetFileName(argv[5]));
        Assert.Equal(2, contents.Count);
        Assert.Equal(Apply.ApplySecrets(ValuesYaml, Db()), contents[argv[3]]);
        Assert.Equal(Apply.ApplySecrets("token: \"\"  # tswap: db-pw\n", Db()), contents[argv[5]]);
        Assert.Equal($"pw={Value}", argv[9]);
        Assert.Equal(RunFolderOf(argv[3]), RunFolderOf(argv[5])); // one run folder, one subfolder per file
        Assert.NotEqual(Path.GetDirectoryName(argv[3]), Path.GetDirectoryName(argv[5]));
    }

    [Fact]
    public void RunFileToken_SameBaseNameTwoFiles()
    {
        WriteFile(Path.Combine("a", "values.yaml"), "a: \"\"  # tswap: db-pw\n");
        WriteFile(Path.Combine("b", "values.yaml"), "b: ''  # tswap: db-pw\n");
        Dictionary<string, string> contents = [];
        _pty.During = argv =>
        {
            foreach (var p in CopyPaths(argv))
                contents[p] = File.ReadAllText(p);
        };

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@a/values.yaml}}", "-f", "{{@b/values.yaml}}");

        Assert.True(exit == 0, err);
        var argv = _pty.Argv!;
        Assert.NotEqual(argv[3], argv[5]);
        Assert.Equal("values.yaml", Path.GetFileName(argv[3]));
        Assert.Equal("values.yaml", Path.GetFileName(argv[5]));
        Assert.Equal($"a: \"{Value}\"  # tswap: db-pw\n", contents[argv[3]]);
        Assert.Equal($"b: '{Value}'  # tswap: db-pw\n", contents[argv[5]]);
    }

    [Fact]
    public void RunFileToken_ValueContainingFileTokenIsText()
    {
        Ingest("looks-like-file", "{{@/etc/passwd}}");
        WriteFile("values.yaml", ValuesYaml);

        var (exit, _, err) = Run("run", "mytool", "--opt={{looks-like-file}}", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        var argv = _pty.Argv!;
        Assert.Equal("--opt={{@/etc/passwd}}", argv[1]);
        Assert.Single(CopyPaths(argv));
        Assert.Equal("values.yaml", Path.GetFileName(argv[3]));
    }

    // ------------------------------------------------------------------ refusals

    public static TheoryData<string, string, string> RefusalCases => new()
    {
        { "missing.yaml", "", "not found" },
        { "values.yaml", "plain: text\n", "no '# tswap:' markers" },
        { "values.yaml", "password: \"\"  # tswap: no-such-secret\n", "'no-such-secret' not found" },
        { "values.yaml", "password: \"\"  # tswap: db-pw:bogus\n", "Unknown marker" },
    };

    [Theory]
    [MemberData(nameof(RefusalCases))]
    public void RunFileToken_Refusals_WriteNothing(string file, string content, string expected)
    {
        if (file != "missing.yaml")
            WriteFile(file, content);
        WriteFile("good.yaml", ValuesYaml); // a good file first: nothing of it is written either

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@good.yaml}}", "-f", "{{@" + file + "}}");

        Assert.NotEqual(0, exit);
        Assert.Contains(expected, err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    [Fact]
    public void RunFileToken_BlocklistStillApplies()
    {
        WriteFile("f", ValuesYaml);

        var (exit, _, err) = Run("run", "sh", "-c", "cat {{@f}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("'sh -c' runs inline code", err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    public static TheoryData<string> PrinterWords => new()
    {
        "cat", "echo", "printf", "tee", "base64", "base32", "basenc", "xxd", "od", "hexdump", "hd", "strings",
        "uuencode", "iconv", "cp", "mv", "dd", "rsync", "scp", "tar", "zip", "gzip", "bzip2", "xz",
        "zstd", "openssl", "gpg", "less", "more", "head", "tail", "nl", "sort", "uniq", "rev", "tac", "split", "ln",
        "certutil",
    };

    [Theory]
    [MemberData(nameof(PrinterWords))]
    public void RunFileToken_EncodersAndCopiersRefused(string word)
    {
        WriteFile("values.yaml", ValuesYaml);

        var (exit, _, err) = Run("run", "mytool", word, "{{@values.yaml}}");

        Assert.NotEqual(0, exit);
        Assert.Contains($"'{word}'", err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    [Theory]
    [InlineData("bash", "'bash'")]
    [InlineData("python3", "'python3'")]
    [InlineData(null, "program")]
    public void RunFileToken_FileAsProgramOrScriptRefused(string? program, string expected)
    {
        WriteFile("values.yaml", ValuesYaml);
        string[] command = program is null ? ["run", "{{@values.yaml}}"] : ["run", program, "{{@values.yaml}}"];

        var (exit, _, err) = Run(command);

        Assert.NotEqual(0, exit);
        Assert.Contains(expected, err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    [Fact]
    public void RunFileToken_EncodersAndCopiersRefused_FileNamedLikeAPrinter()
    {
        WriteFile("cat", ValuesYaml);

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@cat}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("'cat'", err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    [Theory]
    [InlineData("env base64 {{@f}}", "'env'")]
    [InlineData("timeout 5 cat {{@f}}", "'cat'")]
    [InlineData("nice -n 10 cp {{@f}} /tmp/x", "'cp'")]
    [InlineData("env -u FOO base64 {{@f}}", "'env'")]
    [InlineData("xargs cat {{@f}}", "'xargs'")]
    [InlineData("busybox base64 {{@f}}", "'busybox'")]
    public void RunFileToken_WrappersLookedThrough(string command, string named)
    {
        WriteFile("f", ValuesYaml);

        var (exit, _, err) = Run(["run", .. command.Split(' ')]);

        Assert.NotEqual(0, exit);
        Assert.Contains(named, err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    [Theory]
    [InlineData("nice -n 10 helm template -f {{@f}}")]
    [InlineData("timeout 60 helm template -f {{@f}}")]
    public void RunFileToken_WrappersLookedThrough_HelmAllowed(string command)
    {
        WriteFile("f", ValuesYaml);
        string? seenCopy = null;
        _pty.During = argv => seenCopy = File.ReadAllText(CopyPath(argv));

        var (exit, _, err) = Run(["run", .. command.Split(' ')]);

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Equal(Apply.ApplySecrets(ValuesYaml, Db()), seenCopy);
    }

    // Controller ruling (review of task 1, Important 1): 'install' copies files as the program, but
    // as an argument it is Helm's headline subcommand.
    [Fact]
    public void RunFileToken_InstallAsArgumentAllowed()
    {
        WriteFile("values.yaml", ValuesYaml);
        string? copy = null;
        _pty.During = argv => copy = File.ReadAllText(CopyPath(argv));

        var (exit, _, err) = Run("run", "helm", "install", "app", "./chart", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["helm", "install", "app", "./chart", "-f"], _pty.Argv![..5]);
        Assert.Equal(Apply.ApplySecrets(ValuesYaml, Db()), copy);
    }

    [Theory]
    [InlineData("install {{@f}} /tmp/x")]
    [InlineData("nice -n 5 install {{@f}} /tmp/x")]
    [InlineData("timeout 5 install -m 600 {{@f}} /tmp/x")]
    [InlineData("/usr/bin/install {{@f}} /tmp/x")]
    public void RunFileToken_InstallAsProgramRefused(string command)
    {
        WriteFile("f", ValuesYaml);

        var (exit, _, err) = Run(["run", .. command.Split(' ')]);

        Assert.NotEqual(0, exit);
        Assert.Contains("'install'", err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    // Review minor 1: the word check also sees what {{name}} tokens expand to, so a secret whose value
    // is 'base64' can't stand in for the program. The refusal doesn't repeat the value.
    [Theory]
    [InlineData("{{prog}} {{@values.yaml}}")]
    [InlineData("mytool {{prog}} {{@values.yaml}}")]
    public void RunFileToken_SubstitutedValueIsAPrinter_Refused(string command)
    {
        Ingest("prog", "base64");
        WriteFile("values.yaml", ValuesYaml);

        var (exit, _, err) = Run(["run", .. command.Split(' ')]);

        Assert.NotEqual(0, exit);
        Assert.Contains("value of a {{name}} token", err);
        Assert.DoesNotContain("base64", err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    [Fact]
    public void RunFileToken_UnreadableSourceRefused()
    {
        if (OperatingSystem.IsWindows() || new UnixOwnership().EffectiveUid == 0)
        {
            _output.WriteLine("SKIPPED: needs Unix permissions that bind (not root).");
            return;
        }
        var path = WriteFile("values.yaml", ValuesYaml);
        File.SetUnixFileMode(path, UnixFileMode.None);

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("Can't read 'values.yaml'", err);
        Assert.DoesNotContain("Unhandled", err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    [Fact]
    public void SubstituteAllTokensInArgs_NulValueIsATswapRefusal()
    {
        var ex = Assert.Throws<TswapException>(() => Validation.SubstituteAllTokensInArgs(
            ["cmd", "{{tok}}"], new Dictionary<string, string> { ["tok"] = "va\0lue" }, new Dictionary<string, string>()));
        Assert.Contains("'tok'", ex.Message);
    }

    [Theory]
    [InlineData("python3 x.py {{@f}}", "'python3'")]
    [InlineData("awk {print} {{@f}}", "'awk'")]
    [InlineData("sed y/a/A/ {{@f}}", "'sed'")]
    public void RunFileToken_InterpreterAnywhereRefused(string command, string named)
    {
        WriteFile("f", ValuesYaml);

        var (exit, _, err) = Run(["run", .. command.Split(' ')]);

        Assert.NotEqual(0, exit);
        Assert.Contains(named, err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    [Fact]
    public void RunFileToken_AsRootRefused()
    {
        if (OperatingSystem.IsWindows())
        {
            _output.WriteLine("SKIPPED: an elevated Windows tswap is allowed (the per-user temp folder and the ACL keep it private).");
            return;
        }
        WriteFile("values.yaml", ValuesYaml);
        _env = _env with { EffectiveUid = () => 0 };

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("as your own user", err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
    }

    [Theory]
    [InlineData(new[] { "true", "{{@}}" }, "{{@}}")]
    [InlineData(new[] { "true", "{{@va{lues}}" }, "{{@va{lues}}")]
    [InlineData(new[] { "true", "{{@values.yaml" }, "{{@values.yaml")]
    [InlineData(new[] { "helm", "upgrade", "app", "./chart", "-f", "{{@va{lues}}", "{{name}}" }, "{{@va{lues}}")]
    public void RunFileToken_EmptyOrNestedTokenRefused(string[] command, string token)
    {
        var (exit, _, err) = Run(["run", .. command]);

        Assert.NotEqual(0, exit);
        Assert.Contains($"file token '{token}", err);
        Assert.DoesNotContain("No {{tokens}}", err);
        Assert.DoesNotContain("not found", err);
        Assert.Equal(0, _pty.Starts);
    }

    // ------------------------------------------------------------------ signals

    [Fact]
    public void RunFileToken_InterruptRemovesFolder()
    {
        WriteFile("values.yaml", ValuesYaml);
        bool? copyStillThereAfterForwarding = null;
        _pty.During = argv =>
        {
            _signalHandler!(2); // SIGINT while the child runs
            Assert.True(_forwardedEvent.Wait(TimeSpan.FromSeconds(10)), "the signal reaches the child's process group");
            copyStillThereAfterForwarding = File.Exists(CopyPath(argv));
        };
        _pty.ExitCode = 1; // the child handled SIGINT and exited 1: its own code, not 128 + 2, is tswap's

        var (exit, _, _) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.Equal(1, exit);
        lock (_forwarded)
            Assert.Equal([2], _forwarded);
        Assert.True(copyStillThereAfterForwarding, "cleanup waits for the child to exit");
        Assert.Empty(RunFolders());
        Assert.Contains(_cleanup, s => s.Kind == CleanupKind.Zeroed);
    }

    [Fact]
    public void RunFileToken_SignalBeforeTheChildStarts_NoChildAndFolderRemoved()
    {
        if (OperatingSystem.IsWindows())
        {
            _output.WriteLine("SKIPPED: the stat seam is Unix-only.");
            return;
        }
        WriteFile("values.yaml", ValuesYaml);
        // A signal that arrives once the folder exists but before the child starts: the stat seam
        // runs on the copy's subfolder, after the run folder was made.
        var fired = false;
        _env = _env with
        {
            Stat = path =>
            {
                if (!fired && Path.GetFileName(path) == "1")
                {
                    fired = true;
                    _signalHandler!(15);
                }
                return BrokerNative.LStat(path);
            },
        };

        var (exit, _, _) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(fired);
        Assert.Equal(128 + 15, exit);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(RunFolders());
        Assert.Empty(_forwarded);
    }

    // Review minor 4: on Windows the console's close, logoff and shutdown events end tswap once the
    // handler returns, so the handler kills the child and cleans up before it returns.
    [Fact]
    public void RunFileToken_ProcessEndingSignal_CleansUpBeforeTheHandlerReturns()
    {
        WriteFile("values.yaml", ValuesYaml);
        _env = _env with { SignalEndsProcess = signal => signal == 1, ChildGrace = TimeSpan.FromMilliseconds(100) };
        bool? copyGoneWhenHandlerReturned = null;
        _pty.During = argv =>
        {
            var copy = CopyPath(argv);
            _signalHandler!(1);
            copyGoneWhenHandlerReturned = !File.Exists(copy);
        };

        Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(copyGoneWhenHandlerReturned, "the copy is removed inside the handler");
        lock (_forwarded)
            Assert.Contains(9, _forwarded);
        Assert.Empty(RunFolders());
    }

    // Review minor 10: the sweep only touches a stale folder that is the user's own 0700 one, and it
    // never zeroes through a hard link (it only unlinks it).
    [Fact]
    public void RunFileToken_SweepSkipsOpenFolderAndNeverZeroesThroughHardLinks()
    {
        if (OperatingSystem.IsWindows())
        {
            _output.WriteLine("SKIPPED: Unix modes and hard links.");
            return;
        }
        var open = Path.Combine(_tmpRoot, "tswap-run-3333333333333333");
        var linked = Path.Combine(_tmpRoot, "tswap-run-4444444444444444");
        foreach (var dir in new[] { open, linked })
            Directory.CreateDirectory(Path.Combine(dir, "1"));
        File.WriteAllText(Path.Combine(open, "1", "values.yaml"), "left over");
        var victim = Path.Combine(_tempDir, "victim.txt");
        File.WriteAllText(victim, "precious");
        using (var ln = Process.Start("ln", [victim, Path.Combine(linked, "1", "values.yaml")]))
            ln.WaitForExit();
        File.SetUnixFileMode(open, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                                   | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        File.SetUnixFileMode(linked, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        foreach (var dir in new[] { open, linked })
            Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow.AddHours(-2));
        WriteFile("values.yaml", ValuesYaml);

        var (exit, _, err) = Run("run", "helm", "template", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Equal("left over", File.ReadAllText(Path.Combine(open, "1", "values.yaml")));
        Assert.False(Directory.Exists(linked), "a stale private folder is still removed");
        Assert.Equal("precious", File.ReadAllText(victim));
    }
}

/// <summary>
/// Review of task 1: the pieces of <c>run</c>'s signal path that decide whom to signal, without
/// processes (fake snapshots and process groups).
/// </summary>
public sealed class RunFileTokenChildSelectionTests
{
    private static readonly DateTime TswapStart = new(2026, 11, 7, 10, 0, 0, DateTimeKind.Utc);

    // Windows (review Important 2): Toolhelp's parent ids go stale when a parent exits, and pids are
    // reused, so a candidate counts only when it was created after tswap.
    [Fact]
    public void RunFileToken_WindowsChildren_OnlyThoseCreatedAfterTswap()
    {
        (int Pid, int ParentPid)[] snapshot = [(100, 42), (101, 42), (102, 42), (103, 7), (104, 42)];
        Dictionary<int, DateTime?> starts = new()
        {
            [100] = TswapStart.AddSeconds(2),  // tswap's real child
            [101] = TswapStart.AddHours(-3),   // its parent was an earlier process that had pid 42 (pid reuse)
            [102] = null,                      // its start can't be read: not verifiable
            [103] = TswapStart.AddSeconds(5),  // someone else's child
            [104] = TswapStart,                // not later than tswap
        };

        var children = ChildProcesses.SelectWindowsChildren(snapshot, parent: 42, TswapStart, pid => starts[pid]);

        Assert.Equal([100], children);
    }

    // Review minor 3: a child in tswap's own process group, when that group is the terminal's
    // foreground group, already got the terminal's SIGINT (Ctrl+C): never a second one.
    [Theory]
    [InlineData(500, 300, 2, 300, 1)]     // the child leads its own group (PTY): its group, even for SIGINT
    [InlineData(700, 300, 2, 300, -1)]    // in some other group it doesn't lead: the child alone
    [InlineData(300, 300, 2, null, -1)]   // shares tswap's group, no terminal: the child alone
    [InlineData(300, 300, 2, 999, -1)]    // shares tswap's group, which isn't in the foreground: the child alone
    [InlineData(300, 300, 2, 300, 0)]     // shares tswap's foreground group, SIGINT: already delivered
    [InlineData(300, 300, 3, 300, 0)]     // ... SIGQUIT (Ctrl+\) likewise
    [InlineData(300, 300, 15, 300, -1)]   // ... SIGTERM never comes from the terminal: the child alone
    public void RunFileToken_SignalTarget(int childPgid, int ownPgid, int signal, int? foreground, int expected)
    {
        // expected: 1 the child's group, -1 the child alone, 0 none ("already delivered").
        var target = ChildProcesses.Target(pid: 500, childPgid, ownPgid, signal, foreground);

        int? want = expected switch { 0 => null, -1 => 500, _ => -500 };
        Assert.Equal(want, target);
    }
}

/// <summary>
/// The real signal path of <c>run</c> with a file token: the built tswap gets SIGINT while its child
/// holds the filled copy, forwards it, waits for the child and removes the folder.
/// </summary>
[Trait("Category", "E2E")]
public sealed class RunFileTokenEndToEndTests(TswapBinaryFixture binary, ITestOutputHelper output)
    : IClassFixture<TswapBinaryFixture>, IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "tswap-runfile-e2e-" + Guid.NewGuid().ToString("N")[..8]);

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private ProcessStartInfo Psi(string config, string xdg, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = binary.BinaryPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            WorkingDirectory = _tempDir,
        };
        psi.Environment["TSWAP_TEST_KEY"] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        psi.Environment["TSWAP_TEST_SUDO_BYPASS"] = "1";
        psi.Environment["TSWAP_CONFIG_DIR"] = config;
        psi.Environment["XDG_RUNTIME_DIR"] = xdg;
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        return psi;
    }

    private void RunToEnd(ProcessStartInfo psi, string stdin = "")
    {
        using var p = Process.Start(psi)!;
        p.StandardInput.Write(stdin);
        p.StandardInput.Close();
        var err = p.StandardError.ReadToEnd();
        p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, err);
    }

    // A child of pid named name (pgrep: Linux and macOS).
    private static bool HasChildNamed(int pid, string name)
    {
        using var pgrep = Process.Start(new ProcessStartInfo("pgrep", ["-P", pid.ToString(), "-x", name])
            { RedirectStandardOutput = true, UseShellExecute = false })!;
        pgrep.StandardOutput.ReadToEnd();
        pgrep.WaitForExit();
        return pgrep.ExitCode == 0;
    }

    [Fact]
    public async Task RunFileToken_RealSigint_RemovesFolder()
    {
        if (OperatingSystem.IsWindows())
        {
            output.WriteLine("SKIPPED: POSIX signals (Windows has Ctrl+C / Ctrl+Break, not SIGINT from another process).");
            return;
        }
        var config = Path.Combine(_tempDir, "config");
        var xdg = Path.Combine(_tempDir, "xdg");
        Directory.CreateDirectory(config);
        Directory.CreateDirectory(xdg);
        File.SetUnixFileMode(xdg, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var hold = Path.Combine(_tempDir, "hold");
        File.WriteAllText(hold, "#!/bin/sh\nexec sleep 30\n");
        File.SetUnixFileMode(hold, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        File.WriteAllText(Path.Combine(_tempDir, "values.yaml"), "password: \"\"  # tswap: db-pw\n");
        RunToEnd(Psi(config, xdg, "init", "--yubikey"));
        RunToEnd(Psi(config, xdg, "ingest", "db-pw"), "sigint-test-value");

        using var tswap = Process.Start(Psi(config, xdg, "run", hold, "{{@values.yaml}}"))!;
        tswap.StandardInput.Close();
        var stdout = tswap.StandardOutput.ReadToEndAsync();
        var stderr = tswap.StandardError.ReadToEndAsync();
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!HasChildNamed(tswap.Id, "sleep"))
        {
            if (tswap.HasExited)
                Assert.Fail($"tswap exited early ({tswap.ExitCode}): {await stderr}");
            Assert.True(DateTime.UtcNow < deadline, "the child never started");
            await Task.Delay(50);
        }
        Assert.NotEmpty(Directory.EnumerateDirectories(xdg, "tswap-run-*"));

        using (var kill = Process.Start("kill", ["-INT", tswap.Id.ToString()]))
            kill.WaitForExit();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await tswap.WaitForExitAsync(timeout.Token); // throws when tswap doesn't exit once its child has
        var printed = await stdout + await stderr;
        Assert.True(tswap.ExitCode == 130, $"exit {tswap.ExitCode}: {printed}");
        Assert.Empty(Directory.EnumerateDirectories(xdg, "tswap-run-*"));
    }
}
