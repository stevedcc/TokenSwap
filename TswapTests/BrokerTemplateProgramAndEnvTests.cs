using System.Text.Json;
using TswapCore.Broker;
using TswapCore.Broker.Templates;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief I224 D7 H3 and H4 (task 8): a template's program, and <c>bwrap_path</c>, may not live in a
/// template's bind (a container that can write there could replace them); and the env-name denylist
/// grows by the names and prefixes that make an interpreter, library or tool load, trust or write
/// something the template author didn't choose.
/// </summary>
public class BrokerTemplateProgramAndEnvTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly string _root;

    public BrokerTemplateProgramAndEnvTests(ITestOutputHelper output)
    {
        _output = output;
        var root = Path.Combine(Path.GetTempPath(), "tswap-tplprog-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        _root = OperatingSystem.IsWindows() ? root : BrokerNative.RealPath(root) ?? root;
        if (OperatingSystem.IsWindows())
            return;
        File.SetUnixFileMode(_root, Mode755);
        Directory.CreateDirectory(Work);
        File.SetUnixFileMode(Work, Mode755);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, true);
    }

    private static readonly UnixFileMode Mode755 = (UnixFileMode)0b111_101_101;

    /// <summary>A folder a template may bind: this uid's, 0755.</summary>
    private string Work => Path.Combine(_root, "work");

    private static string J(string s) => JsonSerializer.Serialize(s);

    private static BrokerHostContext Host() => new(BrokerHarness.MyUid, [], []);

    private static string Config(string program, string? bind = null, bool rw = false, string? bwrapPath = null, string env = "{}") => $$"""
        {
          "version": 1,
          "socket_dir": "/run/tswap-broker",
          {{(bwrapPath is null ? "" : $"\"bwrap_path\": {J(bwrapPath)},")}}
          "sockets": [ { "name": "lane1", "uid_only": true, "uids": ["100999"], "routes": [], "templates": ["t"] } ],
          "routes": [],
          "templates": [ { "name": "t", "argv": [{{J(program)}}], "env": {{env}},
            "binds": [{{(bind is null ? "" : $$"""{ "path": {{J(bind)}}, "rw": {{(rw ? "true" : "false")}} }""")}}] } ]
        }
        """;

    private static string Refused(string json)
    {
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(json, Host()));
        return ex.Message;
    }

    private static string InsideBind(string program, string bind) =>
        $"template t: program {program} is inside bind {bind}; a program may no longer live in a bind: install it under /usr or ship it in the image";

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private string Tool()
    {
        var tool = Path.Combine(Work, "tool");
        File.WriteAllText(tool, "#!/bin/sh\n");
        File.SetUnixFileMode(tool, Mode755);
        return tool;
    }

    // ------------------------------------------------------------------ H3: the program

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AProgramInsideABind_IsRefused_RwOrReadOnly(bool rw)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var tool = Tool();

        Assert.Equal(InsideBind(tool, Work), Refused(Config(tool, Work, rw)));
    }

    [Fact]
    public void AProgramReachedThroughASymlinkIntoABind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var tool = Tool();
        var link = Path.Combine(_root, "tool-link"); // not in the bind by name; resolves into it
        File.CreateSymbolicLink(link, tool);

        Assert.StartsWith($"template t: program {link} (resolves to {tool}) is inside bind {Work}; a program may no longer live in a bind",
            Refused(Config(link, Work)));
    }

    [Fact]
    public void AProgramThatCanNotBeResolved_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        const string missing = "/usr/bin/tswap-test-no-such-program";
        Assert.False(Path.Exists(missing));

        Assert.Equal($"template t: program {missing} can't be resolved (it must exist on this host, under /usr, /bin, /sbin, /lib or /lib64)",
            Refused(Config(missing, Work)));
    }

    [Fact]
    public void ASystemProgramOutsideTheBinds_IsAccepted()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var t = BrokerPolicy.Parse(Config("/usr/bin/true", Work, rw: true), Host()).Templates["t"];

        Assert.Equal("/usr/bin/true", t.Program);
        Assert.Equal(Work, Assert.Single(t.Binds).Path);
    }

    [Fact]
    public void ABindOverUsr_WithTheProgramInIt_AsksForANarrowerFolder()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Assert.Equal(InsideBind("/usr/bin/true", "/usr") + "; bind /usr covers system programs; bind a narrower folder",
            Refused(Config("/usr/bin/true", "/usr")));
    }

    [Fact]
    public void ABindOverOpt_WithTheProgramInIt_AsksForANarrowerFolder()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        if (BrokerNative.Identify("/opt", follow: false) is not { Uid: 0 } opt
            || (opt.Mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
        {
            _output.WriteLine("SKIPPED: /opt is missing here or not a root-owned 0755 folder, so it can't be a bind");
            return;
        }

        Assert.Equal(InsideBind("/opt/x", "/opt") + "; bind /opt covers system programs; bind a narrower folder",
            Refused(Config("/opt/x", "/opt")));
    }

    // ------------------------------------------------------------------ H3: bwrap_path

    [Fact]
    public void ABwrapPathInsideATemplatesBind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var bwrap = Tool();

        Assert.Equal($"bwrap_path {bwrap} is inside template t's bind {Work}", Refused(Config("/usr/bin/true", Work, bwrapPath: bwrap)));
    }

    [Fact]
    public void AMissingBwrapPathInsideATemplatesBind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var bwrap = Path.Combine(Work, "not-yet", "bwrap");

        Assert.Equal($"bwrap_path {bwrap} is inside template t's bind {Work}", Refused(Config("/usr/bin/true", Work, bwrapPath: bwrap)));
    }

    [Fact]
    public void ABwrapPathReachedThroughASymlinkIntoABind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var link = Path.Combine(_root, "link");
        File.CreateSymbolicLink(link, Work);
        var bwrap = Path.Combine(link, "bwrap"); // missing; its nearest existing ancestor resolves into the bind

        Assert.Equal($"bwrap_path {bwrap} is inside template t's bind {Work}", Refused(Config("/usr/bin/true", Work, bwrapPath: bwrap)));
    }

    [Fact]
    public void ABwrapPathOutsideTheBinds_Loads_AlsoWhenMissing()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var byDefault = BrokerPolicy.Parse(Config("/usr/bin/true", Work), Host());
        Assert.Equal(BrokerPolicy.DefaultBwrapPath, byDefault.BwrapPath);

        var missing = Path.Combine(_root, "no-bwrap");
        var policy = BrokerPolicy.Parse(Config("/usr/bin/true", Work, bwrapPath: missing), Host());
        Assert.Equal(missing, policy.BwrapPath);
    }

    // ------------------------------------------------------------------ H4: the env denylist

    [Theory]
    [InlineData("GCONV_PATH")]
    [InlineData("LOCPATH")]
    [InlineData("NLSPATH")]
    [InlineData("REQUESTS_CA_BUNDLE")]
    [InlineData("NETRC")]
    [InlineData("HOSTALIASES")]
    [InlineData("LOCALDOMAIN")]
    [InlineData("RES_OPTIONS")]
    [InlineData("TMPDIR")]
    [InlineData("HOME")]
    [InlineData("CLASSPATH")]
    [InlineData("SSLKEYLOGFILE")]
    [InlineData("INPUTRC")]
    [InlineData("TERMINFO")]
    [InlineData("TERMINFO_DIRS")]
    [InlineData("MAVEN_OPTS")]
    [InlineData("GRADLE_OPTS")]
    // one name per new prefix
    [InlineData("PYTHONUNBUFFERED")]
    [InlineData("PERL_MM_OPT")]
    [InlineData("RUBY_GC_HEAP_INIT_SLOTS")]
    [InlineData("GEM_HOME")]
    [InlineData("NODE_ENV")]
    [InlineData("DOTNET_CLI_TELEMETRY_OPTOUT")]
    [InlineData("JAVA_HOME")]
    [InlineData("_JAVA_OPTIONS")]
    [InlineData("JDK_JAVA_OPTIONS")]
    [InlineData("OPENSSL_CONF")]
    [InlineData("LUA_PATH")]
    [InlineData("XDG_CONFIG_HOME")]
    [InlineData("SSL_CERT_FILE")]
    [InlineData("CURL_CA_BUNDLE")]
    public void ANewlyDeniedEnvName_IsRefused(string name)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Assert.StartsWith($"Template 't': env may not set {name}: ", Refused(Config("/usr/bin/true", env: $"{{ {J(name)}: \"x\" }}")));
    }

    [Theory]
    [InlineData("LANG", "C.UTF-8")]
    [InlineData("TZ", "UTC")]
    [InlineData("PGPASSWORD", "{{db-pw}}")]
    public void OrdinaryEnvNames_AreStillAccepted(string name, string value)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var t = BrokerPolicy.Parse(Config("/usr/bin/true", env: $"{{ {J(name)}: {J(value)} }}"), Host()).Templates["t"];

        Assert.Equal(name, Assert.Single(t.Env).Name);
    }
}
