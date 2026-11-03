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

    private static BrokerHostContext Host() => new(BrokerHarness.MyUid, [], [], []);

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
    public void AMissingProgramOutsideTheBinds_Loads()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        // Controller ruling: a tool that isn't installed is not a load error (it would take every
        // socket and route offline); the call fails at run time, as before.
        const string missing = "/usr/bin/tswap-test-no-such-program";
        Assert.False(Path.Exists(missing));

        var t = BrokerPolicy.Parse(Config(missing, Work), Host()).Templates["t"];

        Assert.Equal(missing, t.Program);
    }

    [Fact]
    public async Task AMissingProgramOutsideTheBinds_PassesServesValidation()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        const string missing = "/usr/bin/tswap-test-no-such-program";
        await using var h = new BrokerHarness();
        var config = Config(missing, Work).Replace("\"/run/tswap-broker\"", J(h.SocketDir))
            .Replace("\"uids\": [\"100999\"]", $"\"uids\": [\"{BrokerHarness.MyUid}\"]");

        await h.StartAsync(config);

        Assert.Equal(missing, h.Holder!.Current.Templates["t"].Program);
        await h.WaitForLogAsync("started: ");
    }

    [Fact]
    public void AMissingProgramInsideABind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var missing = Path.Combine(Work, "not-yet", "tool");

        Assert.Equal(InsideBind(missing, Work), Refused(Config(missing, Work)));
    }

    [Fact]
    public void AMissingProgramBelowASymlinkIntoABind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var link = Path.Combine(_root, "link");
        File.CreateSymbolicLink(link, Work);
        var missing = Path.Combine(link, "tool"); // its nearest existing ancestor resolves into the bind

        Assert.StartsWith($"template t: program {missing} (resolves to {Path.Combine(Work, "tool")}) is inside bind {Work}",
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

    // ------------------------------------------------------------------ H3: dangling symlinks (I224 fix round 1, MiMo p2 B1)

    /// <summary>
    /// The reviewer's layout: the container can write <see cref="Work"/> (a rw bind); a host symlink
    /// outside every bind points at <c>Work/v2</c>, which doesn't exist yet. A path below the link
    /// would run what the container plants in <c>Work/v2</c>.
    /// </summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private string DanglingLinkIntoTheBind()
    {
        var link = Path.Combine(_root, "tool-link");
        File.CreateSymbolicLink(link, Path.Combine(Work, "v2"));
        Assert.Null(BrokerNative.RealPath(link)); // dangling: realpath fails on it
        return link;
    }

    [Fact]
    public void AProgramBelowADanglingSymlinkIntoABind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var program = Path.Combine(DanglingLinkIntoTheBind(), "deploy");

        Assert.StartsWith($"template t: program {program} (resolves to {Path.Combine(Work, "v2", "deploy")}) is inside bind {Work}; a program may no longer live in a bind",
            Refused(Config(program, Work, rw: true)));
    }

    [Fact]
    public void ABwrapPathBelowADanglingSymlinkIntoABind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var bwrap = Path.Combine(DanglingLinkIntoTheBind(), "bwrap");

        Assert.Equal($"bwrap_path {bwrap} is inside template t's bind {Work}", Refused(Config("/usr/bin/true", Work, rw: true, bwrapPath: bwrap)));
    }

    [Fact]
    public void ARelativeDanglingSymlinkIntoABind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var link = Path.Combine(_root, "rel-link");
        File.CreateSymbolicLink(link, "work/v2"); // relative: against the link's own folder
        var bwrap = Path.Combine(link, "bwrap");

        Assert.Equal($"bwrap_path {bwrap} is inside template t's bind {Work}", Refused(Config("/usr/bin/true", Work, rw: true, bwrapPath: bwrap)));
    }

    [Fact]
    public void ADanglingSymlinkOutsideEveryBind_StillLoads()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var link = Path.Combine(_root, "elsewhere-link");
        File.CreateSymbolicLink(link, Path.Combine(_root, "elsewhere", "v2")); // dangling, and not into a bind
        var bwrap = Path.Combine(link, "bwrap");

        var policy = BrokerPolicy.Parse(Config("/usr/bin/true", Work, rw: true, bwrapPath: bwrap), Host());

        Assert.Equal(bwrap, policy.BwrapPath);
        // A program there is judged outside the binds too: only the system-roots rule refuses it.
        Assert.StartsWith($"Template 't': argv[0] {Path.Combine(link, "deploy")} must be inside the sandbox",
            Refused(Config(Path.Combine(link, "deploy"), Work, rw: true)));
    }

    [Fact]
    public void ASymlinkLoopOnTheProgramPath_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var a = Path.Combine(_root, "loop-a");
        var b = Path.Combine(_root, "loop-b");
        File.CreateSymbolicLink(a, b);
        File.CreateSymbolicLink(b, a);
        var program = Path.Combine(a, "deploy");
        var bwrap = Path.Combine(a, "bwrap");

        Assert.Equal($"template t: program {program} can't be resolved (more than 40 symbolic links), so it can't be checked against the binds",
            Refused(Config(program, Work, rw: true)));
        Assert.Equal($"bwrap_path {bwrap} can't be resolved (more than 40 symbolic links), so it can't be checked against template t's binds",
            Refused(Config("/usr/bin/true", Work, rw: true, bwrapPath: bwrap)));
    }

    [Fact]
    public void AProgramThatStartsResolvingIntoABindAfterLoad_IsRefusedBeforeTheNextRun()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        // Validate never produces a program outside the system roots, and a test can't plant a link
        // under /usr, so the template is built directly: a program below a link that resolves outside
        // the binds now and into one later (the per-run re-check is the same check as at load).
        var elsewhere = Path.Combine(_root, "elsewhere");
        Directory.CreateDirectory(elsewhere);
        var link = Path.Combine(_root, "tool-link");
        File.CreateSymbolicLink(link, elsewhere);
        var program = Path.Combine(link, "deploy");
        var loaded = BrokerPolicy.Parse(Config("/usr/bin/true", Work, rw: true), Host()).Templates["t"];
        var template = new BrokerTemplatePolicy("t", program, [new[] { (program, false) }], loaded.Args, loaded.Env, loaded.Files,
            loaded.Binds, loaded.Cwd, loaded.Network, loaded.Limits, loaded.Timeout, loaded.MaxOutputBytes, loaded.Rate);
        Assert.True(BrokerTemplateValidator.RecheckBinds(template, Host(), null, BrokerPolicy.DefaultBwrapPath, out var before), before);

        File.Delete(link);
        File.CreateSymbolicLink(link, Path.Combine(Work, "v2"));

        Assert.False(BrokerTemplateValidator.RecheckBinds(template, Host(), null, BrokerPolicy.DefaultBwrapPath, out var problem));
        Assert.StartsWith($"template t: program {program} (resolves to {Path.Combine(Work, "v2", "deploy")}) is inside bind {Work}", problem);
    }

    [Fact]
    public void ABwrapPathThatStartsResolvingIntoABindAfterLoad_IsRefusedBeforeTheNextRun()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var elsewhere = Path.Combine(_root, "elsewhere");
        Directory.CreateDirectory(elsewhere);
        var link = Path.Combine(_root, "bwrap-link");
        File.CreateSymbolicLink(link, elsewhere);
        var bwrap = Path.Combine(link, "bwrap");
        var policy = BrokerPolicy.Parse(Config("/usr/bin/true", Work, rw: true, bwrapPath: bwrap), Host());
        var template = policy.Templates["t"];
        Assert.True(BrokerTemplateValidator.RecheckBinds(template, Host(), null, policy.BwrapPath, out var before), before);

        File.Delete(link);
        File.CreateSymbolicLink(link, Work);

        Assert.False(BrokerTemplateValidator.RecheckBinds(template, Host(), null, policy.BwrapPath, out var problem));
        Assert.Equal($"bwrap_path {bwrap} is inside template t's bind {Work}", problem);
    }

    // ------------------------------------------------------------------ H3: ".." through a link (I224 round 2, G1)

    [Theory]
    [InlineData("/usr/bin/../bin/true")]
    [InlineData("/usr/bin/./true")]
    public void AProgramWithADotSegment_IsRefusedWithTheMessage(string program)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Assert.Equal($"template t: program {program} has a \".\" or \"..\" segment; give the literal absolute path (argv[0])",
            Refused(Config(program, Work)));
    }

    [Theory]
    [InlineData("/usr/bin/../bin/bwrap")]
    [InlineData("/usr/./bin/bwrap")]
    public void ABwrapPathWithADotSegment_IsRefusedWithTheMessage(string bwrap)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Assert.Equal($"bwrap_path {bwrap} has a \".\" or \"..\" segment; give the literal absolute path",
            Refused(Config("/usr/bin/true", Work, bwrapPath: bwrap)));
    }

    [Fact]
    public void TheDotDotThroughADanglingLinkLayout_IsRefusedAtLoad()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        // The reviewer's layout: tool-link -> Work/v2 (missing), so the kernel takes tool-link/.. as Work.
        var link = DanglingLinkIntoTheBind();
        var program = link + "/../deploy";
        var bwrap = link + "/../bwrap";

        // Refused either by the "." / ".." rule or, without it, by the resolver: never the system-roots message.
        Assert.Matches("has a \".\" or \"..\" segment|is inside bind", Refused(Config(program, Work, rw: true)));
        Assert.Matches("has a \".\" or \"..\" segment|is inside template t's bind", Refused(Config("/usr/bin/true", Work, rw: true, bwrapPath: bwrap)));
    }

    [Fact]
    public void TheDotDotThroughADanglingLinkLayout_IsRefusedBeforeEveryRun()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        // Validate refuses ".." in argv[0] and bwrap_path, so the template is built directly: the per-run
        // re-check must take tool-link/.. as the kernel does (Work), not lexically (_root).
        var link = DanglingLinkIntoTheBind();
        var program = link + "/../deploy";
        var loaded = BrokerPolicy.Parse(Config("/usr/bin/true", Work, rw: true), Host()).Templates["t"];
        var template = new BrokerTemplatePolicy("t", program, [new[] { (program, false) }], loaded.Args, loaded.Env, loaded.Files,
            loaded.Binds, loaded.Cwd, loaded.Network, loaded.Limits, loaded.Timeout, loaded.MaxOutputBytes, loaded.Rate);

        Assert.False(BrokerTemplateValidator.RecheckBinds(template, Host(), null, BrokerPolicy.DefaultBwrapPath, out var problem));
        Assert.StartsWith($"template t: program {program} (resolves to {Path.Combine(Work, "deploy")}) is inside bind {Work}", problem);

        Assert.False(BrokerTemplateValidator.RecheckBinds(loaded, Host(), null, link + "/../bwrap", out var bwrapProblem));
        Assert.Equal($"bwrap_path {link}/../bwrap is inside template t's bind {Work}", bwrapProblem);
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
    // I224 fix round 1 (MiMo p2 M3, the code-execution ones): hooks of a repo the template's git is pointed
    // at, less's input filter and the browser a tool starts
    [InlineData("GIT_DIR")]
    [InlineData("GIT_WORK_TREE")]
    [InlineData("LESSOPEN")]
    [InlineData("LESSCLOSE")]
    [InlineData("BROWSER")]
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
