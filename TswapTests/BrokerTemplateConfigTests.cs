using System.Net.Sockets;
using System.Text.Json;
using TswapCore;
using TswapCore.Broker;
using TswapCore.Broker.Templates;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T9 item 1: the config model for templates (T9) and ssh keys (T10) in <c>broker.json</c>:
/// what validates and round-trips, what is refused (decisions 2 to 4), and that changing templates
/// needs sudo (decision 9). Templates are Linux only (bwrap); ssh keys validate everywhere the
/// broker runs.
/// </summary>
public class BrokerTemplateConfigTests : IDisposable
{
    private readonly string _root;

    public BrokerTemplateConfigTests()
    {
        var root = Path.Combine(Path.GetTempPath(), "tswap-tplcfg-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        _root = OperatingSystem.IsWindows() ? root : BrokerNative.RealPath(root) ?? root;
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(_root, (UnixFileMode)0b111_101_101);
        Directory.CreateDirectory(Work);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(Work, (UnixFileMode)0b111_101_101);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, true);
    }

    /// <summary>A folder a template may bind: this uid's, 0755, under a temp folder.</summary>
    private string Work => Path.Combine(_root, "work");

    private static string J(string s) => JsonSerializer.Serialize(s);

    /// <summary>A host context for this uid with no protected folders of its own.</summary>
    private static BrokerHostContext Host(uint? vaultUid = null, params string[] protectedPaths) =>
        new(vaultUid ?? BrokerHarness.MyUid, protectedPaths, []);

    /// <summary>A whole broker.json with one template (as JSON) and a socket that may call it.</summary>
    private static string WithTemplate(string templateJson, string socketTemplates = "\"deploy\"") => $$"""
        {
          "version": 1,
          "socket_dir": "/run/tswap-broker",
          "sockets": [ { "name": "lane1", "uids": ["100999"], "routes": [], "templates": [{{socketTemplates}}] } ],
          "routes": [],
          "templates": [ {{templateJson}} ]
        }
        """;

    /// <summary>A valid template, with any field replaced by <paramref name="overrides"/> (a JSON fragment of extra or replacing members).</summary>
    private string Template(string? argv = null, string? args = null, string? binds = null, string? cwd = null, string extra = "") => $$"""
        {
          "name": "deploy",
          "argv": {{argv ?? """["/usr/bin/git", "push", "origin", "{branch}"]"""}},
          "args": {{args ?? """{ "branch": { "pattern": "brief/[a-z0-9-]+", "max_length": 64 } }"""}},
          "binds": {{binds ?? $$"""[ { "path": {{J(Work)}}, "rw": true } ]"""}},
          "cwd": {{cwd ?? J(Work)}}
          {{extra}}
        }
        """;

    private BrokerPolicy Parse(string json, BrokerHostContext? host = null) => BrokerPolicy.Parse(json, host ?? Host());

    private void Refused(string json, string expected, BrokerHostContext? host = null)
    {
        var ex = Assert.Throws<BrokerConfigException>(() => Parse(json, host));
        Assert.Contains(expected, ex.Message);
    }

    // ------------------------------------------------------------------ round trip

    private string FullTemplate => Template(extra: """
        ,
          "env": { "PGPASSWORD": "{{db-pw}}", "PGHOST": "db.example" },
          "files": [ { "path": "/run/secrets/signing-key", "secret": "signing-key" } ],
          "network": "host",
          "limits": { "nproc": 32, "as_mib": 1024, "nofile": 128, "fsize_mib": 64 },
          "timeout_sec": 300,
          "max_output_bytes": 4096,
          "rate": 3
        """);

    [Fact]
    public void ValidTemplate_RoundTrips_AndCompiles()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var policy = Parse(WithTemplate(FullTemplate));
        var again = Parse(BrokerPolicy.Serialize(policy.Source));

        Assert.Equal(BrokerPolicy.Serialize(policy.Source), BrokerPolicy.Serialize(again.Source));
        var t = again.Templates["deploy"];
        Assert.Equal("/usr/bin/git", t.Program);
        Assert.Equal(["/usr/bin/git", "push", "origin", "brief/x-1"], t.BuildArgv(new Dictionary<string, string> { ["branch"] = "brief/x-1" }));
        Assert.Equal(["branch"], t.Args.Keys);
        Assert.Equal(64, t.Args["branch"].MaxLength);
        Assert.False(t.Args["branch"].AllowLeadingDash);
        Assert.Equal(BrokerTemplateNetwork.Host, t.Network);
        Assert.Equal(new BrokerTemplateLimits(32, 1024L << 20, 128, 64L << 20), t.Limits);
        Assert.Equal(TimeSpan.FromSeconds(300), t.Timeout);
        Assert.Equal(4096, t.MaxOutputBytes);
        Assert.Equal(3, t.Rate);
        Assert.Equal(["db-pw", "signing-key"], t.SecretNames.Order(StringComparer.Ordinal));
        Assert.Equal(Work, t.Cwd);
        var bind = Assert.Single(t.Binds);
        Assert.Equal((Work, true), (bind.Path, bind.Writable));
        Assert.Equal(["deploy"], again.Sockets["lane1"].Templates);
        Assert.Equal("/usr/bin/bwrap", again.BwrapPath);
    }

    [Fact]
    public void Template_Defaults()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var t = Parse(WithTemplate(Template(binds: "[]", cwd: "null"))).Templates["deploy"];

        Assert.Equal(BrokerTemplateNetwork.None, t.Network);
        Assert.Equal(new BrokerTemplateLimits(64, 2048L << 20, 256, 256L << 20), t.Limits);
        Assert.Equal(TimeSpan.FromSeconds(120), t.Timeout);
        Assert.Equal(1L << 20, t.MaxOutputBytes);
        Assert.Equal(6, t.Rate);
        Assert.Equal("/tmp", t.Cwd);
        Assert.Empty(t.SecretNames);
    }

    [Fact]
    public void ValidSshKeys_RoundTrip_AndASocketListsThem()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        const string json = """
            {
              "version": 1,
              "socket_dir": "/run/tswap-broker",
              "sockets": [ { "name": "lane1", "uids": ["100999"], "routes": [], "ssh_keys": ["github-deploy"] } ],
              "routes": [],
              "ssh_keys": [
                { "name": "github-deploy", "secret": "gh-ssh-key",
                  "allowed_host_keys": ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"] }
              ]
            }
            """;
        var policy = BrokerPolicy.Parse(json);
        var again = BrokerPolicy.Parse(BrokerPolicy.Serialize(policy.Source));

        Assert.Equal(BrokerPolicy.Serialize(policy.Source), BrokerPolicy.Serialize(again.Source));
        var key = again.SshKeys["github-deploy"];
        Assert.Equal("gh-ssh-key", key.SecretName);
        Assert.Equal(["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"], key.AllowedHostKeys);
        Assert.Equal(["github-deploy"], again.Sockets["lane1"].SshKeys);
        Assert.Empty(again.Sockets["lane1"].Templates);
    }

    [Fact]
    public void ASocketWithoutTemplatesOrSshKeys_AllowsNone()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var policy = Parse(WithTemplate(Template()).Replace(", \"templates\": [\"deploy\"]", ""));

        Assert.Single(policy.Templates);
        Assert.Empty(policy.Sockets["lane1"].Templates);
        Assert.Empty(policy.Sockets["lane1"].SshKeys);
    }

    // ------------------------------------------------------------------ refusals: secrets and placeholders

    [Theory]
    [InlineData("""["/usr/bin/curl", "-H", "Authorization: {{api-key}}"]""")]
    [InlineData("""["/usr/bin/curl", "{{api-key}}"]""")]
    public void ASecretInArgv_IsRefused(string argv)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(argv: argv, args: "{}")), "{{secret}}");
    }

    [Fact]
    public void ASecretInCwd_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(cwd: J(Work + "/{{db-pw}}"))), "{{secret}}");
    }

    [Fact]
    public void ASecretInABind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(binds: $$"""[ { "path": {{J(Work + "/{{db-pw}}")}} } ]""", cwd: "null")), "{{secret}}");
    }

    [Fact]
    public void ASecretInAFilesPath_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(extra: """, "files": [ { "path": "/run/secrets/{{k}}", "secret": "k" } ]""")), "{{secret}}");
    }

    [Theory]
    [InlineData("""["{prog}", "x"]""", """{ "prog": { "pattern": "/usr/bin/[a-z]+" } }""")]
    [InlineData("""["/usr/bin/{prog}"]""", """{ "prog": { "pattern": "[a-z]+" } }""")]
    [InlineData("""["{{tool}}"]""", "{}")]
    [InlineData("""["/usr/bin/{{tool}}"]""", "{}")]
    public void APlaceholderOrSecretInArgv0_IsRefused(string argv, string args)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(argv: argv, args: args)), "argv[0]");
    }

    [Fact]
    public void AnUndeclaredPlaceholder_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(argv: """["/usr/bin/git", "push", "{remote}", "{branch}"]""")), "'remote' is not declared");
    }

    [Fact]
    public void AnUnusedDeclaredArgument_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(args: """{ "branch": { "pattern": "x" }, "extra": { "pattern": "y" } }""")), "'extra' is declared but not used");
    }

    [Theory]
    [InlineData("""["git", "push"]""")]
    [InlineData("""["usr/bin/git", "push"]""")]
    [InlineData("""["./git", "push"]""")]
    [InlineData("""["/usr/bin/../bin/git", "push"]""")]
    [InlineData("""["/home/someone/git", "push"]""")]
    public void ARelativeOrOutsideTheSandboxArgv0_IsRefused(string argv)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(argv: argv, args: "{}")), "argv[0]");
    }

    [Theory]
    [InlineData("""["/usr/bin/sh", "-c", "git push origin {branch}"]""")]
    [InlineData("""["/usr/bin/python3", "-c", "print('{branch}')"]""")]
    [InlineData("""["/usr/bin/env", "git", "{branch}"]""")]
    [InlineData("""["/usr/bin/xargs", "{branch}"]""")]
    public void AnInlineCodeArgv_IsRefused(string argv)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(argv: argv)), "inline");
    }

    [Theory]
    [InlineData("(?i)brief/.*")]
    [InlineData("brief/(?s:.*)")]
    public void AnInlineOptionGroupInAPattern_IsRefused(string pattern)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(args: $$"""{ "branch": { "pattern": {{J(pattern)}} } }""")), "inline option");
    }

    [Fact]
    public void APattern_IsAnchoredAtBothEnds_InvariantWithATimeout()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var arg = Parse(WithTemplate(Template(args: """{ "branch": { "pattern": "a|b" } }"""))).Templates["deploy"].Args["branch"];

        Assert.Matches(arg.Pattern, "a");
        Assert.DoesNotMatch(arg.Pattern, "ab");
        Assert.DoesNotMatch(arg.Pattern, "xa");
        Assert.DoesNotMatch(arg.Pattern, "a\n");
        Assert.Equal(System.Text.RegularExpressions.RegexOptions.CultureInvariant, arg.Pattern.Options);
        Assert.Equal(TimeSpan.FromMilliseconds(100), arg.Pattern.MatchTimeout);
    }

    [Theory]
    [InlineData("""{ "X": "a\u0000b" }""", "control")]
    [InlineData("""{ "X": "a\nb" }""", "control")]
    [InlineData("""{ "PATH": "/x" }""", "PATH")]
    [InlineData("""{ "LD_PRELOAD": "/x.so" }""", "LD_")]
    [InlineData("""{ "1BAD": "x" }""", "variable name")]
    [InlineData("""{ "X": "pre-{{k}}" }""", "{{secret}}")]
    public void ABadEnvEntry_IsRefused(string env, string expected)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(extra: $", \"env\": {env}")), expected);
    }

    [Fact]
    public void AControlCharacterInAnArgvLiteral_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(argv: """["/usr/bin/git", "pu\u0000sh", "{branch}"]""")), "control");
    }

    // ------------------------------------------------------------------ refusals: binds and cwd

    [Fact]
    public void AGroupWritableBind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Parse(WithTemplate(Template())); // the positive: 0755 passes
        File.SetUnixFileMode(Work, (UnixFileMode)0b111_111_101);

        Refused(WithTemplate(Template()), "writable by group or others");
    }

    [Fact]
    public void ABindOwnedByAnotherUser_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Parse(WithTemplate(Template()), Host(BrokerHarness.MyUid)); // the positive: the vault user's own
        Refused(WithTemplate(Template()), "owned by uid", Host(BrokerHarness.MyUid + 1));
    }

    [Fact]
    public void ABindBelowAGroupWritableFolder_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var inner = Path.Combine(Work, "inner");
        Directory.CreateDirectory(inner);
        File.SetUnixFileMode(inner, (UnixFileMode)0b111_101_101);
        var binds = $$"""[ { "path": {{J(inner)}} } ]""";
        Parse(WithTemplate(Template(binds: binds, cwd: J(inner))));
        File.SetUnixFileMode(Work, (UnixFileMode)0b111_111_101);

        Refused(WithTemplate(Template(binds: binds, cwd: J(inner))), "writable by group or others");
    }

    [Fact]
    public void ASymlinkedBind_IsCheckedAtItsTarget()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var target = Path.Combine(Work, "target");
        Directory.CreateDirectory(target);
        File.SetUnixFileMode(target, (UnixFileMode)0b111_101_101);
        var link = Path.Combine(_root, "link");
        File.CreateSymbolicLink(link, target);
        var binds = $$"""[ { "path": {{J(link)}} } ]""";
        var t = Parse(WithTemplate(Template(binds: binds, cwd: "null"))).Templates["deploy"];
        Assert.Equal(target, Assert.Single(t.Binds).Path); // bound (and checked) at the resolved target

        File.SetUnixFileMode(target, (UnixFileMode)0b111_111_111);
        Refused(WithTemplate(Template(binds: binds, cwd: "null")), "writable by group or others");
    }

    [Fact]
    public void ACwdOutsideTheBinds_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Directory.CreateDirectory(Path.Combine(Work, "sub"));
        Parse(WithTemplate(Template(cwd: J(Path.Combine(Work, "sub"))))); // inside: fine

        Refused(WithTemplate(Template(cwd: J(_root))), "cwd");
        Refused(WithTemplate(Template(cwd: J(Work + "x"))), "cwd");
        Refused(WithTemplate(Template(cwd: "\"/etc\"")), "cwd");
    }

    [Theory]
    [InlineData("/dev")]
    [InlineData("/dev/null")]
    [InlineData("/dev/shm")]
    [InlineData("/proc/self")]
    [InlineData("/proc")]
    [InlineData("/sys")]
    [InlineData("/sys/class")]
    [InlineData("/run")]
    public void ABindAtOrUnderDevProcSysOrRun_IsRefused(string path)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        if (!Path.Exists(path))
            return; // not on this host
        Refused(WithTemplate(Template(binds: $$"""[ { "path": {{J(path)}} } ]""", cwd: "null")), "may not");
    }

    [Fact]
    public void ADeviceNodeReachedThroughASymlink_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var link = Path.Combine(Work, "null");
        File.CreateSymbolicLink(link, "/dev/null");

        Refused(WithTemplate(Template(binds: $$"""[ { "path": {{J(link)}} } ]""", cwd: "null")), "may not");
    }

    [Fact]
    public void AFifoOrSocketBind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var socketPath = Path.Combine(Work, "s.sock");
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        socket.Bind(new UnixDomainSocketEndPoint(socketPath));

        Refused(WithTemplate(Template(binds: $$"""[ { "path": {{J(socketPath)}} } ]""", cwd: "null")), "regular file or a folder");
    }

    [Fact]
    public void AMissingBind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(binds: $$"""[ { "path": {{J(Path.Combine(Work, "nope"))}} } ]""", cwd: "null")), "does not exist");
    }

    [Fact]
    public void ARelativeBind_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(binds: """[ { "path": "work" } ]""", cwd: "null")), "absolute");
    }

    [Fact]
    public void AProtectedFolder_ItsParentsAndItsContents_AreRefused_ByDeviceAndInode()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var vault = Path.Combine(Work, "vault");
        var inside = Path.Combine(vault, "records");
        Directory.CreateDirectory(inside);
        File.SetUnixFileMode(vault, (UnixFileMode)0b111_101_101);
        File.SetUnixFileMode(inside, (UnixFileMode)0b111_101_101);
        var sibling = Path.Combine(Work, "deploy");
        Directory.CreateDirectory(sibling);
        File.SetUnixFileMode(sibling, (UnixFileMode)0b111_101_101);
        var alias = Path.Combine(_root, "alias");
        File.CreateSymbolicLink(alias, vault);
        var host = Host(null, vault);

        string Bind(string p) => WithTemplate(Template(binds: $$"""[ { "path": {{J(p)}} } ]""", cwd: "null"));
        Parse(Bind(sibling), host); // a sibling folder is fine

        Refused(Bind(vault), "vault", host);
        Refused(Bind(Work), "vault", host);    // above it
        Refused(Bind(inside), "vault", host);  // below it
        Refused(Bind(alias), "vault", host);   // another name for it
    }

    [Fact]
    public void AHardLinkToAProtectedFile_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var config = Path.Combine(Work, "cfg");
        Directory.CreateDirectory(config);
        File.SetUnixFileMode(config, (UnixFileMode)0b111_101_101);
        var brokerJson = Path.Combine(config, "broker.json");
        File.WriteAllText(brokerJson, "{}");
        File.SetUnixFileMode(brokerJson, (UnixFileMode)0b110_100_100);
        var other = Path.Combine(Work, "other");
        Directory.CreateDirectory(other);
        File.SetUnixFileMode(other, (UnixFileMode)0b111_101_101);
        var hardLink = Path.Combine(other, "innocent.json");
        Assert.Equal(0, TswapTests.BrokerTemplateTestNative.Link(brokerJson, hardLink));
        var plain = Path.Combine(other, "plain.json");
        File.WriteAllText(plain, "{}");
        File.SetUnixFileMode(plain, (UnixFileMode)0b110_100_100);
        var host = Host(null, brokerJson);

        string Bind(string p) => WithTemplate(Template(binds: $$"""[ { "path": {{J(p)}} } ]""", cwd: "null"));
        Parse(Bind(plain), host);
        Refused(Bind(hardLink), "vault", host);
    }

    [Fact]
    public void TheSocketDir_IsProtected()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var sockets = Path.Combine(Work, "sockets");
        Directory.CreateDirectory(sockets);
        File.SetUnixFileMode(sockets, (UnixFileMode)0b111_001_001);
        var json = WithTemplate(Template(binds: $$"""[ { "path": {{J(sockets)}} } ]""", cwd: "null"))
            .Replace("\"/run/tswap-broker\"", J(sockets));

        Refused(json, "vault");
    }

    [Theory]
    [InlineData("/etc")]
    [InlineData("/")]
    public void SudoConfigurationAndTheRoot_AreRefused(string path)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(binds: $$"""[ { "path": {{J(path)}} } ]""", cwd: "null")), "vault");
    }

    [Fact]
    public void TheVaultUsersHome_IsRefused_ButAFolderInsideItIsNot()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var host = new BrokerHostContext(BrokerHarness.MyUid, [], [Work]); // Work plays the home folder
        var inside = Path.Combine(Work, "deploy");
        Directory.CreateDirectory(inside);
        File.SetUnixFileMode(inside, (UnixFileMode)0b111_101_101);

        Parse(WithTemplate(Template(binds: $$"""[ { "path": {{J(inside)}} } ]""", cwd: "null")), host);
        Refused(WithTemplate(Template(binds: $$"""[ { "path": {{J(Work)}} } ]""", cwd: "null")), "home", host);
        Refused(WithTemplate(Template(binds: $$"""[ { "path": {{J(_root)}} } ]""", cwd: "null")), "home", host);
    }

    // ------------------------------------------------------------------ refusals: files, ranges, names

    [Theory]
    [InlineData("/tmp/key")]
    [InlineData("/run/secrets")]
    [InlineData("/run/secrets/")]
    [InlineData("/run/secrets/../passwd")]
    [InlineData("/run/secretsx/key")]
    [InlineData("run/secrets/key")]
    public void AFilesPathOutsideRunSecrets_IsRefused(string path)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(extra: $$""", "files": [ { "path": {{J(path)}}, "secret": "k" } ]""")), "/run/secrets/");
    }

    [Theory]
    [InlineData("\"timeout_sec\": 0", "timeout_sec")]
    [InlineData("\"timeout_sec\": 3601", "timeout_sec")]
    [InlineData("\"max_output_bytes\": 0", "max_output_bytes")]
    [InlineData("\"max_output_bytes\": 67108865", "max_output_bytes")]
    [InlineData("\"rate\": 0", "rate")]
    [InlineData("\"rate\": -1", "rate")]
    [InlineData("\"limits\": { \"nproc\": 65 }", "nproc")]
    [InlineData("\"limits\": { \"nproc\": 0 }", "nproc")]
    [InlineData("\"limits\": { \"as_mib\": 2049 }", "as_mib")]
    [InlineData("\"limits\": { \"nofile\": 257 }", "nofile")]
    [InlineData("\"limits\": { \"fsize_mib\": 257 }", "fsize_mib")]
    [InlineData("\"network\": \"bridge\"", "network")]
    public void OutOfRangeSettings_AreRefused(string member, string expected)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(extra: ", " + member)), expected);
    }

    [Theory]
    [InlineData("\"timeout_sec\": 1")]
    [InlineData("\"timeout_sec\": 3600")]
    [InlineData("\"max_output_bytes\": 1")]
    [InlineData("\"max_output_bytes\": 67108864")]
    [InlineData("\"rate\": 1")]
    [InlineData("\"limits\": { \"nproc\": 64, \"as_mib\": 2048, \"nofile\": 256, \"fsize_mib\": 256 }")]
    public void SettingsAtTheEdgesOfTheirRange_AreAccepted(string member)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Parse(WithTemplate(Template(extra: ", " + member)));
    }

    [Fact]
    public void ADuplicateTemplateName_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var t = Template();
        Refused(WithTemplate(t + ", " + t), "defined twice");
    }

    [Theory]
    [InlineData("_hidden", "reserved")]
    [InlineData("Deploy", "invalid")]
    public void ATemplateNameBreakingTheNamingRules_IsRefused(string name, string expected)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template().Replace("\"deploy\"", J(name)), J(name)), expected);
    }

    [Fact]
    public void ASocketListingAnUnknownTemplateOrSshKey_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(), "\"deploy\", \"nope\""), "'nope'");
        Refused(WithTemplate(Template()).Replace("\"templates\": [\"deploy\"]", "\"ssh_keys\": [\"nokey\"], \"templates\": [\"deploy\"]"), "'nokey'");
    }

    [Fact]
    public void UnknownTemplateFields_AreRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Refused(WithTemplate(Template(extra: ", \"shell\": true")), "can't be read");
    }

    [Theory]
    [InlineData("\"sha256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU\"")]   // the prefix is case-sensitive
    [InlineData("\"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU=\"")]  // padded
    [InlineData("\"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOq\"")]   // too short
    [InlineData("\"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqUU\"")] // too long
    [InlineData("\"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvC!qU\"")]  // not base64
    [InlineData("\"MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48\"")]
    [InlineData("\"\"")]
    public void ABadSshKeyFingerprint_IsRefused(string fingerprint)
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        var json = $$"""
            { "version": 1, "sockets": [], "routes": [],
              "ssh_keys": [ { "name": "k", "secret": "key", "allowed_host_keys": [{{fingerprint}}] } ] }
            """;
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(json));
        Assert.Contains("SHA256:", ex.Message);
    }

    [Theory]
    [InlineData("""{ "name": "k", "secret": "key", "allowed_host_keys": [] }""", "allowed_host_keys")]
    [InlineData("""{ "name": "k", "secret": "{{key}}", "allowed_host_keys": ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"] }""", "secret")]
    [InlineData("""{ "name": "_k", "secret": "key", "allowed_host_keys": ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"] }""", "reserved")]
    public void OtherBadSshKeys_AreRefused(string key, string expected)
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse($$"""{ "version": 1, "sockets": [], "routes": [], "ssh_keys": [ {{key}} ] }"""));
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void ADuplicateSshKeyName_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        const string key = """{ "name": "k", "secret": "key", "allowed_host_keys": ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"] }""";
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse($$"""{ "version": 1, "sockets": [], "routes": [], "ssh_keys": [ {{key}}, {{key}} ] }"""));
        Assert.Contains("defined twice", ex.Message);
    }

    [Fact]
    public void ABwrapPathThatIsNotAbsolute_IsRefused()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse("""{ "version": 1, "bwrap_path": "bwrap", "sockets": [], "routes": [] }"""));
        Assert.Contains("bwrap_path", ex.Message);
    }

    // ------------------------------------------------------------------ the CLI (decision 9)

    [Fact]
    public void WithoutSudo_TemplateChangesAreRefused_AndNothingIsWritten()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged
        using var m = new FleetMachine("tplcfg");
        var file = Path.Combine(_root, "deploy.json");
        File.WriteAllText(file, Template());
        m.Sudo = false;

        foreach (var args in new[] { new[] { "broker", "template", "add", file }, ["broker", "template", "remove", "deploy"] })
        {
            var (exit, _, err) = m.Run("", args);
            Assert.NotEqual(0, exit);
            Assert.Contains("requires", err);
        }
        Assert.False(File.Exists(BrokerConfigFile.PathIn(m.Dir)));
    }

    [Fact]
    public void Sudo_TemplateAdd_AndASocketAllowingIt_LoadAsWritten_AndRemoveRefusesWhileInUse()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        using var m = new FleetMachine("tplcfg");
        var file = Path.Combine(_root, "deploy.json");
        File.WriteAllText(file, Template());

        m.Ok("", "broker", "template", "add", file);
        m.Ok("", "broker", "socket", "add", "lane1", "--uids", "100999", "--templates", "deploy", "--socket-dir", "/run/tswap-broker");

        var policy = BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, m.Dir);
        Assert.Equal("/usr/bin/git", policy.Templates["deploy"].Program);
        Assert.Equal(["deploy"], policy.Sockets["lane1"].Templates);
        Assert.Empty(policy.Sockets["lane1"].Routes);

        var (exit, _, err) = m.Run("", "broker", "template", "add", file);
        Assert.NotEqual(0, exit);
        Assert.Contains("already exists", err);
        (exit, _, err) = m.Run("", "broker", "template", "remove", "deploy");
        Assert.NotEqual(0, exit);
        Assert.Contains("lane1", err);

        m.Ok("", "broker", "socket", "remove", "lane1");
        m.Ok("", "broker", "template", "remove", "deploy");
        Assert.Empty(BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, m.Dir).Templates);
    }

    [Fact]
    public void Sudo_AnInvalidTemplate_IsRefused_AndNothingIsWritten()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        using var m = new FleetMachine("tplcfg");
        var file = Path.Combine(_root, "deploy.json");
        File.WriteAllText(file, Template(argv: """["/usr/bin/curl", "{{api-key}}"]""", args: "{}"));

        var (exit, _, err) = m.Run("", "broker", "template", "add", file);

        Assert.NotEqual(0, exit);
        Assert.Contains("{{secret}}", err);
        Assert.False(File.Exists(BrokerConfigFile.PathIn(m.Dir)));
    }

    [Fact]
    public void TheVaultFolderOfTheMachine_IsProtected_WhenAddingATemplate()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        using var m = new FleetMachine("tplcfg");
        var dir = BrokerNative.RealPath(m.Dir)!;
        File.SetUnixFileMode(dir, (UnixFileMode)0b111_101_101);
        var file = Path.Combine(_root, "deploy.json");
        File.WriteAllText(file, Template(binds: $$"""[ { "path": {{J(dir)}} } ]""", cwd: "null"));

        var (exit, _, err) = m.Run("", "broker", "template", "add", file);

        Assert.NotEqual(0, exit);
        Assert.Contains("vault", err);
    }
}

/// <summary>libc calls the template tests need and .NET doesn't expose.</summary>
internal static class BrokerTemplateTestNative
{
    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "link")]
    public static extern int Link(string existing, string newPath);
}
