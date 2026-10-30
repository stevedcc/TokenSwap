using TswapCore;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T8 item 1: <c>broker.json</c> (decisions 4 and 9): what validates, what is refused, the
/// path-regex wrap, and the reload rule (an invalid file keeps the current config).
/// </summary>
public class BrokerConfigTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tswap-brokercfg-" + Guid.NewGuid().ToString("N")[..8]);

    public BrokerConfigTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
    }

    internal const string ValidJson = """
        {
          "version": 1,
          "socket_dir": "/run/tswap-broker",
          "sockets": [
            { "name": "lane1", "uids": ["100999", "200000-265535"], "routes": ["github", "registry"] }
          ],
          "routes": [
            {
              "name": "github",
              "upstream": "https://github.com/stevedcc",
              "auth": { "type": "basic", "user": "x-access-token", "secret": "{{gh-token}}" },
              "methods": ["GET", "POST"],
              "path": "croft\\.git/",
              "idle_timeout_sec": 60
            },
            {
              "name": "registry",
              "upstream": "https://registry.example.com/",
              "auth": { "type": "header", "header": "X-Api-Key", "secret": "{{reg-key}}" },
              "path": "v2/"
            },
            {
              "name": "models",
              "upstream": "https://api.example.com/v1",
              "auth": { "type": "bearer", "secret": "{{model-key}}" },
              "path": ""
            }
          ]
        }
        """;

    private static string WithRoute(string routeJson) => $$"""
        { "version": 1, "sockets": [], "routes": [ {{routeJson}} ] }
        """;

    private static string Route(string upstream = "https://api.example.com", string auth = """{ "type": "bearer", "secret": "{{k}}" }""",
        string path = "\"x/\"", string extra = "") =>
        $$"""{ "name": "r", "upstream": "{{upstream}}", "auth": {{auth}}, "path": {{path}} {{extra}} }""";

    [Fact]
    public void ValidConfig_RoundTrips_AndCompiles()
    {
        var policy = BrokerPolicy.Parse(ValidJson);
        var again = BrokerPolicy.Parse(BrokerPolicy.Serialize(policy.Source));

        Assert.Equal(BrokerPolicy.Serialize(policy.Source), BrokerPolicy.Serialize(again.Source));
        Assert.Equal("/run/tswap-broker", again.SocketDir);
        var github = again.Routes["github"];
        Assert.Equal(BrokerAuthType.Basic, github.AuthType);
        Assert.Equal("x-access-token", github.User);
        Assert.Equal("gh-token", github.SecretName);
        Assert.Equal("/stevedcc", github.BasePath);
        Assert.Equal(["GET", "POST"], github.Methods.Order());
        Assert.Equal(TimeSpan.FromSeconds(60), github.IdleTimeout);
        Assert.Equal("", again.Routes["registry"].BasePath);
        Assert.Equal("X-Api-Key", again.Routes["registry"].HeaderName);
        Assert.Equal(["GET", "HEAD", "POST"], again.Routes["models"].Methods.Order());
        Assert.Equal(TimeSpan.FromSeconds(120), again.Routes["models"].IdleTimeout);
        var lane = again.Sockets["lane1"];
        Assert.True(lane.AllowsUid(100999));
        Assert.True(lane.AllowsUid(200000));
        Assert.True(lane.AllowsUid(265535));
        Assert.False(lane.AllowsUid(1000));
        Assert.False(lane.AllowsUid(265536));
        Assert.Equal(["github", "registry"], lane.Routes.Order());
    }

    [Fact]
    public void PathRegex_MatchesOnlyAtTheStart_AsAPrefix()
    {
        var route = BrokerPolicy.Parse(WithRoute(Route(path: "\"repo\\\\.git/\""))).Routes["r"];

        Assert.True(route.PathMatches("repo.git/info/refs"));     // prefix match
        Assert.False(route.PathMatches("other/repo.git/info/refs")); // not anywhere: only at the start
        Assert.False(route.PathMatches("xrepo.git/"));
    }

    [Fact]
    public void PathRegex_AlternationCantEscapeTheStartAnchor()
    {
        var route = BrokerPolicy.Parse(WithRoute(Route(path: "\"a/|b/\""))).Routes["r"];

        Assert.True(route.PathMatches("b/x"));
        Assert.False(route.PathMatches("x/b/"));
    }

    [Fact]
    public void PathRegex_IsCaseSensitive_AndNeverMultiline()
    {
        var route = BrokerPolicy.Parse(WithRoute(Route(path: "\"repo/\""))).Routes["r"];

        Assert.False(route.PathMatches("REPO/x"));
        Assert.False(route.PathMatches("x\nrepo/"));
        Assert.Equal(System.Text.RegularExpressions.RegexOptions.CultureInvariant, route.PathRegex.Options);
        Assert.Equal(BrokerPolicy.PathMatchTimeout, route.PathRegex.MatchTimeout);
    }

    [Theory]
    [InlineData("\"http://api.example.com\"", "https://")]
    [InlineData("\"ftp://api.example.com\"", "https://")]
    [InlineData("\"https://user:pw@api.example.com\"", "user info")]
    [InlineData("\"https://api.example.com/?q=1\"", "query")]
    [InlineData("\"https://api.example.com/a/../b\"", "plainly")]
    [InlineData("\"https://api.example.com/a%2fb\"", "base path")]
    [InlineData("\"not a url\"", "absolute URL")]
    public void Upstream_Refused(string upstream, string expected)
    {
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(WithRoute(Route(upstream: upstream.Trim('"')))));
        Assert.Contains(expected, ex.Message);
    }

    [Theory]
    [InlineData("(?i)repo")]
    [InlineData("(?m)^repo")]
    [InlineData("(?s)a.b")]
    [InlineData("(?x) a b")]
    [InlineData("a(?i:b)")]
    [InlineData("(?-i)a")]
    [InlineData("(?imsx)a")]
    public void PathRegex_InlineOptionGroup_Refused(string pattern)
    {
        var json = WithRoute(Route(path: System.Text.Json.JsonSerializer.Serialize(pattern)));
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(json));
        Assert.Contains("inline option", ex.Message);
    }

    [Theory]
    [InlineData(@"\(?i\)")]     // escaped parentheses: literal text
    [InlineData(@"[(?i)]x")]    // inside a character class
    [InlineData(@"(?:a|b)/")]   // a non-capturing group is not an option group
    [InlineData(@"(?<n>a)/")]
    public void PathRegex_LiteralLookalikes_Accepted(string pattern)
    {
        var json = WithRoute(Route(path: System.Text.Json.JsonSerializer.Serialize(pattern)));
        Assert.NotNull(BrokerPolicy.Parse(json));
    }

    [Theory]
    [InlineData("a)|(b")]
    [InlineData("(a")]
    [InlineData("a\\")]
    public void PathRegex_ThatCouldBreakOutOfTheWrap_Refused(string pattern)
    {
        var json = WithRoute(Route(path: System.Text.Json.JsonSerializer.Serialize(pattern)));
        Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(json));
    }

    [Theory]
    [InlineData("_internal", "reserved")]
    [InlineData("_", "reserved")]
    [InlineData("Upper", "invalid")]
    [InlineData("has space", "invalid")]
    [InlineData("dot.name", "invalid")]
    [InlineData("", "invalid")]
    [InlineData("a23456789012345678901234567890123", "invalid")] // 33 characters
    public void RouteName_ReservedOrInvalid_Refused(string name, string expected)
    {
        var json = WithRoute(Route().Replace("\"name\": \"r\"", $"\"name\": \"{name}\""));
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(json));
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void SocketName_Reserved_Refused()
    {
        var json = """{ "version": 1, "socket_dir": "/s", "sockets": [ { "name": "_x", "uids": ["1"], "routes": [] } ], "routes": [] }""";
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(json));
        Assert.Contains("reserved", ex.Message);
    }

    [Theory]
    [InlineData("""{ "type": "basic", "user": "a:b", "secret": "{{k}}" }""", "':'")]
    [InlineData("""{ "type": "basic", "user": "a\u0007b", "secret": "{{k}}" }""", "control")]
    [InlineData("""{ "type": "basic", "secret": "{{k}}" }""", "needs a 'user'")]
    public void BasicUser_Invalid_Refused(string auth, string expected)
    {
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(WithRoute(Route(auth: auth))));
        Assert.Contains(expected, ex.Message);
    }

    [Theory]
    [InlineData("X Api")]
    [InlineData("X:Api")]
    [InlineData("X-Api\r\nEvil")]
    [InlineData("")]
    [InlineData("Host")]
    [InlineData("Content-Length")]
    [InlineData("transfer-encoding")]
    [InlineData("Accept-Encoding")]
    [InlineData("Range")]
    [InlineData("if-range")]
    public void HeaderName_Invalid_Refused(string header)
    {
        var auth = $$$"""{ "type": "header", "header": {{{System.Text.Json.JsonSerializer.Serialize(header)}}}, "secret": "{{k}}" }""";
        Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(WithRoute(Route(auth: auth))));
    }

    [Theory]
    [InlineData("""{ "version": 1, "sockets": [], "routes": [], "extra": true }""")]
    [InlineData("""{ "version": 1, "sockets": [], "routes": [ { "name": "r", "upstream": "https://a.example", "auth": { "type": "bearer", "secret": "{{k}}" }, "path": "", "follow_redirects": true } ] }""")]
    [InlineData("""{ "version": 1, "sockets": [], "routes": [ { "name": "r", "upstream": "https://a.example", "auth": { "type": "bearer", "secret": "{{k}}", "scheme": "x" }, "path": "" } ] }""")]
    [InlineData("""{ "version": 1, "socket_dir": "/s", "sockets": [ { "name": "s", "uids": ["1"], "routes": [], "mode": "0777" } ], "routes": [] }""")]
    public void UnknownFields_Refused(string json)
    {
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(json));
        Assert.Contains("can't be read", ex.Message);
    }

    [Theory]
    [InlineData("""{ "version": 2, "sockets": [], "routes": [] }""", "version")]
    [InlineData("""{ "sockets": [], "routes": [] }""", "can't be read")]
    [InlineData("""{ "version": 1, "version": 1, "sockets": [], "routes": [] }""", "can't be read")]
    [InlineData("""{ "version": 1, "socket_dir": "relative", "sockets": [], "routes": [] }""", "absolute")]
    [InlineData("""{ "version": 1, "sockets": [ { "name": "s", "uids": ["1"], "routes": [] } ], "routes": [] }""", "no socket_dir")]
    [InlineData("""{ "version": 1, "socket_dir": "/s", "sockets": [ { "name": "s", "uids": ["1"], "routes": ["nope"] } ], "routes": [] }""", "not defined")]
    [InlineData("""{ "version": 1, "socket_dir": "/s", "sockets": [ { "name": "s", "uids": ["5-1"], "routes": [] } ], "routes": [] }""", "uid entry")]
    [InlineData("""{ "version": 1, "socket_dir": "/s", "sockets": [ { "name": "s", "uids": ["-1"], "routes": [] } ], "routes": [] }""", "uid entry")]
    [InlineData("""{ "version": 1, "socket_dir": "/s", "sockets": [ { "name": "s", "uids": [], "routes": [] } ], "routes": [] }""", "no uids")]
    public void OtherInvalidConfigs_Refused(string json, string expected)
    {
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(json));
        Assert.Contains(expected, ex.Message);
    }

    [Theory]
    [InlineData("""["CONNECT"]""")]
    [InlineData("""["TRACE"]""")]
    [InlineData("""["get"]""")]
    [InlineData("""[]""")]
    public void Methods_Invalid_Refused(string methods)
    {
        Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(WithRoute(Route(extra: $", \"methods\": {methods}"))));
    }

    [Theory]
    [InlineData("k}}")]
    [InlineData("{{a b}}")]
    [InlineData("{{a}}{{b}}")]
    public void SecretReference_Invalid_Refused(string secret)
    {
        var auth = $$"""{ "type": "bearer", "secret": {{System.Text.Json.JsonSerializer.Serialize(secret)}} }""";
        Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(WithRoute(Route(auth: auth))));
    }

    // ------------------------------------------------------------------ file load and reload

    [Fact]
    public void HandEditedInvalidFile_IsRefusedAtLoad()
    {
        File.WriteAllText(BrokerConfigFile.PathIn(_dir), WithRoute(Route(upstream: "http://plain.example")));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(BrokerConfigFile.PathIn(_dir), UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var ex = Assert.Throws<BrokerConfigException>(() => BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _dir));
        Assert.Contains("https://", ex.Message);
    }

    [Fact]
    public void GroupWritableFile_IsRefusedAtLoad()
    {
        if (OperatingSystem.IsWindows())
            return;
        var path = BrokerConfigFile.PathIn(_dir);
        File.WriteAllText(path, ValidJson);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupWrite);

        var ex = Assert.Throws<BrokerConfigException>(() => BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _dir));
        Assert.Contains("writable by group or others", ex.Message);
    }

    [Fact]
    public void Reload_InvalidOrMissingFile_KeepsTheCurrentConfig_ValidFileSwapsIn()
    {
        var path = BrokerConfigFile.PathIn(_dir);
        BrokerConfigFile.Save(DirectoryOwnerMatcher.Default, _dir, BrokerPolicy.Deserialize(ValidJson));
        var holder = new BrokerPolicyHolder(BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _dir));
        var original = holder.Current;
        var log = new List<string>();
        BrokerPolicy Load() => BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _dir);

        File.WriteAllText(path, ValidJson.Replace("\"version\": 1", "\"version\": 1, \"bogus\": 1"));
        Assert.False(holder.TryReload(Load, log.Add));
        Assert.Same(original, holder.Current);

        File.Delete(path);
        Assert.False(holder.TryReload(Load, log.Add));
        Assert.Same(original, holder.Current);
        Assert.All(log, l => Assert.Contains("keeping the current config", l));

        BrokerConfigFile.Save(DirectoryOwnerMatcher.Default, _dir,
            BrokerPolicy.Deserialize(ValidJson) with { Routes = [.. BrokerPolicy.Deserialize(ValidJson).Routes.Take(2)] });
        Assert.True(holder.TryReload(Load, log.Add));
        Assert.NotSame(original, holder.Current);
        Assert.False(holder.Current.Routes.ContainsKey("models"));
        Assert.True(original.Routes.ContainsKey("models")); // a request holding the old config keeps it
    }

    [Fact]
    public void Save_InvalidConfig_WritesNothing()
    {
        var bad = BrokerPolicy.Deserialize(WithRoute(Route())) with { Version = 7 };

        Assert.Throws<BrokerConfigException>(() => BrokerConfigFile.Save(DirectoryOwnerMatcher.Default, _dir, bad));
        Assert.False(File.Exists(BrokerConfigFile.PathIn(_dir)));
    }

    // ------------------------------------------------------------------ fix round 1

    [Fact]
    public void UnreadableFile_IsACleanConfigError()
    {
        if (OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess)
            return; // root reads a 000 file anyway
        var path = BrokerConfigFile.PathIn(_dir);
        File.WriteAllText(path, ValidJson);
        File.SetUnixFileMode(path, UnixFileMode.None);
        try
        {
            var ex = Assert.Throws<BrokerConfigException>(() => BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _dir));
            Assert.Contains("can't be read", ex.Message);
        }
        finally
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    /// <summary>Owners by path: the config folder's and broker.json's can differ.</summary>
    private sealed class PathOwnership(uint dirUid, uint fileUid) : IUnixOwnership
    {
        public bool IsPrivileged => false;
        public uint EffectiveUid => dirUid;
        public (uint Uid, uint Gid)? GetOwner(string path) =>
            Path.GetFileName(path) == BrokerConfigFile.FileName ? (fileUid, fileUid) : (dirUid, dirUid);
        public IDisposable ActAs(uint uid, uint gid, string path) => throw new InvalidOperationException("no switch expected");
    }

    [Fact]
    public void FileNotOwnedByTheVaultFoldersOwner_IsRefusedAtLoad()
    {
        if (OperatingSystem.IsWindows())
            return;
        var path = BrokerConfigFile.PathIn(_dir);
        File.WriteAllText(path, ValidJson);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var ex = Assert.Throws<BrokerConfigException>(() =>
            BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _dir, new PathOwnership(dirUid: 1000, fileUid: 1001)));
        Assert.Contains("owned by uid 1001", ex.Message);

        Assert.NotNull(BrokerConfigFile.Load(DirectoryOwnerMatcher.Default, _dir, new PathOwnership(dirUid: 1000, fileUid: 1000)));
    }
}
