using System.Text.Json;
using TswapCore.Broker;
using TswapCore.Broker.Templates;
using Xunit;

namespace TswapTests;

/// <summary>
/// I224 round 2 (G5, MiMo r2 Nano 6): a symbolic link on a template's program or bwrap_path that can't be read
/// is refused with its own reason, not as "more than 40 symbolic links". Sets the static readlink seam.
/// </summary>
[Collection(StaticSeamCollection.Name)]
public sealed class BrokerTemplateReadLinkTests : IDisposable
{
    private readonly string _root;

    public BrokerTemplateReadLinkTests()
    {
        var root = Path.Combine(Path.GetTempPath(), "tswap-tplrl-" + Guid.NewGuid().ToString("N")[..8]);
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
        BrokerTemplateValidator.ReadLink = BrokerTemplateValidator.DefaultReadLinkForTests;
        if (Directory.Exists(_root))
            Directory.Delete(_root, true);
    }

    private static readonly UnixFileMode Mode755 = (UnixFileMode)0b111_101_101;

    private string Work => Path.Combine(_root, "work");

    private static string J(string s) => JsonSerializer.Serialize(s);

    private string Config(string program, string? bwrapPath = null) => $$"""
        {
          "version": 1,
          "socket_dir": "/run/tswap-broker",
          {{(bwrapPath is null ? "" : $"\"bwrap_path\": {J(bwrapPath)},")}}
          "sockets": [ { "name": "lane1", "uid_only": true, "uids": ["100999"], "routes": [], "templates": ["t"] } ],
          "routes": [],
          "templates": [ { "name": "t", "argv": [{{J(program)}}], "binds": [ { "path": {{J(Work)}}, "rw": true } ] } ]
        }
        """;

    private static string Refused(string json) =>
        Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(json, new BrokerHostContext(BrokerHarness.MyUid, [], [], []))).Message;

    [Fact]
    public void AnUnreadableLink_OnTheProgramOrBwrapPath_IsRefusedWithItsOwnReason()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var link = Path.Combine(_root, "link");
        File.CreateSymbolicLink(link, Path.Combine(Work, "v2")); // dangling, so the resolver must readlink it
        BrokerTemplateValidator.ReadLink = _ => null; // as readlink failing (EACCES, EIO) on a link lstat sees

        Assert.Equal($"template t: program {link}/deploy can't be resolved (can't read symbolic link {link}), so it can't be checked against the binds",
            Refused(Config($"{link}/deploy")));
        Assert.Equal($"bwrap_path {link}/bwrap can't be resolved (can't read symbolic link {link}), so it can't be checked against template t's binds",
            Refused(Config("/usr/bin/true", $"{link}/bwrap")));
    }
}
