using System.Text.Json;
using TswapCore.Broker;
using TswapCore.Broker.Templates;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief I224 D7 H1 (task 6): a template bind may not be, contain or be inside the broker's run folder
/// (where <c>control.sock</c> lives), whether or not that folder exists yet. The candidate that needs it
/// is <c>~/.cache/tswap/run</c> (used when the vault user has no <c>/run/user/&lt;uid&gt;</c>); the
/// <c>/run/user/&lt;uid&gt;/tswap</c> one is already refused by the <c>/run</c> forbidden root.
/// </summary>
public class BrokerTemplateRunFolderTests : IDisposable
{
    private readonly string _root;

    public BrokerTemplateRunFolderTests()
    {
        var root = Path.Combine(Path.GetTempPath(), "tswap-tplrun-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        _root = OperatingSystem.IsWindows() ? root : BrokerNative.RealPath(root) ?? root;
        if (OperatingSystem.IsWindows())
            return;
        File.SetUnixFileMode(_root, Mode755);
        MakeFolder(Home);
        MakeFolder(Cache);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, true);
    }

    private static readonly UnixFileMode Mode755 = (UnixFileMode)0b111_101_101;

    /// <summary>A stand-in for the vault user's home.</summary>
    private string Home => Path.Combine(_root, "home");

    private string Cache => Path.Combine(Home, ".cache");

    /// <summary>The run folder a vault user without <c>/run/user/&lt;uid&gt;</c> gets.</summary>
    private string RunFolder => Path.Combine(Cache, "tswap", "run");

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void MakeFolder(string path)
    {
        Directory.CreateDirectory(path);
        File.SetUnixFileMode(path, Mode755);
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private void MakeRunFolder()
    {
        MakeFolder(Path.Combine(Cache, "tswap"));
        Directory.CreateDirectory(RunFolder);
        File.SetUnixFileMode(RunFolder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private BrokerHostContext Host(string? runFolder = null) => new(BrokerHarness.MyUid, [], [], [runFolder ?? RunFolder]);

    private static string J(string s) => JsonSerializer.Serialize(s);

    private static string Config(string bind, bool rw) => $$"""
        {
          "version": 1,
          "socket_dir": "/run/tswap-broker",
          "sockets": [ { "name": "lane1", "uid_only": true, "uids": ["100999"], "routes": [], "templates": ["t"] } ],
          "routes": [],
          "templates": [ { "name": "t", "argv": ["/usr/bin/true"], "binds": [ { "path": {{J(bind)}}, "rw": {{(rw ? "true" : "false")}} } ] } ]
        }
        """;

    private void Refused(string bind, bool rw, string relation, BrokerHostContext? host = null)
    {
        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(Config(bind, rw), host ?? Host()));
        Assert.Contains($"bind {bind} {relation} the broker's run folder {RunFolder}", ex.Message);
        Assert.Contains("(a template could delete or use the control socket)", ex.Message);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ABindContainingAnExistingRunFolder_IsRefused(bool rw)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        MakeRunFolder();

        Refused(Cache, rw, "contains");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ABindContainingARunFolderThatDoesNotExistYet_IsRefused(bool rw)
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        Assert.False(Path.Exists(Path.Combine(Cache, "tswap"))); // nothing of the run folder exists yet

        Refused(Cache, rw, "contains");
    }

    [Fact]
    public void TheRunFolderItself_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        MakeRunFolder();

        Refused(RunFolder, rw: false, "is");
    }

    [Fact]
    public void ABindInsideTheRunFolder_IsRefused()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        MakeRunFolder();
        var inside = Path.Combine(RunFolder, "x");
        MakeFolder(inside);

        Refused(inside, rw: true, "is inside");
    }

    [Fact]
    public void ASiblingFolderOfTheRunFoldersParent_IsAccepted()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var other = Path.Combine(Cache, "other");
        MakeFolder(other);

        var notYet = BrokerPolicy.Parse(Config(other, rw: true), Host()).Templates["t"]; // run folder not there yet
        Assert.Equal(other, Assert.Single(notYet.Binds).Path);
        MakeRunFolder();
        var existing = BrokerPolicy.Parse(Config(other, rw: true), Host()).Templates["t"];
        Assert.Equal(other, Assert.Single(existing.Binds).Path);
    }

    [Fact]
    public void ARunFolderBelowASymlink_IsComparedAtItsResolvedPlace()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        // ~/.cache is a symlink to a folder elsewhere; the run folder doesn't exist yet, so only the
        // nearest existing ancestor (the symlink) can be resolved. A bind of the link's target is the
        // run folder's resolved parent and must be refused, though no name of it matches the run folder's.
        var elsewhere = Path.Combine(_root, "elsewhere");
        MakeFolder(elsewhere);
        Directory.Delete(Cache);
        File.CreateSymbolicLink(Cache, elsewhere);

        var ex = Assert.Throws<BrokerConfigException>(() => BrokerPolicy.Parse(Config(elsewhere, rw: true), Host()));
        Assert.Contains($"bind {elsewhere} contains the broker's run folder {RunFolder}", ex.Message);
        Assert.Contains("(a template could delete or use the control socket)", ex.Message);
    }

    [Fact]
    public void TheRunFolder_IsReCheckedBeforeEveryRun()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        // Valid at load against a host whose run folder is elsewhere; the same template against the
        // real host context is refused by the per-run re-check.
        var template = BrokerPolicy.Parse(Config(Cache, rw: true), Host(Path.Combine(_root, "not-here", "run"))).Templates["t"];
        Assert.True(BrokerTemplateValidator.RecheckBinds(template, Host(Path.Combine(_root, "not-here", "run")), null, BrokerPolicy.DefaultBwrapPath, out _));

        Assert.False(BrokerTemplateValidator.RecheckBinds(template, Host(), null, BrokerPolicy.DefaultBwrapPath, out var problem));
        Assert.Contains($"contains the broker's run folder {RunFolder}", problem);
    }

    [Fact]
    public void ForVault_ProtectsBothCandidateRunFolders()
    {
        if (!OperatingSystem.IsLinux())
            return; // templates are Linux only (bwrap)
        var uid = BrokerHarness.MyUid;
        var home = BrokerNative.HomeOf(uid);
        Assert.False(string.IsNullOrEmpty(home)); // the test user has a home folder

        var host = BrokerHostContext.ForVault(_root, null);

        Assert.Equal([$"/run/user/{uid}/tswap", Path.Combine(home!, ".cache", "tswap", "run")], host.RunFolders);
    }
}
