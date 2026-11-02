using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T7 item 6 (#194, rest): a classic vault (<c>Storage</c>) made before T5 may have a 0755
/// folder and 0644 files. The next write narrows the folder to 0700 and its files to 0600, with one
/// notice naming what changed; a read changes nothing. Windows: no change (returns early).
/// <para>
/// Brief T16-S1: commands refuse a classic vault now (ruling 5) except migrate and export, which
/// still read and write it through <see cref="Storage"/>, so the store is exercised directly (a write,
/// a read) where these tests ran <c>ingest</c> and <c>names</c>.
/// </para>
/// </summary>
public class ClassicVaultModeTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode FolderOwnerOnly = OwnerOnly | UnixFileMode.UserExecute;
    private const UnixFileMode WideFolder = FolderOwnerOnly | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
    private const UnixFileMode WideFile = OwnerOnly | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    private readonly FleetMachine _m = new("classic-modes", SimulatedYubiKeyService.WithKeys(SerialA, SerialB));

    public void Dispose() => _m.Dispose();

    private byte[] _key = [];

    /// <summary>A classic XOR vault with one secret, then widened to 0755/0644 as main made them before T5.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private void WideClassicVault()
    {
        _key = ClassicVaultTestSupport.CreateXorVault(_m, SerialA, SerialB, new Dictionary<string, Secret> { ["first"] = new("v1", DateTime.UtcNow, DateTime.UtcNow) });
        Assert.Null(_m.Config.Store);
        File.SetUnixFileMode(_m.Dir, WideFolder);
        File.SetUnixFileMode(_m.ConfigPath, WideFile);
        File.SetUnixFileMode(_m.SecretsPath, WideFile);
    }

    /// <summary>A write through the classic store (what ingest did): adds <paramref name="name"/>.</summary>
    private string Write(string name, string value)
    {
        var warnings = new StringWriter();
        var store = new Storage(_m.Dir, warnings: warnings);
        var db = store.LoadSecrets(_key, warnings);
        db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
        store.SaveSecrets(db, _key);
        return warnings.ToString();
    }

    [Fact]
    public void Ingest_TightensFolderAndFiles_WithOneNotice()
    {
        if (OperatingSystem.IsWindows())
            return;
        WideClassicVault();

        var stderr = Write("second", "v2");

        Assert.Equal(FolderOwnerOnly, File.GetUnixFileMode(_m.Dir));
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(_m.SecretsPath));
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(_m.ConfigPath));
        var notice = Assert.Single(stderr.Split('\n'), l => l.Contains("tightened", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(_m.SecretsPath, notice);
        Assert.Contains(_m.ConfigPath, notice);
        Assert.Contains("second", new Storage(_m.Dir).LoadSecrets(_key, TextWriter.Null).Secrets.Keys);
    }

    [Fact]
    public void Names_ChangesNothing()
    {
        if (OperatingSystem.IsWindows())
            return;
        WideClassicVault();
        var warnings = new StringWriter();

        var names = new Storage(_m.Dir, warnings: warnings).LoadSecrets(_key, warnings).Secrets.Keys;

        Assert.Contains("first", names);
        Assert.Equal(WideFolder, File.GetUnixFileMode(_m.Dir));
        Assert.Equal(WideFile, File.GetUnixFileMode(_m.ConfigPath));
        Assert.Equal(WideFile, File.GetUnixFileMode(_m.SecretsPath));
        Assert.DoesNotContain("tightened", warnings.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AlreadyTightVault_WriteGivesNoNotice()
    {
        if (OperatingSystem.IsWindows())
            return;
        _key = ClassicVaultTestSupport.CreateXorVault(_m, SerialA, SerialB); // written through the store, as init did: already 0700/0600

        var stderr = Write("first", "v1");

        Assert.DoesNotContain("tightened", stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(_m.SecretsPath));
    }
}
