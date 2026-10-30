using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T7 item 6 (#194, rest): a classic vault (<c>Storage</c>) made before T5 may have a 0755
/// folder and 0644 files. The next write narrows the folder to 0700 and its files to 0600, with one
/// notice naming what changed; a read changes nothing. Windows: no change (returns early).
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

    /// <summary>A classic XOR vault with one secret, then widened to 0755/0644 as main made them before T5.</summary>
    private void WideClassicVault()
    {
        _m.Ok("1\n2\n1\n", "init");
        _m.Ok("v1", "ingest", "first");
        Assert.Null(_m.Config.Store);
        File.SetUnixFileMode(_m.Dir, WideFolder);
        File.SetUnixFileMode(_m.ConfigPath, WideFile);
        File.SetUnixFileMode(_m.SecretsPath, WideFile);
    }

    [Fact]
    public void Ingest_TightensFolderAndFiles_WithOneNotice()
    {
        if (OperatingSystem.IsWindows())
            return;
        WideClassicVault();

        var (exit, stdout, stderr) = _m.Run("v2", "ingest", "second");

        Assert.True(exit == 0, stderr);
        Assert.Equal(FolderOwnerOnly, File.GetUnixFileMode(_m.Dir));
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(_m.SecretsPath));
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(_m.ConfigPath));
        var notice = Assert.Single((stdout + stderr).Split('\n'), l => l.Contains("tightened", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(_m.SecretsPath, notice);
        Assert.Contains(_m.ConfigPath, notice);
        Assert.DoesNotContain(notice, stdout); // a notice is on stderr
        Assert.Contains("second", _m.Ok("", "names"));
    }

    [Fact]
    public void Names_ChangesNothing()
    {
        if (OperatingSystem.IsWindows())
            return;
        WideClassicVault();

        var (exit, stdout, stderr) = _m.Run("", "names");

        Assert.True(exit == 0, stderr);
        Assert.Equal(WideFolder, File.GetUnixFileMode(_m.Dir));
        Assert.Equal(WideFile, File.GetUnixFileMode(_m.ConfigPath));
        Assert.Equal(WideFile, File.GetUnixFileMode(_m.SecretsPath));
        Assert.DoesNotContain("tightened", stdout + stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AlreadyTightVault_WriteGivesNoNotice()
    {
        if (OperatingSystem.IsWindows())
            return;
        _m.Ok("1\n2\n1\n", "init");

        var (exit, stdout, stderr) = _m.Run("v1", "ingest", "first");

        Assert.True(exit == 0, stderr);
        Assert.DoesNotContain("tightened", stdout + stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(_m.SecretsPath));
    }
}
