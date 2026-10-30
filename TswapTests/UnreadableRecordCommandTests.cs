using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Fix round 1, A3: commands that cover the whole vault (export, list) fail closed when a record
/// can't be read, naming the hashed file, instead of producing a backup or listing that silently
/// lacks a secret.
/// </summary>
public sealed class UnreadableRecordCommandTests : IDisposable
{
    private readonly FleetMachine _m = new("unreadable-cmds", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly string _damaged;

    public UnreadableRecordCommandTests()
    {
        var vaultKey = VaultKey(_m, InitRecordVault(_m));
        _m.Ok("v1", "ingest", "fine");
        _m.Ok("v2", "ingest", "damaged");
        _damaged = RecordFile(_m, vaultKey, "damaged");
        File.WriteAllBytes(_damaged, File.ReadAllBytes(_damaged)[..120]);
    }

    public void Dispose() => _m.Dispose();

    [Fact]
    public void Export_RefusesAndWritesNoFile()
    {
        var export = _m.PathOf("backup.json");

        var (exit, _, err) = _m.Run("pass\npass\n", "export", export);

        Assert.NotEqual(0, exit);
        Assert.Contains(Path.GetFileName(_damaged), err);
        Assert.False(File.Exists(export));
    }

    [Fact]
    public void List_Refuses_NamingTheFile()
    {
        var (exit, stdout, err) = _m.Run("", "list");

        Assert.NotEqual(0, exit);
        Assert.Contains(Path.GetFileName(_damaged), err);
        Assert.DoesNotContain("fine", stdout);
    }
}
