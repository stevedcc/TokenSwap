using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T6 item 7 (decision 5): <c>vault merge &lt;other-vault-dir&gt;</c> folds another copy of
/// the vault folder (moved by scp, rsync or USB rather than a sync tool) into this one: its keyring
/// as a union, its records by the merge rules. The other copy is only read.
/// </summary>
public sealed class VaultMergeTests : IDisposable
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly FleetMachine _home;
    private readonly FleetMachine _laptop;
    private readonly string _recoveryKey;
    private readonly byte[] _vaultKey;
    private DateTimeOffset _homeNow = T0;
    private DateTimeOffset _laptopNow = T0;

    public VaultMergeTests()
    {
        _home = new FleetMachine("merge-home", _keys) { Clock = () => _homeNow };
        _laptop = new FleetMachine("merge-laptop", _keys) { Clock = () => _laptopNow };
        _keys.PluggedIn = [SerialA];
        _recoveryKey = InitRecordVault(_home);
        _vaultKey = VaultKey(_home, _recoveryKey);
    }

    public void Dispose()
    {
        _home.Dispose();
        _laptop.Dispose();
    }

    /// <summary>The laptop gets its own copy of the home vault folder (scp / USB).</summary>
    private void LaptopCopiesTheFolder()
    {
        var copy = Path.Combine(_laptop.Dir, "vault");
        CopyFolder(_home.VaultDir!, copy);
        File.WriteAllText(_laptop.ConfigPath, JsonSerializer.Serialize(
            _home.Config with { VaultDir = copy, OriginId = RecordVaultStore.NewOriginId(), LastHlc = null }, TswapJsonContext.Default.Config));
    }

    private static string Snapshot(string folder, string into)
    {
        CopyFolder(folder, into);
        return into;
    }

    private static Dictionary<string, string> FolderBytes(string folder) =>
        Directory.GetFiles(folder, "*", SearchOption.AllDirectories)
            .ToDictionary(f => Path.GetRelativePath(folder, f), f => Convert.ToHexString(File.ReadAllBytes(f)));

    private Dictionary<string, SecretRecord> States(string vaultFolder) =>
        Directory.GetFiles(Path.Combine(vaultFolder, "records"))
            .Where(f => Path.GetFileName(f).Length == 64)
            .ToDictionary(f => Path.GetFileName(f), f => SecretRecordCodec.Decode(File.ReadAllBytes(f), _vaultKey));

    /// <summary>Two copies edited separately; returns snapshots of both folders before any merge.</summary>
    private (string HomeSnapshot, string LaptopSnapshot) DivergedCopies(string scratch)
    {
        _home.Ok("base", "ingest", "both");
        _home.Ok("doomed-value", "ingest", "doomed");
        _home.Ok("token-v1", "ingest", "token");
        LaptopCopiesTheFolder();

        _homeNow = T0.AddMinutes(10);
        _home.Ok("home-only", "ingest", "only-home");
        _home.Ok("home-edit\nhome-edit\n", "add", "both");
        _home.Ok("", "delete", "doomed");
        _home.Ok("", "burn", "token", "leaked at home");

        _laptopNow = T0.AddMinutes(20);
        _laptop.Ok("laptop-only", "ingest", "only-laptop");
        _laptop.Ok("laptop-edit\nlaptop-edit\n", "add", "both");
        _laptop.Ok("token-v2", "ingest", "--rotate", "token");

        return (Snapshot(_home.VaultDir!, Path.Combine(scratch, "home-snapshot")),
            Snapshot(_laptop.VaultDir!, Path.Combine(scratch, "laptop-snapshot")));
    }

    [Fact]
    public void TwoCopiesEditedSeparately_MergeToTheRulesResult_InBothDirectionsToTheSameState()
    {
        var scratch = Path.Combine(_home.Dir, "scratch");
        var (homeSnapshot, laptopSnapshot) = DivergedCopies(scratch);
        _homeNow = _laptopNow = T0.AddMinutes(30);

        _home.Ok("", "vault", "merge", laptopSnapshot);
        _laptop.Ok("", "vault", "merge", homeSnapshot);

        foreach (var machine in new[] { _home, _laptop })
        {
            Assert.Equal("home-only", machine.Get("only-home"));
            Assert.Equal("laptop-only", machine.Get("only-laptop"));
            Assert.Equal("laptop-edit", machine.Get("both")); // the later write wins
            Assert.Equal(1, machine.Run("", "get", "doomed").Exit); // the delete on one copy wins
            Assert.Equal("token-v2", machine.Get("token")); // the rotation supersedes the burn...
            var burned = machine.Ok("", "burned");
            Assert.Contains("leaked at home", burned); // ...which is kept as history
            Assert.Contains("Rotated", burned);
            Assert.DoesNotContain("[BURNED]", machine.Ok("", "names"));
        }

        var homeStates = States(_home.VaultDir!);
        var laptopStates = States(_laptop.VaultDir!);
        Assert.Equal(homeStates.Keys.Order(), laptopStates.Keys.Order());
        Assert.All(homeStates, kv => Assert.True(kv.Value.SameState(laptopStates[kv.Key]), $"record {kv.Key} differs"));
    }

    [Fact]
    public void MergingTheSameCopyTwice_ChangesNothingTheSecondTime()
    {
        var scratch = Path.Combine(_home.Dir, "scratch");
        var (_, laptopSnapshot) = DivergedCopies(scratch);
        _home.Ok("", "vault", "merge", laptopSnapshot);
        var vaultAfterFirst = FolderBytes(_home.VaultDir!);
        var configAfterFirst = File.ReadAllText(_home.ConfigPath);

        var second = _home.Ok("", "vault", "merge", laptopSnapshot);

        Assert.Equal(vaultAfterFirst, FolderBytes(_home.VaultDir!));
        Assert.Equal(configAfterFirst, File.ReadAllText(_home.ConfigPath));
        Assert.Contains("Nothing to merge", second);
    }

    [Fact]
    public void TheSourceCopy_IsUnchanged()
    {
        var scratch = Path.Combine(_home.Dir, "scratch");
        DivergedCopies(scratch);
        // A conflicted copy in the source, which a merge into it would remove.
        var source = _laptop.VaultDir!;
        var someRecord = Directory.GetFiles(Path.Combine(source, "records")).First();
        File.Copy(someRecord, someRecord + " (1)");
        var before = FolderBytes(source);

        _home.Ok("", "vault", "merge", source);

        Assert.Equal(before, FolderBytes(source));
    }

    [Fact]
    public void ADifferentVaultId_IsRefused_AndNothingIsWritten()
    {
        _home.Ok("v", "ingest", "s");
        using var stranger = new FleetMachine("merge-stranger", _keys);
        InitRecordVault(stranger);
        stranger.Ok("x", "ingest", "other");
        var before = FolderBytes(_home.VaultDir!);

        var (exit, _, err) = _home.Run("", "vault", "merge", stranger.VaultDir!);

        Assert.NotEqual(0, exit);
        Assert.Contains("another vault", err);
        Assert.Equal(before, FolderBytes(_home.VaultDir!));
    }

    [Fact]
    public void TheSameSlotIdWithDifferentBytes_IsRefused()
    {
        _home.Ok("v", "ingest", "s");
        LaptopCopiesTheFolder();
        var keyringPath = Path.Combine(_laptop.VaultDir!, "keyring");
        var keyring = KeyringCodec.Decode(File.ReadAllBytes(keyringPath));
        var tampered = keyring with
        {
            Slots = [keyring.Slots[0] with { Wrapped = RandomNumberGenerator.GetBytes(keyring.Slots[0].Wrapped.Length) }, .. keyring.Slots.Skip(1)],
        };
        File.WriteAllBytes(keyringPath, KeyringCodec.Encode(tampered));
        var before = FolderBytes(_home.VaultDir!);

        var (exit, _, err) = _home.Run("", "vault", "merge", _laptop.VaultDir!);

        Assert.NotEqual(0, exit);
        Assert.Contains("differs", err);
        Assert.Equal(before, FolderBytes(_home.VaultDir!));
    }

    [Fact]
    public void ANewSlotInTheOtherCopy_NeedsConfirmation_LikeSlotMerge()
    {
        LaptopCopiesTheFolder();
        _keys.PluggedIn = [SerialA, SerialB];
        _laptop.Ok("", "slot", "add", "--yubikey"); // key B gets a slot in the laptop's copy only
        _keys.PluggedIn = [SerialA];
        var before = FolderBytes(_home.VaultDir!);

        var refused = _home.Run("", "vault", "merge", _laptop.VaultDir!);
        Assert.NotEqual(0, refused.Exit);
        Assert.Contains("did not approve", refused.Err);
        Assert.Equal(before, FolderBytes(_home.VaultDir!));

        _home.Ok("", "vault", "merge", _laptop.VaultDir!, "--yes");
        _home.Ok("v", "ingest", "s");
        _keys.PluggedIn = [SerialB];
        Assert.Equal("v", _home.Get("s"));
    }

    [Fact]
    public void WithoutSudo_IsRefused()
    {
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged (Windows CI runs elevated; see SlotCommandTests)
        LaptopCopiesTheFolder();
        _home.Sudo = false;

        Assert.Contains("requires", _home.Run("", "vault", "merge", _laptop.VaultDir!).Err);
    }

    [Fact]
    public void OnAClassicVault_IsRefused()
    {
        using var classic = new FleetMachine("merge-classic", _keys);
        classic.Ok("", "init", "--keyring");

        Assert.Contains("migrate --to-records", classic.Run("", "vault", "merge", _home.VaultDir!).Err);
    }

    private static void CopyFolder(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var file in Directory.GetFiles(from))
            File.Copy(file, Path.Combine(to, Path.GetFileName(file)));
        foreach (var dir in Directory.GetDirectories(from))
            CopyFolder(dir, Path.Combine(to, Path.GetFileName(dir)));
    }
}
