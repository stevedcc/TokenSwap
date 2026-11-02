using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 8 (ruling 4): a plain <c>init</c> makes a record vault (one YubiKey slot plus
/// a recovery slot) in <c>&lt;config dir&gt;/vault</c>, or in <c>--folder &lt;dir&gt;</c>, with the
/// <c>record-format</c> marker; <c>--keyring</c> is a no-op; a classic vault is never initialized over.
/// </summary>
public sealed class InitRecordVaultTests : IDisposable
{
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly FleetMachine _m;
    private readonly string _outside = Path.Combine(Path.GetTempPath(), "tswap-init-folder-" + Guid.NewGuid().ToString("N")[..8]);

    public InitRecordVaultTests() => _m = new FleetMachine("init-record", _keys);

    public void Dispose()
    {
        _m.Dispose();
        if (Directory.Exists(_outside))
            Directory.Delete(_outside, true);
    }

    private void AssertRecordVault(string vaultDir)
    {
        var config = _m.Config;
        Assert.Equal(RecordVaultStore.StoreName, config.Store);
        Assert.Equal(Path.GetFullPath(vaultDir), config.VaultDir);
        Assert.Null(config.Keyring);
        Assert.NotNull(config.OriginId);
        Assert.False(File.Exists(_m.SecretsPath));
        Assert.Equal("3", File.ReadAllText(Path.Combine(vaultDir, RecordVaultStore.RecordFormatMarkerFileName)).Trim());
        var keyring = KeyringCodec.Decode(File.ReadAllBytes(Path.Combine(vaultDir, "keyring")));
        Assert.Equal(2, keyring.Slots.Count);
        Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Machine && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob));
        Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery);
    }

    [Fact]
    public void Init_Plain_MakesARecordVault_WithMarker()
    {
        var output = _m.Ok("", "init");

        var vaultDir = Path.Combine(_m.Dir, "vault");
        AssertRecordVault(vaultDir);
        Assert.Contains(vaultDir, output);
        var key = VaultKey(_m, RecoveryKeyFrom(output));
        _m.Ok("", "create", "s");
        var file = RecordFile(_m, key, "s");
        Assert.Equal((byte?)3, SecretRecordCodec.FormatVersionOf(File.ReadAllBytes(file)));
        Assert.NotNull(ReadRecord(_m, key, "s").Fingerprints);
        Assert.NotEmpty(_m.Get("s"));
    }

    [Fact]
    public void Init_Folder_CreatesTheVaultThere()
    {
        var output = _m.Ok("", "init", "--folder", _outside);

        AssertRecordVault(_outside);
        Assert.False(Directory.Exists(Path.Combine(_m.Dir, "vault")));
        var key = VaultKey(_m, RecoveryKeyFrom(output));
        _m.Ok("v", "ingest", "s");
        Assert.True(File.Exists(Path.Combine(_outside, "records", FilenameHasher.ComputeFilename(RecordKeyDerivation.DeriveNamesKey(key), "s"))));
        Assert.Equal("v", _m.Get("s"));
    }

    [Fact]
    public void Init_Folder_AnEmptyFolder_IsUsed()
    {
        Directory.CreateDirectory(_outside);

        _m.Ok("", "init", "--folder", _outside);

        AssertRecordVault(_outside);
    }

    [Fact]
    public void Init_Folder_RefusesANonEmptyFolder()
    {
        Directory.CreateDirectory(_outside);
        File.WriteAllText(Path.Combine(_outside, "something"), "x");

        var (exit, _, err) = _m.Run("", "init", "--folder", _outside);

        Assert.NotEqual(0, exit);
        Assert.Contains("not empty", err);
        Assert.False(File.Exists(_m.ConfigPath));
        Assert.Equal(["something"], Directory.GetFileSystemEntries(_outside).Select(Path.GetFileName));
    }

    [Fact]
    public void Init_Folder_WithoutAValue_IsAUsageError()
    {
        var (exit, _, err) = _m.Run("", "init", "--folder");

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage", err);
        Assert.False(File.Exists(_m.ConfigPath));
    }

    [Fact]
    public void Init_KeyringFlag_IsAcceptedAsNoOp()
    {
        _m.Ok("", "init", "--keyring");

        AssertRecordVault(Path.Combine(_m.Dir, "vault"));
    }

    [Fact]
    public void Init_NoRecovery_IsAcceptedOnAPlainInit()
    {
        _m.Ok("", "init", "--no-recovery");

        var keyring = KeyringCodec.Decode(File.ReadAllBytes(Path.Combine(_m.Dir, "vault", "keyring")));
        Assert.Single(keyring.Slots);
    }

    [Fact]
    public void Init_OnAClassicVault_Refuses()
    {
        var bothKeys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
        _m.Keys = bothKeys;
        ClassicVaultTestSupport.CreateXorVault(_m);
        var config = File.ReadAllBytes(_m.ConfigPath);
        var secrets = File.ReadAllBytes(_m.SecretsPath);

        var (exit, _, err) = _m.Run("yes\n", "init");

        Assert.Equal(1, exit);
        Assert.Contains(
            "This config folder holds a classic vault. Convert it with 'sudo tswap migrate --to-records', or move config.json " +
            "and secrets.json.enc aside to start a new vault.", err);
        Assert.Equal(config, File.ReadAllBytes(_m.ConfigPath));
        Assert.Equal(secrets, File.ReadAllBytes(_m.SecretsPath));
        Assert.False(Directory.Exists(Path.Combine(_m.Dir, "vault")));
    }

    [Fact]
    public void Init_OnARecordVault_KeepsRefusing()
    {
        _m.Ok("", "init");
        var config = File.ReadAllText(_m.ConfigPath);

        var (exit, _, err) = _m.Run("yes\n", "init");

        Assert.NotEqual(0, exit);
        Assert.Contains("shared record-store vault", err);
        Assert.Equal(config, File.ReadAllText(_m.ConfigPath));
    }

    [Fact]
    public void Init_Folder_WindowsAndUnixPaths()
    {
        // Relative to the working directory, and absolute with '..' segments and the other
        // separator: both are stored as the one full path.
        var relativeName = "tswap-init-rel-" + Guid.NewGuid().ToString("N")[..8];
        var expectedRelative = Path.GetFullPath(relativeName);
        try
        {
            _m.Ok("", "init", "--folder", relativeName);
            Assert.Equal(expectedRelative, _m.Config.VaultDir);
            Assert.True(File.Exists(Path.Combine(expectedRelative, "keyring")));
        }
        finally
        {
            if (Directory.Exists(expectedRelative))
                Directory.Delete(expectedRelative, true);
        }

        var other = new FleetMachine("init-record-abs", SimulatedYubiKeyService.WithKeys(SerialA));
        try
        {
            var spelled = Path.Combine(_outside, "sub", "..", "vault").Replace(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            other.Ok("", "init", "--folder", spelled);
            Assert.Equal(Path.GetFullPath(Path.Combine(_outside, "vault")), other.Config.VaultDir);
        }
        finally
        {
            other.Dispose();
        }
    }

    [Fact]
    public void Init_HelpText_NoLongerOffersTwoYubiKeys()
    {
        var command = TswapCli.CommandRegistry.All.Single(c => c.Name == "init");

        Assert.DoesNotContain("2 YubiKeys", command.Description);
        Assert.Contains("--folder", command.HelpUsage);
    }
}
