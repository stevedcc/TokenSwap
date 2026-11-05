using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 8 (ruling 4): a plain <c>init</c> makes a record vault (one YubiKey slot plus
/// a recovery slot) in <c>&lt;config dir&gt;/vault</c>, or in <c>--folder &lt;dir&gt;</c>, with the
/// <c>record-format</c> marker; a classic vault is never initialized over. Guided init (v0.2.0): that is
/// now <c>init --yubikey</c>; <c>--keyring</c> (a no-op until then) is refused, see <see cref="InitFlagsTests"/>.
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
        Assert.Null(config.UnlockChallenge); // a field of the classic XOR pair: a record vault's init writes none
        Assert.Empty(config.YubiKeySerials);
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
        var output = _m.Ok("", "init", "--yubikey");

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
        var output = _m.Ok("", "init", "--yubikey", "--folder", _outside);

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

        _m.Ok("", "init", "--yubikey", "--folder", _outside);

        AssertRecordVault(_outside);
    }

    [Fact]
    public void Init_Folder_RefusesANonEmptyFolder()
    {
        Directory.CreateDirectory(_outside);
        File.WriteAllText(Path.Combine(_outside, "something"), "x");

        var (exit, _, err) = _m.Run("", "init", "--yubikey", "--folder", _outside);

        Assert.NotEqual(0, exit);
        Assert.Contains("not empty", err);
        Assert.False(File.Exists(_m.ConfigPath));
        Assert.Equal(["something"], Directory.GetFileSystemEntries(_outside).Select(Path.GetFileName));
    }

    [Fact]
    public void Init_Folder_WithoutAValue_IsAUsageError()
    {
        var (exit, _, err) = _m.Run("", "init", "--yubikey", "--folder");

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage", err);
        Assert.False(File.Exists(_m.ConfigPath));
    }

    [Fact]
    public void Init_YubiKeyFlag_MakesTheRecordVault()
    {
        _m.Ok("", "init", "--yubikey");

        AssertRecordVault(Path.Combine(_m.Dir, "vault"));
    }

    [Fact]
    public void Init_NoRecovery_IsAcceptedOnAPlainInit()
    {
        _m.Ok("", "init", "--yubikey", "--no-recovery");

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

        var (exit, _, err) = _m.Run("yes\n", "init", "--yubikey");

        Assert.Equal(1, exit);
        Assert.Contains(
            "This config folder holds a classic vault. Convert it with 'sudo tswap migrate --to-records', or move config.json " +
            "and secrets.json.enc aside to start a new vault.", err);
        Assert.Equal(config, File.ReadAllBytes(_m.ConfigPath));
        Assert.Equal(secrets, File.ReadAllBytes(_m.SecretsPath));
        Assert.False(Directory.Exists(Path.Combine(_m.Dir, "vault")));
    }

    /// <summary>
    /// Fix round 1 (MiMo C1 / GLM S1): ruling 4's refusal is for an actual classic vault only. A
    /// config.json holding just a pending 'slot request' is not one (CommandContext.IsClassicVault's
    /// definition); init keeps what it did before this brief there: it asks, and "no" changes nothing.
    /// </summary>
    [Fact]
    public void Init_OnAPendingSlotRequestConfig_AsksAsBefore_NoChangesNothing()
    {
        _m.Ok("", "slot", "request", _m.PathOf("request.json"));
        var config = File.ReadAllText(_m.ConfigPath);
        Assert.NotNull(_m.Config.PendingSlotId);

        var (exit, stdout, err) = _m.Run("no\n", "init", "--yubikey");

        Assert.True(exit == 0, err);
        Assert.Contains("Already initialized. Reinitialize?", stdout);
        Assert.DoesNotContain("classic", err);
        Assert.Equal(config, File.ReadAllText(_m.ConfigPath));
        Assert.False(Directory.Exists(Path.Combine(_m.Dir, "vault")));
    }

    [Fact]
    public void Init_OnAPendingSlotRequestConfig_Yes_BacksItUpAndMakesTheRecordVault()
    {
        _m.Ok("", "slot", "request", _m.PathOf("request.json"));
        var config = File.ReadAllText(_m.ConfigPath);

        var (exit, _, err) = _m.Run("yes\n", "init", "--yubikey");

        Assert.True(exit == 0, err);
        Assert.Equal(config, File.ReadAllText(Assert.Single(_m.Backups)));
        AssertRecordVault(Path.Combine(_m.Dir, "vault"));
        Assert.Null(_m.Config.PendingSlotId);
    }

    [Fact]
    public void Init_OnALoneClassicSecretsFile_Refuses()
    {
        File.WriteAllBytes(_m.SecretsPath, [1, 2, 3]);

        var (exit, _, err) = _m.Run("yes\n", "init", "--yubikey");

        Assert.Equal(1, exit);
        Assert.Contains("This config folder holds a classic vault.", err);
        Assert.False(File.Exists(_m.ConfigPath));
        Assert.Equal([1, 2, 3], File.ReadAllBytes(_m.SecretsPath));
    }

    [Fact]
    public void Init_OnARecordVault_KeepsRefusing()
    {
        _m.Ok("", "init", "--yubikey");
        var config = File.ReadAllText(_m.ConfigPath);

        var (exit, _, err) = _m.Run("yes\n", "init", "--yubikey");

        Assert.Equal(1, exit);
        Assert.Contains("shared record-store vault", err);
        Assert.Equal(config, File.ReadAllText(_m.ConfigPath));
    }

    /// <summary>A snapshot of every file under <paramref name="folder"/> (path, bytes).</summary>
    private static Dictionary<string, string> Snapshot(string folder) =>
        Directory.GetFiles(folder, "*", SearchOption.AllDirectories).ToDictionary(f => f, f => Convert.ToHexString(File.ReadAllBytes(f)));

    /// <summary>
    /// Fix round 2 (GLM R2 / MiMo 2): the record-vault row is keyed on the config, not on the default
    /// folder. A vault made with --folder elsewhere is refused before any prompt, with empty stdin and
    /// with "yes": config.json, its vault folder and the default folder all stay as they were.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("yes\n")]
    public void Init_OnAFolderRecordVault_RefusesBeforeAnyPrompt(string stdin)
    {
        _m.Ok("", "init", "--yubikey", "--folder", _outside);
        var config = File.ReadAllText(_m.ConfigPath);
        var vault = Snapshot(_outside);

        var (exit, stdout, err) = _m.Run(stdin, "init", "--yubikey");

        Assert.Equal(1, exit);
        Assert.Contains("shared record-store vault", err);
        Assert.DoesNotContain("Reinitialize?", stdout);
        Assert.Equal(config, File.ReadAllText(_m.ConfigPath));
        Assert.Equal(vault, Snapshot(_outside));
        Assert.False(Directory.Exists(Path.Combine(_m.Dir, "vault")));
        Assert.Empty(_m.Backups);
    }

    [Fact]
    public void Init_OnAVaultDirJoinedRecordVault_RefusesBeforeAnyPrompt()
    {
        var home = new FleetMachine("init-record-home", _keys);
        try
        {
            home.Ok("", "init", "--yubikey", "--folder", _outside);
            _m.Ok("", "init", "--vault-dir", _outside);
            var config = File.ReadAllText(_m.ConfigPath);
            var vault = Snapshot(_outside);

            var (exit, stdout, err) = _m.Run("yes\n", "init", "--yubikey");

            Assert.Equal(1, exit);
            Assert.Contains("shared record-store vault", err);
            Assert.DoesNotContain("Reinitialize?", stdout);
            Assert.Equal(config, File.ReadAllText(_m.ConfigPath));
            Assert.Equal(vault, Snapshot(_outside));
            Assert.False(Directory.Exists(Path.Combine(_m.Dir, "vault")));
        }
        finally
        {
            home.Dispose();
        }
    }

    /// <summary>
    /// A config.json that names a vault folder but has lost its Store field is still a record vault's
    /// config by the ruling ("Store == records or a configured VaultDir"): refused, never reinitialised.
    /// </summary>
    [Fact]
    public void Init_OnAConfigWithAVaultDirButNoStore_Refuses()
    {
        _m.Ok("", "init", "--yubikey", "--folder", _outside);
        File.WriteAllText(_m.ConfigPath, System.Text.Json.JsonSerializer.Serialize(
            _m.Config with { Store = null }, TswapJsonContext.Default.Config));
        var config = File.ReadAllText(_m.ConfigPath);
        var vault = Snapshot(_outside);

        var (exit, stdout, err) = _m.Run("yes\n", "init", "--yubikey");

        Assert.Equal(1, exit);
        Assert.Contains(_outside, err);
        Assert.DoesNotContain("Reinitialize?", stdout);
        Assert.Equal(config, File.ReadAllText(_m.ConfigPath));
        Assert.Equal(vault, Snapshot(_outside));
        Assert.False(Directory.Exists(Path.Combine(_m.Dir, "vault")));
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
            _m.Ok("", "init", "--yubikey", "--folder", relativeName);
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
            other.Ok("", "init", "--yubikey", "--folder", spelled);
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
