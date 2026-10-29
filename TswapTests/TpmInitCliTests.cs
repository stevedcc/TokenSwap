using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// <c>init --tpm</c> / <c>--secure-enclave</c> through the real CLI dispatch path, with the
/// simulated hardware backend (issue #153) standing in for the TPM and Secure Enclave. Each
/// "machine" is a temp config dir plus its own test key, wired exactly like the composition
/// root (<c>Program.cs</c>) wires a Debug build with <c>TSWAP_TEST_KEY</c> set:
/// <see cref="HardwareServices.UnlockBackends"/> for unlock and, inside <c>InitCommand</c>,
/// <see cref="HardwareServices.Enrollment"/> for enrollment.
/// </summary>
public class TpmInitCliTests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    private static readonly byte[] KeyA =
        Convert.FromHexString("C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3");
    private static readonly byte[] KeyB =
        Convert.FromHexString("D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4");

    private string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tswap-tpm-cli-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    public void Dispose()
    {
        foreach (var dir in _tempDirs)
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
    }

    private static CommandContext Context(string dir, byte[] testKey, FakeConsole console, string[] args)
    {
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = dir, Verbose = false, CommandArgs = args };
        var yubiKeys = new TestKeyYubiKeyService(testKey);
        var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey,
            additionalBackends: HardwareServices.UnlockBackends(testKey));
        return new CommandContext(console, env, new Storage(dir), yubiKeys, unlocker, testKey, SudoBypass: true);
    }

    private static (int ExitCode, string Stdout, string Stderr) Run(string dir, byte[] testKey, string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var exit = CliRunner.Run(Context(dir, testKey, console, args), args);
        return (exit, console.OutText, console.ErrorText);
    }

    private static Config LoadConfig(string dir) =>
        JsonSerializer.Deserialize(File.ReadAllText(Path.Combine(dir, "config.json")), TswapJsonContext.Default.Config)!;

    [Theory]
    [InlineData("--tpm", HardwareBackend.Tpm)]
    [InlineData("--secure-enclave", HardwareBackend.SecureEnclave)]
    public void Init_WithSimulatedHardware_AddThenGetRoundTrips(string flag, HardwareBackend backend)
    {
        var dir = NewTempDir();

        var (initExit, _, initErr) = Run(dir, KeyA, "", "init", flag);
        Assert.True(initExit == 0, initErr);
        Assert.Equal(backend, LoadConfig(dir).Backend);

        var (addExit, _, addErr) = Run(dir, KeyA, "s3cret-value\ns3cret-value\n", "add", "db-password");
        Assert.True(addExit == 0, addErr);

        var (getExit, getOut, _) = Run(dir, KeyA, "", "get", "db-password");
        Assert.Equal(0, getExit);
        Assert.Contains("s3cret-value", getOut);
    }

    [Fact]
    public void Init_Tpm_VaultDoesNotOpenOnAnotherSimulatedMachine()
    {
        // The config and vault files copied to a machine with a different TPM must not unlock.
        var dir = NewTempDir();
        Assert.Equal(0, Run(dir, KeyA, "", "init", "--tpm").ExitCode);
        Assert.Equal(0, Run(dir, KeyA, "zq-secret-zq\nzq-secret-zq\n", "add", "db-password").ExitCode);

        var (getExit, getOut, getErr) = Run(dir, KeyB, "", "get", "db-password");

        Assert.NotEqual(0, getExit);
        Assert.DoesNotContain("zq-secret-zq", getOut);
        Assert.Contains("different machine", getErr);
    }

    // --- Item 4: init --tpm makes a keyring vault (brief T2 decision 2, #151 work item 3) ---

    private static TswapCore.Keyring.Keyring DecodeKeyring(Config config) =>
        KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));

    private static byte[] UnlockVault(string dir, byte[] testKey)
    {
        var ctx = Context(dir, testKey, new FakeConsole(), []);
        return ctx.Unlock(ctx.Storage.LoadConfig());
    }

    private static string RecoveryPrivateKeyFrom(string stdout)
    {
        var lines = stdout.Split('\n').Select(l => l.Trim()).ToList();
        var header = lines.IndexOf("Recovery Private Key (base64):");
        Assert.True(header >= 0, "init printed no recovery private key");
        return lines[header + 1];
    }

    [Theory]
    [InlineData("--tpm")]
    [InlineData("--keyring", "--tpm")]
    [InlineData("--tpm", "--keyring")]
    public void InitTpm_MakesAKeyringVaultWithAMachineAndARecoverySlot(params string[] flags)
    {
        var dir = NewTempDir();

        var (exit, stdout, stderr) = Run(dir, KeyA, "", ["init", .. flags]);

        Assert.True(exit == 0, stderr);
        var config = LoadConfig(dir);
        Assert.Equal(HardwareBackend.Tpm, config.Backend);
        Assert.Empty(config.YubiKeySerials);
        Assert.Equal("", config.RedundancyXor);
        var keyring = DecodeKeyring(config);
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery], keyring.Slots.Select(s => s.Kind));
        Assert.Equal(config.KeyringSlotId, Convert.ToBase64String(keyring.Slots[0].SlotId));
        Assert.Contains("Recovery Private Key (base64):", stdout);
    }

    [Fact]
    public void InitTpm_CreateNamesApplyRoundTrip_AndSlotsListsBothSlots()
    {
        var dir = NewTempDir();
        Assert.Equal(0, Run(dir, KeyA, "", "init", "--tpm").ExitCode);

        var (createExit, _, createErr) = Run(dir, KeyA, "", "create", "router-password", "24");
        Assert.True(createExit == 0, createErr);

        var (namesExit, namesOut, _) = Run(dir, KeyA, "", "names");
        Assert.Equal(0, namesExit);
        Assert.Contains("router-password", namesOut);

        var valuesFile = Path.Combine(dir, "values.yaml");
        File.WriteAllText(valuesFile, "router:\n  password: \"\"  # tswap: router-password\n");
        var (applyExit, applyOut, applyErr) = Run(dir, KeyA, "", "apply", valuesFile);
        Assert.True(applyExit == 0, applyErr);

        // The applied value is the stored secret itself, read back through the vault.
        var stored = Context(dir, KeyA, new FakeConsole(), []).LoadSecrets(UnlockVault(dir, KeyA)).Secrets["router-password"].Value;
        Assert.Equal(24, stored.Length);
        Assert.Contains($"password: \"{stored}\"  # tswap: router-password", applyOut);

        var (slotsExit, slotsOut, _) = Run(dir, KeyA, "", "slots");
        Assert.Equal(0, slotsExit);
        Assert.Contains("Keyring slots (2, k = 1)", slotsOut);
        var rows = slotsOut.Split('\n').Where(l => l.Contains("machine") || l.Contains("recovery")).ToList();
        Assert.Single(rows, l => l.Contains("  machine  "));
        Assert.Single(rows, l => l.Contains("  recovery  "));
        Assert.Contains("TPM", rows.Single(l => l.Contains("  machine  ")));
        Assert.DoesNotContain("YubiKey", slotsOut);
    }

    [Fact]
    public void InitTpm_NoRecovery_HasOnlyAMachineSlot()
    {
        var dir = NewTempDir();

        var (exit, stdout, stderr) = Run(dir, KeyA, "", "init", "--tpm", "--no-recovery");

        Assert.True(exit == 0, stderr);
        var keyring = DecodeKeyring(LoadConfig(dir));
        Assert.Equal(SlotKind.Machine, Assert.Single(keyring.Slots).Kind);
        Assert.DoesNotContain("Recovery Private Key", stdout);
    }

    [Fact]
    public void InitSecureEnclave_MakesAKeyringVaultToo()
    {
        var dir = NewTempDir();

        var (exit, _, stderr) = Run(dir, KeyA, "", "init", "--secure-enclave");

        Assert.True(exit == 0, stderr);
        var config = LoadConfig(dir);
        Assert.Equal(HardwareBackend.SecureEnclave, config.Backend);
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery], DecodeKeyring(config).Slots.Select(s => s.Kind));
        Assert.Equal(0, Run(dir, KeyA, "x-value\nx-value\n", "add", "x").ExitCode);
    }

    [Fact]
    public void InitTpm_PrintedRecoveryKeyRecoversThisVaultsKv()
    {
        // #151 acceptance: the recovery private key printed at init recovers K_v for an SE/TPM
        // vault, the same K_v the TPM machine slot unlocks.
        var dir = NewTempDir();
        var (_, stdout, _) = Run(dir, KeyA, "", "init", "--tpm");
        var recoveryPrivateKey = Convert.FromBase64String(RecoveryPrivateKeyFrom(stdout));

        var keyring = DecodeKeyring(LoadConfig(dir));
        var recovery = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery);
        var recovered = RecoverySlotWrap.Unwrap(recovery.Wrapped, recovery.PublicKey, recoveryPrivateKey,
            keyring.FormatVersion, keyring.VaultId, keyring.K, recovery.SlotId);

        Assert.Equal(UnlockVault(dir, KeyA), recovered);
    }

    [Fact]
    public void InitTpmAndSecureEnclave_IsAUsageError()
    {
        var dir = NewTempDir();

        var (exit, _, stderr) = Run(dir, KeyA, "", "init", "--tpm", "--secure-enclave");

        Assert.Equal(1, exit);
        Assert.Contains("Usage:", stderr);
        Assert.False(File.Exists(Path.Combine(dir, "config.json")));
    }

    [Fact]
    public void ExistingSingleSlotTpmVault_StillUnlocks()
    {
        // Decision 2: single-slot TPM vaults made before this brief keep working unchanged: the
        // blob in TpmSealedKey recovers the vault key directly (no keyring).
        var dir = NewTempDir();
        var (vaultKey, blob) = new SimulatedHardwareService(HardwareBackend.Tpm, KeyA).Enroll();
        var storage = new Storage(dir);
        storage.SaveConfig(new Config([], "", DateTime.UtcNow, RequiresTouch: false, RngMode: RngMode.System,
            Backend: HardwareBackend.Tpm, TpmSealedKey: Convert.ToBase64String(blob)));
        storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>
        {
            ["legacy"] = new("legacy-value", DateTime.UtcNow, DateTime.UtcNow),
        }), vaultKey);

        var (exit, stdout, stderr) = Run(dir, KeyA, "", "get", "legacy");

        Assert.True(exit == 0, stderr);
        Assert.Contains("legacy-value", stdout);
    }

    // --- init rejects unknown arguments (#177, the init half) ---

    /// <summary>An IYubiKeyService that fails the test if init touches it at all.</summary>
    private sealed class UntouchableYubiKeys : IYubiKeyService
    {
        public bool IsSimulated => false;
        public IReadOnlyList<int> ListSerials() => throw new InvalidOperationException("init must not touch the YubiKey");
        public byte[] Challenge(int serial, string challenge) => throw new InvalidOperationException("init must not touch the YubiKey");
        public bool? DetectTouchRequirement(int serial) => throw new InvalidOperationException("init must not touch the YubiKey");
    }

    [Theory]
    [InlineData("--tmp")]
    [InlineData("--keyring", "x")]
    [InlineData("--help-me")]
    public void Init_UnknownArguments_UsageErrorListingTheValidFlags_NoHardwareCalled(params string[] flags)
    {
        // No test key: today's fall-through to YubiKey init would reach the (untouchable)
        // YubiKey service and fail differently. A usage error must come first. (Cases that name
        // --tpm or --secure-enclave are tested with the simulated backend below, so a
        // regression can never reach real TPM tools from this test.)
        var dir = NewTempDir();
        var console = new FakeConsole();
        string[] args = ["init", .. flags];
        var yubiKeys = new UntouchableYubiKeys();
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = dir, Verbose = false, CommandArgs = args };
        var ctx = new CommandContext(console, env, new Storage(dir), yubiKeys, new VaultUnlocker(yubiKeys), TestKey: null, SudoBypass: true);

        var exit = CliRunner.Run(ctx, args);

        Assert.Equal(1, exit);
        Assert.Contains("Usage:", console.ErrorText);
        foreach (var flag in new[] { "--keyring", "--tpm", "--secure-enclave", "--no-recovery" })
            Assert.Contains(flag, console.ErrorText);
        Assert.DoesNotContain("must not touch", console.ErrorText);
        Assert.False(File.Exists(Path.Combine(dir, "config.json")));
    }

    [Theory]
    [InlineData("--tpm", "--tpm")]
    [InlineData("--tpm", "--keyring", "--keyring")]
    [InlineData("--tpm", "--tmp")]
    [InlineData("--secure-enclave", "extra")]
    public void Init_HardwareFlagWithDuplicateOrUnknownArgument_IsAUsageError(params string[] flags)
    {
        var dir = NewTempDir();

        var (exit, _, stderr) = Run(dir, KeyA, "", ["init", .. flags]);

        Assert.Equal(1, exit);
        Assert.Contains("Usage:", stderr);
        Assert.False(File.Exists(Path.Combine(dir, "config.json")));
    }

    // --- The owner's goal: a YubiKey machine joins the router's TPM keyring vault ---

    [Fact]
    public void YubiKeyMachineJoinsTpmVault_ViaSlotRequestApproveAccept()
    {
        // Machine A (the router): a TPM keyring vault (simulated TPM, key A).
        // Machine B (the desktop): a YubiKey machine (YubiKey test key B) that requests a slot,
        // A approves, B accepts. Separate config dirs per machine, as SlotCommandTests does.
        var routerDir = NewTempDir();
        var desktopDir = NewTempDir();
        Assert.Equal(0, Run(routerDir, KeyA, "", "init", "--tpm").ExitCode);
        Assert.Equal(0, Run(routerDir, KeyA, "router-secret\nrouter-secret\n", "add", "router-pw").ExitCode);
        var routerKv = UnlockVault(routerDir, KeyA);

        var requestFile = Path.Combine(desktopDir, "request.json");
        var (reqExit, _, reqErr) = Run(desktopDir, KeyB, "", "slot", "request", requestFile);
        Assert.True(reqExit == 0, reqErr);
        Assert.Null(LoadConfig(desktopDir).Backend); // a YubiKey machine

        var approveFile = Path.Combine(desktopDir, "approve.json");
        var (approveExit, _, approveErr) = Run(routerDir, KeyA, "", "slot", "approve", requestFile, approveFile);
        Assert.True(approveExit == 0, approveErr);

        var (acceptExit, _, acceptErr) = Run(desktopDir, KeyB, "", "slot", "accept", approveFile);
        Assert.True(acceptExit == 0, acceptErr);

        // Both machines unlock the same K_v, each through its own hardware.
        Assert.Equal(routerKv, UnlockVault(routerDir, KeyA));
        Assert.Equal(routerKv, UnlockVault(desktopDir, KeyB));

        // The desktop's keyring copy lists the three slots, in order: the router's TPM machine
        // slot, the recovery slot, the desktop's own YubiKey machine slot.
        var routerConfig = LoadConfig(routerDir);
        var desktopConfig = LoadConfig(desktopDir);
        var desktopKeyring = DecodeKeyring(desktopConfig);
        Assert.Equal([SlotKind.Machine, SlotKind.Recovery, SlotKind.Machine], desktopKeyring.Slots.Select(s => s.Kind));
        Assert.Equal(routerConfig.KeyringSlotId, Convert.ToBase64String(desktopKeyring.Slots[0].SlotId));
        Assert.Equal(desktopConfig.KeyringSlotId, Convert.ToBase64String(desktopKeyring.Slots[2].SlotId));
        Assert.Equal(DecodeKeyring(routerConfig).VaultId, desktopKeyring.VaultId);

        // The desktop's own slot is its YubiKey's: the router's TPM key cannot open it.
        var ownSlot = desktopKeyring.Slots[2];
        Assert.Throws<TswapException>(() => SlotPayloadWrap.Unwrap(ownSlot.Wrapped, KeyA,
            desktopKeyring.FormatVersion, desktopKeyring.VaultId, desktopKeyring.K, ownSlot.SlotId));
    }

    // --- Item 5: the hardware blob lives in the machine slot (#154, decision 3) ---

    [Theory]
    [InlineData("--tpm", HardwareBackend.Tpm)]
    [InlineData("--secure-enclave", HardwareBackend.SecureEnclave)]
    public void Init_StoresTheHardwareBlobInTheVersion3MachineSlot_NotInTheLegacyField(string flag, HardwareBackend backend)
    {
        var dir = NewTempDir();
        Assert.Equal(0, Run(dir, KeyA, "", "init", flag).ExitCode);

        var config = LoadConfig(dir);
        var keyring = DecodeKeyring(config);

        Assert.Equal(backend, config.Backend);
        Assert.Null(config.TpmSealedKey);
        Assert.Null(config.SecureEnclaveWrappedKey);
        Assert.Equal(3, keyring.FormatVersion);
        var machine = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Machine);
        Assert.NotNull(machine.HwBlob);
        Assert.NotEmpty(machine.HwBlob!);
        Assert.Null(Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery).HwBlob);

        // The slot's blob is what unlocks: the simulated machine recovers KEK_slot from it.
        var kekSlot = new SimulatedHardwareService(backend, KeyA).Unlock(config, _ => 0);
        var (kv, _) = SlotSecretPayload.Decode(SlotPayloadWrap.Unwrap(
            machine.Wrapped, kekSlot, keyring.FormatVersion, keyring.VaultId, keyring.K, machine.SlotId));
        Assert.Equal(UnlockVault(dir, KeyA), kv);
    }

    [Fact]
    public void TpmKeyringVault_WhoseMachineSlotHasNoHwBlob_FailsWithAClearError()
    {
        var dir = NewTempDir();
        Assert.Equal(0, Run(dir, KeyA, "", "init", "--tpm").ExitCode);
        var config = LoadConfig(dir);
        var keyring = DecodeKeyring(config);
        var stripped = keyring with { Slots = keyring.Slots.Select(s => s with { HwBlob = null }).ToList() };
        new Storage(dir).SaveConfig(config with { Keyring = Convert.ToBase64String(KeyringCodec.Encode(stripped)) });

        var (exit, _, stderr) = Run(dir, KeyA, "", "names");

        Assert.NotEqual(0, exit);
        Assert.Contains("Config is corrupted", stderr);
        Assert.Contains("tpm", stderr);
    }

    [Fact]
    public void YubiKeyMachineJoiningTpmVault_KeepsTheRoutersHwBlobInItsKeyringCopy()
    {
        var routerDir = NewTempDir();
        var desktopDir = NewTempDir();
        Assert.Equal(0, Run(routerDir, KeyA, "", "init", "--tpm").ExitCode);
        var requestFile = Path.Combine(desktopDir, "request.json");
        var approveFile = Path.Combine(desktopDir, "approve.json");
        Assert.Equal(0, Run(desktopDir, KeyB, "", "slot", "request", requestFile).ExitCode);
        Assert.Equal(0, Run(routerDir, KeyA, "", "slot", "approve", requestFile, approveFile).ExitCode);
        Assert.Equal(0, Run(desktopDir, KeyB, "", "slot", "accept", approveFile).ExitCode);

        var routerKeyring = DecodeKeyring(LoadConfig(routerDir));
        var desktopKeyring = DecodeKeyring(LoadConfig(desktopDir));

        Assert.Equal(3, desktopKeyring.FormatVersion);
        Assert.Equal(routerKeyring.Slots[0].HwBlob, desktopKeyring.Slots[0].HwBlob);
        Assert.Null(desktopKeyring.Slots[2].HwBlob); // the desktop's YubiKey slot has none
    }
}
