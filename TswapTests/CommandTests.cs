using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// In-process command tests: each invocation constructs a fresh CommandContext with a
/// FakeConsole, TestKeyYubiKeyService, and a temp config dir, then dispatches through
/// CliRunner — the same dispatch/error-mapping path the real binary uses. These are the
/// in-process ports of the former subprocess ProgramTests (test bodies unchanged);
/// scenarios that genuinely need a real process/PTY live in EndToEndTests.
/// </summary>
public class CommandTests : IDisposable
{
    private readonly string _tempDir;
    private readonly byte[] _testKey =
        Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");

    public CommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "tswap-cmd-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private (int exitCode, string stdout, string stderr) RunTswap(params string[] args)
        => Execute(stdin: "", args);

    private (int exitCode, string stdout, string stderr) RunTswapWithStdin(string stdin, params string[] args)
        => Execute(stdin, args);

    private (int exitCode, string stdout, string stderr) Execute(string stdin, string[] args)
    {
        var console = new FakeConsole(stdin);
        // The global flags are split off as the binary does (CliEnvironment.FromSystem).
        var (verbose, commandArgs) = CliEnvironment.SplitGlobalFlags(args);
        var env = new CliEnvironment
        {
            Prefix = "tswap",
            ConfigDir = _tempDir,
            Verbose = verbose,
            CommandArgs = commandArgs,
        };
        // Brief T16-S1: the store is chosen per invocation, as the binary does (VaultStores.Open):
        // init makes a record vault, which the next invocation opens as one.
        var storage = VaultStores.Open(_tempDir, warnings: console.Error);
        var yubiKeys = new TestKeyYubiKeyService(_testKey);
        var unlocker = new VaultUnlocker(yubiKeys, overrideKey: _testKey);
        var ctx = new CommandContext(console, env, storage, yubiKeys, unlocker, _testKey, SudoBypass: true);

        var exit = CliRunner.Run(ctx, env.CommandArgs);
        return (exit, console.OutText, console.ErrorText);
    }

    /// <summary>
    /// Brief T16-S1 (ruling 4): <c>init</c> refuses on an existing vault (it used to re-initialize
    /// after a "yes"), so a test that needs a fresh vault in the same config folder removes the old
    /// one (config.json and the vault folder) and runs init again.
    /// </summary>
    private void FreshVault()
    {
        File.Delete(Path.Combine(_tempDir, "config.json"));
        var vault = Path.Combine(_tempDir, "vault");
        if (Directory.Exists(vault))
            Directory.Delete(vault, true);
        Assert.Equal(0, RunTswap("init", "--yubikey").exitCode);
    }

    /// <summary>The config as the store composes it (a record vault's keyring lives in its vault folder).</summary>
    private Config LoadedConfig() => VaultStores.Open(_tempDir).LoadConfig();

    // --- Init ---

    [Fact]
    public void Init_CreatesConfigFile()
    {
        var (exit, stdout, _) = RunTswap("init", "--yubikey");

        Assert.Equal(0, exit);
        Assert.Contains("Vault folder", stdout);
        Assert.True(File.Exists(Path.Combine(_tempDir, "config.json")));
    }


    [Fact]
    public void Init_SecureEnclaveAndTpmBothPassed_RejectsAsUsageError()
    {
        // Regression test: the checks used to be sequential (--secure-enclave always won,
        // --tpm silently ignored) since neither branch checked for the other flag.
        var (exit, _, stderr) = RunTswap("init", "--secure-enclave", "--tpm");

        Assert.Equal(1, exit);
        Assert.Contains("Usage:", stderr);
    }

    // --- Init --yubikey (Phase 6, issue #119; the flag was --keyring until v0.2.0) ---

    [Fact]
    public void InitKeyring_CreatesConfigWithKeyringFieldAndNoBackend()
    {
        var (exit, stdout, _) = RunTswap("init", "--yubikey");

        Assert.Equal(0, exit);
        Assert.Contains("keyring", stdout);

        var config = LoadedConfig();

        Assert.NotNull(config.Keyring);
        // Still a YubiKey vault as far as VaultUnlocker's backend dispatch is concerned —
        // only the presence of Keyring changes how the recovered 32 bytes are used.
        Assert.Null(config.Backend);
        // Brief T4 decision 4: one key per slot, so no pair fields (the key's serial is in its
        // slot's hardware blob, not in YubiKeySerials).
        Assert.Empty(config.YubiKeySerials);
    }

    [Fact]
    public void InitKeyring_FullRoundTrip_AddThenGetRecoversValue()
    {
        // The end-to-end proof this issue's verification bar asks for: init --yubikey, add a
        // secret, get it back — through the real CLI dispatch path, not just unit-level pieces.
        RunTswap("init", "--yubikey");

        var (addExit, _, _) = RunTswapWithStdin("hunter2\nhunter2\n", "add", "my-secret");
        Assert.Equal(0, addExit);

        var (getExit, getStdout, _) = RunTswap("get", "my-secret");

        Assert.Equal(0, getExit);
        Assert.Contains("hunter2", getStdout);
    }

    [Fact]
    public void InitKeyring_Reinit_GeneratesFreshVaultKey_OldSecretNoLongerAccessible()
    {
        // Every 'init --yubikey' generates a brand-new random K_v (unlike the default flow,
        // where re-init with the same test key would still decrypt an old vault under some
        // circumstances) — reinitializing must leave the old secret behind, not silently expose
        // or destroy data without the documented backup-file dance.
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("first-value\nfirst-value\n", "add", "first-secret");

        // Brief T16-S1: init refuses on an existing vault, so the old vault folder is moved aside
        // and the new vault gets the old record files: they stay unreadable under the new K_v.
        var vault = Path.Combine(_tempDir, "vault");
        var old = Path.Combine(_tempDir, "vault-old");
        Directory.Move(vault, old);
        File.Delete(Path.Combine(_tempDir, "config.json"));
        RunTswap("init", "--yubikey");
        Directory.CreateDirectory(Path.Combine(vault, "records"));
        foreach (var file in Directory.GetFiles(Path.Combine(old, "records")))
            File.Copy(file, Path.Combine(vault, "records", Path.GetFileName(file)));

        var (getExit, _, getStderr) = RunTswap("get", "first-secret");
        Assert.NotEqual(0, getExit);
        Assert.Contains("not found", getStderr);
    }

    // --- Init --yubikey recovery slot (Phase 6, issue #120) ---

    [Fact]
    public void InitKeyring_DefaultOn_GeneratesRecoverySlotAndDisplaysPrivateKeyOnce()
    {
        var (exit, stdout, _) = RunTswap("init", "--yubikey");

        Assert.Equal(0, exit);
        Assert.Contains("CRITICAL: BACKUP RECOVERY PRIVATE KEY NOW", stdout);
        Assert.Contains("Recovery Private Key (base64):", stdout);

        var config = LoadedConfig();
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));

        Assert.Equal(2, keyring.Slots.Count);
        Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Machine);
        Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery);
    }

    [Fact]
    public void InitKeyring_NoRecovery_SkipsRecoverySlotAndDoesNotDisplayAKey()
    {
        var (exit, stdout, _) = RunTswap("init", "--yubikey", "--no-recovery");

        Assert.Equal(0, exit);
        Assert.DoesNotContain("Recovery Private Key", stdout);
        Assert.Contains("No recovery slot generated", stdout);

        var config = LoadedConfig();
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));

        Assert.Single(keyring.Slots);
        Assert.Equal(SlotKind.Machine, keyring.Slots[0].Kind);
    }

    [Fact]
    public void InitKeyring_NoRecovery_VaultStillFullyUsable()
    {
        // --no-recovery must only remove the recovery slot, not otherwise change vault behavior.
        RunTswap("init", "--yubikey", "--no-recovery");
        RunTswapWithStdin("hunter2\nhunter2\n", "add", "my-secret");

        var (getExit, getStdout, _) = RunTswap("get", "my-secret");

        Assert.Equal(0, getExit);
        Assert.Contains("hunter2", getStdout);
    }


    [Fact]
    public void BuildKeyringConfig_RecoveryPrivateKey_RecoversSameVaultKeyAsMachineSlot()
    {
        // The real verification bar for #120: generate exactly the way ExecuteKeyring does
        // (BuildKeyringConfig is internal specifically so this test can drive it directly, per
        // the issue's "expose it from your init logic for testing purposes" instruction), then
        // prove the recovery private key recovers the identical K_v the machine slot's KEK_slot
        // recovers — not just that a keypair was generated with no way to ever use it.
        var kekSlot = RandomNumberGenerator.GetBytes(32);
        var (config, vaultKey, recoveryPrivateKey) = InitCommand.BuildKeyringConfig(
            kekSlot,
            new List<int> { 11111111, 22222222 },
            new string('0', 40),
            requiresTouch: null,
            RngMode.System,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
            RandomNumberGenerator.GetBytes(32),
            includeRecovery: true);

        Assert.NotNull(recoveryPrivateKey);

        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));

        var machineSlot = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Machine);
        var machinePayload = SlotPayloadWrap.Unwrap(
            machineSlot.Wrapped, kekSlot, keyring.FormatVersion, keyring.VaultId, keyring.K, machineSlot.SlotId);
        var (machineVaultKey, _) = SlotSecretPayload.Decode(machinePayload);

        var recoverySlot = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery);
        var recoveredVaultKey = RecoverySlotWrap.Unwrap(
            recoverySlot.Wrapped, recoverySlot.PublicKey, recoveryPrivateKey!,
            keyring.FormatVersion, keyring.VaultId, keyring.K, recoverySlot.SlotId);

        Assert.Equal(vaultKey, machineVaultKey);
        Assert.Equal(vaultKey, recoveredVaultKey);
    }

    [Fact]
    public void BuildKeyringConfig_NoRecovery_ReturnsNullPrivateKeyAndSingleSlotKeyring()
    {
        var kekSlot = RandomNumberGenerator.GetBytes(32);
        var (config, _, recoveryPrivateKey) = InitCommand.BuildKeyringConfig(
            kekSlot,
            new List<int> { 11111111, 22222222 },
            new string('0', 40),
            requiresTouch: null,
            RngMode.System,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
            RandomNumberGenerator.GetBytes(32),
            includeRecovery: false);

        Assert.Null(recoveryPrivateKey);
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        Assert.Single(keyring.Slots);
        Assert.Equal(SlotKind.Machine, keyring.Slots[0].Kind);
    }

    [Fact]
    public void BuildKeyringConfig_RecoverySlot_WrongPrivateKeyFailsCleanly()
    {
        var kekSlot = RandomNumberGenerator.GetBytes(32);
        var (config, _, _) = InitCommand.BuildKeyringConfig(
            kekSlot,
            new List<int> { 11111111, 22222222 },
            new string('0', 40),
            requiresTouch: null,
            RngMode.System,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
            RandomNumberGenerator.GetBytes(32),
            includeRecovery: true);

        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        var recoverySlot = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery);
        var wrongPrivateKey = SlotKeyPair.Generate().PrivateKey;

        var ex = Assert.Throws<TswapException>(() => RecoverySlotWrap.Unwrap(
            recoverySlot.Wrapped, recoverySlot.PublicKey, wrongPrivateKey,
            keyring.FormatVersion, keyring.VaultId, keyring.K, recoverySlot.SlotId));
        Assert.Contains("authentication", ex.Message);
    }

    // --- Slots (Phase 6, issue #123) ---

    [Fact]
    public void SlotsFormat_TouchRequiredMachineSlot_DescribesTouchRequired()
    {
        var (config, _, _) = InitCommand.BuildKeyringConfig(
            RandomNumberGenerator.GetBytes(32),
            new List<int> { 11111111, 22222222 },
            new string('0', 40),
            requiresTouch: true,
            RngMode.System,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
            RandomNumberGenerator.GetBytes(32),
            includeRecovery: false);

        var output = SlotsCommand.Format(config);

        Assert.Contains("touch required", output);
        Assert.DoesNotContain("no touch", output);
    }

    [Fact]
    public void SlotsFormat_NoTouchMachineSlot_DescribesCustodyNotUnprotected()
    {
        // The exact failure mode this issue calls out by name: a no-touch YubiKey slot has a
        // real, if unusual, control (custody) and must never be reduced to a bare
        // "unprotected"/"insecure" label. See docs/design/multi-machine-keying.md §Why not k >= 2 (yet).
        var (config, _, _) = InitCommand.BuildKeyringConfig(
            RandomNumberGenerator.GetBytes(32),
            new List<int> { 11111111, 22222222 },
            new string('0', 40),
            requiresTouch: false,
            RngMode.System,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
            RandomNumberGenerator.GetBytes(32),
            includeRecovery: false);

        var output = SlotsCommand.Format(config);

        Assert.Contains("custody", output);
        Assert.Contains("no touch required", output);
        Assert.DoesNotContain("unprotected", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("insecure", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SlotsFormat_UnknownTouchMachineSlot_DescribesCustodyHonestly()
    {
        // requiresTouch == null (touch detection couldn't determine the answer on both keys) is
        // distinct from a confirmed "false" — describe it as unknown, not as a confident "no
        // touch required", while still noting custody applies either way.
        var (config, _, _) = InitCommand.BuildKeyringConfig(
            RandomNumberGenerator.GetBytes(32),
            new List<int> { 11111111, 22222222 },
            new string('0', 40),
            requiresTouch: null,
            RngMode.System,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
            RandomNumberGenerator.GetBytes(32),
            includeRecovery: false);

        var output = SlotsCommand.Format(config);

        Assert.Contains("unknown", output);
        Assert.Contains("custody", output);
        Assert.DoesNotContain("unprotected", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("insecure", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SlotsFormat_RecoverySlot_DescribesPresenceFreeByDesignNotAsWeakerMachineSlot()
    {
        var (config, _, _) = InitCommand.BuildKeyringConfig(
            RandomNumberGenerator.GetBytes(32),
            new List<int> { 11111111, 22222222 },
            new string('0', 40),
            requiresTouch: true,
            RngMode.System,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
            RandomNumberGenerator.GetBytes(32),
            includeRecovery: true);

        var output = SlotsCommand.Format(config);

        Assert.Contains("recovery", output);
        Assert.Contains("break-glass", output);
        Assert.Contains("no presence required", output);

        var recoveryLine = output.Split('\n').Single(l => l.Contains("recovery"));
        Assert.DoesNotContain("touch", recoveryLine);
    }

    [Fact]
    public void SlotsFormat_NonKeyringVault_ReturnsHonestMessageNotError()
    {
        var config = new Config(new List<int> { 1, 2 }, new string('0', 40), DateTime.UtcNow, RequiresTouch: true);

        var output = SlotsCommand.Format(config);

        Assert.Contains("no keyring", output);
        Assert.DoesNotContain("Exception", output);
    }

    [Fact]
    public void Slots_EndToEnd_InitKeyringThenSlots_ListsMachineAndRecoverySlots()
    {
        RunTswap("init", "--yubikey");

        var (exit, stdout, _) = RunTswap("slots");

        Assert.Equal(0, exit);
        Assert.Contains("machine", stdout);
        Assert.Contains("recovery", stdout);
        Assert.DoesNotContain("unprotected", stdout, StringComparison.OrdinalIgnoreCase);
    }


    // --- Create ---

    [Fact]
    public void Create_GeneratesSecret()
    {
        RunTswap("init", "--yubikey");
        var (exit, stdout, _) = RunTswap("create", "my-secret");

        Assert.Equal(0, exit);
        Assert.Contains("my-secret", stdout);
        Assert.Contains("created", stdout);
    }

    [Fact]
    public void Create_CustomLength()
    {
        RunTswap("init", "--yubikey");
        var (exit, stdout, _) = RunTswap("create", "short-secret", "8");

        Assert.Equal(0, exit);
        Assert.Contains("8 chars", stdout);
    }

    [Fact]
    public void Create_DuplicateNameFails()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "dup-secret");
        var (exit, _, stderr) = RunTswap("create", "dup-secret");

        Assert.NotEqual(0, exit);
        Assert.Contains("already exists", stderr);
    }

    [Fact]
    public void Create_EmptyNameFails()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswap("create", "");

        Assert.NotEqual(0, exit);
        Assert.Contains("empty", stderr);
    }

    [Fact]
    public void Create_NameWithSpaceFails()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswap("create", "bad name");

        Assert.NotEqual(0, exit);
        Assert.Contains("Invalid secret name", stderr);
    }

    [Fact]
    public void Create_NameWithSpecialCharsFails()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswap("create", "bad!name");

        Assert.NotEqual(0, exit);
        Assert.Contains("Invalid secret name", stderr);
    }

    [Fact]
    public void Create_NameTooLongFails()
    {
        RunTswap("init", "--yubikey");
        var longName = new string('a', 65);
        var (exit, _, stderr) = RunTswap("create", longName);

        Assert.NotEqual(0, exit);
        Assert.Contains("too long", stderr);
    }

    [Fact]
    public void Create_NameAtMaxLengthSucceeds()
    {
        RunTswap("init", "--yubikey");
        var maxName = new string('a', 64);
        var (exit, _, _) = RunTswap("create", maxName);

        Assert.Equal(0, exit);
    }

    [Fact]
    public void Create_ZeroLengthFails()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswap("create", "valid-name", "0");

        Assert.NotEqual(0, exit);
        Assert.Contains("at least 1", stderr);
    }

    [Fact]
    public void Create_NegativeLengthFails()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswap("create", "valid-name", "-5");

        Assert.NotEqual(0, exit);
        Assert.Contains("at least 1", stderr);
    }

    [Fact]
    public void Create_TooLongLengthFails()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswap("create", "valid-name", "4097");

        Assert.NotEqual(0, exit);
        Assert.Contains("at most 4096", stderr);
    }

    [Fact]
    public void Create_NonNumericLengthFails()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswap("create", "valid-name", "abc");

        Assert.NotEqual(0, exit);
        Assert.Contains("whole number", stderr);
    }

    [Fact]
    public void Create_MaxLengthSucceeds()
    {
        RunTswap("init", "--yubikey");
        var (exit, stdout, _) = RunTswap("create", "valid-name", "4096");

        Assert.Equal(0, exit);
        Assert.Contains("4096 chars", stdout);
    }

    [Fact]
    public void Create_GeneratedValueIsCorrectLengthAndCharset()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "charset-secret", "200");
        var (exit, stdout, _) = RunTswap("get", "charset-secret");

        Assert.Equal(0, exit);
        var value = stdout.TrimEnd('\n', '\r');
        Assert.Equal(200, value.Length);
        Assert.All(value, c => Assert.Contains(c, CreateCommand.Charset));
    }

    [Fact]
    public void Create_RepeatedCallsProduceDifferentValues()
    {
        // Regression guard: the system-RNG path must not accidentally be deterministic.
        RunTswap("init", "--yubikey");
        RunTswap("create", "rand-a", "64");
        RunTswap("create", "rand-b", "64");
        var (_, valueA, _) = RunTswap("get", "rand-a");
        var (_, valueB, _) = RunTswap("get", "rand-b");

        Assert.NotEqual(valueA, valueB);
    }

    // --- Names ---

    [Fact]
    public void Names_ListsCreatedSecrets()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "alpha");
        RunTswap("create", "beta");

        var (exit, stdout, _) = RunTswap("names");

        Assert.Equal(0, exit);
        Assert.Contains("alpha", stdout);
        Assert.Contains("beta", stdout);
    }

    [Fact]
    public void Names_EmptyVault()
    {
        RunTswap("init", "--yubikey");
        var (exit, stdout, _) = RunTswap("names");

        Assert.Equal(0, exit);
        Assert.Contains("No secrets", stdout);
    }

    // --- Ingest ---

    [Fact]
    public void Ingest_StoresStdinValue()
    {
        RunTswap("init", "--yubikey");
        var (exit, stdout, _) = RunTswapWithStdin("piped-secret-value", "ingest", "from-stdin");

        Assert.Equal(0, exit);
        Assert.Contains("ingested", stdout);

        // Verify it appears in names
        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("from-stdin", namesOut);
    }

    [Fact]
    public void Ingest_DuplicateFails()
    {
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("value1", "ingest", "dup-ingest");
        var (exit, _, stderr) = RunTswapWithStdin("value2", "ingest", "dup-ingest");

        Assert.NotEqual(0, exit);
        Assert.Contains("already exists", stderr);
    }

    [Fact]
    public void Ingest_EmptyNameFails()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswapWithStdin("some-value", "ingest", "");

        Assert.NotEqual(0, exit);
        Assert.Contains("empty", stderr);
    }

    [Fact]
    public void Ingest_NameWithSpaceFails()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswapWithStdin("some-value", "ingest", "bad name");

        Assert.NotEqual(0, exit);
        Assert.Contains("Invalid secret name", stderr);
    }

    [Fact]
    public void Ingest_TooLongValueFails()
    {
        RunTswap("init", "--yubikey");
        var longValue = new string('x', 65537);
        var (exit, _, stderr) = RunTswapWithStdin(longValue, "ingest", "toolong");

        Assert.NotEqual(0, exit);
        Assert.Contains("too long", stderr);
    }

    [Fact]
    public void Ingest_MaxLengthValueSucceeds()
    {
        RunTswap("init", "--yubikey");
        var maxValue = new string('x', 65536);
        var (exit, stdout, _) = RunTswapWithStdin(maxValue, "ingest", "maxlen");

        Assert.Equal(0, exit);
        Assert.Contains("ingested", stdout);
    }

    // --- Burn ---

    [Fact]
    public void Burn_MarksSecretAsBurned()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "burn-me");
        var (exit, stdout, _) = RunTswap("burn", "burn-me", "test reason");

        Assert.Equal(0, exit);
        Assert.Contains("BURNED", stdout);
    }

    [Fact]
    public void Burn_ShowsInNames()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "visible-burn");
        RunTswap("burn", "visible-burn", "oops");

        var (_, stdout, _) = RunTswap("names");
        Assert.Contains("[BURNED]", stdout);
    }

    [Fact]
    public void Burn_NonexistentFails()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswap("burn", "ghost");

        Assert.NotEqual(0, exit);
        Assert.Contains("not found", stderr);
    }

    [Fact]
    public void Burn_AlreadyBurnedFails()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "already-burned");
        RunTswap("burn", "already-burned", "original reason");

        var (exit, _, stderr) = RunTswap("burn", "already-burned", "second reason");

        Assert.NotEqual(0, exit);
        Assert.Contains("already burned", stderr);
        Assert.Contains("original reason", stderr);
    }

    // --- Burned ---

    [Fact]
    public void Burned_ShowsBurnedSecrets()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "leaked");
        RunTswap("burn", "leaked", "seen in logs");

        var (exit, stdout, _) = RunTswap("burned");

        Assert.Equal(0, exit);
        Assert.Contains("leaked", stdout);
        Assert.Contains("seen in logs", stdout);
    }

    [Fact]
    public void Burned_NoBurnedSecrets()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "clean-secret");

        var (exit, stdout, _) = RunTswap("burned");

        Assert.Equal(0, exit);
        Assert.Contains("No burned secrets", stdout);
    }

    // --- Prompt ---

    [Fact]
    public void Prompt_OutputsInstructions()
    {
        // prompt doesn't need init
        var (exit, stdout, _) = RunTswap("prompt");

        Assert.Equal(0, exit);
        Assert.Contains("tswap", stdout);
        Assert.Contains("AI Agent", stdout);
        // SKILL.md frontmatter
        Assert.Contains("---", stdout);
        Assert.Contains("name: tswap", stdout);
        Assert.Contains("must use when", stdout, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PromptHash_OutputsHash()
    {
        var (exit, stdout, _) = RunTswap("prompt-hash");

        Assert.Equal(0, exit);
        var hash = stdout.Trim();
        // SHA-256 hex = 64 chars
        Assert.Equal(64, hash.Length);
        Assert.Matches("^[0-9a-f]{64}$", hash);
    }

    // --- Run (validation paths — execution paths live in EndToEndTests) ---

    [Fact]
    public void Run_MissingTokenFails()
    {
        RunTswap("init", "--yubikey");

        var (exit, _, stderr) = RunTswap("run", "true", "{{nonexistent}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("not found", stderr);
    }

    [Fact]
    public void Run_NoTokensFails()
    {
        RunTswap("init", "--yubikey");

        var (exit, _, stderr) = RunTswap("run", "true");

        Assert.NotEqual(0, exit);
        Assert.Contains("No {{tokens}}", stderr);
    }

    [Fact]
    public void Run_BlockedCommandFails()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "block-test");

        var (exit, _, stderr) = RunTswap("run", "echo", "{{block-test}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("expose secret", stderr);
    }

    [Fact]
    public void Run_BlockedCommandViaTokenSubstitutionFails()
    {
        // A token in argv[0] that expands to a blocked command must still be rejected.
        // The pre-substitution blocklist check sees "{{cmd}}" (not blocked); the
        // post-substitution re-check must catch the expanded value.
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("echo", "ingest", "cmd");

        var (exit, _, stderr) = RunTswap("run", "{{cmd}}", "hello");

        Assert.NotEqual(0, exit);
        Assert.Contains("expose secret", stderr);
    }

    // Issue #105: inline code is refused, a script file is the way out.
    [Fact]
    public void Run_ShellWithInlineCode_IsRefused_AndRunsNothing()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "inline-test");
        var marker = Path.Combine(_tempDir, "ran");

        var (exit, _, stderr) = RunTswap("run", "sh", "-c", $"touch {marker}; true {{{{inline-test}}}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("inline code", stderr);
        Assert.Contains("script file", stderr);
        Assert.False(File.Exists(marker), "a refused command must not run");
    }

    [Fact]
    public void Run_InlineCodeFlagFromATokenAfterSubstitution_IsRefused()
    {
        // `run sh {{opt}} ...` where opt = "-c": the pre-substitution check sees "{{opt}}";
        // the post-substitution re-check must see "-c".
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("-c", "ingest", "opt");
        var marker = Path.Combine(_tempDir, "ran");

        var (exit, _, stderr) = RunTswap("run", "sh", "{{opt}}", $"touch {marker}");

        Assert.NotEqual(0, exit);
        Assert.Contains("inline code", stderr);
        Assert.False(File.Exists(marker), "a refused command must not run");
    }

    // A word the post-substitution check refuses came from a secret's value, so
    // the refusal names the token, never the word.
    [Fact]
    public void Run_ProgramFromATokenAfterSubstitution_RefusalNamesTheTokenNotTheValue()
    {
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("printenv", "ingest", "cmd");

        var (exit, stdout, stderr) = RunTswap("run", "{{cmd}}", "PATH");

        Assert.NotEqual(0, exit);
        Assert.Contains("{{cmd}}", stderr);
        Assert.DoesNotContain("printenv", stderr);
        Assert.DoesNotContain("printenv", stdout);
    }

    // A literal refused word is refused before substitution and named as typed: no token is blamed.
    [Fact]
    public void Run_LiteralBlockedWordWithAToken_RefusalNamesTheWord()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "innocent");

        var (exit, _, stderr) = RunTswap("run", "printenv", "{{innocent}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("'printenv'", stderr);
        Assert.DoesNotContain("{{innocent}}", stderr);
    }

    // rotating-and-burning.md: run warns about a burned {{name}} value too, not only file markers.
    [Fact]
    public void Run_BurnedNameToken_Warns()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "seen");
        Assert.Equal(0, RunTswap("burn", "seen", "in a log").exitCode);

        var (_, _, stderr) = RunTswap("run", "true", "{{seen}}");

        Assert.Contains("Warning: 'seen' is a burned value", stderr);
    }

    [Fact]
    public void Run_InlineCodeFlagFromATokenAfterSubstitution_RefusalDoesNotRepeatTheFlag()
    {
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("-ec", "ingest", "opt");
        var marker = Path.Combine(_tempDir, "ran");

        var (exit, _, stderr) = RunTswap("run", "sh", "{{opt}}", $"touch {marker}");

        Assert.NotEqual(0, exit);
        Assert.Contains("{{opt}}", stderr);
        Assert.DoesNotContain("-ec", stderr);
        Assert.False(File.Exists(marker), "a refused command must not run");
    }

    [Fact]
    public void Run_ShellWithAScriptFile_RunsIt()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // POSIX sh only (until #181: reported as Passed on Windows)

        RunTswap("init", "--yubikey");
        RunTswap("create", "script-test");
        var script = Path.Combine(_tempDir, "script.sh");
        File.WriteAllText(script, "test -n \"$1\" && exit 7\n");

        var (exit, stdout, stderr) = RunTswap("run", "sh", script, "{{script-test}}");

        Assert.True(exit == 7, $"the script should get the secret as $1 and exit 7; exit {exit}: {stdout}{stderr}");
    }

    // Brief T7 item 2 (#182): -v after the command name belongs to the command. `grep -v -x -e
    // <value> file` over a file holding only the value matches nothing inverted (exit 1); with
    // its -v stripped it would match the line (exit 0).
    [Theory]
    [InlineData("-v")]
    [InlineData("--verbose")]
    [InlineData(null)]
    public void Run_ChildsOwnVerboseFlag_ReachesTheChild(string? globalFlag)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // POSIX grep only (until #181: reported as Passed on Windows)

        RunTswap("init", "--yubikey");
        RunTswapWithStdin("grep-pattern-value", "ingest", "grep-pat");
        var file = Path.Combine(_tempDir, "lines.txt");
        File.WriteAllText(file, "grep-pattern-value\n");
        string[] command = ["run", "grep", "-v", "-x", "-e", "{{grep-pat}}", file];

        var (exit, stdout, stderr) = RunTswap(globalFlag == null ? command : [globalFlag, .. command]);

        Assert.True(exit == 1, $"grep must get its -v (exit 1: no non-matching line); exit {exit}: {stdout}{stderr}");
        if (globalFlag != null)
            Assert.Contains("Found tokens: grep-pat", stdout); // tswap's own -v still makes it verbose
        else
            Assert.DoesNotContain("Found tokens", stdout);
    }

    [Fact]
    public void Burn_ReasonThatIsLiterallyDashV_IsKept()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "dash-v-key");

        var (exit, _, stderr) = RunTswap("burn", "dash-v-key", "-v");
        Assert.True(exit == 0, stderr);

        var (_, json, _) = RunTswap("burned", "--json");
        Assert.Contains("\"-v\"", json);
    }

    [Theory]
    [InlineData("-v")]
    [InlineData("--verbose")]
    public void GlobalVerboseFlag_BeforeTheCommand_IsStillVerbose(string flag)
    {
        var (verbose, commandArgs) = CliEnvironment.SplitGlobalFlags([flag, "names"]);

        Assert.True(verbose);
        Assert.Equal(["names"], commandArgs);
    }

    // Fix round 1 (MiMo): `tswap names -v` used to be silently not verbose; a global flag among the
    // command's own options (before its first argument) gets a clear hint instead.
    [Theory]
    [InlineData("names", "-v")]
    [InlineData("names", "--verbose")]
    [InlineData("burned", "--json", "-v")]
    public void GlobalFlagAfterTheCommand_AmongItsOptions_GetsAHint(params string[] args)
    {
        RunTswap("init", "--yubikey");

        var (exit, stdout, stderr) = RunTswap(args);

        Assert.Equal(1, exit);
        Assert.Contains("global flags go before the command", stderr);
        Assert.Contains($"tswap -v {args[0]}", stderr);
        Assert.Equal("", stdout);
    }

    [Fact]
    public void SplitGlobalFlags_KeepsEveryFlagAfterTheCommandName()
    {
        var (verbose, commandArgs) = CliEnvironment.SplitGlobalFlags(["run", "curl", "-v", "--verbose", "https://x", "{{t}}"]);

        Assert.False(verbose);
        Assert.Equal(["run", "curl", "-v", "--verbose", "https://x", "{{t}}"], commandArgs);
    }

    [Fact]
    public void Run_ShellBehindAWrapper_IsRefused()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "wrapped-test");

        var (exit, _, stderr) = RunTswap("run", "timeout", "5", "sh", "-c", "true {{wrapped-test}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("'timeout' runs 'sh'", stderr);
    }

    [Fact]
    public void Run_PipeBlockedFails()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "pipe-test");

        var (exit, _, stderr) = RunTswap("run", "curl", "{{pipe-test}}", "|", "cat");

        Assert.NotEqual(0, exit);
        Assert.Contains("Pipes", stderr);
    }

    // --- No args ---

    [Fact]
    public void NoArgs_ShowsUsage()
    {
        var (exit, stdout, _) = RunTswap();

        Assert.Equal(0, exit);
        Assert.Contains("Usage", stdout);
    }

    // --- Unknown command ---

    [Fact]
    public void UnknownCommand_Fails()
    {
        var (exit, _, stderr) = RunTswap("bogus");

        Assert.NotEqual(0, exit);
        Assert.Contains("Unknown command", stderr);
    }

    // --- Determinism ---

    [Fact]
    public void SameTestKey_ProducesSameMasterKey()
    {
        // Verify determinism: same TSWAP_TEST_KEY encrypts/decrypts consistently
        RunTswap("init", "--yubikey");
        RunTswap("create", "determinism-test");

        // Names should still work (proves decrypt with same key succeeds)
        var (exit, stdout, _) = RunTswap("names");
        Assert.Equal(0, exit);
        Assert.Contains("determinism-test", stdout);
    }

    // --- Apply ---

    [Fact]
    public void Apply_OutputsSubstitutedContent()
    {
        // Initialize and create a secret
        RunTswap("init", "--yubikey");
        RunTswap("create", "test-secret", "16");

        // Create a temp YAML file with tswap marker
        var yamlFile = Path.Combine(_tempDir, "test-values.yaml");
        File.WriteAllText(yamlFile, @"database:
  host: localhost
  password: """"  # tswap: test-secret
  port: 5432");

        // Run apply and check stdout
        var (exit, stdout, _) = RunTswap("apply", yamlFile);

        Assert.Equal(0, exit);
        // Should contain the structure
        Assert.Contains("database:", stdout);
        Assert.Contains("host: localhost", stdout);
        Assert.Contains("port: 5432", stdout);
        // Should have password line with marker
        Assert.Contains("# tswap: test-secret", stdout);
        // Should NOT contain empty password
        Assert.DoesNotContain(@"password: """"", stdout);
        // Should have a populated password (16 chars in double quotes)
        Assert.Matches(@"password: "".{16}""", stdout);
    }

    [Fact]
    public void Apply_FailsOnMissingSecret()
    {
        RunTswap("init", "--yubikey");

        var yamlFile = Path.Combine(_tempDir, "test-values.yaml");
        File.WriteAllText(yamlFile, @"password: """"  # tswap: nonexistent-secret");

        var (exit, _, stderr) = RunTswap("apply", yamlFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("nonexistent-secret", stderr);
        Assert.Contains("not found", stderr);
    }

    [Fact]
    public void Apply_DiagnosticsGoToStderr_NotStdout()
    {
        // In test mode (TSWAP_TEST_KEY set), no security warning banner is generated,
        // so we can only verify that stdout contains clean YAML without warning text.
        // The negative assertions pass regardless of whether warnings go to stderr.
        //
        // However, this test still provides value by ensuring that the apply command's
        // stdout output remains clean YAML that can be safely piped or redirected.

        RunTswap("init", "--yubikey");
        RunTswap("create", "test-secret", "16");

        var yamlFile = Path.Combine(_tempDir, "test-values.yaml");
        File.WriteAllText(yamlFile, @"password: """"  # tswap: test-secret");

        var (exit, stdout, stderr) = RunTswap("apply", yamlFile);

        Assert.Equal(0, exit);

        // Stdout should contain ONLY the YAML output
        Assert.Contains("password:", stdout);
        Assert.Contains("# tswap: test-secret", stdout);

        // Stdout should NOT contain any warning boxes or diagnostic messages
        // (In test mode these assertions always pass, but they document the requirement)
        Assert.DoesNotContain("WARNING", stdout);
        Assert.DoesNotContain("SECURITY", stdout);
        Assert.DoesNotContain("╔═", stdout);  // Box drawing characters
        Assert.DoesNotContain("║", stdout);
        Assert.DoesNotContain("╚═", stdout);
    }

    [Fact]
    public void Apply_BurnedSecret_AppliesWithWarning()
    {
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("burned-secret-value", "ingest", "my-burned");
        RunTswap("burn", "my-burned", "test");

        var yamlFile = Path.Combine(_tempDir, "apply-burned.yaml");
        File.WriteAllText(yamlFile, "token: \"\"  # tswap: my-burned");

        var (exit, stdout, stderr) = RunTswap("apply", yamlFile);

        Assert.Equal(0, exit);
        Assert.Contains("burned-secret-value", stdout);
        Assert.Contains("Warning", stderr);
        Assert.Contains("burned", stderr);
    }

    // --- Check ---

    [Fact]
    public void Check_ExitCode1_WhenSecretMissing()
    {
        RunTswap("init", "--yubikey");

        var yamlFile = Path.Combine(_tempDir, "check-missing.yaml");
        File.WriteAllText(yamlFile, @"password: """"  # tswap: missing-secret");

        var (exit, _, _) = RunTswap("check", yamlFile);

        Assert.Equal(1, exit);
    }

    [Fact]
    public void Check_ExitCode2_WhenSecretBurned()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "burned-check-secret");
        RunTswap("burn", "burned-check-secret", "was leaked");

        var yamlFile = Path.Combine(_tempDir, "check-burned.yaml");
        File.WriteAllText(yamlFile, @"password: """"  # tswap: burned-check-secret");

        var (exit, stdout, _) = RunTswap("check", yamlFile);

        Assert.Equal(2, exit);
        Assert.Contains("BURNED", stdout);
    }

    [Fact]
    public void Check_ExitCode1_WhenMixedMissingAndBurned()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "burned-mixed-secret");
        RunTswap("burn", "burned-mixed-secret", "was leaked");

        var yamlFile = Path.Combine(_tempDir, "check-mixed.yaml");
        File.WriteAllText(yamlFile, @"
password1: """"  # tswap: burned-mixed-secret
password2: """"  # tswap: missing-mixed-secret");

        var (exit, stdout, _) = RunTswap("check", yamlFile);

        // Missing takes precedence over burned, so exit code should be 1
        Assert.Equal(1, exit);
        Assert.Contains("NOT FOUND", stdout);
        Assert.Contains("BURNED", stdout);
    }

    [Fact]
    public void Check_ExitCode0_WhenAllOk()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "ok-check-secret");

        var yamlFile = Path.Combine(_tempDir, "check-ok.yaml");
        File.WriteAllText(yamlFile, @"password: """"  # tswap: ok-check-secret");

        var (exit, _, _) = RunTswap("check", yamlFile);

        Assert.Equal(0, exit);
    }

    // --- Init: new config fields ---


    [Fact]
    public void Init_ConfigHasRngMode()
    {
        RunTswap("init", "--yubikey");
        var json = File.ReadAllText(Path.Combine(_tempDir, "config.json"));
        var config = JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config)!;

        Assert.NotNull(config.RngMode);
        Assert.Equal(RngMode.System, config.RngMode); // test mode uses default
        // On-disk format compatibility: the enum must serialize as the legacy lowercase string
        Assert.Contains("\"RngMode\": \"system\"", json);
    }

    // Regression test for issue #39: init must not hang when stdin is piped.
    // The "Insert YubiKey and press Enter" pauses are TTY-only; when stdin is
    // redirected they must be skipped so that piped "yes" answers only the
    // reinitialise prompt and the command completes normally.
    [Fact]
    public void Init_Reinit_PipedYes_DoesNotHang()
    {
        RunTswap("init", "--yubikey");
        // Brief T16-S1: a second init on a record vault refuses at once, without a prompt to answer.
        var (exit, stdout, stderr) = RunTswapWithStdin("yes\n", "init", "--yubikey");
        Assert.Equal(1, exit);
        Assert.Contains("shared record-store vault", stderr);
        Assert.DoesNotContain("Reinitialize?", stdout);
    }

    [Fact]
    public void Init_CreatesVaultFile()
    {
        var (exit, _, _) = RunTswap("init", "--yubikey");

        // Brief T16-S1: init makes a record vault: its folder holds the keyring and the format
        // marker, and the next command finds a complete (empty) vault without any warning.
        Assert.Equal(0, exit);
        Assert.True(File.Exists(Path.Combine(_tempDir, "vault", "keyring")));
        Assert.True(File.Exists(Path.Combine(_tempDir, "vault", RecordVaultStore.RecordFormatMarkerFileName)));
        var (namesExit, _, namesErr) = RunTswap("names");
        Assert.Equal(0, namesExit);
        Assert.DoesNotContain("arning", namesErr);
    }


    // --- Export / Import ---

    [Fact]
    public void Export_CreatesEncryptedFile()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "my-secret");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        var (exit, stdout, _) = RunTswapWithStdin("passphrase123\npassphrase123\n", "export", exportPath);

        Assert.Equal(0, exit);
        Assert.True(File.Exists(exportPath));
        var written = File.ReadAllText(exportPath);
        // File must not contain the plaintext secret name
        Assert.DoesNotContain("my-secret", written);
        // Fresh exports now produce v2 with explicit Argon2id KDF params (#30, #108).
        Assert.Contains("tswap-export-v2", written);
        Assert.Contains("argon2id", written);
    }

    // #259: an empty passphrase is refused with a tswap message, not Argon2's exception.

    [Fact]
    public void Export_EmptyPassphrase_RefusedBeforeUnlock()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "my-secret");
        var exportPath = Path.Combine(_tempDir, "empty.enc");

        var (exit, _, stderr) = RunTswapWithStdin("\n\n", "export", exportPath);

        Assert.Equal(1, exit);
        Assert.Contains("An empty passphrase can't protect an export. Run 'sudo tswap export' again.", stderr);
        Assert.DoesNotContain("Argon2", stderr);
        Assert.False(File.Exists(exportPath));
    }

    [Fact]
    public void Import_EmptyPassphrase_Refused()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "my-secret");
        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("passphrase\npassphrase\n", "export", exportPath);
        FreshVault();

        var (exit, _, stderr) = RunTswapWithStdin("\n", "import", exportPath);

        Assert.Equal(1, exit);
        Assert.Contains("No import passphrase was entered.", stderr);
        Assert.DoesNotContain("Argon2", stderr);
        var (_, namesOut, _) = RunTswap("names");
        Assert.DoesNotContain("my-secret", namesOut);
    }

    [Fact]
    public void Export_Import_RoundTrip()
    {
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("secret-value", "ingest", "db-pass");
        RunTswap("create", "api-key");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("strongpassphrase\nstrongpassphrase\n", "export", exportPath);

        // Re-init clears the vault (also delete secrets.json.enc — test key is constant
        // so the old encrypted file remains readable if not explicitly removed)
        // "yes\n" answers the "Already initialized. Reinitialize?" prompt via stdin.
        FreshVault();
        var (exit, stdout, _) = RunTswapWithStdin("strongpassphrase\n", "import", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Imported 2 secret(s)", stdout);

        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("db-pass", namesOut);
        Assert.Contains("api-key", namesOut);
    }

    [Fact]
    public void Import_SkipsBurnedSecrets()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "good-secret");
        RunTswap("create", "burned-secret");
        RunTswap("burn", "burned-secret", "compromised");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("passphrase\npassphrase\n", "export", exportPath);

        FreshVault();
        var (exit, stdout, _) = RunTswapWithStdin("passphrase\n", "import", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Skipped", stdout);
        Assert.Contains("burned-secret", stdout);

        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("good-secret", namesOut);
        Assert.DoesNotContain("burned-secret", namesOut);
    }

    [Fact]
    public void Import_SkipsExistingSecrets()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "existing-secret");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("passphrase\npassphrase\n", "export", exportPath);

        // Import into the same vault — existing-secret already there
        var (exit, stdout, _) = RunTswapWithStdin("passphrase\n", "import", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Skipped", stdout);
        Assert.Contains("existing-secret", stdout);
    }

    [Fact]
    public void Import_WrongPassphraseFails()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "a-secret");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("correct-passphrase\ncorrect-passphrase\n", "export", exportPath);

        var (exit, _, stderr) = RunTswapWithStdin("wrong-passphrase\n", "import", exportPath);

        Assert.NotEqual(0, exit);
        Assert.Contains("wrong passphrase", stderr);
    }

    [Fact]
    public void Import_SkipsSecretsWithNulOrNullValues()
    {
        RunTswap("init", "--yubikey");

        // Construct a synthetic export file containing one clean secret, one with a NUL byte,
        // and one with a null value (possible from a tampered/corrupted export file since
        // System.Text.Json can produce null for non-nullable string properties).
        // We bypass tswap for this because ingest now rejects NUL values.
        const string passphrase = "test-passphrase";
        var salt       = RandomNumberGenerator.GetBytes(16);
        var exportKey  = Crypto.DeriveKeyFromPassphrase(passphrase, salt);

        // Inject the null-value secret via raw JSON to bypass the C# type system.
        var dbJson = $$"""
            {
              "Secrets": {
                "good-secret": {"Value":"good-value","Created":"{{DateTime.UtcNow:O}}","Modified":"{{DateTime.UtcNow:O}}"},
                "nul-secret":  {"Value":"bad\u0000val","Created":"{{DateTime.UtcNow:O}}","Modified":"{{DateTime.UtcNow:O}}"},
                "null-secret": {"Value":null,          "Created":"{{DateTime.UtcNow:O}}","Modified":"{{DateTime.UtcNow:O}}"}
              }
            }
            """;
        var ciphertext = Crypto.Encrypt(Encoding.UTF8.GetBytes(dbJson), exportKey);
        var exportFile = new ExportFile(
            "tswap-export-v1", DateTime.UtcNow,
            Convert.ToBase64String(salt),
            Convert.ToBase64String(ciphertext));
        var exportPath = Path.Combine(_tempDir, "nul-test.enc");
        File.WriteAllText(exportPath,
            JsonSerializer.Serialize(exportFile, TswapJsonContext.Default.ExportFile));

        var (exit, stdout, _) = RunTswapWithStdin(passphrase + "\n", "import", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Imported 1 secret(s)", stdout);
        Assert.Contains("nul-secret",  stdout);
        Assert.Contains("null-secret", stdout);

        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("good-secret",      namesOut);
        Assert.DoesNotContain("nul-secret",  namesOut);
        Assert.DoesNotContain("null-secret", namesOut);
    }

    [Fact]
    public void Import_IncludeBurned_ImportsBurnedSecrets()
    {
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("burned-value", "ingest", "was-burned");
        RunTswap("burn", "was-burned", "compromised");
        RunTswap("create", "good-secret");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("passphrase\npassphrase\n", "export", exportPath);

        FreshVault();
        var (exit, stdout, _) = RunTswapWithStdin("passphrase\n", "import", "--include-burned", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Imported 2 secret(s)", stdout);

        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("good-secret", namesOut);
        Assert.Contains("was-burned", namesOut);
        Assert.Contains("[BURNED]", namesOut);
    }

    [Fact]
    public void Import_Default_SkipsBurnedSecrets_WithHint()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "good-secret");
        RunTswap("create", "burned-secret");
        RunTswap("burn", "burned-secret", "compromised");

        var exportPath = Path.Combine(_tempDir, "backup.enc");
        RunTswapWithStdin("passphrase\npassphrase\n", "export", exportPath);

        FreshVault();
        var (exit, stdout, _) = RunTswapWithStdin("passphrase\n", "import", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Skipped", stdout);
        Assert.Contains("burned-secret", stdout);
        Assert.Contains("--include-burned", stdout);

        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("good-secret", namesOut);
        Assert.DoesNotContain("burned-secret", namesOut);
    }

    [Fact]
    public void Export_PromptsAreOnStderr()
    {
        RunTswap("init", "--yubikey");
        var exportPath = Path.Combine(_tempDir, "backup.enc");
        var (exit, stdout, stderr) = RunTswapWithStdin("testpass\ntestpass\n", "export", exportPath);

        Assert.Equal(0, exit);
        // The interactive prompt "Export passphrase:" must not pollute stdout
        // (stdout is the redirect target when the user pipes export output).
        Assert.DoesNotContain("Export passphrase:", stdout);
        Assert.DoesNotContain("Confirm passphrase:", stdout);
        // Prompts must appear on stderr so the user sees them when stdout is redirected
        Assert.Contains("Export passphrase:", stderr);
        Assert.Contains("Confirm passphrase:", stderr);
    }

    [Fact]
    public void Export_Cancel_ExitsWithError()
    {
        RunTswap("init", "--yubikey");
        var exportPath = Path.Combine(_tempDir, "backup.enc");
        File.WriteAllText(exportPath, "existing"); // trigger the overwrite prompt

        // Answer "no" to the overwrite question — should cancel and exit non-zero
        var (exit, _, stderr) = RunTswapWithStdin("no\n", "export", exportPath);

        Assert.NotEqual(0, exit);
        Assert.Contains("cancelled", stderr, StringComparison.OrdinalIgnoreCase);
        // File must not be modified
        Assert.Equal("existing", File.ReadAllText(exportPath));
    }

    [Fact]
    public void Import_InvalidJson_GivesFriendlyError()
    {
        RunTswap("init", "--yubikey");
        var badFile = Path.Combine(_tempDir, "bad.enc");
        File.WriteAllText(badFile, "this is not json at all {{{");

        var (exit, _, stderr) = RunTswapWithStdin("anypassphrase\n", "import", badFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("not valid JSON", stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Import_V1ExportFile_ImportsViaLegacyPbkdf2Path()
    {
        // A v1-shaped ExportFile has no Kdf field at all (it didn't exist yet — #30/#108).
        // Its key must still be derivable exactly as it always was: Crypto.DeriveKeyFromPassphrase
        // (plain PBKDF2-SHA256 at Crypto.Pbkdf2Iterations), dispatched via ExportFile.V1.
        RunTswap("init", "--yubikey");

        const string passphrase = "legacy-passphrase";
        var salt = RandomNumberGenerator.GetBytes(32);
        var exportKey = Crypto.DeriveKeyFromPassphrase(passphrase, salt);
        var dbJson = JsonSerializer.Serialize(
            new SecretsDb(new Dictionary<string, Secret> { ["legacy-secret"] = new("legacy-value", DateTime.UtcNow, DateTime.UtcNow) }),
            TswapJsonContext.Default.SecretsDb);
        var ciphertext = Crypto.Encrypt(Encoding.UTF8.GetBytes(dbJson), exportKey);

        var exportFile = new ExportFile(
            ExportFile.V1, DateTime.UtcNow,
            Convert.ToBase64String(salt),
            Convert.ToBase64String(ciphertext));
        Assert.Null(exportFile.Kdf);
        var exportPath = Path.Combine(_tempDir, "legacy-v1.enc");
        File.WriteAllText(exportPath, JsonSerializer.Serialize(exportFile, TswapJsonContext.Default.ExportFile));

        var (exit, stdout, _) = RunTswapWithStdin(passphrase + "\n", "import", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Imported 1 secret(s)", stdout);
        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("legacy-secret", namesOut);
    }

    /// <summary>Review M5: the empty-passphrase refusal is for Argon2id files; a v1 file made with "" still imports.</summary>
    [Fact]
    public void Import_V1ExportFileWithEmptyPassphrase_StillImports()
    {
        RunTswap("init", "--yubikey");
        var salt = RandomNumberGenerator.GetBytes(32);
        var exportKey = Crypto.DeriveKeyFromPassphrase("", salt);
        var dbJson = JsonSerializer.Serialize(
            new SecretsDb(new Dictionary<string, Secret> { ["empty-pass-secret"] = new("v", DateTime.UtcNow, DateTime.UtcNow) }),
            TswapJsonContext.Default.SecretsDb);
        var exportFile = new ExportFile(ExportFile.V1, DateTime.UtcNow, Convert.ToBase64String(salt),
            Convert.ToBase64String(Crypto.Encrypt(Encoding.UTF8.GetBytes(dbJson), exportKey)));
        var exportPath = Path.Combine(_tempDir, "empty-v1.enc");
        File.WriteAllText(exportPath, JsonSerializer.Serialize(exportFile, TswapJsonContext.Default.ExportFile));

        var (exit, stdout, stderr) = RunTswapWithStdin("\n", "import", exportPath);

        Assert.True(exit == 0, stderr);
        Assert.Contains("Imported 1 secret(s)", stdout);
        Assert.Contains("empty-pass-secret", RunTswap("names").stdout);
    }

    /// <summary>Review M5: the empty export passphrase is refused before the vault is unlocked (no YubiKey challenge).</summary>
    [Fact]
    public void Export_EmptyPassphrase_NoYubiKeyChallenge()
    {
        using var m = new FleetMachine("export-empty", SimulatedYubiKeyService.WithKeys(11111111));
        m.Keys.PluggedIn = [11111111];
        m.Ok("", "init", "--yubikey", "--no-password");
        m.Ok("v\nv\n", "add", "db");
        m.Keys.Challenges.Clear();
        var exportPath = m.PathOf("empty.enc");

        var (exit, _, stderr) = m.Run("\n\n", "export", exportPath);

        Assert.Equal(1, exit);
        Assert.Contains("An empty passphrase can't protect an export.", stderr);
        Assert.Empty(m.Keys.Challenges);
        Assert.False(File.Exists(exportPath));
    }

    [Fact]
    public void Import_V2ExportFile_UsesArgon2idParamsFromFile()
    {
        // A v2 file carries its own explicit Kdf params (#30); import must derive using those,
        // not any hardcoded default, and must use Argon2id rather than PBKDF2 (#108).
        RunTswap("init", "--yubikey");

        const string passphrase = "v2-passphrase";
        var salt = RandomNumberGenerator.GetBytes(32);
        var kdf = ExportCrypto.DefaultArgon2idParams;
        Assert.Equal(KdfAlgorithm.Argon2id, kdf.Algorithm);
        var exportKey = ExportCrypto.DeriveArgon2id(passphrase, salt, kdf);
        var dbJson = JsonSerializer.Serialize(
            new SecretsDb(new Dictionary<string, Secret> { ["v2-secret"] = new("v2-value", DateTime.UtcNow, DateTime.UtcNow) }),
            TswapJsonContext.Default.SecretsDb);
        var ciphertext = Crypto.Encrypt(Encoding.UTF8.GetBytes(dbJson), exportKey);

        var exportFile = new ExportFile(
            ExportFile.V2, DateTime.UtcNow,
            Convert.ToBase64String(salt),
            Convert.ToBase64String(ciphertext),
            kdf);
        var exportPath = Path.Combine(_tempDir, "v2.enc");
        File.WriteAllText(exportPath, JsonSerializer.Serialize(exportFile, TswapJsonContext.Default.ExportFile));

        var (exit, stdout, _) = RunTswapWithStdin(passphrase + "\n", "import", exportPath);

        Assert.Equal(0, exit);
        Assert.Contains("Imported 1 secret(s)", stdout);
        var (_, namesOut, _) = RunTswap("names");
        Assert.Contains("v2-secret", namesOut);
    }

    [Fact]
    public void Import_UnrecognizedVersion_ThrowsClearError()
    {
        RunTswap("init", "--yubikey");

        var exportFile = new ExportFile("tswap-export-v99", DateTime.UtcNow, "c2FsdA==", "Y2lwaGVy");
        var exportPath = Path.Combine(_tempDir, "future.enc");
        File.WriteAllText(exportPath, JsonSerializer.Serialize(exportFile, TswapJsonContext.Default.ExportFile));

        var (exit, _, stderr) = RunTswapWithStdin("anypassphrase\n", "import", exportPath);

        Assert.NotEqual(0, exit);
        Assert.Contains("Unsupported export version: tswap-export-v99", stderr);
    }

    // --- Migrate ---

    [Fact]
    public void Migrate_OldConfig_UpdatesRngMode()
    {
        // Simulate a pre-feature config: init normally then strip UnlockChallenge
        ClassicVaultTestSupport.CreateTestModeVault(_tempDir, _testKey); // brief T16-S1: init makes record vaults now
        var configPath = Path.Combine(_tempDir, "config.json");
        var config = JsonSerializer.Deserialize(
            File.ReadAllText(configPath), TswapJsonContext.Default.Config)!;
        var oldConfig = config with { UnlockChallenge = null, RngMode = null };
        File.WriteAllText(configPath,
            JsonSerializer.Serialize(oldConfig, TswapJsonContext.Default.Config));

        // Run migrate, choose YubiKey entropy mode (option 2), decline detailed instructions
        var (exit, stdout, _) = RunTswapWithStdin("2\nno\n", "migrate");

        Assert.Equal(0, exit);
        Assert.Contains("YubiKey hardware", stdout);

        var updated = JsonSerializer.Deserialize(
            File.ReadAllText(configPath), TswapJsonContext.Default.Config)!;
        Assert.Equal(RngMode.YubiKey, updated.RngMode);
    }

    [Fact]
    public void Migrate_TpmBackend_DoesNotCrashOnEmptyYubiKeySerials()
    {
        // TPM/Secure Enclave vaults have YubiKeySerials: [] — migrate must not blindly index
        // [0]/[1] into that (regression test for the Copilot-flagged crash).
        RunTswap("init", "--yubikey");
        var configPath = Path.Combine(_tempDir, "config.json");
        var tpmConfig = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.Tpm, TpmSealedKey: "irrelevant");
        File.WriteAllText(configPath, JsonSerializer.Serialize(tpmConfig, TswapJsonContext.Default.Config));

        var (exit, stdout, _) = RunTswap("migrate");

        Assert.Equal(0, exit);
        Assert.Contains("only applies to YubiKey vaults", stdout);
    }

    [Fact]
    public void Migrate_ModernConfig_ReportsUpToDate()
    {
        ClassicVaultTestSupport.CreateTestModeVault(_tempDir, _testKey); // brief T16-S1: init makes record vaults now
        // Modern config has UnlockChallenge set and RequiresTouch from synthetic init
        // We need to also set RequiresTouch = true to satisfy all checks
        var configPath = Path.Combine(_tempDir, "config.json");
        var config = JsonSerializer.Deserialize(
            File.ReadAllText(configPath), TswapJsonContext.Default.Config)!;
        var modernConfig = config with { RequiresTouch = true };
        File.WriteAllText(configPath,
            JsonSerializer.Serialize(modernConfig, TswapJsonContext.Default.Config));

        var (exit, stdout, _) = RunTswap("migrate");

        Assert.Equal(0, exit);
        Assert.Contains("up to date", stdout);
    }

    // Regression test for issue #39: migrate must not hang when stdin is piped.
    // Synthetic init leaves RequiresTouch=null → needsTouchMigration=true → the
    // "Show detailed conversion instructions? (yes/no):" prompt is shown.
    // Piped "no\n" must answer it without blocking and the command must exit 0.
    [Fact]
    public void Migrate_PipedNo_DoesNotHang()
    {
        RunTswap("init", "--yubikey");
        // Default synthetic config: RngMode=system, UnlockChallenge=set, RequiresTouch=null
        // → needsReInit=true (touch migration required) → yes/no prompt is shown
        var (exit, _, _) = RunTswapWithStdin("no\n", "migrate");
        Assert.Equal(0, exit);
    }

    // --- tocomment: security ---

    [Fact]
    public void ToComment_DryRun_DoesNotExposeSecretInOutput()
    {
        RunTswap("init", "--yubikey");
        // Ingest a known secret value via stdin
        var (ingestExit, _, _) = RunTswapWithStdin("supersecretvalue123", "ingest", "my-password");
        Assert.Equal(0, ingestExit);

        // Write a YAML file containing the plaintext secret
        var yamlFile = Path.Combine(_tempDir, "applied.yaml");
        File.WriteAllText(yamlFile, "password: supersecretvalue123");

        // Run tocomment --dry-run and capture output
        var (exit, stdout, stderr) = RunTswap("tocomment", yamlFile, "--dry-run");

        Assert.Equal(0, exit);
        // The secret must NOT appear anywhere in the output (stdout or stderr)
        Assert.DoesNotContain("supersecretvalue123", stdout);
        Assert.DoesNotContain("supersecretvalue123", stderr);
        // The diff output is now in stderr (diagnostic output)
        Assert.Contains("[REDACTED: my-password]", stderr);
        Assert.Contains("# tswap: my-password", stderr);
    }

    [Fact]
    public void ToComment_Live_DoesNotExposeSecretInOutput()
    {
        RunTswap("init", "--yubikey");
        var (ingestExit, _, _) = RunTswapWithStdin("supersecretvalue123", "ingest", "my-password");
        Assert.Equal(0, ingestExit);

        var yamlFile = Path.Combine(_tempDir, "applied.yaml");
        File.WriteAllText(yamlFile, "password: supersecretvalue123");

        var (exit, stdout, stderr) = RunTswap("tocomment", yamlFile);

        Assert.Equal(0, exit);
        // Secret must not appear in either stream
        Assert.DoesNotContain("supersecretvalue123", stdout);
        Assert.DoesNotContain("supersecretvalue123", stderr);
        // Diff output is in stderr
        Assert.Contains("[REDACTED: my-password]", stderr);
    }

    [Fact]
    public void ToComment_ContinuationLine_DoesNotLeakFragmentInOutput()
    {
        RunTswap("init", "--yubikey");
        var (ingestExit, _, _) = RunTswapWithStdin("supersecretvalue123", "ingest", "my-password");
        Assert.Equal(0, ingestExit);

        // Simulates a multi-line YAML scalar: the continuation line is a base64-looking
        // fragment. RedactContent cannot redact it (it is only a partial match), so without
        // the fix it would be printed verbatim — the test ensures it is suppressed instead.
        var yamlFile = Path.Combine(_tempDir, "multiline.yaml");
        File.WriteAllText(yamlFile,
            "password: supersecretvalue123\n" +
            "  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");

        var (exit, stdout, stderr) = RunTswap("tocomment", yamlFile, "--dry-run");

        Assert.Equal(0, exit);
        // Raw continuation fragment must NOT appear in either stream
        Assert.DoesNotContain("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", stdout);
        Assert.DoesNotContain("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", stderr);
        // Safe placeholder must appear in stderr (diff output)
        Assert.Contains("[removed continuation line]", stderr);
        // Main secret must also not be leaked in either stream
        Assert.DoesNotContain("supersecretvalue123", stdout);
        Assert.DoesNotContain("supersecretvalue123", stderr);
    }

    // --- issue #81: extend burn handling ---

    [Fact]
    public void Redact_IncludesBurnedSecretValues()
    {
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("burned-secret-value", "ingest", "my-burned");
        RunTswap("burn", "my-burned", "test");

        var yamlFile = Path.Combine(_tempDir, "content.txt");
        File.WriteAllText(yamlFile, "token: burned-secret-value");

        var (exit, stdout, _) = RunTswap("redact", yamlFile);

        Assert.Equal(0, exit);
        Assert.DoesNotContain("burned-secret-value", stdout);
        Assert.Contains("[REDACTED: my-burned]", stdout);
    }

    [Fact]
    public void ToComment_IncludesBurnedSecretValues()
    {
        RunTswap("init", "--yubikey");
        RunTswapWithStdin("burned-secret-value", "ingest", "my-burned");
        RunTswap("burn", "my-burned", "test");

        var yamlFile = Path.Combine(_tempDir, "content.yaml");
        File.WriteAllText(yamlFile, "token: burned-secret-value");

        var (exit, stdout, stderr) = RunTswap("tocomment", yamlFile, "--dry-run");

        Assert.Equal(0, exit);
        Assert.DoesNotContain("burned-secret-value", stdout);
        Assert.DoesNotContain("burned-secret-value", stderr);
        Assert.Contains("# tswap: my-burned", stderr);
    }

    // --- JSON output (--json) ---

    [Fact]
    public void Names_Json_EmptyVault_IsEmptyArray()
    {
        RunTswap("init", "--yubikey");
        var (exit, stdout, _) = RunTswap("names", "--json");

        Assert.Equal(0, exit);
        using var doc = JsonDocument.Parse(stdout);
        Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
        Assert.Equal(0, doc.RootElement.GetArrayLength());
    }

    [Fact]
    public void Names_Json_ReportsBurnFlag()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "alpha");
        RunTswap("create", "beta");
        RunTswap("burn", "beta", "leaked");

        var (exit, stdout, _) = RunTswap("names", "--json");

        Assert.Equal(0, exit);
        using var doc = JsonDocument.Parse(stdout);
        var entries = doc.RootElement.EnumerateArray().ToList();
        Assert.Equal(2, entries.Count);
        // Sorted by name: alpha then beta.
        Assert.Equal("alpha", entries[0].GetProperty("name").GetString());
        Assert.False(entries[0].GetProperty("burned").GetBoolean());
        Assert.Equal("beta", entries[1].GetProperty("name").GetString());
        Assert.True(entries[1].GetProperty("burned").GetBoolean());
        Assert.True(entries[1].TryGetProperty("burnedAt", out _));
    }

    [Fact]
    public void Burned_Json_EmptyIsEmptyArray()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "clean");

        var (exit, stdout, _) = RunTswap("burned", "--json");

        Assert.Equal(0, exit);
        using var doc = JsonDocument.Parse(stdout);
        Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
        Assert.Equal(0, doc.RootElement.GetArrayLength());
    }

    [Fact]
    public void Burned_Json_ListsBurnedWithReason()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "leaked");
        RunTswap("burn", "leaked", "seen in logs");

        var (exit, stdout, _) = RunTswap("burned", "--json");

        Assert.Equal(0, exit);
        using var doc = JsonDocument.Parse(stdout);
        var entries = doc.RootElement.EnumerateArray().ToList();
        Assert.Single(entries);
        Assert.Equal("leaked", entries[0].GetProperty("name").GetString());
        Assert.Equal("seen in logs", entries[0].GetProperty("reason").GetString());
    }

    [Fact]
    public void Check_Json_NoMarkers_IsEmptyReport()
    {
        RunTswap("init", "--yubikey");
        var yamlFile = Path.Combine(_tempDir, "plain.yaml");
        File.WriteAllText(yamlFile, "password: hunter2\n");

        var (exit, stdout, _) = RunTswap("check", yamlFile, "--json");

        Assert.Equal(0, exit);
        using var doc = JsonDocument.Parse(stdout);
        Assert.Equal(0, doc.RootElement.GetProperty("results").GetArrayLength());
        Assert.Equal(0, doc.RootElement.GetProperty("missing").GetInt32());
    }

    [Fact]
    public void Check_Json_ReportsStatusesAndPreservesExitCode()
    {
        RunTswap("init", "--yubikey");
        RunTswap("create", "present");

        var yamlFile = Path.Combine(_tempDir, "mixed.yaml");
        File.WriteAllText(yamlFile,
            "a: \"\"  # tswap: present\nb: \"\"  # tswap: absent\n");

        var (exit, stdout, _) = RunTswap("check", yamlFile, "--json");

        // Missing secret -> exit 1, same as the human-readable path.
        Assert.Equal(1, exit);
        using var doc = JsonDocument.Parse(stdout);
        Assert.Equal(1, doc.RootElement.GetProperty("ok").GetInt32());
        Assert.Equal(1, doc.RootElement.GetProperty("missing").GetInt32());
        var statuses = doc.RootElement.GetProperty("results").EnumerateArray()
            .Select(e => e.GetProperty("status").GetString()).ToList();
        Assert.Contains("ok", statuses);
        Assert.Contains("missing", statuses);
    }

    [Fact]
    public void Check_Json_MissingPath_StillUsageError()
    {
        RunTswap("init", "--yubikey");
        var (exit, _, stderr) = RunTswap("check", "--json");

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage", stderr);
    }

    // --- Shell completion ---

    [Fact]
    public void Completion_Bash_ListsRegisteredCommands()
    {
        var (exit, stdout, _) = RunTswap("completion", "bash");

        Assert.Equal(0, exit);
        Assert.Contains("complete -F", stdout);
        Assert.Contains("names", stdout);
        Assert.Contains("completion", stdout);
    }

    [Fact]
    public void Completion_Zsh_EmitsCompdef()
    {
        var (exit, stdout, _) = RunTswap("completion", "zsh");

        Assert.Equal(0, exit);
        Assert.Contains("#compdef tswap", stdout);
        Assert.Contains("_describe", stdout);
    }

    [Fact]
    public void Completion_Fish_EmitsCompleteLines()
    {
        var (exit, stdout, _) = RunTswap("completion", "fish");

        Assert.Equal(0, exit);
        Assert.Contains("complete -c tswap", stdout);
        Assert.Contains("__fish_use_subcommand", stdout);
    }

    [Fact]
    public void Completion_PowerShell_EmitsRegisterArgumentCompleter()
    {
        var (exit, stdout, _) = RunTswap("completion", "powershell");

        Assert.Equal(0, exit);
        Assert.Contains("Register-ArgumentCompleter", stdout);
        Assert.Contains("names", stdout);
    }

    [Fact]
    public void Completion_UnknownShell_Fails()
    {
        var (exit, _, stderr) = RunTswap("completion", "tcsh");

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage", stderr);
    }

    [Fact]
    public void Completion_NoArg_Fails()
    {
        var (exit, _, stderr) = RunTswap("completion");

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage", stderr);
    }
}


