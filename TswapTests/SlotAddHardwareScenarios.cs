using System.Security.Cryptography;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T24: the scenarios of <c>slot add --tpm</c> and <c>slot add --secure-enclave</c>, written once for either
/// chip (<see cref="SlotAddTpmTests"/> names them). One
/// <see cref="FleetMachine"/> with the chip set (a simulated TPM or Secure Enclave) and YubiKeys A and B.
/// "Nothing written" (<see cref="Snapshot"/>): <c>config.json</c>, the folder's <c>keyring</c> and
/// <c>vault-password</c> byte for byte as they were, and no new <c>config.json.bak-*</c>.
/// </summary>
internal sealed class SlotAddHardwareScenarios : IDisposable
{
    public const int SerialA = 11111111;
    public const int SerialB = 22222222;
    public const string Password = "correct horse battery staple";

    private readonly HardwareBackend _backend;
    private readonly bool _withTouch;

    public SlotAddHardwareScenarios(HardwareBackend backend, bool withTouch = true)
    {
        _backend = backend;
        _withTouch = withTouch;
        M = new FleetMachine(backend == HardwareBackend.Tpm ? "add-tpm" : "add-se", SimulatedYubiKeyService.WithKeys(SerialA, SerialB));
        M.Keys.PluggedIn = [SerialA];
        Chip = RandomNumberGenerator.GetBytes(32);
    }

    public FleetMachine M { get; }

    public void Dispose() => M.Dispose();

    /// <summary>This machine's simulated chip (its key), or null for none.</summary>
    public byte[]? Chip
    {
        get => _backend == HardwareBackend.Tpm ? M.Tpm : M.SecureEnclave;
        set
        {
            if (_backend == HardwareBackend.Tpm) M.Tpm = value;
            else M.SecureEnclave = value;
        }
    }

    public string Name => _backend == HardwareBackend.Tpm ? "TPM" : "Secure Enclave";

    /// <summary>The chip's flags for <c>init</c> and <c>slot add</c>.</summary>
    public string[] Flags => _backend == HardwareBackend.Tpm
        ? ["--tpm"]
        : ["--secure-enclave", _withTouch ? "--with-touch" : "--no-touch"];

    /// <summary>The flags as <c>LegacyPairOwnSlotText</c> names them.</summary>
    public string FlagsText => _backend == HardwareBackend.Tpm ? "--tpm" : "--secure-enclave --with-touch|--no-touch";

    private string EnrollCall => $"{_backend}:Enroll";
    private string UnlockCall => $"{_backend}:Unlock";

    /// <summary>The wrong-password text of the simulated chip's own unlock.</summary>
    public string WrongPasswordAtUnlock => _backend == HardwareBackend.Tpm
        ? VaultPasswordMessages.WrongPasswordKdf
        : VaultPasswordMessages.WrongPasswordSecureEnclave;

    public string[] Add(params string[] more) => ["slot", "add", .. Flags, .. more];

    private static string RecoveryKeyFrom(string initOutput)
    {
        var lines = initOutput.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        return lines[lines.IndexOf("Recovery Private Key (base64):") + 1];
    }

    /// <summary><c>init --yubikey --no-password</c> with key A, then <c>create alpha</c>; returns the recovery key.</summary>
    public string YubiKeyVault()
    {
        var key = RecoveryKeyFrom(M.Ok("", "init", "--yubikey", "--no-password"));
        M.Ok("", "create", "alpha");
        return key;
    }

    /// <summary>A YubiKey vault whose key B slot has the vault password (so the folder has a vault-password file).</summary>
    public void YubiKeyVaultWithAPasswordSlot()
    {
        YubiKeyVault();
        M.Keys.PluggedIn = [SerialA, SerialB];
        M.Ok(Password + "\n" + Password + "\n", "slot", "add", "--yubikey", "--password");
        Assert.True(File.Exists(VaultPasswordPath));
        M.Keys.PluggedIn = [SerialA];
    }

    /// <summary><c>init</c> with this chip (no YubiKey plugged in), then <c>create alpha</c>; returns the recovery key.</summary>
    public string ChipVault(bool password)
    {
        M.Keys.PluggedIn = [];
        string key;
        if (password)
        {
            key = RecoveryKeyFrom(M.Ok(Password + "\n" + Password + "\n", ["init", .. Flags, "--password"]));
            var (exit, _, err) = M.RunOnTerminal(Password + "\n", "create", "alpha");
            Assert.True(exit == 0, err);
        }
        else
        {
            key = RecoveryKeyFrom(M.Ok("", ["init", .. Flags, "--no-password"]));
            M.Ok("", "create", "alpha");
        }
        return key;
    }

    public string VaultPasswordPath => Path.Combine(M.VaultDir!, RecordVaultStore.VaultPasswordFileName);
    private string KeyringPath => Path.Combine(M.VaultDir!, RecordVaultStore.KeyringFileName);

    public Slot OwnSlot()
    {
        var id = Convert.FromBase64String(M.Config.KeyringSlotId!);
        return M.Keyring.Slots.Single(s => s.SlotId.AsSpan().SequenceEqual(id));
    }

    private static int Occurrences(string text, string part) =>
        (text.Length - text.Replace(part, "", StringComparison.Ordinal).Length) / part.Length;

    public static string ShortId(Slot slot) => Convert.ToHexString(slot.SlotId).ToLowerInvariant()[..8];

    /// <summary>Rewrites the folder's keyring with the own slot replaced by <paramref name="change"/>'s result.</summary>
    public void ChangeOwnSlot(Func<Slot, Slot> change)
    {
        var own = OwnSlot();
        var keyring = M.Keyring;
        var slots = keyring.Slots.Select(s => s.SlotId.AsSpan().SequenceEqual(own.SlotId) ? change(s) : s).ToList();
        File.WriteAllBytes(KeyringPath, KeyringCodec.Encode(keyring with { Slots = slots }));
    }

    /// <summary>What "nothing written" compares: config.json, keyring, vault-password (null: absent), the backups.</summary>
    public (string Config, byte[]? Keyring, byte[]? VaultPassword, string[] Backups) Snapshot() =>
    (
        M.ConfigText,
        M.VaultDir is { } dir && File.Exists(Path.Combine(dir, RecordVaultStore.KeyringFileName)) ? File.ReadAllBytes(KeyringPath) : null,
        M.VaultDir is not null && File.Exists(VaultPasswordPath) ? File.ReadAllBytes(VaultPasswordPath) : null,
        [.. M.Backups.Order()]
    );

    public void AssertNothingWritten((string Config, byte[]? Keyring, byte[]? VaultPassword, string[] Backups) before)
    {
        var after = Snapshot();
        Assert.Equal(before.Config, after.Config);
        Assert.Equal(before.Keyring, after.Keyring);
        Assert.Equal(before.VaultPassword, after.VaultPassword);
        Assert.Equal(before.Backups, after.Backups);
    }

    /// <summary>Runs <paramref name="args"/> and records the simulated chip calls it made.</summary>
    public (int Exit, string Out, string Err, List<string> Calls) Observed(Func<(int, string, string)> run)
    {
        List<string> calls = [];
        int exit;
        string stdout, stderr;
        using (SimulatedHardwareService.ObserveCalls((backend, call) => calls.Add($"{backend}:{call}")))
            (exit, stdout, stderr) = run();
        return (exit, stdout, stderr, calls);
    }

    private void AssertNamesListsAlpha(string stdin = "", bool terminal = false)
    {
        var (exit, stdout, stderr) = terminal ? M.RunOnTerminal(stdin, "names") : M.Run(stdin, "names");
        Assert.True(exit == 0, stderr);
        Assert.Contains("alpha", stdout);
    }

    // --- the scenarios ---

    public void ThenTheChipAloneOpensTheVault()
    {
        YubiKeyVault();

        var stdout = M.Ok("", Add("--no-password"));

        var config = M.Config;
        Assert.Equal(_backend, config.Backend);
        Assert.Equal(Convert.ToBase64String(M.Keyring.Slots[^1].SlotId), config.KeyringSlotId);
        Assert.Equal(_backend == HardwareBackend.SecureEnclave && _withTouch, config.RequiresTouch);
        Assert.Contains($"✓ This machine's {Name} added as its own slot — it now opens this vault alone.", stdout);
        Assert.Contains($"Slots in this machine's keyring: {M.Keyring.Slots.Count}", stdout);
        Assert.Contains("Machines that share this vault folder get the new slot with it.", stdout);
        Assert.Contains("sudo tswap vault merge <the copied folder>", stdout);
        Assert.DoesNotContain("no sync in v0", stdout);

        M.Keys.PluggedIn = [];
        AssertNamesListsAlpha();

        Chip = RandomNumberGenerator.GetBytes(32);
        var (exit, stdoutOther, _) = M.Run("", "names");
        Assert.NotEqual(0, exit);
        Assert.DoesNotContain("alpha", stdoutOther);
    }

    public void TheExistingYubiKeySlotStillOpens()
    {
        YubiKeyVault();
        M.Ok("", Add("--no-password"));

        Chip = null;
        M.Keys.PluggedIn = [SerialA];
        AssertNamesListsAlpha();
    }

    public void Password_OnAVaultWithoutOne_CreatesTheFirstPassword()
    {
        YubiKeyVault();
        Assert.False(File.Exists(VaultPasswordPath));

        var (exit, _, stderr) = M.RunOnTerminal(Password + "\n" + Password + "\n", Add("--password"));

        Assert.True(exit == 0, stderr);
        Assert.True(File.Exists(VaultPasswordPath));
        Assert.Equal(SlotPasswordKind.Password, SlotPassword.Classify(M.Keyring.Slots[^1]));
        M.Keys.PluggedIn = [];
        AssertNamesListsAlpha(Password + "\n", terminal: true);
        var (wrongExit, _, wrongErr) = M.RunOnTerminal("not the password\n", "names");
        Assert.NotEqual(0, wrongExit);
        Assert.Contains(WrongPasswordAtUnlock, wrongErr);
    }

    public void Password_Wrong_NothingWritten()
    {
        YubiKeyVaultWithAPasswordSlot();
        var before = Snapshot();

        var (exit, _, stderr, calls) = Observed(() => M.Run("not the password\n", Add("--password")));

        Assert.NotEqual(0, exit);
        Assert.Contains(VaultPasswordChoice.WrongPasswordText, stderr);
        Assert.DoesNotContain(EnrollCall, calls);
        AssertNothingWritten(before);
    }

    public void FirstPassword_WhilePasswordSlotsExistWithoutTheFile_Refused()
    {
        YubiKeyVaultWithAPasswordSlot();
        File.Delete(VaultPasswordPath);
        var before = Snapshot();

        var (exit, _, stderr, calls) = Observed(() => M.Run(Password + "\n" + Password + "\n", Add("--password")));

        Assert.NotEqual(0, exit);
        Assert.Contains(VaultPasswordMessages.MissingFile, stderr);
        Assert.DoesNotContain(EnrollCall, calls);
        Assert.False(File.Exists(VaultPasswordPath));
        AssertNothingWritten(before);
    }

    public void NoTerminal_NoFlag_AddsAPasswordFreeSlot()
    {
        YubiKeyVault();

        var (exit, _, stderr) = M.Run("", Add());

        Assert.True(exit == 0, stderr);
        Assert.Contains(VaultPasswordChoice.NoPasswordLine, stderr);
        Assert.Equal(SlotPasswordKind.None, SlotPassword.Classify(M.Keyring.Slots[^1]));
        Assert.False(File.Exists(VaultPasswordPath));
    }

    public void WorkingChipSlotAlready_Refused_NothingWritten()
    {
        ChipVault(password: false);
        var own = OwnSlot();
        var before = Snapshot();

        var (exit, _, stderr, calls) = Observed(() => M.Run("", Add("--no-password")));

        Assert.NotEqual(0, exit);
        Assert.Contains(SlotCommand.WorkingHardwareSlotText(Name, ShortId(own)), stderr);
        Assert.Equal(
            $"This machine's {Name} already has a working slot in this vault (slot {ShortId(own)} still opens it), so there is " +
            $"nothing to add. Each machine needs only one {Name} slot.",
            SlotCommand.WorkingHardwareSlotText(Name, ShortId(own)));
        Assert.Contains(UnlockCall, calls);
        Assert.DoesNotContain(EnrollCall, calls);
        AssertNothingWritten(before);
    }

    public void WorkingPasswordChipSlot_NoPasswordAtHand_Refused()
    {
        ChipVault(password: true);
        var own = OwnSlot();
        var before = Snapshot();

        var (exit, _, stderr, calls) = Observed(() => M.Run("", Add("--no-password")));

        Assert.NotEqual(0, exit);
        Assert.Contains(SlotCommand.OwnSlotNeedsPasswordText(Name, ShortId(own)), stderr);
        Assert.Equal(
            $"This machine's {Name} slot {ShortId(own)} needs the vault password to check whether it still works. It is read " +
            "at a terminal (or, with --recovery-key-stdin, on the line after the recovery key), and stdin is not a terminal " +
            "here. Run this at a terminal. Nothing was changed.",
            SlotCommand.OwnSlotNeedsPasswordText(Name, ShortId(own)));
        Assert.Empty(calls);
        AssertNothingWritten(before);
    }

    /// <summary>Flips one byte of the own slot's <c>Wrapped</c>: the hardware still answers, the unwrap fails.</summary>
    private void KillOwnSlotByItsUnwrap() => ChangeOwnSlot(s =>
    {
        var wrapped = (byte[])s.Wrapped.Clone();
        wrapped[^1] ^= 1;
        return s with { Wrapped = wrapped };
    });

    /// <summary>The <c>recover</c> flags <c>OwnSlotUncheckedText</c> names for this chip.</summary>
    public string RecoverFlags => FlagsText;

    public void DeadOwnChipSlot_AddsANewOne()
    {
        var recoveryKey = ChipVault(password: false);
        var old = OwnSlot();
        KillOwnSlotByItsUnwrap(); // the definite answer: the chip answered, the slot no longer opens

        var (exit, _, stderr) = M.Run(recoveryKey + "\n", Add("--no-password", "--recovery-key-stdin"));

        Assert.True(exit == 0, stderr);
        Assert.Contains(SlotCommand.OwnSlotDeadLine(Name, ShortId(old)), stderr);
        Assert.Equal(
            $"This machine's {Name} slot {ShortId(old)} no longer opens this vault (the {Name} answered, but its key no " +
            "longer unwraps the slot); adding a new one. The old slot is kept.",
            SlotCommand.OwnSlotDeadLine(Name, ShortId(old)));
        var keyring = M.Keyring;
        Assert.Equal(Convert.ToBase64String(keyring.Slots[^1].SlotId), M.Config.KeyringSlotId);
        Assert.Contains(keyring.Slots, s => s.SlotId.AsSpan().SequenceEqual(old.SlotId));
        M.Keys.PluggedIn = [];
        AssertNamesListsAlpha();
    }

    public void DeadPasswordOwnSlot_RecoveryKeyStdin_ReadsEachLineOnce()
    {
        var recoveryKey = ChipVault(password: true);
        var old = OwnSlot();
        KillOwnSlotByItsUnwrap();

        var (exit, _, stderr) = M.Run(recoveryKey + "\n" + Password + "\n", Add("--password", "--recovery-key-stdin"));

        Assert.True(exit == 0, stderr);
        Assert.Equal("", M.LastConsole!.In.ReadToEnd());
        Assert.Equal(1, Occurrences(stderr, TerminalPasswordProvider.PromptText)); // the password asked once
        Assert.Contains(SlotCommand.OwnSlotDeadLine(Name, ShortId(old)), stderr);
        Assert.Equal(Convert.ToBase64String(M.Keyring.Slots[^1].SlotId), M.Config.KeyringSlotId);
        Assert.Equal(SlotPasswordKind.Password, SlotPassword.Classify(M.Keyring.Slots[^1]));
        M.Keys.PluggedIn = [];
        AssertNamesListsAlpha(Password + "\n", terminal: true);
    }

    public void OwnSlotCheck_HardwareError_Refused_NothingWritten()
    {
        ChipVault(password: false);
        ChangeOwnSlot(s => s with { HwBlob = s.HwBlob![..^2] }); // truncated (one byte off is the old, flagless length): not a definite answer
        var own = OwnSlot();
        var before = Snapshot();
        var error = $"Config is corrupted: the simulated '{_backend.DisplayName}' blob has the wrong length. " +
                    "Restore config.json from backup or re-run 'tswap init'.";

        var (exit, _, stderr, calls) = Observed(() => M.Run("", Add("--no-password")));

        Assert.NotEqual(0, exit);
        Assert.Contains(SlotCommand.OwnSlotUncheckedText(error, Name, ShortId(own), RecoverFlags), stderr);
        Assert.Equal(
            $"{error} This machine's {Name} slot {ShortId(own)} couldn't be checked, so no new slot is added. If this " +
            $"machine's {Name} was cleared or replaced, sudo tswap recover {RecoverFlags} --recovery-key-stdin makes it this " +
            "machine's own slot again. Nothing was changed.",
            SlotCommand.OwnSlotUncheckedText(error, Name, ShortId(own), RecoverFlags));
        Assert.DoesNotContain(EnrollCall, calls);
        AssertNothingWritten(before);
    }

    /// <summary>
    /// Orchestrator ruling (T24): a chip that no longer loads its object (cleared, replaced) throws, and a thrown error
    /// is never a definite "dead": refused, naming recover.
    /// </summary>
    public void ClearedChip_Refused_NamesRecover()
    {
        var recoveryKey = ChipVault(password: false);
        var own = OwnSlot();
        Chip = RandomNumberGenerator.GetBytes(32); // the chip was cleared: its old object no longer opens
        var before = Snapshot();

        var (exit, _, stderr, calls) = Observed(() => M.Run(recoveryKey + "\n", Add("--no-password", "--recovery-key-stdin")));

        Assert.NotEqual(0, exit);
        Assert.Contains($"This machine's {Name} slot {ShortId(own)} couldn't be checked, so no new slot is added.", stderr);
        Assert.Contains($"sudo tswap recover {RecoverFlags} --recovery-key-stdin", stderr);
        Assert.Contains(UnlockCall, calls);
        Assert.DoesNotContain(EnrollCall, calls);
        AssertNothingWritten(before);
    }

    public void LegacyPairOwnSlot_Refused()
    {
        File.WriteAllText(M.ConfigPath, KeyringV3PairFixtureTests.FixtureConfigJson);
        File.WriteAllBytes(M.SecretsPath, Convert.FromBase64String(KeyringV3PairFixtureTests.FixtureSecretsFileBase64));
        M.Keys.PluggedIn = [SerialA];
        M.Ok("", "migrate", "--to-records"); // or the classic-vault refusal comes first
        var before = Snapshot();

        var (exit, _, stderr, calls) = Observed(() => M.Run("", Add("--no-password")));

        Assert.NotEqual(0, exit);
        var expected =
            $"This machine's own slot is a legacy YubiKey pair slot, which opens only through this machine's config. Making " +
            $"the {Name} this machine's slot would stop the pair opening the vault here, so nothing was changed. Give each " +
            "YubiKey its own slot first (sudo tswap slot add --yubikey, once per key), then make the " +
            $"{Name} this machine's own slot with the recovery key: sudo tswap recover {FlagsText} --recovery-key-stdin.";
        Assert.Equal(expected, SlotCommand.LegacyPairOwnSlotText(Name, FlagsText));
        Assert.Contains(expected, stderr);
        Assert.Empty(calls);
        AssertNothingWritten(before);
    }

    public void NoWayIn_Refused_NothingWritten()
    {
        YubiKeyVault();
        M.Keys.PluggedIn = [];
        var before = Snapshot();

        var (exit, _, stderr, calls) = Observed(() => M.Run("", Add("--no-password")));

        Assert.NotEqual(0, exit);
        Assert.DoesNotContain("Usage:", stderr); // refused by the unlock, not by the arguments
        Assert.Contains("YubiKey", stderr);
        Assert.DoesNotContain(EnrollCall, calls);
        AssertNothingWritten(before);
    }

    public void ClassicVault_Refused()
    {
        ClassicVaultTestSupport.CreateTestModeVault(M.Dir, RandomNumberGenerator.GetBytes(32));
        var before = M.ConfigText;

        var (exit, _, stderr) = M.Run("", Add("--no-password"));

        Assert.NotEqual(0, exit);
        Assert.Contains("classic single-file vault", stderr);
        Assert.Contains("migrate --to-records", stderr);
        Assert.Equal(before, M.ConfigText);
        Assert.Empty(M.Backups);
    }

    public void WithoutSudo_Refused()
    {
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged (see SlotCommandTests)

        YubiKeyVault();
        var before = Snapshot();
        M.Sudo = false;
        M.Keys.Challenges.Clear();

        var (exit, _, stderr, calls) = Observed(() => M.Run("", Add("--no-password")));

        Assert.NotEqual(0, exit);
        Assert.Contains("slot add", stderr);
        Assert.Contains("requires", stderr);
        Assert.Empty(calls);
        Assert.Empty(M.Keys.Challenges);
        AssertNothingWritten(before);
    }

    public void RecoveryKeyStdin_Works()
    {
        var recoveryKey = YubiKeyVault();
        M.Keys.PluggedIn = []; // no way in but the recovery key

        var (exit, _, stderr) = M.Run(recoveryKey + "\n", Add("--no-password", "--recovery-key-stdin"));

        Assert.True(exit == 0, stderr);
        Assert.Equal(_backend, M.Config.Backend);
        AssertNamesListsAlpha();
    }
}
