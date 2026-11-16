using System.Security.Cryptography;
using System.Text;
using TswapCli;
using TswapCli.Ssh;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T27 task 2: <c>slot enroll --via &lt;destination&gt;</c>, the four enrolment steps with approve and merge carried
/// over SSH. The joining machine (<see cref="_joiner"/>, YubiKey B) and the host (<see cref="_host"/>, a vault opened by
/// YubiKey A) each have their own config folder and keys; <see cref="LoopbackSshTransport"/> runs the host's side in
/// process, as <c>sudo -n tswap ...</c> would there.
/// </summary>
public class SlotEnrollTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;
    private const int SerialC = 33333333;
    private const string Via = "me@host";
    private const string HostSecret = "host-value-0123";
    private const string Password = "correct horse battery staple";
    /// <summary>What a failing double prints on stdout: it must never reach the local output.</summary>
    private const string Marker = "REMOTE-STDOUT-MARKER-7f3a";

    private readonly FleetMachine _host;
    private readonly FleetMachine _joiner;
    private readonly List<FleetMachine> _others = [];
    private readonly LoopbackSshTransport _ssh;
    private readonly string _hostInitOutput;

    public SlotEnrollTests()
    {
        _host = new FleetMachine("enroll-host", SimulatedYubiKeyService.WithKeys(SerialA));
        _hostInitOutput = _host.Ok("", "init", "--yubikey");
        _host.Ok(HostSecret, "ingest", "on-host");
        _joiner = new FleetMachine("enroll-joiner", SimulatedYubiKeyService.WithKeys(SerialB));
        _ssh = new LoopbackSshTransport(_host, "sudo", "-n", "tswap");
        _joiner.Ssh = _ssh;
    }

    public void Dispose()
    {
        _host.Dispose();
        _joiner.Dispose();
        foreach (var m in _others)
            m.Dispose();
    }

    private string EnrolRoot => _joiner.PathOf("enrol");

    private string[] EnrolFolders => Directory.Exists(EnrolRoot) ? Directory.GetDirectories(EnrolRoot) : [];

    private byte[] HostKeyringBytes() => File.ReadAllBytes(Path.Combine(_host.VaultDir!, "keyring"));

    private string[] CallLines => [.. _ssh.Calls.Select(c => string.Join(' ', c.Args))];

    private (int Exit, string Out, string Err) Enroll(string stdin, params string[] flags) =>
        _joiner.Run(stdin, ["slot", "enroll", "--via", Via, .. flags]);

    /// <summary>The joiner's own copy opens with the vault key: the host's records, copied as a sync would, read back.</summary>
    private void AssertJoinerReadsTheHostsSecret()
    {
        Directory.CreateDirectory(_joiner.RecordsDir);
        foreach (var record in _host.RecordFiles)
            File.Copy(Path.Combine(_host.RecordsDir, record), Path.Combine(_joiner.RecordsDir, record), overwrite: true);
        Assert.Equal(HostSecret, _joiner.Get("on-host"));
    }

    private static bool HasSlot(Keyring keyring, string slotIdBase64) =>
        keyring.Slots.Any(s => Convert.ToBase64String(s.SlotId) == slotIdBase64);

    private void AssertEnrolled(string output, string device)
    {
        var config = _joiner.Config;
        Assert.Null(config.PendingSlotId);
        Assert.True(HasSlot(_host.Keyring, config.KeyringSlotId!), "the host's keyring doesn't have the new slot");
        var publicKey = _joiner.Keyring.Slots.Single(s => Convert.ToBase64String(s.SlotId) == config.KeyringSlotId).PublicKey;
        Assert.Contains($"This machine's slot: {SlotFingerprint.Compute(publicKey)}", output);
        Assert.Contains($"✓ Enrolled: {Via}'s vault now opens with {device}, and this machine has its copy.", output);
        Assert.Empty(EnrolFolders);
    }

    // ------------------------------------------------------------------ happy paths

    [Fact]
    public void YubiKey_EnrolsOverSsh_BothMachinesKnowTheSlot()
    {
        var (exit, stdout, stderr) = Enroll("");

        Assert.True(exit == 0, stderr + stdout);
        AssertEnrolled(stdout, $"YubiKey {SerialB}");
        AssertJoinerReadsTheHostsSecret();
        Assert.Equal(["sudo -n tswap --version", "sudo -n tswap slot approve - -", "sudo -n tswap slot merge -"], CallLines);
        Assert.All(_ssh.Calls, c => Assert.Equal(Via, c.Destination));
        Assert.DoesNotContain(_ssh.Calls, c => c.Args.Contains("--yes"));
        Assert.Null(_host.Config.ApprovedSlots); // the approval was used by the merge
    }

    [Fact]
    public void Tpm_EnrolsOverSsh()
    {
        _joiner.Tpm = RandomNumberGenerator.GetBytes(32);

        var (exit, stdout, stderr) = Enroll("", "--tpm");

        Assert.True(exit == 0, stderr + stdout);
        AssertEnrolled(stdout, "this machine's TPM");
        Assert.Equal(HardwareBackend.Tpm, _joiner.Config.Backend);
        AssertJoinerReadsTheHostsSecret();
    }

    [Fact]
    public void VaultDirWithoutPassword_JoinsTheSharedFolder()
    {
        var folder = _host.VaultDir!;

        var (exit, stdout, stderr) = Enroll("", "--vault-dir", folder);

        // slot request refuses --vault-dir without --password, so success shows the request didn't get it.
        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(Path.GetFullPath(folder), _joiner.Config.VaultDir);
        AssertEnrolled(stdout, $"YubiKey {SerialB}");
        Assert.Equal(HostSecret, _joiner.Get("on-host")); // the records in the shared folder, read with key B
        Assert.Equal(3, _ssh.Calls.Count);
    }

    [Fact]
    public void PasswordAndVaultDir_BothStepsGetTheFolder()
    {
        // The host opens with its password-free YubiKey slot; its folder has a vault-password file.
        var vaultKey = RecordVaultTestSupport.VaultKey(_host, RecordVaultTestSupport.RecoveryKeyFrom(_hostInitOutput));
        var salt = RandomNumberGenerator.GetBytes(VaultPasswordKdf.SaltSize);
        using (var stretched = VaultPasswordKdf.Stretch(Password, salt, PasswordVaultTestSupport.Cheap))
            new RecordVaultStore(_host.Dir).WriteVaultPassword(
                VaultPasswordFile.Create(vaultKey, _host.Keyring.VaultId, stretched, salt, PasswordVaultTestSupport.Cheap));
        var folder = _host.VaultDir!;

        // stdin: request's entropy question (default), then accept's vault password.
        var (exit, stdout, stderr) = Enroll("\n" + Password + "\n", "--password", "--vault-dir", folder);

        Assert.True(exit == 0, stderr + stdout);
        AssertEnrolled(stdout, $"YubiKey {SerialB}");
        Assert.Equal(Path.GetFullPath(folder), _joiner.Config.VaultDir);
        var newSlot = _host.Keyring.Slots.Single(s => Convert.ToBase64String(s.SlotId) == _joiner.Config.KeyringSlotId);
        Assert.Equal(SlotPasswordKind.Password, SlotPassword.Classify(newSlot));
        var (getExit, getOut, getErr) = _joiner.RunOnTerminal(Password + "\n", "get", "on-host");
        Assert.True(getExit == 0, getErr);
        Assert.Equal(HostSecret, getOut.Trim());
    }

    [Fact]
    public void NoRemoteSudo_DropsSudo()
    {
        _joiner.Ssh = new LoopbackSshTransport(_host, "tswap");
        var ssh = (LoopbackSshTransport)_joiner.Ssh;

        var (exit, stdout, stderr) = Enroll("", "--no-remote-sudo");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(["tswap --version", "tswap slot approve - -", "tswap slot merge -"],
            ssh.Calls.Select(c => string.Join(' ', c.Args)));
    }

    [Fact]
    public void RemoteTswap_NamesTheProgramOnTheHost()
    {
        _joiner.Ssh = new LoopbackSshTransport(_host, "sudo", "-n", "/opt/tswap/tswap");
        var ssh = (LoopbackSshTransport)_joiner.Ssh;

        var (exit, stdout, stderr) = Enroll("", "--remote-tswap", "/opt/tswap/tswap");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal(["sudo -n /opt/tswap/tswap --version", "sudo -n /opt/tswap/tswap slot approve - -", "sudo -n /opt/tswap/tswap slot merge -"],
            ssh.Calls.Select(c => string.Join(' ', c.Args)));
    }

    [Fact]
    public void TheHostsLines_ArriveLabelled()
    {
        var (exit, stdout, stderr) = Enroll("");

        Assert.True(exit == 0, stderr + stdout);
        var publicKey = _joiner.Keyring.Slots.Single(s => Convert.ToBase64String(s.SlotId) == _joiner.Config.KeyringSlotId).PublicKey;
        // approve's human lines (stderr on the host) and merge's output (stdout on the host).
        Assert.Contains($"[{Via}] Requesting machine's slot fingerprint: {SlotFingerprint.Compute(publicKey)}", stderr);
        Assert.Contains($"[{Via}] ✓ Approved. Approve file written to stdout.", stderr);
        Assert.Contains($"[{Via}] Adding approved slot: slot ", stdout);
    }

    // ------------------------------------------------------------------ machine states

    [Fact]
    public void ACompleteConfig_AndNoToTheOverwriteQuestion_ChangesNothing()
    {
        _joiner.Ok("", "init", "--yubikey");
        var config = _joiner.ConfigText;

        var (exit, stdout, stderr) = Enroll("no\n");

        Assert.Equal(1, exit);
        Assert.Contains("This machine already has a config. Overwrite and start a new slot request?", stdout);
        Assert.Contains("Nothing was changed.", stderr);
        Assert.Equal(["sudo -n tswap --version"], CallLines);
        Assert.Equal(config, _joiner.ConfigText);
        Assert.Empty(EnrolFolders);
    }

    [Fact]
    public void AHandMadePendingRequest_IsRefused_WithoutAnSshCall()
    {
        _joiner.Ok("", "slot", "request", _joiner.PathOf("by-hand.json"));
        var config = _joiner.ConfigText;

        var (exit, _, stderr) = Enroll("");

        Assert.NotEqual(0, exit);
        Assert.Contains(
            "This machine has a pending slot request that 'slot enroll' has no files for. If you still have its request file, " +
            "finish it by hand (slot approve on the vault's machine, then slot accept here); otherwise, or to start over, run " +
            "'tswap slot enroll ... --fresh'.", stderr);
        Assert.Empty(_ssh.Calls);
        Assert.Equal(config, _joiner.ConfigText);
    }

    [Fact]
    public void AHandMadePendingRequest_WithFreshAndYes_EnrolsANewSlot()
    {
        _joiner.Ok("", "slot", "request", _joiner.PathOf("by-hand.json"));
        var handMade = _joiner.Config.PendingSlotId;

        var (exit, stdout, stderr) = Enroll("yes\n", "--fresh");

        Assert.True(exit == 0, stderr + stdout);
        Assert.NotEqual(handMade, _joiner.Config.KeyringSlotId);
        AssertEnrolled(stdout, $"YubiKey {SerialB}");
    }

    /// <summary>A first enroll whose approve the host refuses (exit 1): the pending request and its folder are kept.</summary>
    private string FailedApprove()
    {
        _ssh.Override = rest => rest is ["slot", "approve", ..] ? new SshResult(1, []) : null;
        var (exit, _, _) = Enroll("");
        Assert.NotEqual(0, exit);
        _ssh.Override = null;
        _ssh.Calls.Clear();
        return Assert.Single(EnrolFolders);
    }

    [Fact]
    public void ContinuingAYubiKeyRequest_WithTpm_IsRefused_WithoutAnSshCall()
    {
        FailedApprove();
        var config = _joiner.ConfigText;
        _joiner.Tpm = RandomNumberGenerator.GetBytes(32);

        var (exit, _, stderr) = Enroll("", "--tpm");

        Assert.NotEqual(0, exit);
        Assert.Contains($"This machine's pending enrolment is for YubiKey {SerialB}, without the vault password, not what this command " +
                        "names. Run the same command without those flags to continue it, or add --fresh to start over.", stderr);
        Assert.Empty(_ssh.Calls);
        Assert.Equal(config, _joiner.ConfigText);
    }

    [Fact]
    public void ContinuingAPasswordFreeRequest_WithPassword_IsRefused()
    {
        FailedApprove();

        var (exit, _, stderr) = Enroll("", "--password");

        Assert.NotEqual(0, exit);
        Assert.Contains("This machine's pending enrolment is for", stderr);
        Assert.Empty(_ssh.Calls);
    }

    [Fact]
    public void ARetryAfterAFailedApprove_ContinuesFromTheKeptRequest()
    {
        var folder = FailedApprove();
        var pending = _joiner.Config.PendingSlotId;

        var (exit, stdout, stderr) = Enroll("");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains($"Continuing the pending enrolment of YubiKey {SerialB} kept in {folder} (run with --fresh to start over).", stdout);
        Assert.Equal(pending, _joiner.Config.KeyringSlotId);
        AssertEnrolled(stdout, $"YubiKey {SerialB}");
        // One enrolment: request challenged key B once, and every challenge since was the same one (accept re-derives).
        Assert.Single(_joiner.Keys.Challenges.Where(c => c.Serial == SerialB).Select(c => c.Challenge).Distinct());
        Assert.DoesNotContain("Overwrite", stdout);
    }

    [Fact]
    public void Fresh_AsksTheOverwriteQuestion_AndDeletesTheOldFolderOnlyAfterTheNewRequest()
    {
        var old = FailedApprove();

        var (exit, stdout, stderr) = Enroll("yes\n", "--fresh");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("This machine already has a config. Overwrite and start a new slot request?", stdout);
        Assert.False(Directory.Exists(old));
        AssertEnrolled(stdout, $"YubiKey {SerialB}");
    }

    [Fact]
    public void Fresh_AndNo_ChangesNothing_FoldersIncluded()
    {
        var old = FailedApprove();
        var config = _joiner.ConfigText;

        var (exit, _, stderr) = Enroll("no\n", "--fresh");

        Assert.Equal(1, exit);
        Assert.Contains("Nothing was changed.", stderr);
        Assert.True(File.Exists(Path.Combine(old, "request.json")));
        Assert.Equal(config, _joiner.ConfigText);
    }

    // ------------------------------------------------------------------ step 2 fails after its save

    [Fact]
    public void RequestFileNotWritten_AfterTheSave_WithoutAnEarlierConfig()
    {
        File.WriteAllText(EnrolRoot, "not a folder"); // the enrolment folder can't be made: the request file isn't written

        var (exit, stdout, stderr) = Enroll("");

        Assert.NotEqual(0, exit);
        Assert.Contains("The pending request was saved but its request file was not written (", stderr);
        Assert.Contains("). Run 'tswap slot enroll ... --fresh' to start over, or 'tswap slot request <file>' by hand.", stderr);
        Assert.DoesNotContain("backed up", stderr);
        Assert.DoesNotContain("Nothing was changed", stdout + stderr);
        Assert.NotNull(_joiner.Config.PendingSlotId);
        Assert.Equal(["sudo -n tswap --version"], CallLines);
    }

    [Fact]
    public void RequestFileNotWritten_AfterTheSave_NamesTheBackupOfAnEarlierConfig()
    {
        _joiner.Ok("", "init", "--yubikey");
        File.WriteAllText(EnrolRoot, "not a folder");

        var (exit, stdout, stderr) = Enroll("yes\n");

        Assert.NotEqual(0, exit);
        var backup = Assert.Single(_joiner.Backups);
        Assert.Contains($"; the previous config was backed up to {backup}. Run 'tswap slot enroll ... --fresh' to start over", stderr);
        Assert.DoesNotContain("Nothing was changed", stdout + stderr);
        Assert.NotNull(_joiner.Config.PendingSlotId);
    }

    // ------------------------------------------------------------------ accept's receipt write fails

    /// <summary>Makes the receipt path a folder once the enrolment folder exists (at the approve call).</summary>
    private void ReceiptPathIsAFolder() =>
        _ssh.BeforeCall = rest =>
        {
            if (rest is ["slot", "approve", ..])
                Directory.CreateDirectory(Path.Combine(Assert.Single(EnrolFolders), "receipt.json"));
        };

    [Fact]
    public void ReceiptNotWritten_OwnCopy_SaysTheHostDoesntKnowTheSlot()
    {
        ReceiptPathIsAFolder();
        var hostKeyring = HostKeyringBytes();

        var (exit, _, stderr) = Enroll("");

        Assert.NotEqual(0, exit);
        Assert.Contains($"This machine has joined the vault but no receipt was written, so {Via} doesn't know the slot. Run 'tswap " +
                        "slot enroll ... --fresh' for a new enrolment (the simplest way), or have the host merge this machine's vault " +
                        "folder with 'sudo tswap vault merge <folder>' (that needs sudo beyond the three-command rule).", stderr);
        Assert.Null(_joiner.Config.PendingSlotId);
        Assert.NotNull(_joiner.Config.KeyringSlotId);
        Assert.False(File.Exists(Path.Combine(Assert.Single(EnrolFolders), "receipt.json")));
        Assert.Equal(["sudo -n tswap --version", "sudo -n tswap slot approve - -"], CallLines);
        Assert.Equal(hostKeyring, HostKeyringBytes());
    }

    [Fact]
    public void ReceiptNotWritten_SharedFolder_NothingMoreIsNeeded()
    {
        ReceiptPathIsAFolder();
        var folder = Path.GetFullPath(_host.VaultDir!);

        var (exit, stdout, stderr) = Enroll("", "--vault-dir", folder);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains($"This machine has joined the shared vault folder {folder}; its keyring already has the new slot, so nothing " +
                        "more is needed (a receipt is only for a machine with its own copy).", stdout);
        Assert.Equal(["sudo -n tswap --version", "sudo -n tswap slot approve - -"], CallLines);
        Assert.True(HasSlot(_host.Keyring, _joiner.Config.KeyringSlotId!));
        Assert.Contains($"✓ Enrolled: {Via}'s vault now opens with YubiKey {SerialB}, and this machine has its copy.", stdout);
    }

    // ------------------------------------------------------------------ each step's failure

    [Fact]
    public void PreflightFails_NothingIsWritten()
    {
        _ssh.Override = rest => rest is ["--version"] ? new SshResult(255, Encoding.UTF8.GetBytes(Marker)) : null;

        var (exit, stdout, stderr) = Enroll("");

        Assert.NotEqual(0, exit);
        Assert.Contains($"Couldn't run tswap on {Via} over SSH (`sudo -n tswap --version` exited 255). Nothing was changed. Check that " +
                        $"ssh {Via} works and that the remote command runs there without a prompt " +
                        "(docs/multi-machine.md#enrolling-over-ssh); or carry the files by hand (slot request, approve, accept, merge).", stderr);
        Assert.False(File.Exists(_joiner.ConfigPath));
        Assert.False(Directory.Exists(EnrolRoot));
        Assert.DoesNotContain(Marker, stdout + stderr);
        Assert.Single(_ssh.Calls);
    }

    [Fact]
    public void PreflightWithNoOutput_IsRefused()
    {
        _ssh.Override = rest => rest is ["--version"] ? new SshResult(0, []) : null;

        var (exit, _, stderr) = Enroll("");

        Assert.NotEqual(0, exit);
        Assert.Contains($"Couldn't run tswap on {Via} over SSH (`sudo -n tswap --version` printed nothing). Nothing was changed.", stderr);
        Assert.False(File.Exists(_joiner.ConfigPath));
    }

    public static TheoryData<int, string, string> ApproveFailures => new()
    {
        { 1, Marker, "exit code 1" },
        { 0, "", "no output" },
        { 0, Marker, "its output is not an approve file" },
    };

    [Theory]
    [MemberData(nameof(ApproveFailures))]
    public void ApproveFails_ThePendingRequestIsKept_AndTheHostIsUnchanged(int code, string output, string reason)
    {
        _ssh.Override = rest => rest is ["slot", "approve", ..] ? new SshResult(code, Encoding.UTF8.GetBytes(output)) : null;
        var hostKeyring = HostKeyringBytes();

        var (exit, stdout, stderr) = Enroll("");

        Assert.NotEqual(0, exit);
        var folder = Assert.Single(EnrolFolders);
        var request = Path.Combine(folder, "request.json");
        Assert.True(File.Exists(request));
        Assert.False(File.Exists(Path.Combine(folder, "approve.json")));
        Assert.NotNull(_joiner.Config.PendingSlotId);
        Assert.Contains($"The host didn't approve the request ({reason}). This machine's pending request is kept; nothing was added on " +
                        $"{Via}. Fix the cause above and run the same 'tswap slot enroll' again (it continues from the kept request), or " +
                        $"carry {request} to the host and run 'sudo tswap slot approve - - < request.json > approve.json' there, then " +
                        "'tswap slot accept approve.json' here.", stderr);
        Assert.Equal(hostKeyring, HostKeyringBytes());
        Assert.DoesNotContain(Marker, stdout + stderr);
        Assert.Equal(["sudo -n tswap --version", "sudo -n tswap slot approve - -"], CallLines);
    }

    [Fact]
    public void ApproveFails_TheHandCommandUsesTheRemoteProgram()
    {
        _joiner.Ssh = new LoopbackSshTransport(_host, "/opt/tswap/tswap")
        {
            Override = rest => rest is ["slot", "approve", ..] ? new SshResult(1, []) : null,
        };

        var (exit, _, stderr) = Enroll("", "--no-remote-sudo", "--remote-tswap", "/opt/tswap/tswap");

        Assert.NotEqual(0, exit);
        Assert.Contains("run '/opt/tswap/tswap slot approve - - < request.json > approve.json' there", stderr);
    }

    [Fact]
    public void AcceptFails_OnAnApproveFileForAnotherRequest_ThePendingRequestSurvives()
    {
        var other = new FleetMachine("enroll-other", SimulatedYubiKeyService.WithKeys(SerialC));
        _others.Add(other);
        other.Ok("", "slot", "request", other.PathOf("request.json"));
        var otherApprove = _host.Ok("", "slot", "approve", other.PathOf("request.json"), "-");
        var hostKeyring = HostKeyringBytes();
        _ssh.Override = rest => rest is ["slot", "approve", ..] ? new SshResult(0, Encoding.UTF8.GetBytes(otherApprove)) : null;

        var (exit, _, stderr) = Enroll("");

        Assert.NotEqual(0, exit);
        var approve = Path.Combine(Assert.Single(EnrolFolders), "approve.json");
        Assert.Contains("This approve file targets a different slot id than this machine's pending request.", stderr);
        Assert.Contains($"The host approved this slot but its keyring is unchanged. After fixing that, run 'tswap slot accept {approve}' " +
                        $"here, then 'sudo tswap slot merge - < receipt.json' on {Via}.", stderr);
        Assert.NotNull(_joiner.Config.PendingSlotId);
        Assert.Equal(hostKeyring, HostKeyringBytes());
        Assert.Equal(["sudo -n tswap --version", "sudo -n tswap slot approve - -"], CallLines);
    }

    [Fact]
    public void MergeFails_ThisMachineHasItsCopy_TheReceiptIsKept()
    {
        _ssh.Override = rest => rest is ["slot", "merge", ..] ? new SshResult(1, Encoding.UTF8.GetBytes(Marker)) : null;
        var hostKeyring = HostKeyringBytes();

        var (exit, stdout, stderr) = Enroll("");

        Assert.NotEqual(0, exit);
        var receipt = Path.Combine(Assert.Single(EnrolFolders), "receipt.json");
        Assert.True(File.Exists(receipt));
        Assert.Contains($"This machine has its copy of the vault, but {Via} didn't add the slot (exit code 1), so the host's own keyring " +
                        $"doesn't know it yet. Carry {receipt} to the host and run 'sudo tswap slot merge - < receipt.json' there. " +
                        "Running 'slot enroll' again would start a new enrolment; the kept receipt is the way to finish this one.", stderr);
        Assert.Equal(hostKeyring, HostKeyringBytes());
        Assert.DoesNotContain(Marker, stdout + stderr);
        AssertJoinerReadsTheHostsSecret();
        // The kept receipt finishes it by hand.
        _host.Ok(File.ReadAllText(receipt), "slot", "merge", "-");
        Assert.True(HasSlot(_host.Keyring, _joiner.Config.KeyringSlotId!));
    }

    [Fact]
    public void ATransportFailure_IsAReason_NotACrash()
    {
        _ssh.Override = rest => rest is ["slot", "merge", ..] ? throw new SshTransportException("its output was larger than 1 MiB, so ssh was stopped") : null;

        var (exit, _, stderr) = Enroll("");

        Assert.NotEqual(0, exit);
        Assert.Contains($"didn't add the slot (its output was larger than 1 MiB, so ssh was stopped)", stderr);
    }

    // ------------------------------------------------------------------ usage

    public static TheoryData<string[]> UsageErrors => new()
    {
        new[] { "slot", "enroll", "--via", "-oProxyCommand=x" },
        new[] { "slot", "enroll", "--via", "a b" },
        new[] { "slot", "enroll", "--via", "a\tb" },
        new[] { "slot", "enroll", "--via", "a\u001bb" },
        new[] { "slot", "enroll", "--via", "" },
        new[] { "slot", "enroll", "--via", Via, "--remote-tswap", "tswap; rm" },
        new[] { "slot", "enroll", "--via", Via, "--remote-tswap", "-x" },
        new[] { "slot", "enroll", "--via", Via, "--bogus" },
        new[] { "slot", "enroll", "--via", Via, "extra" },
        new[] { "slot", "enroll", "--via", Via, "--via", Via },
        new[] { "slot", "enroll", "--via", Via, "--tpm", "--secure-enclave", "--no-touch" },
        new[] { "slot", "enroll", "--via", Via, "--secure-enclave" },
        new[] { "slot", "enroll", "--via", Via, "--vault-dir" },
        new[] { "slot", "enroll", "--via" },
        new[] { "slot", "enroll" },
    };

    [Theory]
    [MemberData(nameof(UsageErrors))]
    public void UsageErrors_RefuseBeforeAnySshCall(string[] args)
    {
        var (exit, _, stderr) = _joiner.Run("", args);

        Assert.Equal(1, exit);
        Assert.Contains("Usage: tswap slot enroll --via <user@host>", stderr);
        Assert.Empty(_ssh.Calls);
        Assert.False(File.Exists(_joiner.ConfigPath));
    }

    // ------------------------------------------------------------------ the process transport

    [Fact]
    public void BuildArgv_PutsTheDestinationAfterDoubleDash()
    {
        Assert.Equal(["-T", "--", "me@host", "sudo -n tswap slot merge -"],
            ProcessSshTransport.BuildArgv("me@host", ["sudo", "-n", "tswap", "slot", "merge", "-"]));
    }

    [Fact]
    public void ProcessSshTransport_RunsTheProgram_WithStdin_AndRelaysStderr()
    {
        if (OperatingSystem.IsWindows())
            return; // the stub is a POSIX shell script
        var dir = Directory.CreateTempSubdirectory("tswap-ssh-stub-").FullName;
        try
        {
            var argvFile = Path.Combine(dir, "argv");
            var stdinFile = Path.Combine(dir, "stdin");
            var stub = Path.Combine(dir, "ssh");
            File.WriteAllText(stub,
                "#!/bin/sh\n" +
                $"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{argvFile}'; done\n" +
                $"cat > '{stdinFile}'\n" +
                "printf ok\n" +
                "echo 'first line' >&2\n" +
                "echo 'second line' >&2\n" +
                "exit 3\n");
            File.SetUnixFileMode(stub, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var stderr = new StringWriter();

            var result = new ProcessSshTransport(stub).Run("me@host", ["sudo", "-n", "tswap", "slot", "merge", "-"],
                Encoding.UTF8.GetBytes("the receipt"), stderr);

            Assert.Equal(["-T", "--", "me@host", "sudo -n tswap slot merge -"], File.ReadAllLines(argvFile));
            Assert.Equal("the receipt", File.ReadAllText(stdinFile)); // cat ended: stdin was closed
            Assert.Equal("ok", Encoding.UTF8.GetString(result.Stdout));
            Assert.Equal(3, result.ExitCode);
            Assert.Equal(["[me@host] first line", "[me@host] second line"],
                stderr.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.TrimEnd('\r')));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void ProcessSshTransport_StopsAndRefusesPastOneMiBOfStdout()
    {
        if (OperatingSystem.IsWindows())
            return; // the stub is a POSIX shell script
        var dir = Directory.CreateTempSubdirectory("tswap-ssh-stub-").FullName;
        try
        {
            var stub = Path.Combine(dir, "ssh");
            // Endless output: only the cap's kill ends it.
            File.WriteAllText(stub, "#!/bin/sh\ncat > /dev/null\nwhile :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n'; done\n");
            File.SetUnixFileMode(stub, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            var ex = Assert.Throws<SshTransportException>(() =>
                new ProcessSshTransport(stub).Run("me@host", ["tswap", "slot", "approve", "-", "-"], Encoding.UTF8.GetBytes("req"), new StringWriter()));

            Assert.Equal("its output was larger than 1 MiB, so ssh was stopped", ex.Message);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void SshRelay_ReplacesControlCharacters()
    {
        Assert.Equal("[h] a?[31mb\tc", SshRelay.Line("h", "a\u001b[31mb\tc\r"));
    }
}

/// <summary>
/// Brief T27's SSH double: for remote arguments that start with the expected prefix (<c>sudo -n tswap</c> by default),
/// runs the rest in process on <see cref="_host"/> (its config folder and keys, sudo bypassed) with the given stdin,
/// relays its stderr through <see cref="SshRelay"/> and returns its exit code and stdout. <c>--version</c> runs
/// <c>version</c>. Records every call; <see cref="Override"/> answers a call instead of the host.
/// </summary>
internal sealed class LoopbackSshTransport(FleetMachine host, params string[] prefix) : ISshTransport
{
    private readonly FleetMachine _host = host;

    public List<(string Destination, string[] Args)> Calls { get; } = [];

    /// <summary>Given the arguments after the prefix: a result to return instead of running them, or null.</summary>
    public Func<string[], SshResult?>? Override { get; set; }

    /// <summary>Called with the arguments after the prefix before each call is answered.</summary>
    public Action<string[]>? BeforeCall { get; set; }

    public SshResult Run(string destination, IReadOnlyList<string> remoteArgs, ReadOnlyMemory<byte> stdin, TextWriter stderr)
    {
        Calls.Add((destination, [.. remoteArgs]));
        Assert.Equal(prefix, remoteArgs.Take(prefix.Length));
        var rest = remoteArgs.Skip(prefix.Length).ToArray();
        BeforeCall?.Invoke(rest);
        if (Override?.Invoke(rest) is { } answer)
            return answer;
        string[] args = rest is ["--version"] ? ["version"] : rest;
        var sudo = _host.Sudo;
        _host.Sudo = true;
        try
        {
            var (exit, stdout, err) = _host.Run(Encoding.UTF8.GetString(stdin.Span), args);
            SshRelay.WriteLines(stderr, destination, err);
            return new SshResult(exit, Encoding.UTF8.GetBytes(stdout));
        }
        finally
        {
            _host.Sudo = sudo;
        }
    }
}
