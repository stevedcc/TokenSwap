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

    /// <summary>Brief T28: T27's flow is <c>--batch</c> now (the sanctioned input change: every T27 test runs it).</summary>
    private (int Exit, string Out, string Err) Enroll(string stdin, params string[] flags) =>
        _joiner.Run(stdin, ["slot", "enroll", "--via", Via, "--batch", .. flags]);

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

    // ------------------------------------------------------------------ brief T28: the interactive default

    /// <summary>The interactive mode's double: <c>tswap</c> on batch-form calls, <c>sudo tswap</c> on the interactive steps.</summary>
    private LoopbackSshTransport InteractiveSsh(FleetMachine? host = null, string program = "tswap", bool noSudo = false) =>
        new(host ?? _host, program) { InteractivePrefix = noSudo ? [program] : ["sudo", program], BareCallsPrivileged = noSudo };

    /// <summary>Enrols with the joiner's stdin and stdout a terminal (no <c>--batch</c>).</summary>
    private (int Exit, string Out, string Err) EnrollOnTerminal(string stdin, params string[] flags) =>
        _joiner.RunOnTerminal(stdin, ["slot", "enroll", "--via", Via, .. flags]);

    private static string Sha256Hex(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static string ShortIdOf(string slotIdBase64) => Convert.ToHexStringLower(Convert.FromBase64String(slotIdBase64))[..8];

    private static string StagedFolderOf(FleetMachine host, string id) => host.PathOf(Path.Combine("enrol-staged", id));

    /// <summary>
    /// What the joiner's terminal answers: request's three questions on a terminal (vault password, insert the key, entropy
    /// source: each the default), then the Enter after the approve file's fingerprint.
    /// </summary>
    private const string TerminalAnswers = "\n\n\n\n";

    /// <summary>Records the SHA-256 of the local request.json / receipt.json at each interactive step (A1: what was sent).</summary>
    private (List<string> Request, List<string> Receipt) RecordLocalHashes(LoopbackSshTransport ssh)
    {
        List<string> request = [], receipt = [];
        ssh.BeforeCall = rest =>
        {
            if (rest is ["slot", "approve", "--staged", ..])
                request.Add(Sha256Hex(File.ReadAllBytes(Path.Combine(Assert.Single(EnrolFolders), "request.json"))));
            if (rest is ["slot", "merge", "--staged", ..])
                receipt.Add(Sha256Hex(File.ReadAllBytes(Path.Combine(Assert.Single(EnrolFolders), "receipt.json"))));
        };
        return (request, receipt);
    }

    [Fact]
    public void Interactive_EnrolsThroughTheStagingFolder_WithTheHostsCommandsOnATerminal()
    {
        var ssh = InteractiveSsh();
        _joiner.Ssh = ssh;
        var (requestHash, receiptHash) = RecordLocalHashes(ssh);

        var (exit, stdout, stderr) = EnrollOnTerminal(TerminalAnswers);

        Assert.True(exit == 0, stderr + stdout);
        AssertEnrolled(stdout, $"YubiKey {SerialB}");
        AssertJoinerReadsTheHostsSecret();
        var id = ShortIdOf(_joiner.Config.KeyringSlotId!);
        Assert.Equal([
            "tswap --version",
            $"tswap slot stage {id} put request",
            $"interactive: sudo tswap slot approve --staged {id} --expect {Assert.Single(requestHash)}",
            $"tswap slot stage {id} get approve",
            $"tswap slot stage {id} put receipt",
            $"interactive: sudo tswap slot merge --staged {id} --expect {Assert.Single(receiptHash)}",
            $"tswap slot stage {id} clean",
            $"end {Via}",
        ], ssh.Log);
        Assert.DoesNotContain(ssh.Calls, c => c.Args.Contains("-n") || c.Args.Contains("--yes"));
        Assert.False(Directory.Exists(StagedFolderOf(_host, id)));
        Assert.Null(_host.Config.ApprovedSlots);
    }

    [Fact]
    public void Interactive_TheTwoApproveFingerprintLines_Agree()
    {
        var ssh = InteractiveSsh();
        _joiner.Ssh = ssh;

        var (exit, stdout, stderr) = EnrollOnTerminal(TerminalAnswers);

        Assert.True(exit == 0, stderr + stdout);
        var hostLine = Assert.Single(ssh.InteractiveOutput.ToString().Split('\n'), l => l.StartsWith("Approve file fingerprint: ")).TrimEnd('\r');
        var fingerprint = hostLine["Approve file fingerprint: ".Length..];
        Assert.Matches("^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$", fingerprint);
        var id = ShortIdOf(_joiner.Config.KeyringSlotId!);
        Assert.Contains(
            $"Approve file received: {fingerprint}. It must match the approve file fingerprint the host printed above; if it doesn't, " +
            $"press Ctrl-C now (the host's staging folder is then left; remove it with 'tswap slot stage {id} clean').", stdout);
    }

    [Fact]
    public void Interactive_AnApproveFileSwappedOnTheHost_ShowsAnotherFingerprint_AndEofAtTheEnterKeepsTheRequest()
    {
        // A3: a same-user process on the host swaps approve.json between approve and get, for a valid approve file of its own.
        var other = new FleetMachine("enroll-other", SimulatedYubiKeyService.WithKeys(SerialC));
        _others.Add(other);
        other.Ok("", "slot", "request", other.PathOf("request.json"));
        var crafted = _host.Ok("", "slot", "approve", other.PathOf("request.json"), "-");
        _host.StagedSeams = new TswapCli.Commands.StagedFileSeams { AfterApproveWritten = path => File.WriteAllText(path, crafted) };
        var ssh = InteractiveSsh();
        _joiner.Ssh = ssh;
        var hostKeyring = HostKeyringBytes();

        var (exit, stdout, stderr) = EnrollOnTerminal("\n\n\n"); // request's answers; then EOF at the Enter

        Assert.NotEqual(0, exit);
        var hostLine = Assert.Single(ssh.InteractiveOutput.ToString().Split('\n'), l => l.StartsWith("Approve file fingerprint: ")).TrimEnd('\r');
        var received = TswapCli.Commands.SlotCommand.ApproveFileFingerprint(Encoding.UTF8.GetBytes(crafted));
        Assert.Contains($"Approve file received: {received}.", stdout);
        Assert.NotEqual($"Approve file fingerprint: {received}", hostLine);
        // Left as T27's approve-failed state: the pending request and its request file, no approve file, the host unchanged.
        var folder = Assert.Single(EnrolFolders);
        Assert.True(File.Exists(Path.Combine(folder, "request.json")));
        Assert.False(File.Exists(Path.Combine(folder, "approve.json")));
        Assert.NotNull(_joiner.Config.PendingSlotId);
        Assert.Equal(hostKeyring, HostKeyringBytes());
        var id = Path.GetFileName(folder);
        Assert.Contains($"remove it with 'tswap slot stage {id} clean' there.", stderr);
        Assert.DoesNotContain(ssh.Log, l => l.Contains("merge"));
        Assert.Equal($"end {Via}", ssh.Log[^1]);
    }

    [Fact]
    public void Interactive_OnAHostWhoseVaultNeedsItsPassword_Enrols_WhereBatchFailsAtApprove()
    {
        var host = new FleetMachine("enroll-pw-host", SimulatedYubiKeyService.WithKeys(SerialA)) { Tpm = RandomNumberGenerator.GetBytes(32) };
        _others.Add(host);
        PasswordVaultTestSupport.InitTpmPasswordVault(host, Password);
        var batch = new LoopbackSshTransport(host, "sudo", "-n", "tswap");
        _joiner.Ssh = batch;

        // --batch: the host's approve can't ask for its vault password.
        var (batchExit, _, batchErr) = Enroll("");
        Assert.NotEqual(0, batchExit);
        Assert.Contains("The host didn't approve the request (exit code ", batchErr);
        Assert.Contains($"[{Via}] ", batchErr);

        // The interactive default: the host's terminal reads it (approve and merge each unlock).
        var ssh = InteractiveSsh(host);
        ssh.HostTerminalInput = Password + "\n";
        _joiner.Ssh = ssh;
        var (exit, stdout, stderr) = EnrollOnTerminal(TerminalAnswers);

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("Continuing the pending enrolment", stdout);
        var slotId = _joiner.Config.KeyringSlotId!;
        Assert.True(HasSlot(host.Keyring, slotId), "the host's keyring doesn't have the new slot");
        Assert.Equal(2, ssh.InteractiveOutput.ToString().Split("Vault password: ").Length - 1);
    }

    [Fact]
    public void Interactive_NoRemoteSudo_RunsEveryCallAsTheSshUser()
    {
        var ssh = InteractiveSsh(program: "/opt/tswap/tswap", noSudo: true);
        _joiner.Ssh = ssh;

        var (exit, stdout, stderr) = EnrollOnTerminal(TerminalAnswers, "--no-remote-sudo", "--remote-tswap", "/opt/tswap/tswap");

        Assert.True(exit == 0, stderr + stdout);
        Assert.All(ssh.Calls, c => Assert.Equal("/opt/tswap/tswap", c.Args[0]));
        Assert.Contains(ssh.Calls, c => c.Interactive && c.Args[1..3] is ["slot", "approve"]);
    }

    [Fact]
    public void Interactive_FramesEachHostStep_WithLocalLines()
    {
        var ssh = InteractiveSsh();
        _joiner.Ssh = ssh;
        List<string> before = [];
        ssh.BeforeCall = rest =>
        {
            if (rest is ["slot", "approve" or "merge", "--staged", ..])
                before.Add(_joiner.LastConsole!.OutText);
        };

        var (exit, stdout, stderr) = EnrollOnTerminal(TerminalAnswers);

        Assert.True(exit == 0, stderr + stdout);
        var id = ShortIdOf(_joiner.Config.KeyringSlotId!);
        var approveLine = $"On {Via}: sudo tswap slot approve --staged {id} --expect ";
        var mergeLine = $"On {Via}: sudo tswap slot merge --staged {id} --expect ";
        const string Tail = " (it may ask for your sudo password or the vault's unlock there).";
        Assert.Equal(2, before.Count);
        // Just before each host step, its line is the last thing printed here; the step before it has said "Back".
        var lastBeforeApprove = before[0].TrimEnd().Split('\n')[^1].TrimEnd('\r');
        Assert.StartsWith(approveLine, lastBeforeApprove);
        Assert.EndsWith(Tail, lastBeforeApprove);
        Assert.Equal(0, CountOf(before[0], "Back on this machine."));
        var lastBeforeMerge = before[1].TrimEnd().Split('\n')[^1].TrimEnd('\r');
        Assert.StartsWith(mergeLine, lastBeforeMerge);
        Assert.Equal(1, CountOf(before[1], "Back on this machine."));
        Assert.Equal(2, CountOf(stdout, "Back on this machine."));
        Assert.DoesNotContain($"[{Via}] ", stdout + stderr); // no prefix on the interactive steps
    }

    private static int CountOf(string text, string part) => text.Split(part).Length - 1;

    [Fact]
    public void Interactive_WithoutATerminal_AndWithoutBatch_IsRefusedBeforeAnything()
    {
        var (exit, stdout, stderr) = _joiner.Run("", "slot", "enroll", "--via", Via);

        Assert.Equal(1, exit);
        Assert.Contains(
            "slot enroll needs a terminal here, because the host's sudo and vault may ask for a password. In a script, add --batch " +
            "(the host then must need no password: docs/multi-machine.md#enrolling-over-ssh). Nothing was changed.", stderr);
        Assert.Empty(_ssh.Calls);
        Assert.Empty(_ssh.Ended);
        Assert.False(File.Exists(_joiner.ConfigPath));
        Assert.False(Directory.Exists(EnrolRoot));
        Assert.Equal("", stdout);
    }

    [Fact]
    public void Interactive_PreflightFails_WithItsOwnText()
    {
        var ssh = InteractiveSsh();
        ssh.Override = rest => rest is ["--version"] ? new SshResult(255, Encoding.UTF8.GetBytes(Marker)) : null;
        _joiner.Ssh = ssh;

        var (exit, stdout, stderr) = EnrollOnTerminal(TerminalAnswers);

        Assert.NotEqual(0, exit);
        Assert.Contains($"Couldn't run tswap on {Via} over SSH (`tswap --version` exited 255). Nothing was changed. Check that ssh {Via} " +
                        "works and that tswap is on the SSH session's PATH there (or give --remote-tswap its full path).", stderr);
        Assert.False(File.Exists(_joiner.ConfigPath));
        Assert.DoesNotContain(Marker, stdout + stderr);
        Assert.Equal(["tswap --version", $"end {Via}"], ssh.Log);
    }

    /// <summary>The interactive approve-failed message for <paramref name="reason"/>, as the joiner prints it.</summary>
    private string InteractiveApproveFailed(string reason, string folder, string extra = "") =>
        $"The host didn't approve the request ({reason}){extra}. This machine's pending request is kept; nothing was added on {Via}. Fix " +
        "the cause above and run the same 'tswap slot enroll' again (it continues from the kept request), or carry " +
        $"{Path.Combine(folder, "request.json")} to the host and run 'sudo tswap slot approve request.json approve.json' there, then " +
        "'tswap slot accept approve.json' here. The host's staging folder may be left; remove it with " +
        $"'tswap slot stage {Path.GetFileName(folder)} clean' there.";

    public static TheoryData<string, string> InteractiveApproveFailures => new()
    {
        { "put", "exit code 1" },
        { "approve", "exit code 1" },
        { "get-empty", "no output" },
        { "get-garbage", "its output is not an approve file" },
    };

    [Theory]
    [MemberData(nameof(InteractiveApproveFailures))]
    public void Interactive_ApproveStepFails_ThePendingRequestIsKept_AndTheCleanCommandIsNamed(string step, string reason)
    {
        var ssh = InteractiveSsh();
        ssh.Override = rest => (step, rest) switch
        {
            ("put", ["slot", "stage", _, "put", "request"]) => new SshResult(1, Encoding.UTF8.GetBytes(Marker)),
            ("get-empty", ["slot", "stage", _, "get", "approve"]) => new SshResult(0, []),
            ("get-garbage", ["slot", "stage", _, "get", "approve"]) => new SshResult(0, Encoding.UTF8.GetBytes(Marker)),
            _ => null,
        };
        ssh.InteractiveOverride = rest => step == "approve" && rest is ["slot", "approve", ..] ? 1 : null;
        _joiner.Ssh = ssh;
        var hostKeyring = HostKeyringBytes();

        var (exit, stdout, stderr) = EnrollOnTerminal(TerminalAnswers);

        Assert.NotEqual(0, exit);
        var folder = Assert.Single(EnrolFolders);
        Assert.Contains(InteractiveApproveFailed(reason, folder), stderr);
        Assert.True(File.Exists(Path.Combine(folder, "request.json")));
        Assert.False(File.Exists(Path.Combine(folder, "approve.json")));
        Assert.NotNull(_joiner.Config.PendingSlotId);
        Assert.Equal(hostKeyring, HostKeyringBytes());
        Assert.DoesNotContain(Marker, stdout + stderr);
        Assert.DoesNotContain(ssh.Log, l => l.Contains("merge") || l.Contains("receipt"));
        Assert.Equal($"end {Via}", ssh.Log[^1]);
        if (step != "put")
            Assert.True(File.Exists(Path.Combine(StagedFolderOf(_host, Path.GetFileName(folder)), "request.json"))); // left on the host
    }

    [Fact]
    public void Interactive_ARetryAfterAFailedApprove_Continues_AndEnrols()
    {
        var ssh = InteractiveSsh();
        ssh.InteractiveOverride = rest => rest is ["slot", "approve", ..] ? 1 : null;
        _joiner.Ssh = ssh;
        Assert.NotEqual(0, EnrollOnTerminal(TerminalAnswers).Exit);
        ssh.InteractiveOverride = null;

        var (exit, stdout, stderr) = EnrollOnTerminal("\n");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("Continuing the pending enrolment", stdout);
        AssertEnrolled(stdout, $"YubiKey {SerialB}");
    }

    public static TheoryData<string> InteractiveMergeFailures => new() { "put", "merge" };

    [Theory]
    [MemberData(nameof(InteractiveMergeFailures))]
    public void Interactive_MergeStepFails_ThisMachineHasItsCopy_TheReceiptIsKept(string step)
    {
        var ssh = InteractiveSsh();
        ssh.Override = rest => step == "put" && rest is ["slot", "stage", _, "put", "receipt"] ? new SshResult(1, Encoding.UTF8.GetBytes(Marker)) : null;
        ssh.InteractiveOverride = rest => step == "merge" && rest is ["slot", "merge", ..] ? 1 : null;
        _joiner.Ssh = ssh;
        var hostKeyring = HostKeyringBytes();

        var (exit, stdout, stderr) = EnrollOnTerminal(TerminalAnswers);

        Assert.NotEqual(0, exit);
        var folder = Assert.Single(EnrolFolders);
        var receipt = Path.Combine(folder, "receipt.json");
        Assert.True(File.Exists(receipt));
        Assert.Contains(
            $"This machine has its copy of the vault, but {Via} didn't add the slot (exit code 1), so the host's own keyring doesn't know " +
            $"it yet. Carry {receipt} to the host and run 'sudo tswap slot merge receipt.json' there. Running 'slot enroll' again would " +
            "start a new enrolment; the kept receipt is the way to finish this one. The host's staging folder may be left; remove it with " +
            $"'tswap slot stage {Path.GetFileName(folder)} clean' there.", stderr);
        Assert.Equal(hostKeyring, HostKeyringBytes());
        Assert.DoesNotContain(Marker, stdout + stderr);
        AssertJoinerReadsTheHostsSecret();
        Assert.DoesNotContain(ssh.Log, l => l.EndsWith(" clean"));
    }

    [Fact]
    public void Interactive_ACleanThatFails_AfterTheMerge_IsANote()
    {
        var ssh = InteractiveSsh();
        ssh.Override = rest => rest is ["slot", "stage", _, "clean"] ? new SshResult(1, []) : null;
        _joiner.Ssh = ssh;

        var (exit, stdout, stderr) = EnrollOnTerminal(TerminalAnswers);

        Assert.True(exit == 0, stderr + stdout);
        var id = ShortIdOf(_joiner.Config.KeyringSlotId!);
        Assert.Contains($"Note: couldn't remove the host's staging folder; run 'tswap slot stage {id} clean' there.", stderr);
        AssertEnrolled(stdout, $"YubiKey {SerialB}");
    }

    [Fact]
    public void Interactive_AnOlderHost_SaysWhichVersionsMet()
    {
        var ssh = InteractiveSsh();
        ssh.Override = rest => rest is ["--version"] ? new SshResult(0, Encoding.UTF8.GetBytes("tswap 0.0.1\n")) : null;
        ssh.InteractiveOverride = rest => rest is ["slot", "approve", ..] ? 1 : null;
        _joiner.Ssh = ssh;

        var (exit, _, stderr) = EnrollOnTerminal(TerminalAnswers);

        Assert.NotEqual(0, exit);
        Assert.Contains(InteractiveApproveFailed("exit code 1", Assert.Single(EnrolFolders),
            $" (the host runs tswap 0.0.1, this machine {TswapCli.Commands.VersionCommand.Current}; 'slot stage' needs this version or newer there)"),
            stderr);
    }

    [Fact]
    public void Interactive_ASameVersionHost_AddsNoVersionNote()
    {
        var ssh = InteractiveSsh();
        ssh.InteractiveOverride = rest => rest is ["slot", "approve", ..] ? 1 : null;
        _joiner.Ssh = ssh;

        var (_, _, stderr) = EnrollOnTerminal(TerminalAnswers);

        Assert.Contains(InteractiveApproveFailed("exit code 1", Assert.Single(EnrolFolders)), stderr);
        Assert.DoesNotContain("the host runs tswap", stderr);
    }

    [Fact]
    public void Batch_EndsTheSessionToo()
    {
        var (exit, stdout, stderr) = Enroll("");

        Assert.True(exit == 0, stderr + stdout);
        Assert.Equal([Via], _ssh.Ended);
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

    // ------------------------------------------------------------------ brief T28: the transport's interactive form and sharing

    private static string[] SharingOptions(string controlPath) =>
        ["-o", "ControlMaster=auto", "-o", $"ControlPath={controlPath}", "-o", "ControlPersist=60"];

    [Fact]
    public void BuildArgv_InteractiveAndBatchForms_WithTheSharingOptions()
    {
        string[] remote = ["sudo", "tswap", "slot", "approve", "--staged", "0a1b2c3d", "--expect", "ab"];

        Assert.Equal(["-t", .. SharingOptions("/run/user/1000/tswap-ssh/%C"), "--", "me@host", "sudo tswap slot approve --staged 0a1b2c3d --expect ab"],
            ProcessSshTransport.BuildArgv("me@host", remote, interactive: true, controlPath: "/run/user/1000/tswap-ssh/%C"));
        Assert.Equal(["-T", .. SharingOptions("/s/%C"), "--", "me@host", "tswap --version"],
            ProcessSshTransport.BuildArgv("me@host", ["tswap", "--version"], interactive: false, controlPath: "/s/%C"));
        Assert.Equal(["-t", "--", "me@host", "tswap --version"],
            ProcessSshTransport.BuildArgv("me@host", ["tswap", "--version"], interactive: true, controlPath: null));
    }

    /// <summary>A short folder for a socket test (<c>/tmp</c>: macOS's temp folder is too long for a socket path).</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static string ShortTempFolder()
    {
        var dir = Path.Combine("/tmp", "tswap-xdg-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return dir;
    }

    private static Func<string, string?> RuntimeDir(string? dir) => name => name == "XDG_RUNTIME_DIR" ? dir : null;

    [Fact]
    public void Sharing_OnUnix_UsesAPrivateFolderInTheRuntimeDir()
    {
        if (OperatingSystem.IsWindows())
            return; // Windows' OpenSSH has no connection sharing
        var xdg = ShortTempFolder();
        try
        {
            var transport = new ProcessSshTransport(shareConnection: true) { GetEnv = RuntimeDir(xdg) };
            var note = new StringWriter();

            var argv = transport.ArgvFor("me@host", ["tswap", "--version"], interactive: false, note);

            var socketDir = Path.Combine(xdg, "tswap-ssh");
            Assert.Equal(["-T", .. SharingOptions(Path.Combine(socketDir, "%C")), "--", "me@host", "tswap --version"], argv);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(socketDir));
            Assert.Equal("", note.ToString());
        }
        finally
        {
            Directory.Delete(xdg, true);
        }
    }

    [Fact]
    public void Sharing_WithoutARuntimeDir_UsesTheTempFolderWithTheUid()
    {
        if (OperatingSystem.IsWindows())
            return;
        var temp = ShortTempFolder();
        try
        {
            var transport = new ProcessSshTransport(shareConnection: true) { GetEnv = RuntimeDir(null), TempDirectory = temp };

            var argv = transport.ArgvFor("me@host", ["tswap"], interactive: true, TextWriter.Null);

            var socketDir = Path.Combine(temp, $"tswap-ssh-{new UnixOwnership().EffectiveUid}");
            Assert.Equal(["-t", .. SharingOptions(Path.Combine(socketDir, "%C")), "--", "me@host", "tswap"], argv);
            Assert.True(Directory.Exists(socketDir));
        }
        finally
        {
            Directory.Delete(temp, true);
        }
    }

    [Fact]
    public void Sharing_IsOff_ByDefault_AndOnWindows()
    {
        Assert.Equal(["-T", "--", "me@host", "tswap"],
            new ProcessSshTransport().ArgvFor("me@host", ["tswap"], interactive: false, TextWriter.Null));
        var windows = new ProcessSshTransport(shareConnection: true) { IsWindows = true, GetEnv = RuntimeDir("/tmp") };
        var note = new StringWriter();
        Assert.Equal(["-t", "--", "me@host", "tswap"], windows.ArgvFor("me@host", ["tswap"], interactive: true, note));
        Assert.Equal("", note.ToString());
    }

    [Fact]
    public void Sharing_IsOff_ForAFolderOfAnotherMode()
    {
        if (OperatingSystem.IsWindows())
            return;
        var xdg = ShortTempFolder();
        try
        {
            var socketDir = Path.Combine(xdg, "tswap-ssh");
            Directory.CreateDirectory(socketDir);
            File.SetUnixFileMode(socketDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
            var note = new StringWriter();

            var argv = new ProcessSshTransport(shareConnection: true) { GetEnv = RuntimeDir(xdg) }
                .ArgvFor("me@host", ["tswap"], interactive: false, note);

            Assert.Equal(["-T", "--", "me@host", "tswap"], argv);
            Assert.Equal($"Note: not sharing one SSH connection ({socketDir} is not this user's own 0700 folder); each step logs in again.",
                note.ToString().TrimEnd());
        }
        finally
        {
            Directory.Delete(xdg, true);
        }
    }

    [Fact]
    public void Sharing_IsOff_ForASymlinkedFolder()
    {
        if (OperatingSystem.IsWindows())
            return;
        var xdg = ShortTempFolder();
        try
        {
            var target = Path.Combine(xdg, "elsewhere");
            Directory.CreateDirectory(target, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.CreateSymbolicLink(Path.Combine(xdg, "tswap-ssh"), target);

            var argv = new ProcessSshTransport(shareConnection: true) { GetEnv = RuntimeDir(xdg) }
                .ArgvFor("me@host", ["tswap"], interactive: false, TextWriter.Null);

            Assert.Equal(["-T", "--", "me@host", "tswap"], argv);
        }
        finally
        {
            Directory.Delete(xdg, true);
        }
    }

    [Fact]
    public void Sharing_IsOff_WhenTheSocketPathWouldBeOver100Bytes()
    {
        if (OperatingSystem.IsWindows())
            return;
        // "<runtime dir>/tswap-ssh/%C" expanded is 101 bytes with a 50-byte runtime dir.
        var xdg = "/tmp/" + new string('x', 45);
        var note = new StringWriter();

        var argv = new ProcessSshTransport(shareConnection: true) { GetEnv = RuntimeDir(xdg) }
            .ArgvFor("me@host", ["tswap"], interactive: false, note);

        Assert.Equal(["-T", "--", "me@host", "tswap"], argv);
        Assert.Contains("would be over 100 bytes", note.ToString());
        Assert.False(Directory.Exists(xdg)); // nothing made
        // One byte shorter fits.
        var fits = "/tmp/" + new string('y', 44);
        try
        {
            Assert.Contains("-o", new ProcessSshTransport(shareConnection: true) { GetEnv = RuntimeDir(fits) }
                .ArgvFor("me@host", ["tswap"], interactive: false, TextWriter.Null));
        }
        finally
        {
            if (Directory.Exists(fits))
                Directory.Delete(fits, true);
        }
    }

    /// <summary>A stub ssh that appends each call's argv (tab-separated, one line per call) to <c>calls</c> and exits <paramref name="exit"/>.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static (string Stub, string Calls) RecordingStub(string dir, int exit)
    {
        var calls = Path.Combine(dir, "calls");
        var stub = Path.Combine(dir, "ssh");
        File.WriteAllText(stub,
            "#!/bin/sh\n" +
            $"printf '%s\\t' \"$@\" >> '{calls}'\n" +
            $"printf '\\n' >> '{calls}'\n" +
            $"exit {exit}\n");
        File.SetUnixFileMode(stub, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return (stub, calls);
    }

    private static string[][] RecordedCalls(string calls) =>
        [.. File.ReadAllLines(calls).Select(l => l.Split('\t', StringSplitOptions.None)[..^1])];

    [Fact]
    public void ProcessSshTransport_RunInteractive_RunsSshDashT_AndReturnsItsExitCode()
    {
        if (OperatingSystem.IsWindows())
            return; // the stub is a POSIX shell script
        var dir = Directory.CreateTempSubdirectory("tswap-ssh-stub-").FullName;
        try
        {
            var (stub, calls) = RecordingStub(dir, 3);

            var exit = new ProcessSshTransport(stub).RunInteractive("me@host", ["sudo", "tswap", "slot", "merge", "--staged", "0a1b2c3d"]);

            Assert.Equal(3, exit);
            Assert.Equal([["-t", "--", "me@host", "sudo tswap slot merge --staged 0a1b2c3d"]], RecordedCalls(calls));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void ProcessSshTransport_EndSession_ClosesTheSharedConnection_Once()
    {
        if (OperatingSystem.IsWindows())
            return;
        var dir = Directory.CreateTempSubdirectory("tswap-ssh-stub-").FullName;
        var xdg = ShortTempFolder();
        try
        {
            var (stub, calls) = RecordingStub(dir, 0);
            var transport = new ProcessSshTransport(stub, shareConnection: true) { GetEnv = RuntimeDir(xdg) };

            transport.Run("me@host", ["tswap", "--version"], ReadOnlyMemory<byte>.Empty, TextWriter.Null);
            transport.RunInteractive("me@host", ["sudo", "tswap", "slot", "approve"]);
            transport.EndSession("me@host");

            var socket = Path.Combine(xdg, "tswap-ssh", "%C");
            Assert.Equal([
                ["-T", .. SharingOptions(socket), "--", "me@host", "tswap --version"],
                ["-t", .. SharingOptions(socket), "--", "me@host", "sudo tswap slot approve"],
                ["-o", $"ControlPath={socket}", "-O", "exit", "--", "me@host"],
            ], RecordedCalls(calls));
        }
        finally
        {
            Directory.Delete(dir, true);
            Directory.Delete(xdg, true);
        }
    }

    [Fact]
    public void ProcessSshTransport_EndSession_WithoutSharing_RunsNothing_AndAFailingExitIsIgnored()
    {
        if (OperatingSystem.IsWindows())
            return;
        var dir = Directory.CreateTempSubdirectory("tswap-ssh-stub-").FullName;
        var xdg = ShortTempFolder();
        try
        {
            var (stub, calls) = RecordingStub(dir, 255);
            var plain = new ProcessSshTransport(stub);
            plain.Run("me@host", ["tswap"], ReadOnlyMemory<byte>.Empty, TextWriter.Null);
            plain.EndSession("me@host");
            Assert.Single(RecordedCalls(calls));

            var shared = new ProcessSshTransport(stub, shareConnection: true) { GetEnv = RuntimeDir(xdg) };
            shared.Run("me@host", ["tswap"], ReadOnlyMemory<byte>.Empty, TextWriter.Null);
            shared.EndSession("me@host"); // exits 255: ignored
            Assert.Equal(3, RecordedCalls(calls).Length);

            // A program that can't start is ignored too.
            var missing = new ProcessSshTransport(Path.Combine(dir, "no-such-ssh"), shareConnection: true) { GetEnv = RuntimeDir(xdg) };
            missing.SocketDirectory(TextWriter.Null);
            missing.EndSession("me@host");
        }
        finally
        {
            Directory.Delete(dir, true);
            Directory.Delete(xdg, true);
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
/// runs the rest in process on <see cref="_host"/> (its config folder and keys) with the given stdin, relays its stderr
/// through <see cref="SshRelay"/> and returns its exit code and stdout. <c>--version</c> runs <c>version</c>. Records
/// every call; <see cref="Override"/> answers a call instead of the host.
/// <para>Brief T28: <see cref="Run"/> calls must carry exactly the constructor's prefix (<c>sudo -n tswap</c> for
/// <c>--batch</c>, <c>tswap</c> for the interactive mode's pre-flight and <c>slot stage</c> calls), and
/// <see cref="RunInteractive"/> calls exactly <see cref="InteractivePrefix"/> (<c>sudo tswap</c>). The host's sudo comes
/// from each call's prefix (A14): a <c>sudo</c> prefix is the sudo bypass and a sudo escalation (as <c>SUDO_USER</c>
/// is set there); a bare one is neither, unless <see cref="BareCallsPrivileged"/> (a root login, <c>--no-remote-sudo</c>).
/// An interactive call runs on a terminal-like console fed <see cref="HostTerminalInput"/>, its output recorded in
/// <see cref="InteractiveOutput"/> (on a real <c>ssh -t</c> it would be on the local terminal).</para>
/// </summary>
internal sealed class LoopbackSshTransport(FleetMachine host, params string[] prefix) : ISshTransport
{
    private readonly FleetMachine _host = host;
    private bool? _bareCallsPrivileged;

    public List<(string Destination, string[] Args, bool Interactive)> Calls { get; } = [];

    /// <summary>Brief T28: every call in order (interactive ones as <c>interactive: ...</c>) and each <c>end &lt;destination&gt;</c>.</summary>
    public List<string> Log { get; } = [];

    /// <summary>Given the arguments after the prefix: a result to return instead of running them, or null.</summary>
    public Func<string[], SshResult?>? Override { get; set; }

    /// <summary>Brief T28: given an interactive call's arguments after its prefix, an exit code instead of running it, or null.</summary>
    public Func<string[], int?>? InteractiveOverride { get; set; }

    /// <summary>Called with the arguments after the prefix before each call is answered.</summary>
    public Action<string[]>? BeforeCall { get; set; }

    /// <summary>Brief T28: the prefix interactive calls must carry (null: no interactive call expected).</summary>
    public string[]? InteractivePrefix { get; set; }

    /// <summary>
    /// Brief T28: whether a call without <c>sudo</c> runs privileged (sudo bypass, no escalation). Default: when no
    /// expected prefix has <c>sudo</c> (<c>--no-remote-sudo</c>: an elevated Windows session or a root login).
    /// </summary>
    public bool BareCallsPrivileged
    {
        get => _bareCallsPrivileged ?? (!prefix.Contains("sudo") && InteractivePrefix?.Contains("sudo") != true);
        set => _bareCallsPrivileged = value;
    }

    /// <summary>Brief T28: what the host's terminal reads in an interactive call (its vault password, say).</summary>
    public string HostTerminalInput { get; set; } = "";

    /// <summary>Brief T28: the host's output of every interactive call, stdout then stderr.</summary>
    public System.Text.StringBuilder InteractiveOutput { get; } = new();

    /// <summary>Brief T28: the ends of a session (<see cref="ISshTransport.EndSession"/>), by destination.</summary>
    public List<string> Ended { get; } = [];

    public SshResult Run(string destination, IReadOnlyList<string> remoteArgs, ReadOnlyMemory<byte> stdin, TextWriter stderr)
    {
        Calls.Add((destination, [.. remoteArgs], false));
        Log.Add(string.Join(' ', remoteArgs));
        Assert.Equal(prefix, remoteArgs.Take(prefix.Length));
        var rest = remoteArgs.Skip(prefix.Length).ToArray();
        BeforeCall?.Invoke(rest);
        if (Override?.Invoke(rest) is { } answer)
            return answer;
        string[] args = rest is ["--version"] ? ["version"] : rest;
        return AsHost(prefix, () =>
        {
            var (exit, stdout, err) = _host.Run(Encoding.UTF8.GetString(stdin.Span), args);
            SshRelay.WriteLines(stderr, destination, err);
            return new SshResult(exit, Encoding.UTF8.GetBytes(stdout));
        });
    }

    public int RunInteractive(string destination, IReadOnlyList<string> remoteArgs)
    {
        Calls.Add((destination, [.. remoteArgs], true));
        Log.Add("interactive: " + string.Join(' ', remoteArgs));
        Assert.NotNull(InteractivePrefix);
        Assert.Equal(InteractivePrefix, remoteArgs.Take(InteractivePrefix.Length));
        var rest = remoteArgs.Skip(InteractivePrefix.Length).ToArray();
        BeforeCall?.Invoke(rest);
        if (InteractiveOverride?.Invoke(rest) is { } code)
            return code;
        return AsHost(InteractivePrefix, () =>
        {
            var (exit, stdout, err) = _host.RunOnTerminal(HostTerminalInput, rest);
            InteractiveOutput.Append(stdout).Append(err);
            return exit;
        });
    }

    public void EndSession(string destination)
    {
        Ended.Add(destination);
        Log.Add("end " + destination);
    }

    /// <summary>Runs <paramref name="action"/> with the host's sudo as <paramref name="callPrefix"/> gives it (A14).</summary>
    private T AsHost<T>(string[] callPrefix, Func<T> action)
    {
        var (sudo, escalated) = (_host.Sudo, _host.SudoEscalated);
        var elevated = callPrefix.Contains("sudo");
        _host.Sudo = elevated || BareCallsPrivileged;
        _host.SudoEscalated = elevated;
        try
        {
            return action();
        }
        finally
        {
            (_host.Sudo, _host.SudoEscalated) = (sudo, escalated);
        }
    }
}
