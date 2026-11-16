using System.Security.Cryptography;
using System.Text;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T28 task 1: <c>slot stage &lt;id&gt; put|get|clean</c>, the host's staging folder
/// (<c>&lt;config dir&gt;/enrol-staged/&lt;id&gt;/</c>), and <c>slot approve|merge --staged &lt;id&gt; --expect &lt;sha256&gt;</c>.
/// The joining machine (<see cref="_joiner"/>, YubiKey B) and the host (<see cref="_host"/>, a vault opened by YubiKey A)
/// each have their own config folder and keys, as in <see cref="SlotEnrollTests"/>. <c>stage</c> runs as the SSH user
/// (no sudo bypass); approve and merge run with the sudo bypass, as under <c>sudo</c>.
/// </summary>
public class SlotStageTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;
    private const int SerialC = 33333333;
    private const string Id = "0a1b2c3d";
    private const string Password = "correct horse battery staple";

    private readonly FleetMachine _host;
    private readonly FleetMachine _joiner;
    private readonly List<FleetMachine> _others = [];

    public SlotStageTests()
    {
        _host = new FleetMachine("stage-host", SimulatedYubiKeyService.WithKeys(SerialA)) { Time = new FuncTimeProvider(() => TestTime.Fixed) };
        _host.Ok("", "init", "--yubikey");
        _host.Ok("host-value-0123", "ingest", "on-host");
        _joiner = new FleetMachine("stage-joiner", SimulatedYubiKeyService.WithKeys(SerialB)) { Time = new FuncTimeProvider(() => TestTime.Fixed) };
    }

    public void Dispose()
    {
        _host.Dispose();
        _joiner.Dispose();
        foreach (var m in _others)
            m.Dispose();
    }

    private string StagedFolder(FleetMachine host, string id = Id) => host.PathOf(Path.Combine("enrol-staged", id));

    private static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static string Sha256(string text) => Sha256(Encoding.UTF8.GetBytes(text));

    /// <summary>A machine's request file (<c>slot request</c> into its own folder), as text.</summary>
    private static string RequestOf(FleetMachine machine)
    {
        var path = machine.PathOf("request.json");
        machine.Ok("", "slot", "request", path);
        return File.ReadAllText(path);
    }

    private FleetMachine Other(string name, int serial)
    {
        var other = new FleetMachine(name, SimulatedYubiKeyService.WithKeys(serial)) { Time = new FuncTimeProvider(() => TestTime.Fixed) };
        _others.Add(other);
        return other;
    }

    /// <summary>Runs <c>slot stage ...</c> on <paramref name="host"/> as the SSH user: no sudo bypass, not under sudo.</summary>
    private static (int Exit, string Out, string Err) Stage(FleetMachine host, string stdin, params string[] args)
    {
        var sudo = host.Sudo;
        host.Sudo = false;
        try
        {
            return host.Run(stdin, ["slot", "stage", .. args]);
        }
        finally
        {
            host.Sudo = sudo;
        }
    }

    private static string SlotIdOf(string requestText) => SlotEnrollmentFileCodec.DeserializeRequest(requestText).SlotId;

    private static bool IsApproved(FleetMachine host, string slotId) => host.Config.ApprovedSlots?.Any(a => a.SlotId == slotId) == true;

    private byte[] HostKeyringBytes() => File.ReadAllBytes(Path.Combine(_host.VaultDir!, "keyring"));

    /// <summary>The joiner's request staged, approved with its hash, the approve file taken back; returns its text.</summary>
    private string StagedApprove(FleetMachine joiner, string id = Id)
    {
        var request = RequestOf(joiner);
        Assert.Equal(0, Stage(_host, request, id, "put", "request").Exit);
        _host.Ok("", "slot", "approve", "--staged", id, "--expect", Sha256(request));
        var (exit, approve, err) = Stage(_host, "", id, "get", "approve");
        Assert.True(exit == 0, err);
        return approve;
    }

    /// <summary>Accepts <paramref name="approveText"/> on <paramref name="joiner"/>; returns the receipt's text.</summary>
    private static string Accept(FleetMachine joiner, string approveText)
    {
        var approve = joiner.PathOf("approve.json");
        File.WriteAllText(approve, approveText);
        joiner.Ok("", "slot", "accept", approve);
        return File.ReadAllText(approve + ".receipt.json");
    }

    // ------------------------------------------------------------------ the round trip

    [Fact]
    public void PutApproveGet_GivesOneApproveFile_ThatTheJoinerAccepts()
    {
        var request = RequestOf(_joiner);

        var (putExit, putOut, putErr) = Stage(_host, request, Id, "put", "request");
        Assert.True(putExit == 0, putErr);
        Assert.Equal("", putOut);
        Assert.Equal(Encoding.UTF8.GetBytes(request), File.ReadAllBytes(Path.Combine(StagedFolder(_host), "request.json")));

        var (exit, stdout, stderr) = _host.Run("", "slot", "approve", "--staged", Id, "--expect", Sha256(request));
        Assert.True(exit == 0, stderr + stdout);

        var (getExit, approve, getErr) = Stage(_host, "", Id, "get", "approve");
        Assert.True(getExit == 0, getErr);
        // Nothing before or after the file: parsing and re-serialising gives the very same text (untrimmed).
        Assert.Equal(SlotEnrollmentFileCodec.SerializeApprove(SlotEnrollmentFileCodec.DeserializeApprove(approve)), approve);
        Assert.True(IsApproved(_host, SlotIdOf(request)));

        // The staged closing lines (A3): the requester's fingerprint as the file form prints it, then the approve file's.
        var publicKey = Convert.FromBase64String(SlotEnrollmentFileCodec.DeserializeRequest(request).PublicKey);
        Assert.Contains($"Requesting machine's slot fingerprint: {SlotFingerprint.Compute(publicKey)}", stdout);
        Assert.Contains("✓ Approved. The joining machine collects the approve file next.", stdout);
        Assert.Equal($"Approve file fingerprint: {SlotFingerprint.Compute(Encoding.UTF8.GetBytes(approve))}",
            stdout.TrimEnd().Split('\n')[^1].TrimEnd('\r'));
        Assert.DoesNotContain("Approve file written to", stdout);
        Assert.DoesNotContain("slot merge <receipt-file>", stdout);

        Accept(_joiner, approve);
        Assert.Null(_joiner.Config.PendingSlotId);
    }

    [Fact]
    public void Put_WritesTheStdinBytesVerbatim()
    {
        const string Text = "﻿{\"a\": 1}\r\nsecond line\n\n";

        var (exit, _, stderr) = Stage(_host, Text, Id, "put", "receipt");

        Assert.True(exit == 0, stderr);
        Assert.Equal(Encoding.UTF8.GetBytes(Text), File.ReadAllBytes(Path.Combine(StagedFolder(_host), "receipt.json")));
    }

    [Fact]
    public void Put_MakesAPrivateFolder_AndClean_RemovesIt()
    {
        if (OperatingSystem.IsWindows())
            return; // the modes are Unix's; on Windows the folder is inside the user's config folder
        Stage(_host, "x", Id, "put", "request");
        const UnixFileMode Private = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Assert.Equal(Private, File.GetUnixFileMode(StagedFolder(_host)));
        Assert.Equal(Private, File.GetUnixFileMode(Path.GetDirectoryName(StagedFolder(_host))!));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(StagedFolder(_host), "request.json")));

        var (exit, stdout, stderr) = Stage(_host, "", Id, "clean");

        Assert.True(exit == 0, stderr);
        Assert.Equal("", stdout);
        Assert.False(Directory.Exists(StagedFolder(_host)));
        // Absent is fine.
        Assert.Equal(0, Stage(_host, "", Id, "clean").Exit);
    }

    [Fact]
    public void Get_WithNothingStaged_IsRefused_AndPrintsNothingOnStdout()
    {
        var (exit, stdout, stderr) = Stage(_host, "", Id, "get", "approve");

        Assert.NotEqual(0, exit);
        Assert.Equal("", stdout);
        Assert.Contains($"No staged approve file for {Id} in {StagedFolder(_host)}", stderr);
    }

    // ------------------------------------------------------------------ --expect binds what the joiner sent

    [Fact]
    public void Approve_WithAnotherHash_IsRefused_AndNothingIsApproved()
    {
        var request = RequestOf(_joiner);
        Stage(_host, request, Id, "put", "request");
        var config = _host.ConfigText;

        var (exit, stdout, stderr) = _host.Run("", "slot", "approve", "--staged", Id, "--expect", Sha256(request + " "));

        Assert.NotEqual(0, exit);
        Assert.Contains("The staged request file isn't the one the joining machine sent (its SHA-256 differs). Nothing was approved.", stderr);
        Assert.Equal(config, _host.ConfigText);
        Assert.Null(_host.Config.ApprovedSlots);
        Assert.False(File.Exists(Path.Combine(StagedFolder(_host), "approve.json")));
        Assert.DoesNotContain("Approved", stdout);
    }

    [Fact]
    public void Merge_WithAnotherHash_IsRefused_AndTheKeyringIsUnchanged()
    {
        var receipt = Accept(_joiner, StagedApprove(_joiner));
        Stage(_host, receipt, Id, "put", "receipt");
        var config = _host.ConfigText;
        var keyring = HostKeyringBytes();

        var (exit, _, stderr) = _host.Run("", "slot", "merge", "--staged", Id, "--expect", Sha256(receipt + "\n"));

        Assert.NotEqual(0, exit);
        Assert.Contains("The staged receipt isn't the one the joining machine sent (its SHA-256 differs). Nothing was merged.", stderr);
        Assert.Equal(keyring, HostKeyringBytes());
        Assert.Equal(config, _host.ConfigText);
    }

    [Fact]
    public void Merge_WithTheHash_AddsTheApprovedSlot()
    {
        var receipt = Accept(_joiner, StagedApprove(_joiner));
        Stage(_host, receipt, Id, "put", "receipt");

        var (exit, stdout, stderr) = _host.Run("", "slot", "merge", "--staged", Id, "--expect", Sha256(receipt));

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains("Adding approved slot:", stdout);
        Assert.Contains(_host.Keyring.Slots, s => Convert.ToBase64String(s.SlotId) == _joiner.Config.KeyringSlotId);
    }

    [Fact]
    public void ASwappedStagedRequest_IsRefused_NothingApproved()
    {
        var request = RequestOf(_joiner);
        var other = RequestOf(Other("stage-other", SerialC));
        Stage(_host, request, Id, "put", "request");
        File.WriteAllText(Path.Combine(StagedFolder(_host), "request.json"), other);

        var (exit, _, stderr) = _host.Run("", "slot", "approve", "--staged", Id, "--expect", Sha256(request));

        Assert.NotEqual(0, exit);
        Assert.Contains("The staged request file isn't the one the joining machine sent (its SHA-256 differs). Nothing was approved.", stderr);
        Assert.Null(_host.Config.ApprovedSlots);
        Assert.False(File.Exists(Path.Combine(StagedFolder(_host), "approve.json")));
    }

    [Fact]
    public void ARequestSwappedAfterTheRead_ChangesNothing_TheApprovedSlotIsTheOneThatWasHashed()
    {
        // A1: one read, then hash, then parse that buffer; the path is never read again.
        var request = RequestOf(_joiner);
        var other = RequestOf(Other("stage-other", SerialC));
        Stage(_host, request, Id, "put", "request");
        _host.StagedSeams = new StagedFileSeams { AfterHashChecked = path => File.WriteAllText(path, other) };

        var (exit, stdout, stderr) = _host.Run("", "slot", "approve", "--staged", Id, "--expect", Sha256(request));

        Assert.True(exit == 0, stderr + stdout);
        _host.StagedSeams = null;
        var approve = Stage(_host, "", Id, "get", "approve").Out;
        Assert.Equal(SlotIdOf(request), SlotEnrollmentFileCodec.DeserializeApprove(approve).NewSlotId);
        Assert.True(IsApproved(_host, SlotIdOf(request)));
        Assert.False(IsApproved(_host, SlotIdOf(other)));
        Assert.DoesNotContain(SlotIdOf(other), approve);
        Assert.DoesNotContain(SlotEnrollmentFileCodec.DeserializeRequest(other).PublicKey, approve);
        Accept(_joiner, approve); // the joiner's own request was approved
    }

    [Fact]
    public void AReceiptSwappedAfterTheRead_ChangesNothing_TheMergedSlotIsTheOneThatWasHashed()
    {
        var receipt = Accept(_joiner, StagedApprove(_joiner));
        var other = Other("stage-other", SerialC);
        var otherReceipt = Accept(other, StagedApprove(other, "11223344")); // approved too: only the hash keeps it out
        Stage(_host, receipt, Id, "put", "receipt");
        _host.StagedSeams = new StagedFileSeams { AfterHashChecked = path => File.WriteAllText(path, otherReceipt) };

        var (exit, stdout, stderr) = _host.Run("", "slot", "merge", "--staged", Id, "--expect", Sha256(receipt));

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(_host.Keyring.Slots, s => Convert.ToBase64String(s.SlotId) == _joiner.Config.KeyringSlotId);
        Assert.DoesNotContain(_host.Keyring.Slots, s => Convert.ToBase64String(s.SlotId) == other.Config.KeyringSlotId);
        Assert.True(IsApproved(_host, other.Config.KeyringSlotId!)); // still waiting for its own merge
    }

    [Fact]
    public void AnApproveFileSwappedAfterItIsWritten_TheHostsFingerprintIsOfWhatItWrote()
    {
        // A3: the fingerprint is computed over the written buffer, never a re-read; a swapped file shows a different one.
        var request = RequestOf(_joiner);
        Stage(_host, request, Id, "put", "request");
        var crafted = "{\"crafted\": true}\n";
        string? written = null;
        _host.StagedSeams = new StagedFileSeams
        {
            AfterApproveWritten = path =>
            {
                written = File.ReadAllText(path);
                File.WriteAllText(path, crafted);
            },
        };

        var (exit, stdout, stderr) = _host.Run("", "slot", "approve", "--staged", Id, "--expect", Sha256(request));

        Assert.True(exit == 0, stderr + stdout);
        Assert.NotNull(written);
        var got = Stage(_host, "", Id, "get", "approve").Out;
        Assert.Equal(crafted, got);
        Assert.Contains($"Approve file fingerprint: {SlotFingerprint.Compute(Encoding.UTF8.GetBytes(written!))}", stdout);
        Assert.DoesNotContain(SlotFingerprint.Compute(Encoding.UTF8.GetBytes(got)), stdout);
    }

    // ------------------------------------------------------------------ the outcome T28 exists for

    [Fact]
    public void ApproveStaged_OnAHostThatNeedsItsVaultPassword_ReadsItAtTheTerminal_WhereTheDashFormCant()
    {
        var host = Other("stage-pw-host", 44444444);
        host.Tpm = RandomNumberGenerator.GetBytes(32);
        PasswordVaultTestSupport.InitTpmPasswordVault(host, Password);
        var request = RequestOf(_joiner);
        Assert.Equal(0, Stage(host, request, Id, "put", "request").Exit);

        var (exit, stdout, stderr) = host.RunOnTerminal(Password + "\n", "slot", "approve", "--staged", Id, "--expect", Sha256(request));

        Assert.True(exit == 0, stderr + stdout);
        Assert.Contains(TerminalPasswordProviderPrompt, stderr);
        Assert.True(IsApproved(host, SlotIdOf(request)));
        Accept(_joiner, Stage(host, "", Id, "get", "approve").Out);

        // T27's stdin form on the same host: stdin carries the file, so the password can't be asked.
        var second = RequestOf(Other("stage-pw-joiner2", SerialC));
        var (dashExit, _, dashErr) = host.Run(second, "slot", "approve", "-", "-");
        Assert.NotEqual(0, dashExit);
        Assert.Contains(VaultPasswordMessages.NoTerminal, dashErr);
        Assert.False(IsApproved(host, SlotIdOf(second)));
    }

    private const string TerminalPasswordProviderPrompt = "Vault password: ";

    // ------------------------------------------------------------------ A6: no staged file

    [Fact]
    public void ApproveStaged_WithNothingStaged_SaysWhereItLooked()
    {
        var (exit, _, stderr) = _host.Run("", "slot", "approve", "--staged", Id, "--expect", Sha256("x"));

        Assert.NotEqual(0, exit);
        Assert.Contains($"No staged request file for {Id} in {StagedFolder(_host)}. If the SSH user sets TSWAP_CONFIG_DIR or " +
                        "XDG_CONFIG_HOME, sudo doesn't see it: see docs/multi-machine.md#enrolling-over-ssh. Nothing was approved.", stderr);
        Assert.DoesNotContain("SHA-256 differs", stderr);
        Assert.Null(_host.Config.ApprovedSlots);
    }

    [Fact]
    public void MergeStaged_WithNothingStaged_SaysWhereItLooked()
    {
        var keyring = HostKeyringBytes();

        var (exit, _, stderr) = _host.Run("", "slot", "merge", "--staged", Id, "--expect", Sha256("x"));

        Assert.NotEqual(0, exit);
        Assert.Contains($"No staged receipt for {Id} in {StagedFolder(_host)}. If the SSH user sets TSWAP_CONFIG_DIR or " +
                        "XDG_CONFIG_HOME, sudo doesn't see it: see docs/multi-machine.md#enrolling-over-ssh. Nothing was merged.", stderr);
        Assert.Equal(keyring, HostKeyringBytes());
    }

    // ------------------------------------------------------------------ usage (A2, A4)

    private static readonly string GoodHash = new('a', 64);

    public static TheoryData<string[]> StagedUsageErrors => new()
    {
        new[] { "--staged", Id },
        new[] { "--expect", new string('a', 64) },
        new[] { "--staged", Id, "--expect", new string('a', 63) },
        new[] { "--staged", Id, "--expect", new string('A', 64) },
        new[] { "--staged", Id, "--expect", new string('g', 64) },
        new[] { "--staged", Id, "--expect", new string('a', 65) },
        new[] { "--staged", "../x", "--expect", new string('a', 64) },
        new[] { "--staged", "ABCDEF12", "--expect", new string('a', 64) },
        new[] { "--staged", Id, "--expect", new string('a', 64), "file.json" },
        new[] { "--staged", Id, "--expect", new string('a', 64), "-" },
        new[] { "--staged", Id, "--expect", new string('a', 64), "--recovery-key-stdin" },
        new[] { "--staged", Id, "--staged", Id, "--expect", new string('a', 64) },
    };

    [Theory]
    [MemberData(nameof(StagedUsageErrors))]
    public void ApproveStaged_UsageErrors_ComeBeforeSudoAndAnyRead(string[] flags)
    {
        Stage(_host, "x", Id, "put", "request"); // a read would find this file and refuse its hash instead
        _host.Sudo = false;

        var (exit, _, stderr) = _host.Run("", ["slot", "approve", .. flags]);

        Assert.Equal(1, exit);
        Assert.Contains("Usage: tswap slot approve", stderr);
        Assert.DoesNotContain("requires", stderr);
        Assert.Null(_host.Config.ApprovedSlots);
    }

    [Theory]
    [MemberData(nameof(StagedUsageErrors))]
    public void MergeStaged_UsageErrors_ComeBeforeSudoAndAnyRead(string[] flags)
    {
        Stage(_host, "x", Id, "put", "receipt");
        _host.Sudo = false;

        var (exit, _, stderr) = _host.Run("", ["slot", "merge", .. flags]);

        Assert.Equal(1, exit);
        Assert.Contains("Usage: tswap slot merge", stderr);
        Assert.DoesNotContain("requires", stderr);
    }

    // ------------------------------------------------------------------ stage refusals

    public static TheoryData<string[]> StageUsageErrors => new()
    {
        new[] { "../x", "put", "request" },
        new[] { "ABCDEF12", "put", "request" },
        new[] { "0a1b2c3", "put", "request" },
        new[] { "0a1b2c3d4", "put", "request" },
        new[] { "0a1b2c3g", "clean" },
        new[] { Id, "put", "approve" },
        new[] { Id, "put" },
        new[] { Id, "get", "request" },
        new[] { Id, "get" },
        new[] { Id, "frob" },
        new[] { Id, "clean", "extra" },
        new[] { Id },
        System.Array.Empty<string>(),
    };

    [Theory]
    [MemberData(nameof(StageUsageErrors))]
    public void Stage_UsageErrors(string[] args)
    {
        var (exit, stdout, stderr) = Stage(_host, "x", args);

        Assert.Equal(1, exit);
        Assert.Contains("Usage: tswap slot stage <id> put request|receipt", stderr);
        Assert.Equal("", stdout);
        Assert.False(Directory.Exists(_host.PathOf("enrol-staged")));
    }

    [Fact]
    public void StagePut_OnATerminalStdin_IsRefused()
    {
        var sudo = _host.Sudo;
        _host.Sudo = false;
        var (exit, _, stderr) = _host.RunOnTerminal("x\n", "slot", "stage", Id, "put", "request");
        _host.Sudo = sudo;

        Assert.NotEqual(0, exit);
        Assert.Contains("slot stage: put reads the request file from stdin, and stdin is a terminal here. Pipe the file in.", stderr);
        Assert.False(Directory.Exists(StagedFolder(_host)));
    }

    [Fact]
    public void StagePut_OverOneMiB_IsRefused()
    {
        var (exit, _, stderr) = Stage(_host, new string('x', 1024 * 1024 + 1), Id, "put", "receipt");

        Assert.NotEqual(0, exit);
        Assert.Contains("slot stage: stdin is larger than 1 MiB, so it is not a receipt. Nothing was changed.", stderr);
        Assert.False(File.Exists(Path.Combine(StagedFolder(_host), "receipt.json")));
    }

    [Fact]
    public void Stage_UnderSudo_IsRefused()
    {
        if (Environment.IsPrivilegedProcess)
            return; // AGENTS.md's sudo-refusal convention
        _host.SudoEscalated = true;

        var (exit, _, stderr) = Stage(_host, "x", Id, "put", "request");

        Assert.NotEqual(0, exit);
        Assert.Contains("slot stage runs as the SSH user, not under sudo.", stderr);
        Assert.False(Directory.Exists(_host.PathOf("enrol-staged")));
    }

    [Fact]
    public void Stage_AsARootLoginWithoutSudoUser_Runs()
    {
        // A8: a privileged process without SUDO_USER (a root SSH login with --no-remote-sudo) is the SSH user there.
        _host.SudoEscalated = false;
        _host.Sudo = true;

        var (exit, _, stderr) = _host.Run("x", "slot", "stage", Id, "put", "request");

        Assert.True(exit == 0, stderr);
        Assert.True(File.Exists(Path.Combine(StagedFolder(_host), "request.json")));
    }

    public static TheoryData<string?, string?, bool, bool> SudoEscalation => new()
    {
        { "alice", "1000", true, true },   // sudo to root by alice
        { "alice", "1000", false, false }, // not privileged: SUDO_USER is ignored
        { null, null, true, false },       // a root login or service, no sudo
        { "root", "0", true, false },      // sudo by root itself
        { "alice", "0", true, false },     // SUDO_UID 0 is root
    };

    [Theory]
    [MemberData(nameof(SudoEscalation))]
    public void SudoEscalated_IsPrivilegedWithANonRootSudoUser(string? sudoUser, string? sudoUid, bool privileged, bool expected)
    {
        var env = CliEnvironment.Create(["slot", "stage"], name => name switch
        {
            "SUDO_USER" => sudoUser,
            "SUDO_UID" => sudoUid,
            _ => null,
        }, privileged, null, TextWriter.Null);

        Assert.Equal(expected && !OperatingSystem.IsWindows(), env.SudoEscalated);
    }
}
