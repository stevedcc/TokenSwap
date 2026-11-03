using System.Security.Cryptography;
using System.Text.Json.Nodes;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 7, ruling 16: joining a machine with a password slot through <c>slot request --password</c>,
/// <c>slot approve</c> and <c>slot accept</c>. Two <see cref="FleetMachine"/>s: the approver (a TPM vault with
/// the vault password) and the new machine.
/// </summary>
public class VaultPasswordJoinTests : IDisposable
{
    private const int SerialB = RecordVaultTestSupport.SerialB;
    private const string Password = "correct horse battery staple";

    private const string NoFolderText =
        "slot request --password needs the shared vault folder (its vault-password file). Enrol without the password and re-enrol this slot later, or pass --vault-dir.";
    private const string NotThisVaultsPassword =
        "That is not this vault's password (every slot with a password uses the same one).";
    private const string RequestDiffersText = "The password typed at 'slot request' differs; run 'slot request' again.";

    private readonly FleetMachine _approver;
    private readonly FleetMachine _joiner;
    private readonly string _files = Directory.CreateTempSubdirectory("tswap-join-pw-").FullName;

    public VaultPasswordJoinTests()
    {
        _approver = new FleetMachine("approver", SimulatedYubiKeyService.WithKeys()) { Tpm = RandomNumberGenerator.GetBytes(32) };
        _approver.Ok(Password + "\n" + Password + "\n", "init", "--tpm", "--password", "--no-recovery");
        _joiner = new FleetMachine("joiner", SimulatedYubiKeyService.WithKeys(SerialB)) { Tpm = RandomNumberGenerator.GetBytes(32) };
    }

    public void Dispose()
    {
        _approver.Dispose();
        _joiner.Dispose();
        Directory.Delete(_files, true);
    }

    private string RequestPath => Path.Combine(_files, "request.json");
    private string ApprovePath => Path.Combine(_files, "approve.json");

    private byte[] ApproverVaultPasswordBytes => File.ReadAllBytes(PasswordVaultTestSupport.VaultPasswordPath(_approver));

    private void Approve()
    {
        // The approver unlocks its own password slot at the terminal prompt.
        var (exit, _, err) = _approver.RunOnTerminal(Password + "\n", "slot", "approve", RequestPath, ApprovePath);
        Assert.True(exit == 0, err);
    }

    private void RequestTpm(string requestPassword)
    {
        var (exit, _, err) = _joiner.Run(requestPassword + "\n", "slot", "request", "--tpm", "--password", "--vault-dir", _approver.VaultDir!, RequestPath);
        Assert.True(exit == 0, err);
    }

    private static Slot OwnSlot(FleetMachine m)
    {
        var id = Convert.FromBase64String(m.Config.KeyringSlotId!);
        return m.Keyring.Slots.Single(s => s.SlotId.AsSpan().SequenceEqual(id));
    }

    [Fact]
    public void RequestTpmWithPassword_ApproveAccept_Joins_AndUnlocksWithThePassword()
    {
        _approver.RunOnTerminal(Password + "\n", "create", "db");
        RequestTpm(Password);
        Assert.Equal(Convert.ToBase64String(ApproverVaultPasswordBytes), _joiner.Config.PendingVaultPassword);
        Approve();

        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "accept", ApprovePath);

        Assert.True(exit == 0, err);
        Assert.True(SlotPassword.Requires(OwnSlot(_joiner)));
        Assert.Null(_joiner.Config.PendingVaultPassword);
        // The joined machine opens its own copy with its TPM and the password, and not without it.
        var (unlockExit, _, unlockErr) = _joiner.RunOnTerminal(Password + "\n", "names");
        Assert.True(unlockExit == 0, unlockErr);
        var (wrongExit, _, wrongErr) = _joiner.RunOnTerminal("not the password\n", "names");
        Assert.NotEqual(0, wrongExit);
        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, wrongErr);
    }

    [Fact]
    public void RequestWithPassword_NoFolder_RefusesWithRuling16Text()
    {
        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "request", "--tpm", "--password", RequestPath);

        Assert.NotEqual(0, exit);
        Assert.Contains(NoFolderText, err);
        Assert.False(File.Exists(RequestPath));
        Assert.False(File.Exists(_joiner.ConfigPath));
    }

    [Fact]
    public void RequestWithPassword_FolderWithoutVaultPasswordFile_RefusesWithRuling16Text()
    {
        using var plain = new FleetMachine("plain") { Tpm = RandomNumberGenerator.GetBytes(32) };
        plain.Ok("", "init", "--tpm", "--no-password", "--no-recovery");

        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "request", "--tpm", "--password", "--vault-dir", plain.VaultDir!, RequestPath);

        Assert.NotEqual(0, exit);
        Assert.Contains(NoFolderText, err);
        Assert.False(File.Exists(RequestPath));
    }

    [Fact]
    public void Accept_WrongPassword_RefusesBeforeTouchingTheTpm()
    {
        RequestTpm(Password);
        Approve();
        var calls = new List<string>();

        int exit;
        string err;
        using (SimulatedHardwareService.ObserveCalls((backend, call) => calls.Add($"{backend}:{call}")))
            (exit, _, err) = _joiner.Run("not the password\n", "slot", "accept", ApprovePath);

        Assert.NotEqual(0, exit);
        Assert.Contains(NotThisVaultsPassword, err);
        Assert.DoesNotContain("Tpm:Unlock", calls); // the verifier refused first
        Assert.NotNull(_joiner.Config.PendingSlotId); // still pending: nothing was accepted
        Assert.False(Directory.Exists(Path.Combine(_joiner.Dir, "vault")));
    }

    [Fact]
    public void Accept_DifferentPasswordAtRequest_SaysRequestAgain()
    {
        RequestTpm("a different password");
        Approve();

        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "accept", ApprovePath);

        Assert.NotEqual(0, exit);
        Assert.Contains(RequestDiffersText, err);
        Assert.NotNull(_joiner.Config.PendingSlotId);
    }

    [Fact]
    public void Accept_VaultPasswordFilesDiffer_Refuses()
    {
        RequestTpm(Password);
        Approve();
        // The approve file carries another vault-password file (one byte of the salt changed).
        var approve = JsonNode.Parse(File.ReadAllText(ApprovePath))!.AsObject();
        var other = Convert.FromBase64String(approve["VaultPassword"]!.GetValue<string>());
        other[40] ^= 1;
        approve["VaultPassword"] = Convert.ToBase64String(other);
        File.WriteAllText(ApprovePath, approve.ToJsonString());
        var configBefore = _joiner.ConfigText;

        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "accept", ApprovePath);

        Assert.NotEqual(0, exit);
        Assert.Contains("vault-password", err);
        Assert.Contains("differ", err);
        Assert.Equal(configBefore, _joiner.ConfigText);
        Assert.Equal(0, _joiner.LastConsole!.Reads); // refused before asking for the password
    }

    [Fact]
    public void Accept_TargetFolderHasAnotherVaultPasswordFile_Refuses()
    {
        RequestTpm(Password);
        Approve();
        // The shared folder's file changed after the request (it is not the one the request recorded).
        var path = PasswordVaultTestSupport.VaultPasswordPath(_approver);
        var other = File.ReadAllBytes(path);
        other[40] ^= 1;
        File.WriteAllBytes(path, other);

        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "accept", ApprovePath, "--vault-dir", _approver.VaultDir!);

        Assert.NotEqual(0, exit);
        Assert.Contains("differ", err);
        Assert.NotNull(_joiner.Config.PendingSlotId);
    }

    [Fact]
    public void PlainAccept_WritesVaultPasswordIntoTheNewFolder()
    {
        RequestTpm(Password);
        Approve();

        _joiner.Ok(Password + "\n", "slot", "accept", ApprovePath);

        Assert.Equal(ApproverVaultPasswordBytes, File.ReadAllBytes(PasswordVaultTestSupport.VaultPasswordPath(_joiner)));
    }

    [Fact]
    public void AcceptIntoTheSharedFolder_KeepsItsVaultPasswordFile()
    {
        RequestTpm(Password);
        Approve();
        var before = ApproverVaultPasswordBytes;

        _joiner.Ok(Password + "\n", "slot", "accept", ApprovePath, "--vault-dir", _approver.VaultDir!);

        Assert.Equal(before, ApproverVaultPasswordBytes);
        Assert.True(SlotPassword.Requires(OwnSlot(_joiner)));
        var (exit, _, err) = _joiner.RunOnTerminal(Password + "\n", "names");
        Assert.True(exit == 0, err);
    }

    [Fact]
    public void RequestYubiKeyWithPassword_AcceptDerivesV2Kek()
    {
        _approver.RunOnTerminal(Password + "\n", "create", "db");
        // A YubiKey request records only the v2 blob: no password is asked for here.
        var (requestExit, _, requestErr) = _joiner.Run("", "slot", "request", "--password", "--vault-dir", _approver.VaultDir!, RequestPath);
        Assert.True(requestExit == 0, requestErr);
        Assert.DoesNotContain("Vault password", requestErr);
        var pendingBlob = YubiKeySlotBlob.Decode(Convert.FromBase64String(_joiner.Config.PendingSlotHwBlob!));
        Assert.True(pendingBlob.RequiresPassword);
        Approve();

        var (exit, _, err) = _joiner.Run(Password + "\n", "slot", "accept", ApprovePath);

        Assert.True(exit == 0, err);
        var own = OwnSlot(_joiner);
        Assert.True(YubiKeySlotBlob.Decode(own.HwBlob!).RequiresPassword);
        // KEK_slot is the v2 derivation from the key's response and the stretched password: it unwraps the slot.
        var file = VaultPasswordFile.Decode(File.ReadAllBytes(PasswordVaultTestSupport.VaultPasswordPath(_joiner)), _joiner.Keyring.VaultId);
        using var stretched = VaultPasswordKdf.Stretch(Password, file.Salt, file.Params);
        var response = _joiner.Keys.Challenge(SerialB, pendingBlob.ChallengeString);
        var kek = YubiKeySlotKek.DeriveV2(response, stretched, pendingBlob.Salt, own.SlotId);
        var keyring = _joiner.Keyring;
        Assert.Equal(_approver.Keyring.VaultId, keyring.VaultId);
        var payload = SlotPayloadWrap.Unwrap(own.Wrapped, kek, keyring.FormatVersion, keyring.VaultId, keyring.K, own.SlotId);
        Assert.Equal(32, SlotSecretPayload.Decode(payload).VaultKey.Length);
        // And through the CLI, with the password typed at the prompt.
        var (namesExit, _, namesErr) = _joiner.RunOnTerminal(Password + "\n", "names");
        Assert.True(namesExit == 0, namesErr);
    }

    [Fact]
    public void ApproveFile_UnknownMember_IsIgnored()
    {
        RequestTpm(Password);
        Approve();
        var json = JsonNode.Parse(File.ReadAllText(ApprovePath))!.AsObject();
        json["SomeFutureMember"] = "ignored by this reader";

        var approve = SlotEnrollmentFileCodec.DeserializeApprove(json.ToJsonString());

        Assert.Equal(Convert.ToBase64String(ApproverVaultPasswordBytes), approve.VaultPassword);
    }

    [Fact]
    public void Approve_PasswordFreeRequest_FromAPasswordVault_CarriesTheFile_AndAcceptWritesIt()
    {
        // A password-free request: the new machine's copy still gets the vault's file (its other slots need it).
        var (requestExit, _, requestErr) = _joiner.Run("", "slot", "request", "--tpm", "--no-password", RequestPath);
        Assert.True(requestExit == 0, requestErr);
        Approve();

        var (exit, _, err) = _joiner.Run("", "slot", "accept", ApprovePath);

        Assert.True(exit == 0, err);
        Assert.False(SlotPassword.Requires(OwnSlot(_joiner)));
        Assert.Equal(ApproverVaultPasswordBytes, File.ReadAllBytes(PasswordVaultTestSupport.VaultPasswordPath(_joiner)));
        Assert.Equal(0, _joiner.LastConsole!.Reads);
    }
}
