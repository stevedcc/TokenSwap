using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T5 item 3 (decision 2, issue #152): <c>slot request --tpm</c> and
/// <c>slot request --secure-enclave</c> enroll the joining machine's own hardware through
/// <c>IHardwareEnrollmentService</c> and send the slot's hardware blob in the request; accept builds
/// the slot with that blob. Every machine here is a <see cref="FleetMachine"/> with its own
/// simulated TPM or Secure Enclave key, so a blob sealed on one machine fails on another.
/// </summary>
public class SlotRequestHardwareTests : IDisposable
{
    private const int SerialA = 11111111;

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA);
    private readonly List<FleetMachine> _machines = [];
    private readonly FleetMachine _router;

    public SlotRequestHardwareTests()
    {
        _keys.PluggedIn = [];
        _router = Machine("router", tpm: RandomNumberGenerator.GetBytes(32));
    }

    public void Dispose()
    {
        foreach (var m in _machines) m.Dispose();
    }

    private FleetMachine Machine(string name, byte[]? tpm = null, byte[]? secureEnclave = null)
    {
        var m = new FleetMachine(name, _keys) { Tpm = tpm, SecureEnclave = secureEnclave };
        _machines.Add(m);
        return m;
    }

    private void RouterVault()
    {
        _router.Ok("", "init", "--tpm");
        _router.Ok("router-pw\nrouter-pw\n", "add", "router");
    }

    /// <summary>request (joiner, with <paramref name="flag"/>) → approve (router) → accept (joiner) → merge (router).</summary>
    private void Join(FleetMachine joiner, string? flag)
    {
        var request = joiner.PathOf("request.json");
        var approve = joiner.PathOf("approve.json");
        joiner.Ok("", flag == null ? ["slot", "request", request] : ["slot", "request", flag, request]);
        _router.Ok("", "slot", "approve", request, approve);
        joiner.Ok("", "slot", "accept", approve);
        _router.Ok("", "slot", "merge", approve + ".receipt.json");
        // v0 carries no secrets: accept makes an empty secrets file; take the router's.
        File.Copy(_router.SecretsPath, joiner.SecretsPath, overwrite: true);
    }

    /// <summary>
    /// Opens <paramref name="copyOf"/>'s vault files on a fresh machine that has only the given
    /// hardware (no YubiKey plugged in).
    /// </summary>
    private string OpenCopyOn(FleetMachine copyOf, byte[]? tpm = null, byte[]? secureEnclave = null)
    {
        var m = Machine("copy", tpm, secureEnclave);
        copyOf.CopyVaultTo(m);
        return m.Get("router");
    }

    [Fact]
    public void ASecondTpmMachineJoins_BothCopiesOpenWithBothTpms()
    {
        RouterVault();
        var server = Machine("server", tpm: RandomNumberGenerator.GetBytes(32));

        Join(server, "--tpm");

        var config = server.Config;
        Assert.Equal(HardwareBackend.Tpm, config.Backend);
        Assert.Null(config.PendingSlotId);
        Assert.Null(config.PendingSlotHwBlob);
        var own = server.Keyring.Slots.Single(s => Convert.ToBase64String(s.SlotId) == config.KeyringSlotId);
        Assert.NotNull(own.HwBlob);
        Assert.False(YubiKeySlotBlob.IsYubiKeyBlob(own.HwBlob));
        Assert.Equal(server.Keyring.Slots.Select(s => s.SlotId), _router.Keyring.Slots.Select(s => s.SlotId));

        // Each copy on its own machine.
        Assert.Equal("router-pw", _router.Get("router"));
        Assert.Equal("router-pw", server.Get("router"));
        // And each copy on the other machine's TPM.
        Assert.Equal("router-pw", OpenCopyOn(_router, tpm: server.Tpm));
        Assert.Equal("router-pw", OpenCopyOn(server, tpm: _router.Tpm));
        // A third TPM opens neither.
        var stranger = Machine("stranger", tpm: RandomNumberGenerator.GetBytes(32));
        _router.CopyVaultTo(stranger);
        var (exit, stdout, _) = stranger.Run("", "get", "router");
        Assert.NotEqual(0, exit);
        Assert.DoesNotContain("router-pw", stdout);
        Assert.Empty(_keys.Challenges);
    }

    [Fact]
    public void TheRequestCarriesTheSealedBlob_AndTouchesNoYubiKey()
    {
        RouterVault();
        var server = Machine("server", tpm: RandomNumberGenerator.GetBytes(32));
        var requestPath = server.PathOf("request.json");

        var stdout = server.Ok("", "slot", "request", "--tpm", requestPath);

        var request = SlotEnrollmentFileCodec.DeserializeRequest(File.ReadAllText(requestPath));
        Assert.Equal(HardwareBackend.Tpm, request.Backend);
        Assert.Equal(server.Config.PendingSlotHwBlob, request.HwBlob);
        Assert.Equal(HardwareBackend.Tpm, server.Config.Backend);
        Assert.Contains("fingerprint", stdout);
        Assert.Empty(_keys.Challenges);

        var approveOut = _router.Ok("", "slot", "approve", requestPath, server.PathOf("approve.json"));
        Assert.Contains("TPM", approveOut);
        var approve = SlotEnrollmentFileCodec.DeserializeApprove(File.ReadAllText(server.PathOf("approve.json")));
        Assert.Equal(HardwareBackend.Tpm, approve.NewSlotBackend);
        Assert.Equal(request.HwBlob, approve.NewSlotHwBlob);
    }

    [Fact]
    public void ASecureEnclaveMachineJoins_TheSameWay()
    {
        RouterVault();
        var mac = Machine("mac", secureEnclave: RandomNumberGenerator.GetBytes(32));

        Join(mac, "--secure-enclave");

        Assert.Equal(HardwareBackend.SecureEnclave, mac.Config.Backend);
        Assert.True(mac.Config.RequiresTouch);
        Assert.Equal("router-pw", mac.Get("router"));
        Assert.Equal("router-pw", _router.Get("router"));
        Assert.Equal("router-pw", OpenCopyOn(_router, secureEnclave: mac.SecureEnclave));
        Assert.Equal("router-pw", OpenCopyOn(mac, tpm: _router.Tpm));
    }

    [Fact]
    public void AKeyringWithYubiKeyTpmAndSecureEnclaveSlots_OpensOnEach()
    {
        RouterVault();
        var server = Machine("server", tpm: RandomNumberGenerator.GetBytes(32));
        var mac = Machine("mac", secureEnclave: RandomNumberGenerator.GetBytes(32));
        var desktop = Machine("desktop");
        Join(server, "--tpm");
        Join(mac, "--secure-enclave");
        _keys.PluggedIn = [SerialA];
        Join(desktop, null);
        _keys.PluggedIn = [];

        Assert.Equal(5, _router.Keyring.Slots.Count); // router, recovery, server, mac, desktop
        Assert.Equal("router-pw", OpenCopyOn(_router, tpm: server.Tpm));
        Assert.Equal("router-pw", OpenCopyOn(_router, secureEnclave: mac.SecureEnclave));
        _keys.PluggedIn = [SerialA];
        Assert.Equal("router-pw", OpenCopyOn(_router));
    }

    [Theory]
    [InlineData("--tpm", "--secure-enclave")]
    [InlineData("--secure-enclave", "--tpm")]
    [InlineData("--tpm", "--tpm")]
    [InlineData("--yubikey")]
    public void BadFlags_AreAUsageError_AndWriteNothing(params string[] flags)
    {
        var server = Machine("server", tpm: RandomNumberGenerator.GetBytes(32));
        var requestPath = server.PathOf("request.json");

        var (exit, _, stderr) = server.Run("", ["slot", "request", .. flags, requestPath]);

        Assert.NotEqual(0, exit);
        Assert.Contains("Usage:", stderr);
        Assert.Contains("--tpm", stderr);
        Assert.False(File.Exists(requestPath));
        Assert.False(File.Exists(server.ConfigPath));
    }

    [Fact]
    public void AcceptWithAnotherMachinesBlob_Fails()
    {
        RouterVault();
        var server = Machine("server", tpm: RandomNumberGenerator.GetBytes(32));
        var other = Machine("other", tpm: RandomNumberGenerator.GetBytes(32));
        var request = server.PathOf("request.json");
        var approve = server.PathOf("approve.json");
        server.Ok("", "slot", "request", "--tpm", request);
        other.Ok("", "slot", "request", "--tpm", other.PathOf("request.json"));
        _router.Ok("", "slot", "approve", request, approve);
        var file = SlotEnrollmentFileCodec.DeserializeApprove(File.ReadAllText(approve));
        var otherBlob = SlotEnrollmentFileCodec.DeserializeRequest(File.ReadAllText(other.PathOf("request.json"))).HwBlob;
        File.WriteAllText(approve, SlotEnrollmentFileCodec.SerializeApprove(file with { NewSlotHwBlob = otherBlob }));
        var pending = server.ConfigText;

        var (exit, _, stderr) = server.Run("", "slot", "accept", approve);

        Assert.NotEqual(0, exit);
        Assert.Contains("does not match this machine's pending request", stderr);
        Assert.Equal(pending, server.ConfigText);
    }

    [Fact]
    public void ARequestNamingTpmWithAYubiKeyBlob_IsRefused()
    {
        var request = new SlotRequestFile(SlotRequestFile.CurrentFormatVersion,
            Convert.ToBase64String(new byte[16]), Convert.ToBase64String(new byte[32]),
            Convert.ToBase64String(YubiKeySlotBlob.Create(SerialA, true).Encode()), HardwareBackend.Tpm);

        var ex = Assert.Throws<TswapException>(() =>
            SlotEnrollmentFileCodec.DeserializeRequest(SlotEnrollmentFileCodec.SerializeRequest(request)));
        Assert.Contains("YubiKey", ex.Message);
    }

    [Fact]
    public void ARequestWithAnOversizeTpmBlob_IsRefused()
    {
        var request = new SlotRequestFile(SlotRequestFile.CurrentFormatVersion,
            Convert.ToBase64String(new byte[16]), Convert.ToBase64String(new byte[32]),
            Convert.ToBase64String(new byte[KeyringFormat.MaxHwBlobSize + 1]), HardwareBackend.Tpm);

        var ex = Assert.Throws<TswapException>(() =>
            SlotEnrollmentFileCodec.DeserializeRequest(SlotEnrollmentFileCodec.SerializeRequest(request)));
        Assert.Contains($"{KeyringFormat.MaxHwBlobSize}-byte limit", ex.Message);
    }

    [Fact]
    public void ATpmRequestWithoutABlob_IsRefusedByApprove()
    {
        RouterVault();
        var request = _router.PathOf("request.json");
        File.WriteAllText(request, SlotEnrollmentFileCodec.SerializeRequest(new SlotRequestFile(
            SlotRequestFile.CurrentFormatVersion, Convert.ToBase64String(new byte[16]),
            Convert.ToBase64String(new byte[32]), HwBlob: null, Backend: HardwareBackend.Tpm)));

        var (exit, _, stderr) = _router.Run("", "slot", "approve", request, _router.PathOf("approve.json"));

        Assert.NotEqual(0, exit);
        Assert.Contains("no hardware blob", stderr);
        Assert.False(File.Exists(_router.PathOf("approve.json")));
    }
}
