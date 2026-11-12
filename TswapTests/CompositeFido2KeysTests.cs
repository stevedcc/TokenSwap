using System.Security.Cryptography;
using System.Text;
using TswapCore.Vault.Fido2;
using TswapCore.Vault.Fido2.Libfido2;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T19, item 3: <see cref="CompositeFido2Keys"/>, Yubico's SDK and libfido2 at once on Linux and macOS. Both
/// backends are the real classes: <see cref="SdkFido2Keys"/> over stand-in devices, <see cref="Libfido2Fido2Keys"/>
/// over <see cref="FakeLibfido2"/>. Key refs carry their backend (<c>sdk:</c>, <c>libfido2:</c>), and a call goes to
/// the backend that listed the key.
/// </summary>
public class CompositeFido2KeysTests
{
    private static readonly Guid YubiKey5 = Fido2TestSlots.Aaguid;
    private static readonly byte[] CredentialId = RandomNumberGenerator.GetBytes(64);
    private static readonly byte[] PrfInput = RandomNumberGenerator.GetBytes(32);

    /// <summary>The SDK backend's devices: a list, a holder, or a failure, and every key handle it was asked to open.</summary>
    private sealed class SdkDevices : ISdkFido2Devices
    {
        public List<Fido2KeyInfo> Keys { get; } = [];
        public Fido2DeviceException? FindFails { get; set; }
        public Fido2KeyInfo? Holder { get; set; }
        public Fido2DeviceException? ProbeFails { get; set; }
        public List<Fido2KeyRef> OpenedKeys { get; } = [];

        public IReadOnlyList<Fido2KeyInfo> Find() => FindFails is { } e ? throw e : Keys;

        public Fido2KeyInfo? FindHolder(byte[] credentialId) => ProbeFails is { } e ? throw e : Holder;

        public IFido2SdkSession Open(Fido2KeyRef key, SdkPinCollector collector)
        {
            OpenedKeys.Add(key);
            throw new Fido2DeviceException(Fido2Failure.Other, null, "ReachedTheSdkBackend");
        }
    }

    private readonly SdkDevices _sdk = new();
    private readonly FakeLibfido2 _fido = new();
    private int _loads;

    private CompositeFido2Keys Composite(Libfido2Status status = Libfido2Status.Loaded, TextWriter? notices = null) =>
        new(new SdkFido2Keys(_sdk), () =>
        {
            _loads++;
            return new Libfido2LoadResult(status,
                status == Libfido2Status.Loaded ? new Libfido2Fido2Keys(_fido, notices, null, linux: true, includeYubico: false) : null);
        }, notices);

    private static Fido2KeyInfo SdkKey(string id = "fido2-1") => new(new Fido2KeyRef(id), 33060000, YubiKey5, PinSet: true, PinRetries: 8);

    private static Fido2DevicePin Pin => _ => Encoding.UTF8.GetBytes("246810");

    // --- routing ---

    [Fact]
    public void Routing_AnSdkRefNeverReachesLibfido2()
    {
        _sdk.Keys.Add(SdkKey());
        _fido.AddDevice("/dev/hidraw3");
        var composite = Composite();
        var key = composite.Find().Single(k => k.Key.Id.StartsWith("sdk:", StringComparison.Ordinal));

        var e = Assert.Throws<Fido2DeviceException>(() => composite.GetHmacSecret(key.Key, [(CredentialId, PrfInput)], Pin));

        Assert.Equal("ReachedTheSdkBackend", e.Detail);
        Assert.Equal([new Fido2KeyRef("fido2-1")], _sdk.OpenedKeys); // the prefix is stripped
        Assert.Empty(_fido.Asserts);
    }

    [Fact]
    public void Routing_ALibfido2RefNeverReachesTheSdk()
    {
        _sdk.Keys.Add(SdkKey());
        _fido.AddDevice("/dev/hidraw3");
        var composite = Composite();
        var key = composite.Find().Single(k => k.Key.Id.StartsWith("libfido2:", StringComparison.Ordinal));

        composite.MakeCredential(key.Key, new byte[16], [], Pin);
        composite.GetHmacSecret(key.Key, [(CredentialId, PrfInput)], Pin);

        Assert.Equal("libfido2:/dev/hidraw3", key.Key.Id);
        Assert.Equal("/dev/hidraw3", Assert.Single(_fido.Creds).DevicePath);
        Assert.Equal("/dev/hidraw3", Assert.Single(_fido.Asserts).DevicePath);
        Assert.Empty(_sdk.OpenedKeys);
    }

    [Fact]
    public void Routing_SetPinGoesToTheListingBackend()
    {
        var device = _fido.AddDevice("/dev/hidraw3");
        device.ClientPin = false;
        var composite = Composite();

        composite.SetPin(new Fido2KeyRef("libfido2:/dev/hidraw3"), Pin);
        Assert.Throws<Fido2DeviceException>(() => composite.SetPin(new Fido2KeyRef("sdk:fido2-1"), Pin));

        Assert.Equal("/dev/hidraw3", Assert.Single(_fido.PinsSet).Path);
        Assert.Equal([new Fido2KeyRef("fido2-1")], _sdk.OpenedKeys);
    }

    [Fact]
    public void Routing_ARefWithoutABackendPrefix_IsRefused()
    {
        var composite = Composite();

        Assert.Throws<ArgumentException>(() => composite.GetHmacSecret(new Fido2KeyRef("fido2-1"), [(CredentialId, PrfInput)], Pin));
        Assert.Empty(_sdk.OpenedKeys);
        Assert.Empty(_fido.Opened);
    }

    // --- Find ---

    [Fact]
    public void Find_ListsOneKeyPerBackend()
    {
        _sdk.Keys.Add(SdkKey());
        _fido.AddDevice("/dev/hidraw3");

        var keys = Composite().Find();

        Assert.Equal(["sdk:fido2-1", "libfido2:/dev/hidraw3"], keys.Select(k => k.Key.Id));
        Assert.Equal(33060000, keys[0].Serial);
        Assert.Equal(Guid.Parse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf"), keys[1].Aaguid);
    }

    [Fact]
    public void Find_OneBackendThrowingBesideKeysOnTheOther_ReportsItAndListsTheOther()
    {
        _sdk.FindFails = new Fido2DeviceException(Fido2Failure.Busy, null, "ChannelBusy");
        _fido.AddDevice("/dev/hidraw3");
        var notices = new StringWriter();

        var keys = Composite(notices: notices).Find();

        Assert.Equal(["libfido2:/dev/hidraw3"], keys.Select(k => k.Key.Id));
        Assert.Equal(Fido2Texts.KeyLeftOut("ChannelBusy") + Environment.NewLine, notices.ToString());
    }

    [Fact]
    public void Find_Libfido2ThrowingBesideSdkKeys_ReportsItAndListsTheSdkKeys()
    {
        _sdk.Keys.Add(SdkKey());
        _fido.ManifestResult = Libfido2Errors.Internal;
        var notices = new StringWriter();

        var keys = Composite(notices: notices).Find();

        Assert.Equal(["sdk:fido2-1"], keys.Select(k => k.Key.Id));
        Assert.Equal(Fido2Texts.KeyLeftOut("FIDO_ERR_INTERNAL") + Environment.NewLine, notices.ToString());
    }

    [Fact]
    public void Find_BothEmptyAndOneThrowing_Throws()
    {
        _fido.ManifestResult = Libfido2Errors.Internal;
        var notices = new StringWriter();

        var e = Assert.Throws<Fido2DeviceException>(() => Composite(notices: notices).Find());

        Assert.Equal("FIDO_ERR_INTERNAL", e.Detail);
        Assert.Equal("", notices.ToString());
    }

    [Fact]
    public void Find_BothThrowing_ThrowsTheSdkBackends()
    {
        _sdk.FindFails = new Fido2DeviceException(Fido2Failure.Busy, null, "ChannelBusy");
        _fido.ManifestResult = Libfido2Errors.Internal;

        Assert.Equal("ChannelBusy", Assert.Throws<Fido2DeviceException>(() => Composite().Find()).Detail);
    }

    [Theory]
    [InlineData(Libfido2Status.NotInstalled)]
    [InlineData(Libfido2Status.Unusable)]
    [InlineData(Libfido2Status.RefusedUnderSudo)]
    public void Find_WithoutLibfido2_ListsTheSdkKeysAndNothingThrows(Libfido2Status status)
    {
        _sdk.Keys.Add(SdkKey());

        var composite = Composite(status);

        Assert.Equal(["sdk:fido2-1"], composite.Find().Select(k => k.Key.Id));
        Assert.Empty(new CompositeFido2Keys(new SdkFido2Keys(new SdkDevices()), () => new Libfido2LoadResult(status, null)).Find());
        Assert.Equal(status, composite.OtherBrands);
    }

    // --- FindHolder ---

    [Fact]
    public void FindHolder_OnTheSdkBackend()
    {
        _sdk.Holder = SdkKey();
        _fido.AddDevice("/dev/hidraw3");

        Assert.Equal("sdk:fido2-1", Composite().FindHolder(CredentialId)!.Key.Id);
    }

    [Fact]
    public void FindHolder_OnLibfido2_WithTheSdkBackendThrowing()
    {
        _sdk.ProbeFails = new Fido2DeviceException(Fido2Failure.Busy, null, "ChannelBusy");
        _fido.AddDevice("/dev/hidraw3").Holds.Add(Convert.ToHexString(CredentialId));

        Assert.Equal("libfido2:/dev/hidraw3", Composite().FindHolder(CredentialId)!.Key.Id);
    }

    [Fact]
    public void FindHolder_OnTheSdkBackend_WithLibfido2Throwing()
    {
        _sdk.Holder = SdkKey();
        _fido.ManifestResult = Libfido2Errors.Internal;

        Assert.Equal("sdk:fido2-1", Composite().FindHolder(CredentialId)!.Key.Id);
    }

    [Fact]
    public void FindHolder_NoHolderAndOneThrew_ThrowsThatFailure()
    {
        _fido.AddDevice("/dev/hidraw3").ProbeResult = Libfido2Errors.ChannelBusy;

        Assert.Equal("FIDO_ERR_CHANNEL_BUSY", Assert.Throws<Fido2DeviceException>(() => Composite().FindHolder(CredentialId)).Detail);
    }

    [Fact]
    public void FindHolder_NoHolderAndBothThrew_ThrowsTheSdkBackends()
    {
        _sdk.ProbeFails = new Fido2DeviceException(Fido2Failure.Busy, null, "ChannelBusy");
        _fido.AddDevice("/dev/hidraw3").ProbeResult = Libfido2Errors.Internal;

        Assert.Equal("ChannelBusy", Assert.Throws<Fido2DeviceException>(() => Composite().FindHolder(CredentialId)).Detail);
    }

    [Fact]
    public void FindHolder_NoHolderNoFailure_IsNone()
    {
        _fido.AddDevice("/dev/hidraw3");

        Assert.Null(Composite().FindHolder(CredentialId));
    }

    // --- loading ---

    [Fact]
    public void Building_LoadsNothing_TheFirstListingLoadsOnce()
    {
        var composite = Composite();
        Assert.Equal(0, _loads);

        composite.Find();
        composite.FindHolder(CredentialId);
        _ = composite.OtherBrands;

        Assert.Equal(1, _loads);
    }

    [Fact]
    public void OtherBrands_IsTheLoadedStatus() => Assert.Equal(Libfido2Status.Loaded, Composite().OtherBrands);
}
