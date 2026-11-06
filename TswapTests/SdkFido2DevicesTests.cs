using TswapCore.Vault.Fido2;
using Xunit;
using Yubico.YubiKey.Fido2;
using SdkFido2Exception = Yubico.YubiKey.Fido2.Fido2Exception;

namespace TswapTests;

/// <summary>
/// Final review: the loops of <see cref="SdkFido2Devices"/>' listing and silent probe, over stand-in devices (no key is
/// touched). One key that can't be read must not sink the listing; the probe's first holder wins over an earlier
/// failure, and a failure counts only when no key holds the credential.
/// </summary>
public class SdkFido2DevicesTests
{
    private static Fido2KeyInfo Info(string name) => new(new Fido2KeyRef(name), 33060000, Fido2TestSlots.Aaguid, PinSet: true, PinRetries: 8);

    private static readonly Exception Busy = new SdkFido2Exception(CtapStatus.ChannelBusy, "the SDK's prose");

    private static Fido2KeyInfo ReadOrThrow(string device) =>
        device.StartsWith("bad", StringComparison.Ordinal) ? throw Busy : Info(device);

    [Fact]
    public void Find_OneUnreadableKeyAmongTwo_IsLeftOutAndReported()
    {
        List<Fido2DeviceException> leftOut = [];

        var keys = SdkFido2Devices.ReadEach(["bad-1", "good"], ReadOrThrow, leftOut.Add);

        Assert.Equal("good", Assert.Single(keys).Key.Id);
        var reported = Assert.Single(leftOut);
        Assert.Equal(Fido2Failure.Busy, reported.Kind);
        Assert.Equal("ChannelBusy", reported.Detail);
    }

    [Fact]
    public void Find_NoKeyReadable_FailsAsBefore()
    {
        List<Fido2DeviceException> leftOut = [];

        var e = Assert.Throws<Fido2DeviceException>(() => SdkFido2Devices.ReadEach(["bad-1", "bad-2"], ReadOrThrow, leftOut.Add));

        Assert.Equal(Fido2Failure.Busy, e.Kind);
        Assert.Empty(leftOut); // the failure is the error itself, not a note
    }

    [Fact]
    public void Find_NonePluggedIn_IsEmpty() =>
        Assert.Empty(SdkFido2Devices.ReadEach<string>([], ReadOrThrow, _ => throw new InvalidOperationException("reported")));

    [Fact]
    public void FindHolder_FirstHolderWinsOverAnEarlierFailure()
    {
        var holder = SdkFido2Devices.FirstHolder(["bad-1", "other", "holder"], d => d == "holder" || ReadOrThrow(d) is null, Info);

        Assert.Equal("holder", holder!.Key.Id);
    }

    [Fact]
    public void FindHolder_NoneHolds_AFailure_Throws()
    {
        var e = Assert.Throws<Fido2DeviceException>(() =>
            SdkFido2Devices.FirstHolder(["other", "bad-1"], d => ReadOrThrow(d) is null, Info));

        Assert.Equal(Fido2Failure.Busy, e.Kind);
    }

    [Fact]
    public void FindHolder_NoneHolds_NoFailure_IsNone() =>
        Assert.Null(SdkFido2Devices.FirstHolder(["a", "b"], _ => false, Info));

    [Fact]
    public void FindHolder_HoldersInfoUnreadable_CountsAsAFailure()
    {
        var e = Assert.Throws<Fido2DeviceException>(() =>
            SdkFido2Devices.FirstHolder(["holder"], _ => true, _ => throw Busy));

        Assert.Equal(Fido2Failure.Busy, e.Kind);
    }

    [Fact]
    public void KeyLeftOut_NamesTheProblem() =>
        Assert.Equal("A plugged-in key's FIDO2 interface couldn't be read (ChannelBusy), so it is left out of the list.",
            Fido2Texts.KeyLeftOut("ChannelBusy"));
}
