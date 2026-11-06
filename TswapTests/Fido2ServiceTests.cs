using System.Security.Cryptography;
using System.Text;
using TswapCore.Keyring;
using TswapCore.Vault.Fido2;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 3: <see cref="Fido2Service"/> over the device seam (<see cref="FakeFido2Keys"/>): the YubiKey
/// check, the PIN policy (one request per operation, no retries), the probe before any PIN, the exclude list, the
/// Windows one-ceremony path and every text.
/// </summary>
public class Fido2ServiceTests
{
    private const int Serial = 33060005;
    private const int OtherSerial = 33060006;

    /// <summary>YubiKey 5 NFC or 5C NFC (<see cref="YubicoAaguids"/>).</summary>
    private static readonly Guid Yubico5Nfc = Guid.Parse("d7781e5d-e353-46aa-afe2-3ca49f13332a");

    /// <summary>Security Key NFC by Yubico: a series that reports no serial.</summary>
    private static readonly Guid SecurityKeyNfc = Guid.Parse("e77e3c64-05e3-428b-8824-0cbeb04b829d");

    /// <summary>Not one of Yubico's AAGUIDs.</summary>
    private static readonly Guid OtherBrand = Guid.Parse("42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3");

    private readonly FakeFido2Keys _keys = new();
    private readonly List<Fido2PinRequest> _requests = [];

    private Fido2Service Service => new(_keys);

    /// <summary>A terminal where the person types <paramref name="pin"/> at every request.</summary>
    private Fido2Pin Typing(string pin = FakeFido2Keys.DefaultPin) => request =>
    {
        _requests.Add(request);
        return Encoding.UTF8.GetBytes(pin);
    };

    private Fido2SlotBlob SlotOn(FakeFido2Keys.Key key, bool requiresPassword = false) =>
        Fido2SlotBlob.Create(key.Serial, key.Aaguid, _keys.AddCredential(key), requiresPassword);

    // ---- Enrol ----

    [Fact]
    public void Enrol_YubiKey_ReturnsTheMadeCredentialsBlob()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        var existing = SlotOn(_keys.AddKey(OtherSerial, Yubico5Nfc));

        var blob = Service.Enrol(FakeFido2Keys.Info(key), requiresPassword: true, [existing], Typing());

        Assert.Equal(Serial, blob.Serial);
        Assert.Equal(Yubico5Nfc, blob.Aaguid);
        Assert.True(blob.RequiresPassword);
        Assert.True(_keys.Holds(key, blob.CredentialId));
        var make = Assert.Single(_keys.Calls, c => c.Op == FakeFido2Op.MakeCredential);
        Assert.Equal(key.Ref, make.Key);
        Assert.Equal(existing.CredentialId, Assert.Single(make.CredentialIds));
        Assert.Equal(16, make.UserId!.Length);
        var request = Assert.Single(_requests);
        Assert.Equal(new Fido2PinRequest("YubiKey 33060005", 8, NewPin: false), request);
        Assert.All(_keys.PinBuffers, buffer => Assert.All(buffer, b => Assert.Equal(0, b)));
    }

    [Fact]
    public void Enrol_NonYubicoAaguid_RefusedNamingIssue193()
    {
        _keys.CanList = false;
        _keys.Picked = _keys.AddKey(null, OtherBrand);

        Fido2SlotBlob? blob = null;
        var error = Assert.Throws<Fido2Exception>(() => blob = Service.Enrol(null, false, [], Typing()));

        Assert.Equal(Fido2Failure.NotAYubiKey, error.Kind);
        Assert.Contains("#193", error.Message);
        Assert.Contains("not a YubiKey", error.Message);
        Assert.Null(blob);
    }

    [Fact]
    public void Enrol_MadeWithoutUv_Refused()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        key.MakesWithoutUv = true;

        var error = Assert.Throws<Fido2Exception>(() => Service.Enrol(FakeFido2Keys.Info(key), false, [], Typing()));

        Assert.Equal(
            "YubiKey 33060005 made the credential without verifying the PIN (no user verification); a FIDO2 slot needs the PIN and a touch, so no slot was added.",
            error.Message);
    }

    [Fact]
    public void Enrol_NonYubicoKey_RefusedBeforeMakeCredential()
    {
        var key = _keys.AddKey(Serial, OtherBrand);

        var error = Assert.Throws<Fido2Exception>(() => Service.Enrol(FakeFido2Keys.Info(key), false, [], Typing()));

        Assert.Equal(Fido2Failure.NotAYubiKey, error.Kind);
        Assert.Contains("#193", error.Message);
        Assert.DoesNotContain(_keys.Calls, c => c.Op == FakeFido2Op.MakeCredential);
        Assert.Empty(_requests);
    }

    [Fact]
    public void Enrol_KeyAlreadyInVault_RefusedBeforePin()
    {
        var key = _keys.AddKey(null, SecurityKeyNfc);
        var other = SlotOn(_keys.AddKey(OtherSerial, Yubico5Nfc));
        var mine = SlotOn(key);

        var error = Assert.Throws<Fido2Exception>(() => Service.Enrol(FakeFido2Keys.Info(key), false, [other, mine], Typing()));

        Assert.Equal(Fido2Failure.CredentialExcluded, error.Kind);
        Assert.Equal(
            "Security Key NFC by Yubico: this key already has a FIDO2 slot in this vault (one per key; `tswap slots` lists them). No slot was added.",
            error.Message);
        Assert.Empty(_requests);
        Assert.DoesNotContain(_keys.Calls, c => c.Op == FakeFido2Op.MakeCredential);
    }

    [Fact]
    public void Enrol_ExcludedByAuthenticator_SaysAlreadyHasASlot()
    {
        _keys.CanList = false;
        var key = _keys.AddKey(null, Yubico5Nfc);
        _keys.Picked = key;
        var other = SlotOn(_keys.AddKey(null, Yubico5Nfc));
        var mine = SlotOn(key);

        var error = Assert.Throws<Fido2Exception>(() => Service.Enrol(null, false, [other, mine], Typing()));

        Assert.Equal(Fido2Failure.CredentialExcluded, error.Kind);
        Assert.Contains("this key already has a FIDO2 slot in this vault", error.Message);
        var make = Assert.Single(_keys.Calls);
        Assert.Equal(FakeFido2Op.MakeCredential, make.Op);
        Assert.Equal([other.CredentialId, mine.CredentialId], make.CredentialIds);
    }

    [Fact]
    public void Enrol_ZeroAaguidOnWindows_Refused()
    {
        _keys.CanList = false;
        _keys.Picked = _keys.AddKey(null, Guid.Empty);

        Fido2SlotBlob? blob = null;
        var error = Assert.Throws<Fido2Exception>(() => blob = Service.Enrol(null, false, [], Typing()));

        Assert.Null(blob);
        Assert.Equal(Fido2Failure.NotAYubiKey, error.Kind);
        Assert.Contains("Windows didn't report which key this is", error.Message);
    }

    [Fact]
    public void Enrol_KeyWithoutPin_Refused()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc, pin: null);

        var error = Assert.Throws<Fido2Exception>(() => Service.Enrol(FakeFido2Keys.Info(key), false, [], Typing()));

        Assert.Equal(Fido2Failure.NoPin, error.Kind);
        Assert.Equal("YubiKey 33060005 has no FIDO2 PIN; a FIDO2 slot needs one.", error.Message);
        Assert.DoesNotContain(_keys.Calls, c => c.Op == FakeFido2Op.MakeCredential);
    }

    [Fact]
    public void Enrol_PinPromptCancelled_IsCancelledNoPinSent()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);

        var error = Assert.Throws<Fido2Exception>(() => Service.Enrol(FakeFido2Keys.Info(key), false, [], Typing("")));

        Assert.Equal(Fido2Failure.Cancelled, error.Kind);
        Assert.Empty(_keys.PinBuffers);
        Assert.Equal(8, key.Retries);
    }

    // ---- Open ----

    [Fact]
    public void Open_ReturnsTheUvOutput()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        var blob = SlotOn(key);

        var opened = Service.Open([blob], FakeFido2Keys.Info(key), Typing());

        Assert.Same(blob, opened.Blob);
        Assert.Equal(_keys.UvOutput(blob.CredentialId, blob.PrfInput), opened.Output);
        Assert.NotEqual(_keys.NonUvOutput(blob.CredentialId, blob.PrfInput), opened.Output);
        Assert.Single(_requests);
    }

    [Fact]
    public void Open_OutputWithoutUv_Refused()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        key.AnswersWithoutUv = true;
        var blob = SlotOn(key);

        var error = Assert.Throws<Fido2Exception>(() => Service.Open([blob], FakeFido2Keys.Info(key), Typing()));

        Assert.Equal(
            "YubiKey 33060005 answered without verifying the PIN (no user verification); tswap doesn't use such an answer.",
            error.Message);
        Assert.All(_keys.LastOutput!, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Open_WrongPin_SaysTriesLeft()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc, retries: 7);
        var blob = SlotOn(key);

        var error = Assert.Throws<Fido2Exception>(() => Service.Open([blob], FakeFido2Keys.Info(key), Typing("000000")));

        Assert.Equal(Fido2Failure.PinWrong, error.Kind);
        Assert.Equal(Serial, error.Serial);
        Assert.Equal(6, error.RetriesLeft);
        Assert.Equal(
            "YubiKey 33060005: wrong FIDO2 PIN; 6 tries left before this key's FIDO2 is blocked (a key allows 8 wrong PINs in all). After three wrong PINs in a row, unplug the key and plug it in again before the next try.",
            error.Message);
    }

    [Fact]
    public void Open_ThirdWrongInARow_SaysReinsert()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc, retries: 6);
        key.WrongInARow = 2;
        var blob = SlotOn(key);

        var error = Assert.Throws<Fido2Exception>(() => Service.Open([blob], FakeFido2Keys.Info(key), Typing("000000")));

        Assert.Equal(Fido2Failure.PinNeedsReinsert, error.Kind);
        Assert.Equal(
            "YubiKey 33060005: three wrong FIDO2 PINs in a row. Unplug the key and plug it in again before the next try; 5 tries left before this key's FIDO2 is blocked (a key allows 8 wrong PINs in all).",
            error.Message);
    }

    [Fact]
    public void Open_PinBlocked_SaysResetNeededAndWhatItDeletes()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc, retries: 1);
        var blob = SlotOn(key);

        var error = Assert.Throws<Fido2Exception>(() => Service.Open([blob], FakeFido2Keys.Info(key), Typing("000000")));

        Assert.Equal(Fido2Failure.PinBlocked, error.Kind);
        Assert.Equal(
            "YubiKey 33060005: its FIDO2 PIN is blocked (8 wrong PINs). Only a FIDO2 reset unblocks it, and a reset deletes every FIDO2 credential on the key: its FIDO2 slots in this and any other vault, and every passkey or security-key login it holds. tswap never resets a key. Open the vault another way; after a reset, enrol the key again with `tswap slot add --fido2`.",
            error.Message);
    }

    [Fact]
    public void Open_PinRequestedOnce_NoRetry()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        var blob = SlotOn(key);

        Assert.Throws<Fido2Exception>(() => Service.Open([blob], FakeFido2Keys.Info(key), Typing("000000")));

        Assert.Single(_requests);
        Assert.Single(_keys.Calls, c => c.Op == FakeFido2Op.GetHmacSecret);
        Assert.Equal(7, key.Retries);
    }

    [Fact]
    public void Open_DeviceAsksForThePinTwice_SecondRequestRefused()
    {
        var service = new Fido2Service(new AskingTwiceKeys());

        var error = Assert.Throws<Fido2Exception>(() => service.Open(
            [Fido2TestSlots.Blob()], new Fido2KeyInfo(new Fido2KeyRef("k"), Serial, Yubico5Nfc, true, 8), Typing()));

        Assert.Equal(Fido2Failure.PinWrong, error.Kind);
        Assert.Equal(7, error.RetriesLeft);
        Assert.Single(_requests);
    }

    [Fact]
    public void Assertion_NoCredential_SaysResetKillsTheSlot()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        var blob = SlotOn(key);
        _keys.Reset(key);
        key.Pin = FakeFido2Keys.DefaultPin;

        var error = Assert.Throws<Fido2Exception>(() => Service.Open([blob], FakeFido2Keys.Info(key), Typing()));

        Assert.Equal(Fido2Failure.NoCredential, error.Kind);
        Assert.Equal(
            "YubiKey 33060005 no longer holds this slot's credential (a FIDO2 reset deletes it, and the slot can't be opened again); enrol the key again with `tswap slot add --fido2`.",
            error.Message);
    }

    [Fact]
    public void Assertion_NoCredentialOnWindows_SaysAnotherKeyOrReset()
    {
        _keys.CanList = false;
        var blob = SlotOn(_keys.AddKey(null, Yubico5Nfc));
        _keys.Picked = _keys.AddKey(null, Yubico5Nfc);

        var error = Assert.Throws<Fido2Exception>(() => Service.Open([blob], null, Typing()));

        Assert.Equal(Fido2Failure.NoCredential, error.Kind);
        Assert.Equal(
            "The key you picked holds none of this vault's FIDO2 credentials: another key, or a FIDO2 reset deleted it (then enrol the key again with `tswap slot add --fido2`).",
            error.Message);
    }

    [Fact]
    public void Open_NoTerminal_RefusesBeforeAnyKeyCall()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        var blob = SlotOn(key);

        var error = Assert.Throws<Fido2Exception>(() => Service.Open([blob], FakeFido2Keys.Info(key), pin: null));

        Assert.Equal(Fido2Failure.NoTerminal, error.Kind);
        Assert.Equal(
            "A FIDO2 slot needs a person at a terminal to type the key's PIN and touch the key; there is no terminal here, so the key was not used.",
            error.Message);
        Assert.Empty(_keys.Calls);
    }

    [Fact]
    public void Open_Windows_AllSlotsInOneCeremony_PicksTheAnsweringSlot()
    {
        _keys.CanList = false;
        var first = SlotOn(_keys.AddKey(null, Yubico5Nfc));
        var secondKey = _keys.AddKey(null, SecurityKeyNfc);
        var second = SlotOn(secondKey);
        _keys.Picked = secondKey;

        var opened = Service.Open([first, second], null, Typing());

        Assert.Same(second, opened.Blob);
        Assert.Equal(_keys.UvOutput(second.CredentialId, second.PrfInput), opened.Output);
        var call = Assert.Single(_keys.Calls);
        Assert.Equal(FakeFido2Op.GetHmacSecret, call.Op);
        Assert.Null(call.Key);
        Assert.Equal([first.CredentialId, second.CredentialId], call.CredentialIds);
    }

    [Fact]
    public void Open_Busy_SaysBusyAndNamesTheKey()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        var blob = SlotOn(key);
        _keys.FailNext(FakeFido2Op.GetHmacSecret, Fido2Failure.Busy);

        var error = Assert.Throws<Fido2Exception>(() => Service.Open([blob], FakeFido2Keys.Info(key), Typing()));

        Assert.Equal(Fido2Failure.Busy, error.Kind);
        Assert.Equal("YubiKey 33060005 is busy: another program is using it. Try again when it's done.", error.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    public void Open_MissingOrShortOutput_Refused(int length)
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        key.OutputLength = length;
        var blob = SlotOn(key);

        var error = Assert.Throws<Fido2Exception>(() => Service.Open([blob], FakeFido2Keys.Info(key), Typing()));

        Assert.Equal(
            $"YubiKey 33060005 answered without a usable hmac-secret output ({length} bytes; a FIDO2 slot needs 32). On Windows, Windows' WebAuthn API may be too old for FIDO2 slots (they need version 4).",
            error.Message);
        Assert.All(_keys.LastOutput!, b => Assert.Equal(0, b));
    }

    // ---- Locate ----

    [Fact]
    public void Locate_FindsTheRightKeyAmongTwo()
    {
        _keys.AddKey(OtherSerial, Yubico5Nfc);
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        var blob = SlotOn(key);

        var found = Assert.IsType<Fido2Locate.Found>(Service.Locate(blob));

        Assert.Equal(key.Ref, found.Key.Key);
        Assert.Empty(_keys.DevicePinCalls);
    }

    [Fact]
    public void Locate_SerialLessKey_Found()
    {
        var key = _keys.AddKey(null, SecurityKeyNfc);
        var blob = SlotOn(key);

        var found = Assert.IsType<Fido2Locate.Found>(Service.Locate(blob));

        Assert.Equal(key.Ref, found.Key.Key);
        Assert.Null(found.Key.Serial);
    }

    [Fact]
    public void Locate_SameSerialNoCredential_IsResetOrOtherKey()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        var blob = SlotOn(key);
        _keys.Reset(key);

        var located = Assert.IsType<Fido2Locate.ResetOrOtherKey>(Service.Locate(blob));

        Assert.Equal(key.Ref, located.PluggedKey.Key);
        Assert.True(located.SerialMatched);
    }

    [Fact]
    public void Locate_SameSerialNoCredential_TextSaysReset()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        var blob = SlotOn(key);
        _keys.Reset(key);

        var text = Fido2Texts.Describe(Service.Locate(blob));

        Assert.Equal(
            "YubiKey 33060005 is plugged in but no longer holds this slot's credential: a FIDO2 reset deleted it, and the slot can't be opened again. Enrol the key again with `tswap slot add --fido2`.",
            text);
    }

    [Fact]
    public void Locate_SerialLessSameModelNoCredential_IsResetOrOtherKey()
    {
        var blob = SlotOn(_keys.AddKey(null, SecurityKeyNfc));
        _keys.Keys[0].PluggedIn = false;
        var sameModel = _keys.AddKey(null, SecurityKeyNfc);

        var located = Service.Locate(blob);

        var reset = Assert.IsType<Fido2Locate.ResetOrOtherKey>(located);
        Assert.Equal(sameModel.Ref, reset.PluggedKey.Key);
        Assert.False(reset.SerialMatched);
        Assert.Equal(
            "Security Key NFC by Yubico is plugged in but doesn't hold this slot's credential: another key of the same model, or a FIDO2 reset deleted it (then enrol the key again with `tswap slot add --fido2`).",
            Fido2Texts.Describe(located));
    }

    [Fact]
    public void Locate_KeyAbsent_NotPluggedInNamesIt()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);
        var blob = SlotOn(key);
        key.PluggedIn = false;
        _keys.AddKey(OtherSerial, Yubico5Nfc);

        var located = Service.Locate(blob);

        Assert.Equal(new Fido2Locate.NotPluggedIn("YubiKey 33060005"), located);
        Assert.Equal("The FIDO2 slot of YubiKey 33060005: plug it in.", Fido2Texts.Describe(located));
        Assert.Empty(_keys.DevicePinCalls);
    }

    [Fact]
    public void Locate_Windows_UnknownWithoutAnyKeyCall()
    {
        _keys.CanList = false;
        var blob = SlotOn(_keys.AddKey(Serial, Yubico5Nfc));

        Assert.IsType<Fido2Locate.Unknown>(Service.Locate(blob));
        Assert.Empty(_keys.Calls);
    }

    // ---- Listing, PIN setting, names ----

    [Fact]
    public void ListYubiKeys_LeavesOutOtherBrands()
    {
        var yubiKey = _keys.AddKey(Serial, Yubico5Nfc);
        _keys.AddKey(OtherSerial, OtherBrand);
        var securityKey = _keys.AddKey(null, SecurityKeyNfc);

        var listed = Service.ListYubiKeys();

        Assert.Equal([yubiKey.Ref, securityKey.Ref], listed.Select(k => k.Key));
    }

    [Fact]
    public void ListYubiKeys_Windows_EmptyWithoutAnyKeyCall()
    {
        _keys.CanList = false;
        _keys.AddKey(Serial, Yubico5Nfc);

        Assert.Empty(Service.ListYubiKeys());
        Assert.Empty(_keys.Calls);
    }

    [Fact]
    public void SetPin_KeyWithoutPin_AsksForANewPinOnce()
    {
        var key = _keys.AddKey(null, SecurityKeyNfc, pin: null);

        Service.SetPin(FakeFido2Keys.Info(key), Typing("246810"));

        Assert.Equal("246810", key.Pin);
        Assert.Equal(new Fido2PinRequest("Security Key NFC by Yubico", null, NewPin: true), Assert.Single(_requests));
        Assert.All(_keys.PinBuffers, buffer => Assert.All(buffer, b => Assert.Equal(0, b)));
    }

    [Fact]
    public void SetPin_KeyWithAPin_RefusedWithoutAKeyCall()
    {
        var key = _keys.AddKey(Serial, Yubico5Nfc);

        var error = Assert.Throws<Fido2Exception>(() => Service.SetPin(FakeFido2Keys.Info(key), Typing("246810")));

        Assert.Equal("YubiKey 33060005 already has a FIDO2 PIN; tswap never changes an existing PIN.", error.Message);
        Assert.Empty(_keys.Calls);
        Assert.Equal(FakeFido2Keys.DefaultPin, key.Pin);
    }

    [Fact]
    public void KeyName_SerialElseModel()
    {
        Assert.Equal("YubiKey 33060005", Service.KeyName(new Fido2KeyInfo(new Fido2KeyRef("a"), Serial, SecurityKeyNfc, true, 8)));
        Assert.Equal("Security Key NFC by Yubico", Service.KeyName(Fido2SlotBlob.Create(null, SecurityKeyNfc, new byte[16], false)));
    }

    /// <summary>A device that, against the contract, asks for the PIN a second time after a wrong one.</summary>
    private sealed class AskingTwiceKeys : IFido2Keys
    {
        public bool CanList => true;
        public IReadOnlyList<Fido2KeyInfo> Find() => [];
        public Fido2KeyInfo? FindHolder(byte[] credentialId) => null;
        public void SetPin(Fido2KeyRef key, Fido2DevicePin newPin) { }

        public Fido2Made MakeCredential(Fido2KeyRef? key, byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds, Fido2DevicePin pin) =>
            throw new NotSupportedException();

        public Fido2Output GetHmacSecret(Fido2KeyRef? key, IReadOnlyList<(byte[] CredentialId, byte[] PrfInput)> allowed, Fido2DevicePin pin)
        {
            CryptographicOperations.ZeroMemory(pin(8));
            CryptographicOperations.ZeroMemory(pin(7));
            throw new InvalidOperationException("unreachable: the second request is refused");
        }
    }
}
