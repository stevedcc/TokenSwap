using System.Security.Cryptography;
using System.Text;
using TswapCore.Keyring;
using TswapCore.Vault.Fido2;
using TswapCore.Vault.Fido2.Libfido2;
using Xunit;
using Yubico.YubiKey.Fido2;
using Yubico.YubiKey.Fido2.Cose;

namespace TswapTests;

/// <summary>
/// Brief T19, item 2: <see cref="Libfido2Fido2Keys"/> over <see cref="FakeLibfido2"/>. Its CTAP2 parameters must be
/// <see cref="SdkFido2Keys"/>' (a slot made by one backend opens on the other), the probe silent (<c>up</c>
/// <see cref="FidoOpt.False"/>, no PIN), and every failure a <see cref="Fido2DeviceException"/> named after its
/// <c>FIDO_ERR_*</c> constant.
/// </summary>
public class Libfido2Fido2KeysTests
{
    private static readonly byte[] CredentialId = RandomNumberGenerator.GetBytes(64);
    private static readonly byte[] PrfInput = RandomNumberGenerator.GetBytes(32);
    private const string PinText = "246810";

    private readonly FakeLibfido2 _fido = new();

    private Libfido2Fido2Keys Keys(TextWriter? notices = null, bool linux = true, bool includeYubico = false) =>
        new(_fido, notices, verbose: null, linux, includeYubico);

    private static Fido2DevicePin Pin(List<int?> asked) => retries =>
    {
        asked.Add(retries);
        return Encoding.UTF8.GetBytes(PinText);
    };

    private static Fido2DevicePin NoPin => _ => throw new InvalidOperationException("the PIN delegate must not be called");

    private (FakeLibfido2.Device Device, Fido2KeyRef Ref) Token2(string path = "/dev/hidraw3")
    {
        var device = _fido.AddDevice(path);
        return (device, new Fido2KeyRef(path));
    }

    // --- make-credential: the SDK path's parameters ---

    [Fact]
    public void MakeCredential_SendsTheSdkPathsParameters()
    {
        var (_, key) = Token2();
        var userId = RandomNumberGenerator.GetBytes(Fido2Service.UserIdSize);
        byte[] excludedA = RandomNumberGenerator.GetBytes(64), excludedB = RandomNumberGenerator.GetBytes(48);
        var sdk = SdkFido2Keys.BuildMakeCredentialParameters(userId, [excludedA, excludedB]);

        Keys().MakeCredential(key, userId, [excludedA, excludedB], Pin([]));

        var cred = Assert.Single(_fido.Creds);
        Assert.True(cred.Sent);
        Assert.Equal(sdk.RelyingParty.Id, cred.RpId);
        Assert.Equal(sdk.RelyingParty.Name, cred.RpName);
        Assert.Equal(sdk.UserEntity.Id.ToArray(), cred.UserId);
        Assert.Equal(sdk.UserEntity.Name, cred.UserName);
        Assert.Equal(sdk.UserEntity.DisplayName, cred.UserDisplayName);
        Assert.Null(cred.UserIcon);
        Assert.Equal(CoseAlgorithmIdentifier.ES256, (CoseAlgorithmIdentifier)cred.Type!.Value);
        Assert.Equal(CoseAlgorithmIdentifier.ES256, Assert.Single(sdk.Algorithms).Item2);
        Assert.Equal(Libfido2Params.ExtHmacSecret, cred.Extensions);
        Assert.False(sdk.Options[AuthenticatorOptions.rk]);
        Assert.Equal(1, cred.Rk); // FIDO_OPT_FALSE, not 0 (FIDO_OPT_OMIT: the key's default)
        Assert.Equal(sdk.ExcludeList!.Select(c => c.Id.ToArray()), cred.Excluded);
        Assert.Equal(32, cred.ClientDataHash!.Length);
        Assert.Equal(sdk.ClientDataHash.Length, cred.ClientDataHash.Length);
        Assert.Equal(PinText, cred.Pin);
    }

    [Fact]
    public void MakeCredential_ReturnsIdAaguidNoSerialAndUvFromTheFlags()
    {
        var (device, key) = Token2();

        var made = Keys().MakeCredential(key, new byte[16], [], Pin([]));

        Assert.Equal(device.MadeId, made.CredentialId);
        Assert.Equal(Guid.Parse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf"), made.Aaguid);
        Assert.Null(made.Serial);
        Assert.True(made.UserVerified);
        Assert.Equal(0, _fido.Live);
    }

    [Fact]
    public void MakeCredential_WithoutTheUvFlag_IsNotUserVerified()
    {
        var (device, key) = Token2();
        device.MadeFlags = Libfido2Params.FlagUserPresent;

        Assert.False(Keys().MakeCredential(key, new byte[16], [], Pin([])).UserVerified);
    }

    [Fact]
    public void MakeCredential_AsksForThePinExactlyOnce()
    {
        var (_, key) = Token2();
        List<int?> asked = [];

        Keys().MakeCredential(key, new byte[16], [], Pin(asked));

        Assert.Single(asked);
    }

    [Fact]
    public void MakeCredential_ZeroesThePinArray()
    {
        var (_, key) = Token2();
        var bytes = Encoding.UTF8.GetBytes(PinText);

        Keys().MakeCredential(key, new byte[16], [], _ => bytes);

        Assert.All(bytes, b => Assert.Equal(0, b));
    }

    [Fact]
    public void MakeCredential_APinWithANulByte_IsRefusedWithNothingSent()
    {
        var (_, key) = Token2();

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().MakeCredential(key, new byte[16], [], _ => [0x31, 0x00, 0x32, 0x33]));

        Assert.Equal("PinNotSendable", e.Detail);
        Assert.False(Assert.Single(_fido.Creds).Sent);
        Assert.Equal(0, _fido.Live);
    }

    [Fact]
    public void MakeCredential_AKeyWithoutAPin_IsRefusedBeforeThePinIsAsked()
    {
        var (device, key) = Token2();
        device.ClientPin = false;

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().MakeCredential(key, new byte[16], [], NoPin));

        Assert.Equal(Fido2Failure.NoPin, e.Kind);
        Assert.Equal(0, _fido.Live);
    }

    // --- hmac-secret ---

    [Fact]
    public void GetHmacSecret_SendsTheSdkPathsSaltAndParameters()
    {
        var (device, key) = Token2();
        var sdk = SdkFido2Keys.BuildAssertionParameters(CredentialId, PrfInput);

        var answer = Keys().GetHmacSecret(key, [(CredentialId, PrfInput)], Pin([]));

        var assert = Assert.Single(_fido.Asserts);
        Assert.Equal(sdk.RelyingParty.Id, assert.RpId);
        Assert.Equal(Assert.Single(sdk.AllowList!).Id.ToArray(), Assert.Single(assert.Allowed));
        Assert.Equal(Fido2Prf.Salt(PrfInput), assert.Salt);
        Assert.NotEqual(PrfInput, assert.Salt);
        Assert.Equal(Libfido2Params.ExtHmacSecret, assert.Extensions);
        Assert.False(sdk.Options.ContainsKey(AuthenticatorOptions.up)); // the SDK leaves up at its default: on
        Assert.Equal((int)FidoOpt.True, assert.Up);
        Assert.Equal(32, assert.ClientDataHash!.Length);
        Assert.Equal(PinText, assert.Pin);
        Assert.Equal(HMACSHA256.HashData(device.Secret, Fido2Prf.Salt(PrfInput)), answer.Output);
        Assert.Equal(CredentialId, answer.CredentialId);
        Assert.True(answer.UserVerified);
        Assert.Equal(0, _fido.Live);
    }

    [Fact]
    public void GetHmacSecret_ACredentialIdLeftOutOfTheAnswer_IsTheAllowedOne()
    {
        var (device, key) = Token2();
        device.OmitsAssertId = true;

        var answer = Keys().GetHmacSecret(key, [(CredentialId, PrfInput)], Pin([]));

        Assert.Equal(CredentialId, answer.CredentialId);
    }

    [Fact]
    public void GetHmacSecret_WithoutTheUvFlag_IsNotUserVerified()
    {
        var (device, key) = Token2();
        device.AssertFlags = Libfido2Params.FlagUserPresent;

        Assert.False(Keys().GetHmacSecret(key, [(CredentialId, PrfInput)], Pin([])).UserVerified);
    }

    [Fact]
    public void GetHmacSecret_AsksForThePinExactlyOnce()
    {
        var (_, key) = Token2();
        List<int?> asked = [];

        Keys().GetHmacSecret(key, [(CredentialId, PrfInput)], Pin(asked));

        Assert.Single(asked);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public void GetHmacSecret_NotExactlyOneAllowed_IsRefusedAsOnTheSdkPath(int count)
    {
        var (_, key) = Token2();
        var allowed = Enumerable.Range(0, count).Select(_ => (RandomNumberGenerator.GetBytes(64), PrfInput)).ToList();

        var mine = Assert.Throws<ArgumentException>(() => Keys().GetHmacSecret(key, allowed, NoPin));
        var sdks = Assert.Throws<ArgumentException>(() => new SdkFido2Keys().GetHmacSecret(key, allowed, NoPin));

        Assert.Equal(sdks.Message, mine.Message);
        Assert.Empty(_fido.Opened);
    }

    // --- AAGUIDs ---

    [Fact]
    public void Aaguid_TheToken2sBytes_AreReadBigEndian() =>
        Assert.Equal(Guid.Parse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf"),
            Fido2Aaguid.ToGuid(Convert.FromHexString("eabb46cce24180bfae9e96fa6d2975cf")));

    [Fact]
    public void Aaguid_NotSixteenBytes_IsEmpty() => Assert.Equal(Guid.Empty, Fido2Aaguid.ToGuid(new byte[15]));

    // --- Find ---

    [Fact]
    public void Find_ListsAToken2_WithItsAaguidPinAndRetries()
    {
        var (device, _) = Token2();
        device.Retries = 5;

        var key = Assert.Single(Keys().Find());

        Assert.Equal("/dev/hidraw3", key.Key.Id);
        Assert.Null(key.Serial);
        Assert.Equal(Guid.Parse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf"), key.Aaguid);
        Assert.True(key.PinSet);
        Assert.Equal(5, key.PinRetries);
        Assert.Equal(0, _fido.Live);
    }

    [Fact]
    public void Find_WithoutAPin_ReadsNoRetries()
    {
        var (device, _) = Token2();
        device.ClientPin = null;
        device.RetryCountResult = Libfido2Errors.PinNotSet;

        var key = Assert.Single(Keys().Find());

        Assert.False(key.PinSet);
        Assert.Null(key.PinRetries);
    }

    [Fact]
    public void Find_SkipsYubicoDevices()
    {
        _fido.AddDevice("/dev/hidraw1", vendor: 0x1050);
        Token2();

        Assert.Equal(["/dev/hidraw3"], Keys().Find().Select(k => k.Key.Id));
        Assert.DoesNotContain("/dev/hidraw1", _fido.Opened);
    }

    [Fact]
    public void Find_TheTestOnlyFlag_IncludesYubicoDevices()
    {
        _fido.AddDevice("/dev/hidraw1", vendor: 0x1050);

        Assert.Equal(["/dev/hidraw1"], Keys(includeYubico: true).Find().Select(k => k.Key.Id));
    }

    [Fact]
    public void Find_ADeviceWithoutHmacSecret_IsLeftOutWithANotice()
    {
        var plain = _fido.AddDevice("/dev/hidraw2");
        plain.Extensions.Remove("hmac-secret");
        Token2();
        var notices = new StringWriter();

        var keys = Keys(notices).Find();

        Assert.Equal(["/dev/hidraw3"], keys.Select(k => k.Key.Id));
        Assert.Equal(Fido2Texts.KeyLeftOut("HmacSecretUnsupported") + Environment.NewLine, notices.ToString());
    }

    [Fact]
    public void Find_OneUnreadableDeviceBesideAReadableOne_IsLeftOutWithANotice()
    {
        var bad = _fido.AddDevice("/dev/hidraw2");
        bad.CborInfoResult = Libfido2Errors.ChannelBusy;
        Token2();
        var notices = new StringWriter();

        var keys = Keys(notices, linux: false).Find();

        Assert.Equal(["/dev/hidraw3"], keys.Select(k => k.Key.Id));
        Assert.Equal(Fido2Texts.KeyLeftOut("FIDO_ERR_CHANNEL_BUSY") + Environment.NewLine, notices.ToString());
        Assert.Equal(0, _fido.Live);
    }

    [Fact]
    public void Find_NothingReadable_ThrowsTheFailure()
    {
        var bad = _fido.AddDevice("/dev/hidraw2");
        bad.CborInfoResult = Libfido2Errors.ChannelBusy;
        var notices = new StringWriter();

        var e = Assert.Throws<Fido2DeviceException>(() => Keys(notices).Find());

        Assert.Equal(Fido2Failure.Busy, e.Kind);
        Assert.Equal("", notices.ToString());
        Assert.Equal(0, _fido.Live);
    }

    [Fact]
    public void Find_ADeviceThatCantBeOpened_OnLinux_SaysThisUserHasNoAccess()
    {
        var locked = _fido.AddDevice("/dev/hidraw2");
        locked.OpenResult = Libfido2Errors.Internal;
        Token2();
        var notices = new StringWriter();

        Keys(notices, linux: true).Find();

        Assert.Equal(Fido2Texts.KeyLeftOut("OpenFailed:FIDO_ERR_INTERNAL") + Environment.NewLine + Fido2Texts.NoDeviceAccess + Environment.NewLine,
            notices.ToString());
    }

    [Fact]
    public void Find_ADeviceThatCantBeOpened_OnMacOs_HasNoAccessLine()
    {
        var locked = _fido.AddDevice("/dev/hidraw2");
        locked.OpenResult = Libfido2Errors.Internal;
        Token2();
        var notices = new StringWriter();

        Keys(notices, linux: false).Find();

        Assert.Equal(Fido2Texts.KeyLeftOut("OpenFailed:FIDO_ERR_INTERNAL") + Environment.NewLine, notices.ToString());
    }

    [Fact]
    public void Find_TheManifestFailing_Throws()
    {
        _fido.ManifestResult = Libfido2Errors.Internal;

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().Find());

        Assert.Equal("FIDO_ERR_INTERNAL", e.Detail);
        Assert.Equal(0, _fido.Live);
    }

    // --- FindHolder: the silent probe ---

    [Fact]
    public void FindHolder_IsSilent_UpOffNoPinNoExtensions()
    {
        var (device, _) = Token2();
        device.Holds.Add(Convert.ToHexString(CredentialId));

        var holder = Keys().FindHolder(CredentialId);

        Assert.Equal("/dev/hidraw3", holder!.Key.Id);
        var probe = Assert.Single(_fido.Asserts);
        Assert.Equal(1, probe.Up); // FIDO_OPT_FALSE: 0 would leave user presence on, and the key would blink
        Assert.True(probe.PinPointerNull);
        Assert.Null(probe.Extensions);
        Assert.Null(probe.Salt);
        Assert.Equal(Fido2SlotBlob.TswapRpId, probe.RpId);
        Assert.Equal(CredentialId, Assert.Single(probe.Allowed));
        Assert.Equal(0, _fido.Live);
    }

    [Theory]
    [InlineData(Libfido2Errors.NoCredentials)]
    [InlineData(Libfido2Errors.InvalidCredential)]
    public void FindHolder_BothDoesntHoldItCodes_MeanNone(int code)
    {
        var (device, _) = Token2();
        device.ProbeMissResult = code;

        Assert.Null(Keys().FindHolder(CredentialId));
    }

    [Fact]
    public void FindHolder_AFailingDeviceBesideTheHolder_FindsTheHolder()
    {
        var bad = _fido.AddDevice("/dev/hidraw2");
        bad.ProbeResult = Libfido2Errors.ChannelBusy;
        var (device, _) = Token2();
        device.Holds.Add(Convert.ToHexString(CredentialId));

        Assert.Equal("/dev/hidraw3", Keys().FindHolder(CredentialId)!.Key.Id);
    }

    [Fact]
    public void FindHolder_AFailingDeviceAndNoHolder_Fails()
    {
        var bad = _fido.AddDevice("/dev/hidraw2");
        bad.ProbeResult = Libfido2Errors.ChannelBusy;
        Token2();

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().FindHolder(CredentialId));

        Assert.Equal(Fido2Failure.Busy, e.Kind);
        Assert.Equal(0, _fido.Live);
    }

    [Fact]
    public void FindHolder_SkipsYubicoDevices()
    {
        var yubikey = _fido.AddDevice("/dev/hidraw1", vendor: 0x1050);
        yubikey.Holds.Add(Convert.ToHexString(CredentialId));

        Assert.Null(Keys().FindHolder(CredentialId));
        Assert.Empty(_fido.Opened);
    }

    // --- SetPin ---

    [Fact]
    public void SetPin_AKeyWithoutAPin_SendsTheNewPinOnce()
    {
        var (device, key) = Token2();
        device.ClientPin = false;
        List<int?> asked = [];

        Keys().SetPin(key, Pin(asked));

        Assert.Equal([("/dev/hidraw3", (string?)PinText)], _fido.PinsSet);
        Assert.Single(asked);
        Assert.Equal(0, _fido.Live);
    }

    [Fact]
    public void SetPin_AKeyWithAPin_IsRefused()
    {
        var (_, key) = Token2();

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().SetPin(key, NoPin));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("PinAlreadySet", e.Detail);
        Assert.Empty(_fido.PinsSet);
    }

    // --- errors ---

    [Theory]
    [InlineData(Libfido2Errors.PinBlocked, Fido2Failure.PinBlocked, "FIDO_ERR_PIN_BLOCKED")]
    [InlineData(Libfido2Errors.PinNotSet, Fido2Failure.NoPin, "FIDO_ERR_PIN_NOT_SET")]
    [InlineData(Libfido2Errors.NoCredentials, Fido2Failure.NoCredential, "FIDO_ERR_NO_CREDENTIALS")]
    [InlineData(Libfido2Errors.InvalidCredential, Fido2Failure.NoCredential, "FIDO_ERR_INVALID_CREDENTIAL")]
    [InlineData(Libfido2Errors.CredentialExcluded, Fido2Failure.CredentialExcluded, "FIDO_ERR_CREDENTIAL_EXCLUDED")]
    [InlineData(Libfido2Errors.ActionTimeout, Fido2Failure.TimedOut, "FIDO_ERR_ACTION_TIMEOUT")]
    [InlineData(Libfido2Errors.UserActionTimeout, Fido2Failure.TimedOut, "FIDO_ERR_USER_ACTION_TIMEOUT")]
    [InlineData(Libfido2Errors.OperationDenied, Fido2Failure.Cancelled, "FIDO_ERR_OPERATION_DENIED")]
    [InlineData(Libfido2Errors.KeepaliveCancel, Fido2Failure.Cancelled, "FIDO_ERR_KEEPALIVE_CANCEL")]
    [InlineData(Libfido2Errors.ChannelBusy, Fido2Failure.Busy, "FIDO_ERR_CHANNEL_BUSY")]
    [InlineData(Libfido2Errors.UnsupportedExtension, Fido2Failure.Unsupported, "FIDO_ERR_UNSUPPORTED_EXTENSION")]
    [InlineData(Libfido2Errors.UnsupportedOption, Fido2Failure.Unsupported, "FIDO_ERR_UNSUPPORTED_OPTION")]
    [InlineData(Libfido2Errors.PinPolicyViolation, Fido2Failure.Other, "FIDO_ERR_PIN_POLICY_VIOLATION")]
    [InlineData(Libfido2Errors.Rx, Fido2Failure.Other, "FIDO_ERR_RX")]
    [InlineData(0x5d, Fido2Failure.Other, "FIDO_ERR_0x5d")]
    public void Errors_MapToAKindAndTheConstantsName(int code, Fido2Failure kind, string detail)
    {
        foreach (var operation in new[] { "make", "assert" })
        {
            var fido = new FakeLibfido2();
            var device = fido.AddDevice("/dev/hidraw3");
            device.MakeCredResult = code;
            device.AssertResult = code;
            var keys = new Libfido2Fido2Keys(fido, null, null, linux: true, includeYubico: false);
            var key = new Fido2KeyRef("/dev/hidraw3");

            var e = Assert.Throws<Fido2DeviceException>(() =>
            {
                if (operation == "make")
                    keys.MakeCredential(key, new byte[16], [], Pin([]));
                else
                    keys.GetHmacSecret(key, [(CredentialId, PrfInput)], Pin([]));
            });

            Assert.Equal(kind, e.Kind);
            Assert.Equal(detail, e.Detail);
            Assert.Equal(0, fido.Live);
        }
    }

    [Fact]
    public void Errors_NeverCarryFidoStrerrsProse()
    {
        var (device, key) = Token2();
        device.MakeCredResult = Libfido2Errors.Rx;

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().MakeCredential(key, new byte[16], [], Pin([])));

        Assert.DoesNotContain("prose", e.Message);
        Assert.DoesNotContain("prose", e.Detail);
    }

    [Theory]
    [InlineData(Libfido2Errors.PinInvalid, 5, Fido2Failure.PinWrong, "FIDO_ERR_PIN_INVALID")]
    [InlineData(Libfido2Errors.PinAuthBlocked, 5, Fido2Failure.PinNeedsReinsert, "FIDO_ERR_PIN_AUTH_BLOCKED")]
    [InlineData(Libfido2Errors.PinInvalid, 0, Fido2Failure.PinBlocked, "FIDO_ERR_PIN_INVALID")]
    [InlineData(Libfido2Errors.PinAuthBlocked, 0, Fido2Failure.PinBlocked, "FIDO_ERR_PIN_AUTH_BLOCKED")]
    public void WrongPin_ReadsTheRetriesAfterwards(int code, int retries, Fido2Failure kind, string detail)
    {
        var (device, key) = Token2();
        device.AssertResult = code;
        device.Retries = retries; // what the key reports after the refusal

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().GetHmacSecret(key, [(CredentialId, PrfInput)], Pin([])));

        Assert.Equal(kind, e.Kind);
        Assert.Equal(retries, e.RetriesLeft);
        Assert.Equal(detail, e.Detail);
    }

    [Fact]
    public void WrongPin_TheRetriesUnreadable_AreUnknown()
    {
        var (device, key) = Token2();
        device.MakeCredResult = Libfido2Errors.PinInvalid;
        device.RetryCountResult = Libfido2Errors.Rx;

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().MakeCredential(key, new byte[16], [], Pin([])));

        Assert.Equal(Fido2Failure.PinWrong, e.Kind);
        Assert.Null(e.RetriesLeft);
    }

    [Fact]
    public void AKeyGoneSinceItWasListed_IsNotPluggedIn()
    {
        var (device, key) = Token2();
        device.Gone = true;

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().GetHmacSecret(key, [(CredentialId, PrfInput)], NoPin));

        Assert.Equal(Fido2Failure.NotPluggedIn, e.Kind);
        Assert.Equal(0, _fido.Live);
    }

    [Fact]
    public void AListedKeyThatCantBeOpened_IsOpenFailed()
    {
        var (device, key) = Token2();
        device.OpenResult = Libfido2Errors.Internal;

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().GetHmacSecret(key, [(CredentialId, PrfInput)], NoPin));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("OpenFailed:FIDO_ERR_INTERNAL", e.Detail);
    }

    // --- Product (brief T19, item 4): USB strings, untrusted ---

    [Fact]
    public void Find_TheProductIsTheUsbProductString()
    {
        Token2();

        Assert.Equal("Token2 PIN+ Dual", Assert.Single(Keys().Find()).Product);
    }

    [Theory]
    [InlineData("Token2", "Token2 PIN+ Dual", "Token2 PIN+ Dual")]          // the product already starts with the maker
    [InlineData("Nitrokey", "Nitrokey 3", "Nitrokey 3")]
    [InlineData("SoloKeys", "Solo 2", "SoloKeys Solo 2")]
    [InlineData(null, "Solo 2", "Solo 2")]
    [InlineData("Feitian", null, "Feitian")]
    [InlineData("  Token2 ", " PIN+ ", "Token2 PIN+")]
    [InlineData("\u001b[31mEvil\u001b[0m", "Key\nNext line", "[31mEvil[0m KeyNext line")] // ESC and newline gone
    [InlineData("", "", null)]
    [InlineData(null, null, null)]
    [InlineData("\u001b", "\r\n", null)]
    public void ProductName_DropsControlCharactersAndAvoidsRepeatingTheMaker(string? manufacturer, string? product, string? expected)
    {
        var name = Libfido2Fido2Keys.ProductName(manufacturer, product);

        Assert.Equal(expected, name);
        Assert.DoesNotContain(name ?? "", c => char.IsControl(c));
    }

    [Fact]
    public void ProductName_IsAtMost64Characters()
    {
        var name = Libfido2Fido2Keys.ProductName("Maker", new string('x', 100));

        Assert.Equal(64, name!.Length);
        Assert.StartsWith("Maker xxx", name);
    }

    // --- fix round 1 (review F4, F6) ---

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(64)]
    public void GetHmacSecret_AnOutputThatIsNot32Bytes_IsRefusedAndZeroed(int length)
    {
        var (device, key) = Token2();
        device.HmacSecretLength = length;

        var e = Assert.Throws<Fido2DeviceException>(() => Keys().GetHmacSecret(key, [(CredentialId, PrfInput)], Pin([])));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("BadHmacSecretLength", e.Detail);
        Assert.All(Assert.Single(_fido.HmacSecretsReturned), b => Assert.Equal(0, b));
        Assert.Equal(0, _fido.Live);
    }

    [Theory]
    [InlineData("Token2\u202E", "PIN+ Dual", "Token2 PIN+ Dual")]   // RIGHT-TO-LEFT OVERRIDE
    [InlineData("Evil\u200F", "Key\u2066x\u2069", "Evil Keyx")]      // RLM, isolates
    [InlineData("\u200B\uFEFF", "\u202D", null)]                     // zero-width space, BOM, LRO: nothing left
    public void ProductName_DropsUnicodeFormatCharacters(string? manufacturer, string? product, string? expected)
    {
        var name = Libfido2Fido2Keys.ProductName(manufacturer, product);

        Assert.Equal(expected, name);
        Assert.DoesNotContain(name ?? "", c => char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format);
    }

    [Fact]
    public void ProductName_TheCapNeverCutsASurrogatePair()
    {
        // 63 characters, then an emoji (a surrogate pair) across the 64-character cap.
        var name = Libfido2Fido2Keys.ProductName(null, new string('x', 63) + "\U0001F600" + "yy");

        Assert.Equal(new string('x', 63), name);
    }

    [Fact]
    public void ProductName_ASurrogatePairInsideTheCapIsKept()
    {
        var name = Libfido2Fido2Keys.ProductName(null, new string('x', 62) + "\U0001F600" + "yy");

        Assert.Equal(new string('x', 62) + "\U0001F600", name);
        Assert.Equal(64, name!.Length);
    }
}
