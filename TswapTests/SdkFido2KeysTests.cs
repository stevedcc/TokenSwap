using System.Formats.Cbor;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Fido2;
using TswapCore.Vault.Interop;
using Xunit;
using Yubico.Core.Iso7816;
using Yubico.PlatformInterop;
using Yubico.YubiKey;
using Yubico.YubiKey.Fido2;
using Yubico.YubiKey.Fido2.Commands;
using Yubico.YubiKey.Fido2.Cose;
using Yubico.YubiKey.Fido2.PinProtocols;
using SdkFido2Exception = Yubico.YubiKey.Fido2.Fido2Exception;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 4: the pure parts of <see cref="SdkFido2Keys"/>, Yubico's SDK as the FIDO2 device on Linux and
/// macOS. The SDK session is replaced by <see cref="FakeSession"/> (no key is touched); what is pinned here is what
/// tswap hands the SDK (parameters, PIN token request, salt), how the SDK's failures become
/// <see cref="Fido2DeviceException"/>s, and the PIN rules (one request, no retry, zeroed after use).
/// </summary>
public class SdkFido2KeysTests
{
    private static readonly Fido2KeyRef Key = new("fido2-1");
    private static readonly byte[] CredentialId = [.. Enumerable.Range(1, 64).Select(i => (byte)i)];
    private static readonly byte[] PrfInput = [.. Enumerable.Range(100, 32).Select(i => (byte)i)];
    private static readonly byte[] Pin = "123456"u8.ToArray();

    // ---- SdkFido2Keys_MapsSdkExceptions ----

    public static TheoryData<CtapStatus, Fido2Failure, string> CtapStatuses => new()
    {
        { CtapStatus.PinInvalid, Fido2Failure.PinWrong, "PinInvalid" },
        { CtapStatus.PinBlocked, Fido2Failure.PinBlocked, "PinBlocked" },
        // CTAP2_ERR_PIN_AUTH_BLOCKED (0x34): the SDK calls it PowerCycleRequired.
        { CtapStatus.PowerCycleRequired, Fido2Failure.PinNeedsReinsert, "PowerCycleRequired" },
        { CtapStatus.NoCredentials, Fido2Failure.NoCredential, "NoCredentials" },
        // CTAP2_ERR_INVALID_CREDENTIAL (0x22): not in the SDK's enum.
        { (CtapStatus)0x22, Fido2Failure.NoCredential, "InvalidCredential" },
        { CtapStatus.OperationDenied, Fido2Failure.Cancelled, "OperationDenied" },
        { CtapStatus.KeepAliveCancel, Fido2Failure.Cancelled, "KeepAliveCancel" },
        { CtapStatus.ActionTimeout, Fido2Failure.TimedOut, "ActionTimeout" },
        { CtapStatus.UserActionTimeout, Fido2Failure.TimedOut, "UserActionTimeout" },
        { CtapStatus.CredentialExcluded, Fido2Failure.CredentialExcluded, "CredentialExcluded" },
        { CtapStatus.PinNotSet, Fido2Failure.NoPin, "PinNotSet" },
        { CtapStatus.ChannelBusy, Fido2Failure.Busy, "ChannelBusy" },
        { CtapStatus.PinAuthInvalid, Fido2Failure.Other, "PinAuthInvalid" },
        { CtapStatus.UnsupportedOption, Fido2Failure.Other, "UnsupportedOption" },
        { (CtapStatus)0xF3, Fido2Failure.Other, "0xF3" },
    };

    [Theory]
    [MemberData(nameof(CtapStatuses))]
    public void SdkFido2Keys_MapsSdkExceptions_CtapStatus(CtapStatus status, Fido2Failure expected, string detail)
    {
        var fromStatus = SdkFido2Keys.FromStatus(status);
        var fromException = SdkFido2Keys.Classify(new SdkFido2Exception(status, "the SDK's prose"));

        Assert.Equal(expected, fromStatus.Kind);
        Assert.Equal(detail, fromStatus.Detail);
        Assert.Equal(expected, fromException.Kind);
        Assert.Equal(detail, fromException.Detail);
    }

    public static TheoryData<Exception, Fido2Failure, string> OtherSdkExceptions => new()
    {
        // Fido2Session's high-level calls (not used for the ceremony itself, but reachable through the session).
        { new TimeoutException("The YubiKey was not touched in the allotted time."), Fido2Failure.TimedOut, "TimeoutException" },
        { new OperationCanceledException("The user cancelled the operation."), Fido2Failure.Cancelled, "OperationCanceledException" },
        { new SecurityException("There are no more retries remaining."), Fido2Failure.PinBlocked, "PinBlocked" },
        { new SecurityException("something else"), Fido2Failure.Other, "SecurityException" },
        { new InvalidOperationException("The YubiKey does not have a PIN set."), Fido2Failure.NoPin, "PinNotSet" },
        { new SdkFido2Exception("status lost"), Fido2Failure.Other, "Fido2Exception" },
        // A CTAPHID error frame read as a CTAP status: SW 0x6F00 (or 0x6700/0x6900/0x6A00) has a low byte of Ok.
        { new SdkFido2Exception(CtapStatus.Ok, "status Ok, yet an exception"), Fido2Failure.Other, "CtapHidError" },
        // macOS: another program holds the key's HID device exclusively (kIOReturnExclusiveAccess).
        { new PlatformApiException("IOHIDDeviceOpen", unchecked((int)0xE00002C5), "Can't open IOKit device."), Fido2Failure.Busy, "ExclusiveAccess" },
        { new PlatformApiException("No IOKit registry entry was found for the device."), Fido2Failure.NotPluggedIn, "RegistryEntryNotFound" },
        { new PlatformApiException("Could not open HID node on Linux."), Fido2Failure.Other, "HidOpenFailed" },
        { new PlatformApiException("A HIDRAW operation failed."), Fido2Failure.Other, "HidrawFailed" },
        { new UnauthorizedAccessException("Access is denied."), Fido2Failure.Other, "AccessDenied" },
        { new MalformedYubiKeyResponseException("bad"), Fido2Failure.Other, "MalformedYubiKeyResponseException" },
    };

    [Theory]
    [MemberData(nameof(OtherSdkExceptions))]
    public void SdkFido2Keys_MapsSdkExceptions_OtherExceptions(Exception sdkException, Fido2Failure expected, string detail)
    {
        var e = SdkFido2Keys.Classify(sdkException);

        Assert.Equal(expected, e.Kind);
        Assert.Equal(detail, e.Detail);
        Assert.Null(e.RetriesLeft);
    }

    [Fact]
    public void SdkFido2Keys_MapsSdkExceptions_DeviceExceptionPassesThroughUnchanged()
    {
        var mine = new Fido2DeviceException(Fido2Failure.Cancelled, 3, "PinEntryCancelled");

        Assert.Same(mine, SdkFido2Keys.Classify(mine));
    }

    [Theory]
    [InlineData(5, null, Fido2Failure.PinWrong, "PinInvalid")]
    [InlineData(5, false, Fido2Failure.PinWrong, "PinInvalid")]
    [InlineData(null, null, Fido2Failure.PinWrong, "PinInvalid")]
    [InlineData(5, true, Fido2Failure.PinNeedsReinsert, "PinAuthBlocked")]
    [InlineData(0, null, Fido2Failure.PinBlocked, "PinBlocked")]
    public void SdkFido2Keys_MapsSdkExceptions_RefusedPinCarriesTheRetriesTheSdkReports(
        int? retries, bool? reinsert, Fido2Failure expected, string detail)
    {
        var e = SdkFido2Keys.PinRefused(retries, reinsert);

        Assert.Equal(expected, e.Kind);
        Assert.Equal(retries, e.RetriesLeft);
        Assert.Equal(detail, e.Detail);
    }

    [Fact]
    public void SdkFido2Keys_MapsSdkExceptions_WrongPinStopsBeforeTheAssertion()
    {
        var session = new FakeSession { VerifyResult = false, VerifyRetries = 5 };
        var keys = Keys(session);

        var e = Assert.Throws<Fido2DeviceException>(() => keys.GetHmacSecret(Key, [(CredentialId, PrfInput)], _ => Pin.ToArray()));

        Assert.Equal(Fido2Failure.PinWrong, e.Kind);
        Assert.Equal(5, e.RetriesLeft);
        Assert.Equal(0, session.Assertions);
        Assert.True(session.Disposed);
    }

    [Fact]
    public void SdkFido2Keys_MapsSdkExceptions_SessionFailureBecomesDeviceException()
    {
        var session = new FakeSession { AssertionFailure = new PlatformApiException("IOHIDDeviceOpen", unchecked((int)0xE00002C5), "Can't open IOKit device.") };
        var keys = Keys(session);

        var e = Assert.Throws<Fido2DeviceException>(() => keys.GetHmacSecret(Key, [(CredentialId, PrfInput)], _ => Pin.ToArray()));

        Assert.Equal(Fido2Failure.Busy, e.Kind);
        Assert.DoesNotContain("IOKit", e.Message);
    }

    [Fact]
    public void SdkFido2Keys_MapsSdkExceptions_KeyWithoutPinRefusedBeforeAskingForOne()
    {
        var asked = 0;
        var keys = Keys(new FakeSession { PinSet = false });

        var e = Assert.Throws<Fido2DeviceException>(() => keys.GetHmacSecret(Key, [(CredentialId, PrfInput)], _ =>
        {
            asked++;
            return Pin.ToArray();
        }));

        Assert.Equal(Fido2Failure.NoPin, e.Kind);
        Assert.Equal(0, asked);
    }

    // ---- SdkFido2Keys_KeyCollector_RefusesRetry ----

    [Fact]
    public void SdkFido2Keys_KeyCollector_RefusesRetry()
    {
        var asked = 0;
        var collector = new SdkPinCollector(_ =>
        {
            asked++;
            return Pin.ToArray();
        });

        var answered = collector.Collect(new KeyEntryData { Request = KeyEntryRequest.VerifyFido2Pin, IsRetry = true, RetriesRemaining = 4 });

        Assert.False(answered);
        Assert.Equal(0, asked);
        var e = Assert.Throws<Fido2DeviceException>(collector.ThrowIfCaptured);
        Assert.Equal(Fido2Failure.PinWrong, e.Kind);
        Assert.Equal(4, e.RetriesLeft);
    }

    [Fact]
    public void SdkFido2Keys_KeyCollector_AnswersThePinOnceThenRefuses()
    {
        var asked = 0;
        byte[]? handedOut = null;
        var collector = new SdkPinCollector(_ =>
        {
            asked++;
            handedOut = Pin.ToArray();
            return handedOut;
        });
        var first = new KeyEntryData { Request = KeyEntryRequest.VerifyFido2Pin };

        Assert.True(collector.Collect(first));
        Assert.Equal(Pin, first.GetCurrentValue().ToArray());
        Assert.All(handedOut!, b => Assert.Equal(0, b));

        Assert.False(collector.Collect(new KeyEntryData { Request = KeyEntryRequest.VerifyFido2Pin }));
        Assert.Equal(1, asked);
        Assert.Equal(Fido2Failure.Other, Assert.Throws<Fido2DeviceException>(collector.ThrowIfCaptured).Kind);
    }

    [Fact]
    public void SdkFido2Keys_KeyCollector_DelegateRefusalIsCapturedUnchanged()
    {
        var refusal = new Fido2DeviceException(Fido2Failure.Cancelled, null, "PinEntryCancelled");
        var collector = new SdkPinCollector(_ => throw refusal);
        var data = new KeyEntryData { Request = KeyEntryRequest.VerifyFido2Pin };

        Assert.False(collector.Collect(data));
        Assert.True(data.GetCurrentValue().IsEmpty);
        Assert.Same(refusal, Assert.Throws<Fido2DeviceException>(collector.ThrowIfCaptured));
    }

    [Theory]
    [InlineData(KeyEntryRequest.VerifyFido2Uv, false)]
    [InlineData(KeyEntryRequest.SetFido2Pin, false)]
    [InlineData(KeyEntryRequest.ChangeFido2Pin, false)]
    [InlineData(KeyEntryRequest.TouchRequest, true)]
    [InlineData(KeyEntryRequest.Release, true)]
    public void SdkFido2Keys_KeyCollector_AnswersNothingButThePin(KeyEntryRequest request, bool expected)
    {
        var asked = 0;
        var collector = new SdkPinCollector(_ =>
        {
            asked++;
            return Pin.ToArray();
        });

        Assert.Equal(expected, collector.Collect(new KeyEntryData { Request = request }));
        Assert.Equal(0, asked);
    }

    [Fact]
    public void SdkFido2Keys_KeyCollector_CapturedRefusalWinsOverTheSdksException()
    {
        var session = new FakeSession
        {
            // The SDK asks the collector again after a wrong PIN, the collector refuses, and the SDK gives up with its
            // own exception (Fido2Session.VerifyPin: OperationCanceledException).
            OnAssertion = collector =>
            {
                collector.Collect(new KeyEntryData { Request = KeyEntryRequest.VerifyFido2Pin, IsRetry = true, RetriesRemaining = 2 });
                throw new OperationCanceledException("The user cancelled the PIN collection operation.");
            },
        };

        var e = Assert.Throws<Fido2DeviceException>(() => Keys(session).GetHmacSecret(Key, [(CredentialId, PrfInput)], _ => Pin.ToArray()));

        Assert.Equal(Fido2Failure.PinWrong, e.Kind);
        Assert.Equal(2, e.RetriesLeft);
    }

    [Fact]
    public void SdkFido2Keys_KeyCollector_CapturedRefusalWinsOverADeviceException()
    {
        var session = new FakeSession
        {
            OnAssertion = collector =>
            {
                collector.Collect(new KeyEntryData { Request = KeyEntryRequest.VerifyFido2Pin, IsRetry = true, RetriesRemaining = 2 });
                throw new Fido2DeviceException(Fido2Failure.Other, null, "PinAuthInvalid");
            },
        };

        var e = Assert.Throws<Fido2DeviceException>(() => Keys(session).GetHmacSecret(Key, [(CredentialId, PrfInput)], _ => Pin.ToArray()));

        Assert.Equal(Fido2Failure.PinWrong, e.Kind);
        Assert.Equal(2, e.RetriesLeft);
    }

    [Fact]
    public void SdkFido2Keys_KeyCollector_SecondPinRequestRefusedWithoutCallingTheDelegate()
    {
        var session = new FakeSession
        {
            // The SDK asks for a PIN after tswap's own verification used it.
            OnAssertion = collector =>
            {
                collector.Collect(new KeyEntryData { Request = KeyEntryRequest.VerifyFido2Pin });
                throw new OperationCanceledException("The user cancelled the PIN collection operation.");
            },
        };
        var calls = 0;

        var e = Assert.Throws<Fido2DeviceException>(() => Keys(session).GetHmacSecret(Key, [(CredentialId, PrfInput)], _ =>
        {
            calls++;
            return Pin.ToArray();
        }));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("PinRequestedTwice", e.Detail);
        Assert.Equal(1, calls);
    }

    [Fact]
    public void SdkFido2Keys_KeyCollector_PromptRefusalPropagatesUnchangedWithoutVerifying()
    {
        var refusal = new Fido2DeviceException(Fido2Failure.Cancelled, null, "PinEntryCancelled");
        var session = new FakeSession();
        var keys = Keys(session);

        var e = Assert.Throws<Fido2DeviceException>(() => keys.GetHmacSecret(Key, [(CredentialId, PrfInput)], _ => throw refusal));

        Assert.Same(refusal, e);
        Assert.Empty(session.Verifications);
        Assert.Equal(0, session.Assertions);
    }

    // ---- SdkFido2Keys_UvAssertion_UsesPinTokenWithGetAssertionPermission ----

    [Fact]
    public void SdkFido2Keys_UvAssertion_UsesPinTokenWithGetAssertionPermission()
    {
        byte[]? handedOut = null;
        int? retriesAsked = -1;
        var session = new FakeSession();
        var keys = Keys(session);

        var answer = keys.GetHmacSecret(Key, [(CredentialId, PrfInput)], retries =>
        {
            retriesAsked = retries;
            handedOut = Pin.ToArray();
            return handedOut;
        });

        var verification = Assert.Single(session.Verifications);
        Assert.Equal(PinUvAuthTokenPermissions.GetAssertion, verification.Permissions);
        Assert.Equal(Fido2SlotBlob.TswapRpId, verification.RpId);
        Assert.Equal(Pin, verification.Pin);
        Assert.Equal(["verify", "assert"], session.Order);
        Assert.Null(retriesAsked);
        Assert.All(handedOut!, b => Assert.Equal(0, b));
        Assert.Equal(session.Output, answer.Output);
        Assert.True(session.Disposed);
    }

    [Fact]
    public void SdkFido2Keys_UvAssertion_KeyWithoutTokenPermissionsUsesALegacyPinToken()
    {
        var session = new FakeSession { PinUvAuthTokenSupported = false };

        Keys(session).GetHmacSecret(Key, [(CredentialId, PrfInput)], _ => Pin.ToArray());

        var verification = Assert.Single(session.Verifications);
        Assert.Null(verification.Permissions);
        Assert.Null(verification.RpId);
    }

    [Fact]
    public void SdkFido2Keys_UvAssertion_AssertsForTheOneAllowedCredentialWithTouch()
    {
        var session = new FakeSession();

        Keys(session).GetHmacSecret(Key, [(CredentialId, PrfInput)], _ => Pin.ToArray());

        var parameters = session.LastAssertion!;
        Assert.Equal(Fido2SlotBlob.TswapRpId, parameters.RelyingParty.Id);
        Assert.Equal(CredentialId, Assert.Single(parameters.AllowList!).Id.ToArray());
        Assert.False(parameters.Options.ContainsKey(AuthenticatorOptions.up));
        Assert.False(parameters.Options.ContainsKey(AuthenticatorOptions.uv));
    }

    [Fact]
    public void SdkFido2Keys_UvAssertion_TakesExactlyOneSlot()
    {
        var keys = Keys(new FakeSession());

        Assert.Throws<ArgumentException>(() => keys.GetHmacSecret(Key, [(CredentialId, PrfInput), (CredentialId, PrfInput)], _ => Pin.ToArray()));
        Assert.Throws<ArgumentNullException>(() => keys.GetHmacSecret(null, [(CredentialId, PrfInput)], _ => Pin.ToArray()));
    }

    [Fact]
    public void SdkFido2Keys_MakeCredential_UsesPinTokenWithMakeCredentialPermission()
    {
        byte[]? handedOut = null;
        var session = new FakeSession();
        var made = Keys(session).MakeCredential(Key, RandomNumberGenerator.GetBytes(16), [], _ => handedOut = Pin.ToArray());

        var verification = Assert.Single(session.Verifications);
        Assert.Equal(PinUvAuthTokenPermissions.MakeCredential, verification.Permissions);
        Assert.Equal(Fido2SlotBlob.TswapRpId, verification.RpId);
        Assert.Equal(["verify", "make"], session.Order);
        Assert.All(handedOut!, b => Assert.Equal(0, b));
        Assert.Same(session.Made, made);
    }

    [Fact]
    public void SdkFido2Keys_SetPin_SendsTheNewPinOnceAndZeroesIt()
    {
        byte[]? handedOut = null;
        var session = new FakeSession { PinSet = false };

        Keys(session).SetPin(Key, _ => handedOut = Pin.ToArray());

        Assert.Equal(Pin, Assert.Single(session.NewPins));
        Assert.All(handedOut!, b => Assert.Equal(0, b));
        Assert.Empty(session.Verifications);
    }

    [Fact]
    public void SdkFido2Keys_SetPin_KeyWithAPinRefusedBeforeAskingForOne()
    {
        var asked = 0;
        var session = new FakeSession { PinSet = true };

        var e = Assert.Throws<Fido2DeviceException>(() => Keys(session).SetPin(Key, _ =>
        {
            asked++;
            return Pin.ToArray();
        }));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("PinAlreadySet", e.Detail);
        Assert.Equal(0, asked);
        Assert.Empty(session.NewPins);
    }

    // ---- SdkFido2Keys_MakeCredentialParameters_AreTswaps ----

    [Fact]
    public void SdkFido2Keys_MakeCredentialParameters_AreTswaps()
    {
        var userId = RandomNumberGenerator.GetBytes(16);
        byte[] excludedA = [.. Enumerable.Repeat((byte)0xA1, 48)];
        byte[] excludedB = [.. Enumerable.Repeat((byte)0xB2, 64)];

        var parameters = SdkFido2Keys.BuildMakeCredentialParameters(userId, [excludedA, excludedB]);

        Assert.Equal(Fido2SlotBlob.TswapRpId, parameters.RelyingParty.Id);
        Assert.Equal(false, Assert.Contains(AuthenticatorOptions.rk, parameters.Options));
        // UV comes from the PIN token (pinUvAuthParam), not the "uv" option: a key without built-in UV refuses that.
        Assert.False(parameters.Options.ContainsKey(AuthenticatorOptions.uv));
        Assert.Equal([0xF5], Assert.Contains(Yubico.YubiKey.Fido2.Extensions.HmacSecret, parameters.Extensions));
        var algorithm = Assert.Single(parameters.Algorithms);
        Assert.Equal("public-key", algorithm.Item1);
        Assert.Equal(CoseAlgorithmIdentifier.ES256, algorithm.Item2);
        Assert.Equal([excludedA, excludedB], parameters.ExcludeList!.Select(c => c.Id.ToArray()));
        Assert.All(parameters.ExcludeList!, c => Assert.Equal("public-key", c.Type));
        Assert.Equal(userId, parameters.UserEntity.Id.ToArray());
        Assert.Equal("tswap", parameters.UserEntity.Name);
        Assert.Null(parameters.UserEntity.DisplayName);
        Assert.Equal(32, parameters.ClientDataHash.Length);
        Assert.Null(parameters.PinUvAuthParam);
    }

    [Theory]
    [InlineData(15)]
    [InlineData(17)]
    public void SdkFido2Keys_MakeCredentialParameters_UserIdIsSixteenBytes(int length) =>
        Assert.Throws<ArgumentException>(() => SdkFido2Keys.BuildMakeCredentialParameters(new byte[length], []));

    // ---- SdkFido2Keys_SaltIsPrfOfInput ----

    [Fact]
    public void SdkFido2Keys_SaltIsPrfOfInput()
    {
        var session = new FakeSession();

        Keys(session).GetHmacSecret(Key, [(CredentialId, PrfInput)], _ => Pin.ToArray());

        Assert.Equal(Fido2Prf.Salt(PrfInput), EncodedSalt(session.LastAssertion!));
    }

    // Final review: both paths hand the key the same hmac-secret salt for one PRF input, so a slot enrolled on one OS
    // opens on the others (Windows passes it raw under WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG).
    [Fact]
    public void SdkAndWindowsPaths_SendTheKeyTheSameSalt()
    {
        var session = new FakeSession();
        Keys(session).GetHmacSecret(Key, [(CredentialId, PrfInput)], _ => Pin.ToArray());
        var sdkSalt = EncodedSalt(session.LastAssertion!);

        using var call = WebAuthnFido2Keys.BuildGetAssertion([(CredentialId, PrfInput)]);
        var options = Marshal.PtrToStructure<WebAuthnGetAssertionOptionsV6>(call.Options);
        var values = Marshal.PtrToStructure<WebAuthnHmacSecretSaltValues>(options.pHmacSecretSaltValues);
        var entry = Marshal.PtrToStructure<WebAuthnCredWithHmacSecretSalt>(values.pCredWithHmacSecretSaltList);
        var salt = Marshal.PtrToStructure<WebAuthnHmacSecretSalt>(entry.pHmacSecretSalt);
        var windowsSalt = new byte[salt.cbFirst];
        Marshal.Copy(salt.pbFirst, windowsSalt, 0, windowsSalt.Length);

        Assert.Equal(WebAuthn.AuthenticatorHmacSecretValuesFlag, options.dwFlags & WebAuthn.AuthenticatorHmacSecretValuesFlag);
        Assert.Equal(32, sdkSalt.Length);
        Assert.Equal(sdkSalt, windowsSalt);
    }

    // ---- FindHolder's silent probe ----

    [Fact]
    public void SdkFido2Keys_ProbeIsSilent()
    {
        var parameters = SdkFido2Keys.BuildProbeParameters(CredentialId);

        Assert.Equal(Fido2SlotBlob.TswapRpId, parameters.RelyingParty.Id);
        Assert.Equal(CredentialId, Assert.Single(parameters.AllowList!).Id.ToArray());
        Assert.Equal(false, Assert.Contains(AuthenticatorOptions.up, parameters.Options));
        Assert.False(parameters.Options.ContainsKey(AuthenticatorOptions.uv));
        Assert.Null(parameters.PinUvAuthParam);
        Assert.Null(parameters.Protocol);
        Assert.Empty(parameters.Extensions);
    }

    [Theory]
    [InlineData(CtapStatus.Ok, true)]
    [InlineData(CtapStatus.NoCredentials, false)]
    [InlineData((CtapStatus)0x22, false)]
    public void SdkFido2Keys_ProbeAnswer_HoldsOrNot(CtapStatus status, bool holds) =>
        Assert.Equal(holds, SdkFido2Keys.ProbeHolds(CtapAnswer(status)));

    [Theory]
    [InlineData(CtapStatus.PinRequired, Fido2Failure.Other)]
    [InlineData(CtapStatus.ChannelBusy, Fido2Failure.Busy)]
    public void SdkFido2Keys_ProbeAnswer_OtherStatusesFail(CtapStatus status, Fido2Failure expected) =>
        Assert.Equal(expected, Assert.Throws<Fido2DeviceException>(() => SdkFido2Keys.ProbeHolds(CtapAnswer(status))).Kind);

    public static TheoryData<byte, Fido2Failure, string> CtapHidErrors => new()
    {
        // ERR_CHANNEL_BUSY: another process is mid-transaction on the shared hidraw node.
        { 0x06, Fido2Failure.Busy, "ChannelBusy" },
        // ERR_MSG_TIMEOUT.
        { 0x05, Fido2Failure.TimedOut, "MessageTimeout" },
        { 0x7F, Fido2Failure.Other, "CtapHidError0x7F" },
        // ERR_INVALID_CMD, ERR_INVALID_PAR, ERR_INVALID_LEN: the SDK gives these SW 0x6900, 0x6A00, 0x6700 (low byte 0 too).
        { 0x01, Fido2Failure.Other, "CtapHidError0x01" },
        { 0x02, Fido2Failure.Other, "CtapHidError0x02" },
        { 0x03, Fido2Failure.Other, "CtapHidError0x03" },
    };

    /// <summary>
    /// A CTAPHID error frame reaches tswap as the SDK's FidoTransform turns it into an APDU (SW 0x6F00 or 0x6700/0x6900/
    /// 0x6A00, data the one error byte), which <see cref="Fido2Response"/> reads as <see cref="CtapStatus.Ok"/>. The
    /// probe must never take such a key for the holder.
    /// </summary>
    [Theory]
    [MemberData(nameof(CtapHidErrors))]
    public void SdkFido2Keys_ProbeAnswer_CtapHidErrorIsNeverTheHolder(byte error, Fido2Failure expected, string detail)
    {
        var apdu = CtapHidErrorAnswer(error);
        Assert.Equal(CtapStatus.Ok, new GetAssertionResponse(apdu).CtapStatus);

        var e = Assert.Throws<Fido2DeviceException>(() => SdkFido2Keys.ProbeHolds(apdu));

        Assert.Equal(expected, e.Kind);
        Assert.Equal(detail, e.Detail);
    }

    [Theory]
    [MemberData(nameof(CtapHidErrors))]
    public void SdkFido2Keys_CeremonyAnswer_CtapHidErrorFails(byte error, Fido2Failure expected, string detail)
    {
        var e = Assert.Throws<Fido2DeviceException>(() => SdkFido2Keys.RequireOk(CtapHidErrorAnswer(error)));

        Assert.Equal(expected, e.Kind);
        Assert.Equal(detail, e.Detail);
    }

    [Theory]
    [InlineData(CtapStatus.CredentialExcluded, Fido2Failure.CredentialExcluded)]
    [InlineData(CtapStatus.OperationDenied, Fido2Failure.Cancelled)]
    [InlineData(CtapStatus.NoCredentials, Fido2Failure.NoCredential)]
    public void SdkFido2Keys_CeremonyAnswer_CtapStatusFails(CtapStatus status, Fido2Failure expected) =>
        Assert.Equal(expected, Assert.Throws<Fido2DeviceException>(() => SdkFido2Keys.RequireOk(CtapAnswer(status))).Kind);

    [Fact]
    public void SdkFido2Keys_CeremonyAnswer_OkPasses() => SdkFido2Keys.RequireOk(CtapAnswer(CtapStatus.Ok));

    // ---- an assertion that leaves out the credential ----

    [Fact]
    public void SdkFido2Keys_AssertionWithoutCredential_IsTheRequestedOne()
    {
        var withoutCredential = AssertionCbor(credentialId: null);

        using var data = new GetAssertionData(SdkFido2Keys.WithCredential(withoutCredential, CredentialId));

        Assert.Equal(CredentialId, data.CredentialId.Id.ToArray());
        Assert.Equal("public-key", data.CredentialId.Type);
        Assert.True(data.AuthenticatorData.UserVerification);
        Assert.Equal(new byte[] { 0x51, 0x52 }, data.Signature.ToArray());
    }

    [Fact]
    public void SdkFido2Keys_AssertionWithCredential_IsLeftAsTheKeySentIt()
    {
        byte[] answered = [.. Enumerable.Repeat((byte)0xEE, 48)];
        var withCredential = AssertionCbor(answered);

        Assert.Equal(withCredential, SdkFido2Keys.WithCredential(withCredential, CredentialId).ToArray());
        using var data = new GetAssertionData(SdkFido2Keys.WithCredential(withCredential, CredentialId));
        Assert.Equal(answered, data.CredentialId.Id.ToArray());
    }

    [Fact]
    public void SdkFido2Keys_CanList() => Assert.True(Keys(new FakeSession()).CanList);

    // ---- helpers ----

    private static SdkFido2Keys Keys(FakeSession session) => new(new FakeDevices(session));

    /// <summary>A CTAP2 answer as the SDK's FidoErrorTransform builds it: 0x9000 and the CBOR, or 0x6F00 | status.</summary>
    private static ResponseApdu CtapAnswer(CtapStatus status) =>
        status == CtapStatus.Ok
            ? new ResponseApdu([0xA0], unchecked((short)0x9000))
            : new ResponseApdu([], (short)(0x6F00 | (byte)status));

    /// <summary>A CTAPHID error frame as the SDK's CtapToApduResponse.ToCtap1ResponseApdu builds it.</summary>
    private static ResponseApdu CtapHidErrorAnswer(byte error) =>
        new([error], error switch { 1 => (short)0x6900, 2 => (short)0x6A00, 3 => (short)0x6700, _ => (short)0x6F00 });

    /// <summary>
    /// A GetAssertion answer's CBOR (canonical, integer keys): the credential (key 1) when given, authenticator data
    /// (key 2: an RP id hash, flags UP|UV, a counter) and a signature (key 3).
    /// </summary>
    private static byte[] AssertionCbor(byte[]? credentialId)
    {
        var authData = new byte[37];
        authData[32] = 0x05;
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(credentialId is null ? 2 : 3);
        if (credentialId is not null)
        {
            writer.WriteInt32(1);
            writer.WriteStartMap(2);
            writer.WriteTextString("id");
            writer.WriteByteString(credentialId);
            writer.WriteTextString("type");
            writer.WriteTextString("public-key");
            writer.WriteEndMap();
        }
        writer.WriteInt32(2);
        writer.WriteByteString(authData);
        writer.WriteInt32(3);
        writer.WriteByteString([0x51, 0x52]);
        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>
    /// The salt the hmac-secret extension carries: encoded with a PIN protocol of the test's own (as the session's
    /// would be), read back out of the extension's CBOR (saltEnc, key 2) and decrypted with the same protocol.
    /// </summary>
    private static byte[] EncodedSalt(GetAssertionParameters parameters)
    {
        YubicoSdk.EnsureInitialized();
        using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var protocol = new PinUvAuthProtocolTwo();
        protocol.Encapsulate(new CoseEcPublicKey(peer.ExportParameters(includePrivateParameters: false)));
        parameters.EncodeHmacSecretExtension(protocol);

        var reader = new CborReader(parameters.Extensions[Yubico.YubiKey.Fido2.Extensions.HmacSecret], CborConformanceMode.Ctap2Canonical);
        var entries = reader.ReadStartMap() ?? 0;
        for (var i = 0; i < entries; i++)
        {
            var key = reader.ReadInt32();
            if (key == 2)
                return protocol.Decrypt(reader.ReadByteString());
            reader.SkipValue();
        }
        throw new InvalidOperationException("no saltEnc in the hmac-secret extension");
    }

    private sealed class FakeDevices(FakeSession session) : ISdkFido2Devices
    {
        public IReadOnlyList<Fido2KeyInfo> Find() => throw new NotSupportedException("not used here");

        public Fido2KeyInfo? FindHolder(byte[] credentialId) => throw new NotSupportedException("not used here");

        public IFido2SdkSession Open(Fido2KeyRef key, SdkPinCollector collector)
        {
            Assert.Equal(Key, key);
            session.Collector = collector;
            return session;
        }
    }

    private sealed record Verification(byte[] Pin, PinUvAuthTokenPermissions? Permissions, string? RpId);

    private sealed class FakeSession : IFido2SdkSession
    {
        public bool PinSet { get; init; } = true;
        public bool HmacSecretSupported { get; init; } = true;
        public bool PinUvAuthTokenSupported { get; init; } = true;
        public bool VerifyResult { get; init; } = true;
        public int? VerifyRetries { get; init; }
        public Exception? AssertionFailure { get; init; }
        public Action<SdkPinCollector>? OnAssertion { get; init; }

        public SdkPinCollector? Collector { get; set; }
        public List<Verification> Verifications { get; } = [];
        public List<byte[]> NewPins { get; } = [];
        public List<string> Order { get; } = [];
        public int Assertions { get; private set; }
        public GetAssertionParameters? LastAssertion { get; private set; }
        public bool Disposed { get; private set; }
        public byte[] Output { get; } = RandomNumberGenerator.GetBytes(32);
        public Fido2Made Made { get; } = new(CredentialId, Guid.Parse("d7781e5d-e353-46aa-afe2-3ca49f13332a"), 33060005, true);

        public bool TryVerifyPin(byte[] pin, PinUvAuthTokenPermissions? permissions, string? rpId, out int? retriesLeft, out bool? reinsertRequired)
        {
            Order.Add("verify");
            Verifications.Add(new Verification(pin.ToArray(), permissions, rpId));
            retriesLeft = VerifyResult ? null : VerifyRetries;
            reinsertRequired = null;
            return VerifyResult;
        }

        public Fido2Made MakeCredential(MakeCredentialParameters parameters)
        {
            Order.Add("make");
            return Made;
        }

        public Fido2Output GetAssertion(GetAssertionParameters parameters)
        {
            Order.Add("assert");
            Assertions++;
            LastAssertion = parameters;
            OnAssertion?.Invoke(Collector!);
            if (AssertionFailure is not null)
                throw AssertionFailure;
            return new Fido2Output(CredentialId, Output.ToArray(), true);
        }

        public bool TrySetPin(byte[] newPin)
        {
            NewPins.Add(newPin.ToArray());
            return true;
        }

        public void Dispose() => Disposed = true;
    }
}
