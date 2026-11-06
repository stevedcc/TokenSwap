using System.Formats.Cbor;
using System.Security;
using System.Security.Cryptography;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Fido2;
using Xunit;
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
        var refusal = new Fido2DeviceException(Fido2Failure.PinWrong, 2, "PinRetryRefused");
        var session = new FakeSession
        {
            // The SDK asks the collector for a PIN, the collector refuses, and the SDK gives up with its own exception.
            OnAssertion = collector =>
            {
                collector.Collect(new KeyEntryData { Request = KeyEntryRequest.VerifyFido2Pin });
                throw new OperationCanceledException("The user cancelled the PIN collection operation.");
            },
        };
        var calls = 0;
        var keys = Keys(session);

        var e = Assert.Throws<Fido2DeviceException>(() => keys.GetHmacSecret(Key, [(CredentialId, PrfInput)], _ =>
            ++calls == 1 ? Pin.ToArray() : throw refusal));

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
        Assert.Equal(holds, SdkFido2Keys.ProbeHolds(status));

    [Theory]
    [InlineData(CtapStatus.PinRequired, Fido2Failure.Other)]
    [InlineData(CtapStatus.ChannelBusy, Fido2Failure.Busy)]
    public void SdkFido2Keys_ProbeAnswer_OtherStatusesFail(CtapStatus status, Fido2Failure expected) =>
        Assert.Equal(expected, Assert.Throws<Fido2DeviceException>(() => SdkFido2Keys.ProbeHolds(status)).Kind);

    [Fact]
    public void SdkFido2Keys_CanList() => Assert.True(Keys(new FakeSession()).CanList);

    // ---- helpers ----

    private static SdkFido2Keys Keys(FakeSession session) => new(new FakeDevices(session));

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
