using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using TswapCore.Keyring;
using TswapCore.Vault.Fido2;
using TswapCore.Vault.Interop;
using Xunit;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 5: the pure parts of <see cref="WebAuthnFido2Keys"/>, <c>webauthn.dll</c> as the FIDO2 device on
/// Windows. <c>webauthn.dll</c> is replaced by <see cref="FakeApi"/> (nothing is P/Invoked, so these run on every OS);
/// what is pinned is the memory tswap hands Windows (read back through the pointers, as <c>webauthn.dll</c> would),
/// how Windows' answers are read, and how its HRESULTs become <see cref="Fido2DeviceException"/>s.
/// </summary>
public class WebAuthnFido2KeysTests
{
    private static readonly byte[] UserId = [.. Enumerable.Range(1, 16).Select(i => (byte)i)];
    private static readonly byte[] CredentialA = [.. Enumerable.Range(10, 64).Select(i => (byte)i)];
    private static readonly byte[] CredentialB = [.. Enumerable.Range(80, 48).Select(i => (byte)i)];
    private static readonly byte[] PrfInputA = [.. Enumerable.Range(150, 32).Select(i => (byte)i)];
    private static readonly byte[] PrfInputB = [.. Enumerable.Range(200, 32).Select(i => (byte)i)];

    // Yubico's YubiKey 5 Series with NFC, as the owner's Windows run reported it under direct attestation.
    private static readonly Guid YubiKey5Nfc = new("d7781e5d-e353-46aa-afe2-3ca49f13332a");

    /// <summary>Windows' dialog asks for the PIN: the device's delegate must never be called.</summary>
    private static readonly Fido2DevicePin NoPinCall = _ => throw new InvalidOperationException("the PIN delegate was called");

    // ---- WebAuthn_HResultsMapToFailures ----

    // Every HRESULT webauthn.h names (WebAuthNGetErrorName's list, l.1348-1362 at ef82c15) plus the ones the plan asks
    // for that the header doesn't list (busy and the PIN-class results: unconfirmed, see the task 5 report). Values from
    // winerror.h. Wrong-PIN results carry no count: Windows' dialog doesn't say how many tries are left.
    public static TheoryData<uint, Fido2Failure, string> HResults => new()
    {
        // In WebAuthNGetErrorName's list.
        { 0x8009000F, Fido2Failure.CredentialExcluded, "NTE_EXISTS" },                          // InvalidStateError
        { 0x80070032, Fido2Failure.Other, "ERROR_NOT_SUPPORTED" },                              // ConstraintError
        { 0x80090029, Fido2Failure.Other, "NTE_NOT_SUPPORTED" },                                // ConstraintError
        { 0x80090023, Fido2Failure.Other, "NTE_TOKEN_KEYSET_STORAGE_FULL" },                    // ConstraintError
        { 0x80090027, Fido2Failure.Other, "NTE_INVALID_PARAMETER" },                            // NotSupportedError
        { 0x80090035, Fido2Failure.NotPluggedIn, "NTE_DEVICE_NOT_FOUND" },                      // NotAllowedError
        { 0x80090011, Fido2Failure.NoCredential, "NTE_NOT_FOUND" },                             // NotAllowedError
        { 0x800704C7, Fido2Failure.Cancelled, "ERROR_CANCELLED" },                              // NotAllowedError
        { 0x80090036, Fido2Failure.Cancelled, "NTE_USER_CANCELLED" },                           // NotAllowedError
        { 0x800705B4, Fido2Failure.TimedOut, "ERROR_TIMEOUT" },                                 // NotAllowedError
        // Not in the header's list (unconfirmed).
        { 0x800700AA, Fido2Failure.Busy, "ERROR_BUSY" },
        { 0x80090033, Fido2Failure.PinWrong, "NTE_INCORRECT_PASSWORD" },
        { 0x8010006B, Fido2Failure.PinWrong, "SCARD_W_WRONG_CHV" },
        { 0x8010006C, Fido2Failure.PinBlocked, "SCARD_W_CHV_BLOCKED" },
    };

    [Theory]
    [MemberData(nameof(HResults))]
    public void WebAuthn_HResultsMapToFailures(uint hr, Fido2Failure kind, string name)
    {
        var e = WebAuthnFido2Keys.FromHResult(unchecked((int)hr), atAssertion: true);

        Assert.Equal(kind, e.Kind);
        Assert.Equal(name, e.Detail);
        Assert.Null(e.RetriesLeft);
    }

    // Final review (carry-forward 1): the HRESULT travels beside the name, so `-v` can print it for runbook A5/A6.
    [Fact]
    public void WebAuthn_MappedHResult_KeepsTheNameAndCarriesTheHResult()
    {
        var e = WebAuthnFido2Keys.FromHResult(unchecked((int)0x80090011), atAssertion: true);

        Assert.Equal("NTE_NOT_FOUND", e.Detail);
        Assert.Equal(unchecked((int)0x80090011), e.WindowsHResult);
    }

    [Fact]
    public void WebAuthn_Verbose_PrintsTheHResultLine()
    {
        var api = new FakeApi { Result = unchecked((int)0x8009000F) };
        var verbose = new StringWriter();
        var service = new Fido2Service(new WebAuthnFido2Keys(api), verbose);

        var e = Assert.Throws<Fido2Exception>(() => service.Enrol(null, false, [], _ => "123456"u8.ToArray()));

        Assert.Equal(Fido2Failure.CredentialExcluded, e.Kind);
        Assert.Equal("Windows HRESULT 0x8009000F (NTE_EXISTS)" + Environment.NewLine, verbose.ToString());
    }

    [Fact]
    public void WebAuthn_Verbose_UnnamedHResult_PrintsItOnce()
    {
        var api = new FakeApi { Result = unchecked((int)0x80004005) };
        var verbose = new StringWriter();
        var service = new Fido2Service(new WebAuthnFido2Keys(api), verbose);

        Assert.Throws<Fido2Exception>(() => service.Enrol(null, false, [], _ => "123456"u8.ToArray()));

        Assert.Equal("Windows HRESULT 0x80004005" + Environment.NewLine, verbose.ToString());
    }

    [Fact]
    public void WebAuthn_NotVerbose_PrintsNoHResult()
    {
        var api = new FakeApi { Result = unchecked((int)0x80090011) };
        var service = new Fido2Service(new WebAuthnFido2Keys(api));

        var e = Assert.Throws<Fido2Exception>(() =>
            service.Open([Fido2Slot(CredentialA, PrfInputA)], null, _ => "123456"u8.ToArray()));

        Assert.DoesNotContain("0x", e.Message);
    }

    // Nothing ties ERROR_DEVICE_REINITIALIZATION_NEEDED to CTAP2_ERR_PIN_AUTH_BLOCKED: no PIN text for it (review).
    [Fact]
    public void WebAuthn_DeviceReinitialisationNeeded_IsOther() =>
        Assert.Equal((Fido2Failure.Other, "HRESULT 0x8007048C"),
            (WebAuthnFido2Keys.FromHResult(unchecked((int)0x8007048C), atAssertion: true).Kind,
             WebAuthnFido2Keys.FromHResult(unchecked((int)0x8007048C), atAssertion: true).Detail));

    // At make-credential no credential was asked for: NTE_NOT_FOUND must not become "the key you picked holds none of
    // this vault's FIDO2 credentials" (review).
    [Fact]
    public void WebAuthn_NotFoundAtMakeCredential_IsOther()
    {
        var api = new FakeApi { Result = unchecked((int)0x80090011) };

        var e = Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("NTE_NOT_FOUND", e.Detail);
    }

    [Fact]
    public void WebAuthn_UnknownHResult_IsOtherWithItsValue()
    {
        var e = WebAuthnFido2Keys.FromHResult(unchecked((int)0x80004005), atAssertion: true);

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("HRESULT 0x80004005", e.Detail);
    }

    [Fact]
    public void WebAuthn_FailedCeremony_ThrowsTheMappedFailureAndFrees()
    {
        var api = new FakeApi { Result = unchecked((int)0x80090011) };
        using var answer = api.Assertion(CredentialA, new byte[32], userVerified: true);
        var keys = new WebAuthnFido2Keys(api);

        var e = Assert.Throws<Fido2DeviceException>(() => keys.GetHmacSecret(null, [(CredentialA, PrfInputA)], NoPinCall));

        Assert.Equal(Fido2Failure.NoCredential, e.Kind);
        Assert.Equal([api.Returned], api.FreedAssertions);
    }

    [Fact]
    public void WebAuthn_NoCredential_IsThePickedKeyHoldsNoneText()
    {
        var api = new FakeApi { Result = unchecked((int)0x80090011) };
        var service = new Fido2Service(new WebAuthnFido2Keys(api));

        var e = Assert.Throws<Fido2Exception>(() =>
            service.Open([Fido2Slot(CredentialA, PrfInputA)], null, _ => "123456"u8.ToArray()));

        Assert.Equal(Fido2Failure.NoCredential, e.Kind);
        Assert.Equal(Fido2Texts.PickedHoldsNone, e.Message);
    }

    [Fact]
    public void WebAuthn_ApiThrows_IsADeviceException()
    {
        var api = new FakeApi { Throw = new DllNotFoundException("webauthn.dll") };
        var keys = new WebAuthnFido2Keys(api);

        var e = Assert.Throws<Fido2DeviceException>(() => keys.MakeCredential(null, UserId, [], NoPinCall));

        Assert.Equal(Fido2Failure.Unsupported, e.Kind);
        Assert.Null(e.Detail);
    }

    // ---- WebAuthn_ApiBelow4_Unsupported ----

    [Fact]
    public void WebAuthn_ApiBelow4_Unsupported()
    {
        var api = new FakeApi { Version = 3 };
        var keys = new WebAuthnFido2Keys(api);

        var make = Assert.Throws<Fido2DeviceException>(() => keys.MakeCredential(null, UserId, [], NoPinCall));
        var assert = Assert.Throws<Fido2DeviceException>(() => keys.GetHmacSecret(null, [(CredentialA, PrfInputA)], NoPinCall));

        Assert.Equal(Fido2Failure.Unsupported, make.Kind);
        Assert.Equal("3", make.Detail);
        Assert.Equal(Fido2Failure.Unsupported, assert.Kind);
        Assert.Equal("3", assert.Detail);
        Assert.Equal(0, api.Ceremonies);
    }

    [Fact]
    public void WebAuthn_ApiBelow4_Unsupported_WithTheVersionInTheText()
    {
        var service = new Fido2Service(new WebAuthnFido2Keys(new FakeApi { Version = 3 }));

        var e = Assert.Throws<Fido2Exception>(() => service.Enrol(null, false, [], _ => "123456"u8.ToArray()));

        Assert.Equal(Fido2Failure.Unsupported, e.Kind);
        Assert.Equal("Windows' WebAuthn API on this machine is too old for FIDO2 slots (version 3; needs 4).", e.Message);
    }

    [Fact]
    public void WebAuthn_Api4_IsEnough()
    {
        var api = new FakeApi { Version = 4 };
        using var answer = api.Assertion(CredentialA, new byte[32], userVerified: true);

        new WebAuthnFido2Keys(api).GetHmacSecret(null, [(CredentialA, PrfInputA)], NoPinCall);

        Assert.Equal(1, api.Ceremonies);
    }

    // ---- WebAuthn_MakeCredentialOptions_AreTswaps ----

    [Fact]
    public void WebAuthn_MakeCredentialOptions_AreTswaps()
    {
        using var call = WebAuthnFido2Keys.BuildMakeCredential(UserId, [CredentialA, CredentialB]);

        var options = Marshal.PtrToStructure<WebAuthnMakeCredentialOptionsV5>(call.Options);
        Assert.Equal(5u, options.dwVersion);
        Assert.Equal(0, options.bRequireResidentKey);
        Assert.Equal(0, options.bPreferResidentKey);
        Assert.Equal(1u, options.dwUserVerificationRequirement); // WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
        Assert.Equal(3u, options.dwAttestationConveyancePreference); // WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
        Assert.Equal(2u, options.dwAuthenticatorAttachment); // WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM
        Assert.Equal(0u, options.dwFlags);
        Assert.Equal(0u, options.CredentialList.cCredentials); // ignored: pExcludeCredentialList is set
        Assert.Equal(0, options.bBrowserInPrivateMode);

        // The hmac-secret extension: a BOOL TRUE.
        Assert.Equal(1u, options.Extensions.cExtensions);
        var extension = Marshal.PtrToStructure<WebAuthnExtension>(options.Extensions.pExtensions);
        Assert.Equal("hmac-secret", Marshal.PtrToStringUni(extension.pwszExtensionIdentifier));
        Assert.Equal(4u, extension.cbExtension);
        Assert.Equal(1, Marshal.ReadInt32(extension.pvExtension));

        // The exclude list: every credential passed, as public-key credentials.
        var exclude = Marshal.PtrToStructure<WebAuthnCredentialList>(options.pExcludeCredentialList);
        Assert.Equal(2u, exclude.cCredentials);
        AssertCredentialEx(Marshal.ReadIntPtr(exclude.ppCredentials, 0), CredentialA);
        AssertCredentialEx(Marshal.ReadIntPtr(exclude.ppCredentials, IntPtr.Size), CredentialB);

        // The relying party and the small user entity: the 16 bytes passed, name "tswap", no display name.
        var rp = Marshal.PtrToStructure<WebAuthnRpEntityInformation>(call.Rp);
        Assert.Equal(1u, rp.dwVersion);
        Assert.Equal(Fido2SlotBlob.TswapRpId, Marshal.PtrToStringUni(rp.pwszId));
        Assert.Equal("tswap", Marshal.PtrToStringUni(rp.pwszName));
        Assert.Equal(IntPtr.Zero, rp.pwszIcon);
        var user = Marshal.PtrToStructure<WebAuthnUserEntityInformation>(call.User);
        Assert.Equal(1u, user.dwVersion);
        Assert.Equal(UserId, Bytes(user.pbId, user.cbId));
        Assert.Equal("tswap", Marshal.PtrToStringUni(user.pwszName));
        Assert.Equal(IntPtr.Zero, user.pwszDisplayName);
        Assert.Equal(IntPtr.Zero, user.pwszIcon);

        // ES256 only.
        var parameters = Marshal.PtrToStructure<WebAuthnCoseCredentialParameters>(call.PubKeyCredParams);
        Assert.Equal(1u, parameters.cCredentialParameters);
        var es256 = Marshal.PtrToStructure<WebAuthnCoseCredentialParameter>(parameters.pCredentialParameters);
        Assert.Equal("public-key", Marshal.PtrToStringUni(es256.pwszCredentialType));
        Assert.Equal(-7, es256.lAlg);

        AssertClientData(call.ClientData, "webauthn.create");
    }

    [Fact]
    public void WebAuthn_MakeCredential_NoVaultCredentials_SendsNoExcludeList()
    {
        using var call = WebAuthnFido2Keys.BuildMakeCredential(UserId, []);

        var options = Marshal.PtrToStructure<WebAuthnMakeCredentialOptionsV5>(call.Options);
        Assert.Equal(IntPtr.Zero, options.pExcludeCredentialList);
    }

    [Fact]
    public void WebAuthn_MakeCredential_UserIdIs16Bytes() =>
        Assert.Throws<ArgumentException>(() => WebAuthnFido2Keys.BuildMakeCredential(new byte[32], []));

    [Fact]
    public void WebAuthn_MakeCredential_PassesTheBuiltOptions()
    {
        var api = new FakeApi();
        using var answer = api.Attestation(Aaguid(YubiKey5Nfc), CredentialA, CredentialA, userVerified: true);

        new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [CredentialB], NoPinCall);

        Assert.NotNull(api.MadeWith);
        Assert.Equal(UserId, api.MadeWith.UserId);
        Assert.Equal([CredentialB], api.MadeWith.Excluded);
        Assert.Equal(3u, api.MadeWith.Conveyance);
    }

    // ---- reading the attestation ----

    [Fact]
    public void WebAuthn_MakeCredential_ReadsAaguidAndCredentialId()
    {
        var api = new FakeApi();
        using var answer = api.Attestation(Aaguid(YubiKey5Nfc), CredentialA, CredentialA, userVerified: true);

        var made = new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall);

        Assert.Equal(CredentialA, made.CredentialId);
        Assert.Equal(YubiKey5Nfc, made.Aaguid);
        Assert.Null(made.Serial);
        Assert.True(made.UserVerified);
        Assert.Equal([api.Returned], api.FreedAttestations);
    }

    [Fact]
    public void WebAuthn_MakeCredential_WithoutUv_SaysSo()
    {
        var api = new FakeApi();
        using var answer = api.Attestation(Aaguid(YubiKey5Nfc), CredentialA, CredentialA, userVerified: false);

        Assert.False(new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall).UserVerified);
    }

    [Fact]
    public void WebAuthn_MakeCredential_CredentialIdNotTheAuthenticatorDatas_IsRefused()
    {
        var api = new FakeApi();
        using var answer = api.Attestation(Aaguid(YubiKey5Nfc), CredentialA, CredentialB, userVerified: true);

        var e = Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("CredentialIdMismatch", e.Detail);
        Assert.Equal([api.Returned], api.FreedAttestations);
    }

    [Fact]
    public void WebAuthn_MakeCredential_NoAttestedCredentialData_IsRefused()
    {
        var api = new FakeApi();
        using var answer = api.Attestation(aaguid: null, CredentialA, CredentialA, userVerified: true);

        var e = Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("NoAttestedCredentialData", e.Detail);
    }

    [Fact]
    public void WebAuthn_MakeCredential_TruncatedAuthenticatorData_IsADeviceException()
    {
        var api = new FakeApi();
        using var answer = api.Attestation(Aaguid(YubiKey5Nfc), CredentialA, CredentialA, userVerified: true, authDataLength: 40);

        var e = Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("MalformedAuthenticatorData", e.Detail);
    }

    [Fact]
    public void WebAuthn_MakeCredential_HmacSecretNotCreated_IsRefused()
    {
        var api = new FakeApi();
        using var answer = api.Attestation(Aaguid(YubiKey5Nfc), CredentialA, CredentialA, userVerified: true, hmacSecretCreated: false);

        var e = Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("HmacSecretNotCreated", e.Detail);
    }

    // ---- final review: attestation hardening ----

    // (a) A version-4 attestation (API 4-5) has no bPrfEnabled: it is never read (here it says FALSE; the extension
    // output says TRUE, and that is what counts).
    [Fact]
    public void WebAuthn_MakeCredential_Version4Attestation_ReadsNoV5Field()
    {
        var api = new FakeApi();
        using var answer = api.Attestation(Aaguid(YubiKey5Nfc), CredentialA, CredentialA, userVerified: true, version: 4, prfEnabled: false);

        var made = new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall);

        Assert.Equal(CredentialA, made.CredentialId);
    }

    // (a) bResidentKey is a v4 field: a version-3 attestation's is never read.
    [Fact]
    public void WebAuthn_MakeCredential_Version3Attestation_ReadsNoResidentKeyField()
    {
        var api = new FakeApi();
        using var answer = api.Attestation(Aaguid(YubiKey5Nfc), CredentialA, CredentialA, userVerified: true, version: 3, residentKey: true);

        Assert.Equal(CredentialA, new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall).CredentialId);
    }

    // (b) A discoverable (resident) credential stores something on the key: refused.
    [Theory]
    [InlineData(4u)]
    [InlineData(5u)]
    public void WebAuthn_MakeCredential_ResidentCredential_IsRefused(uint version)
    {
        var api = new FakeApi();
        using var answer = api.Attestation(Aaguid(YubiKey5Nfc), CredentialA, CredentialA, userVerified: true, version: version, residentKey: true);

        var e = Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("ResidentCredential", e.Detail);
        Assert.Equal([api.Returned], api.FreedAttestations);
    }

    // (c) Which signal says hmac-secret was made: the extension output's BOOL when present (bPrfEnabled is about the
    // PRF extension, which tswap doesn't request); without it, bPrfEnabled TRUE in a v5 attestation; else refused.
    [Theory]
    [InlineData(true, true, 5u, true)]
    [InlineData(true, false, 5u, true)]
    [InlineData(false, true, 5u, false)]
    [InlineData(false, false, 5u, false)]
    [InlineData(null, true, 5u, true)]
    [InlineData(null, false, 5u, false)]
    [InlineData(null, true, 4u, false)] // no bPrfEnabled before v5: no signal at all
    [InlineData(true, false, 4u, true)]
    public void WebAuthn_MakeCredential_HmacSecretSignals(bool? extension, bool prfEnabled, uint version, bool accepted)
    {
        var api = new FakeApi();
        using var answer = api.Attestation(Aaguid(YubiKey5Nfc), CredentialA, CredentialA, userVerified: true,
            hmacSecretCreated: extension, version: version, prfEnabled: prfEnabled);
        var keys = new WebAuthnFido2Keys(api);

        if (accepted)
            Assert.Equal(CredentialA, keys.MakeCredential(null, UserId, [], NoPinCall).CredentialId);
        else
            Assert.Equal("HmacSecretNotCreated", Assert.Throws<Fido2DeviceException>(() => keys.MakeCredential(null, UserId, [], NoPinCall)).Detail);
    }

    // (d) On failure webauthn.dll may return no answer at all: nothing is freed.
    [Fact]
    public void WebAuthn_FailedCeremonyWithNoAnswer_FreesNothing()
    {
        var api = new FakeApi { Result = unchecked((int)0x800704C7) }; // ERROR_CANCELLED, no answer built: NULL

        Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).MakeCredential(null, UserId, [], NoPinCall));
        Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).GetHmacSecret(null, [(CredentialA, PrfInputA)], NoPinCall));

        Assert.Empty(api.FreedAttestations);
        Assert.Empty(api.FreedAssertions);
    }

    // (h)
    [Fact]
    public void WebAuthn_MakeCredential_UserIdGuard_SaysTheLength()
    {
        var e = Assert.Throws<ArgumentException>(() => WebAuthnFido2Keys.BuildMakeCredential(new byte[32], []));

        Assert.StartsWith("The user id must be 16 bytes, got 32", e.Message);
    }

    [Fact]
    public void WebAuthn_MakeCredential_ZeroAaguid_IsReturnedForTheServiceToRefuse()
    {
        var api = new FakeApi();
        using var answer = api.Attestation(new byte[16], CredentialA, CredentialA, userVerified: true);
        var service = new Fido2Service(new WebAuthnFido2Keys(api));

        var e = Assert.Throws<Fido2Exception>(() => service.Enrol(null, false, [], _ => "123456"u8.ToArray()));

        Assert.Equal(Fido2Texts.WindowsNoAaguid, e.Message);
    }

    // ---- WebAuthn_AssertionSetsRawSaltFlagAndPassesThePrfSalt / WebAuthn_AssertionAllowsEveryVaultCredential ----

    // Changed rule (final review): WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG is set and tswap hashes the PRF input
    // itself (Fido2Prf.Salt, the SDK path's function). An API-4 webauthn.dll from before the PRF default (Feb 2022) may
    // pass salts raw; with the flag and tswap's own hash, both DLL generations send the key the same 32-byte salt.
    [Fact]
    public void WebAuthn_AssertionSetsRawSaltFlagAndPassesThePrfSalt()
    {
        using var call = WebAuthnFido2Keys.BuildGetAssertion([(CredentialA, PrfInputA), (CredentialB, PrfInputB)]);

        var options = Marshal.PtrToStructure<WebAuthnGetAssertionOptionsV6>(call.Options);
        Assert.Equal(0x00100000u, options.dwFlags); // WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG

        var values = Marshal.PtrToStructure<WebAuthnHmacSecretSaltValues>(options.pHmacSecretSaltValues);
        Assert.Equal(IntPtr.Zero, values.pGlobalHmacSalt);
        Assert.Equal(2u, values.cCredWithHmacSecretSaltList);
        AssertCredWithSalt(values.pCredWithHmacSecretSaltList, 0, CredentialA, PrfInputA);
        AssertCredWithSalt(values.pCredWithHmacSecretSaltList, 1, CredentialB, PrfInputB);
    }

    [Fact]
    public void WebAuthn_AssertionAllowsEveryVaultCredential()
    {
        using var call = WebAuthnFido2Keys.BuildGetAssertion([(CredentialA, PrfInputA), (CredentialB, PrfInputB)]);

        var options = Marshal.PtrToStructure<WebAuthnGetAssertionOptionsV6>(call.Options);
        var allow = Marshal.PtrToStructure<WebAuthnCredentialList>(options.pAllowCredentialList);
        Assert.Equal(2u, allow.cCredentials);
        AssertCredentialEx(Marshal.ReadIntPtr(allow.ppCredentials, 0), CredentialA);
        AssertCredentialEx(Marshal.ReadIntPtr(allow.ppCredentials, IntPtr.Size), CredentialB);
        Assert.Equal(0u, options.CredentialList.cCredentials); // ignored: pAllowCredentialList is set
    }

    [Fact]
    public void WebAuthn_AssertionOptions_AreTswaps()
    {
        using var call = WebAuthnFido2Keys.BuildGetAssertion([(CredentialA, PrfInputA)]);

        var options = Marshal.PtrToStructure<WebAuthnGetAssertionOptionsV6>(call.Options);
        Assert.Equal(6u, options.dwVersion);
        Assert.Equal(1u, options.dwUserVerificationRequirement); // required
        Assert.Equal(2u, options.dwAuthenticatorAttachment); // cross-platform
        Assert.Equal(0u, options.Extensions.cExtensions);
        Assert.Equal(IntPtr.Zero, options.pwszU2fAppId);
        Assert.Equal(0u, options.dwCredLargeBlobOperation);
        Assert.Equal(Fido2SlotBlob.TswapRpId, Marshal.PtrToStringUni(call.RpId));
        AssertClientData(call.ClientData, "webauthn.get");
    }

    [Fact]
    public void WebAuthn_Assertion_NeedsACredential() =>
        Assert.Throws<ArgumentException>(() => new WebAuthnFido2Keys(new FakeApi()).GetHmacSecret(null, [], NoPinCall));

    // ---- reading the assertion ----

    [Fact]
    public void WebAuthn_Assertion_ReturnsTheAnsweringCredentialAndZeroesWindowsCopy()
    {
        var api = new FakeApi();
        byte[] output = [.. Enumerable.Range(0, 32).Select(i => (byte)(i + 1))];
        using var answer = api.Assertion(CredentialB, output, userVerified: true);

        var result = new WebAuthnFido2Keys(api).GetHmacSecret(null, [(CredentialA, PrfInputA), (CredentialB, PrfInputB)], NoPinCall);

        Assert.Equal(CredentialB, result.CredentialId);
        Assert.Equal(output, result.Output);
        Assert.True(result.UserVerified);
        Assert.Equal(new byte[32], Bytes(api.NativeOutput, 32)); // webauthn.dll's copy, zeroed before it is freed
        Assert.Equal([api.Returned], api.FreedAssertions);
        Assert.Equal(2, api.AssertedWith!.Count);
    }

    [Fact]
    public void WebAuthn_Assertion_WithoutUv_SaysSo()
    {
        var api = new FakeApi();
        using var answer = api.Assertion(CredentialA, new byte[32], userVerified: false);

        Assert.False(new WebAuthnFido2Keys(api).GetHmacSecret(null, [(CredentialA, PrfInputA)], NoPinCall).UserVerified);
    }

    // (e) An hmac-secret output that isn't 32 bytes, or has no bytes at all, is refused.
    [Theory]
    [InlineData(16)]
    [InlineData(64)]
    public void WebAuthn_Assertion_OutputNot32Bytes_IsRefused(int length)
    {
        var api = new FakeApi();
        using var answer = api.Assertion(CredentialA, new byte[length], userVerified: true);

        var e = Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).GetHmacSecret(null, [(CredentialA, PrfInputA)], NoPinCall));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("BadHmacSecretOutput", e.Detail);
        Assert.Equal([api.Returned], api.FreedAssertions);
    }

    [Fact]
    public void WebAuthn_Assertion_OutputPointerNull_IsRefused()
    {
        var api = new FakeApi();
        using var answer = api.Assertion(CredentialA, new byte[32], userVerified: true, nullFirst: true);

        var e = Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).GetHmacSecret(null, [(CredentialA, PrfInputA)], NoPinCall));

        Assert.Equal("BadHmacSecretOutput", e.Detail);
    }

    // (f) Windows answered with a credential that wasn't asked for: refused.
    [Fact]
    public void WebAuthn_Assertion_CredentialNotAllowed_IsRefused()
    {
        var api = new FakeApi();
        using var answer = api.Assertion(CredentialB, Enumerable.Repeat((byte)5, 32).ToArray(), userVerified: true);

        var e = Assert.Throws<Fido2DeviceException>(() => new WebAuthnFido2Keys(api).GetHmacSecret(null, [(CredentialA, PrfInputA)], NoPinCall));

        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("UnknownCredential", e.Detail);
        Assert.Equal(new byte[32], Bytes(api.NativeOutput, 32)); // Windows' copy is still zeroed
        Assert.Equal([api.Returned], api.FreedAssertions);
    }

    [Fact]
    public void WebAuthn_Assertion_WithoutHmacSecret_ReturnsNoOutput()
    {
        var api = new FakeApi();
        using var answer = api.Assertion(CredentialA, output: null, userVerified: true);

        var result = new WebAuthnFido2Keys(api).GetHmacSecret(null, [(CredentialA, PrfInputA)], NoPinCall);

        Assert.Empty(result.Output);
    }

    [Fact]
    public void WebAuthn_AssertionBelowVersion3_HasNoOutputEvenWithAPointer()
    {
        // pHmacSecret is a v3 field: in a v2 assertion that memory is not Windows' to give, so it is never read.
        var api = new FakeApi();
        using var answer = api.Assertion(CredentialA, Enumerable.Repeat((byte)9, 32).ToArray(), userVerified: true, version: 2);

        var result = new WebAuthnFido2Keys(api).GetHmacSecret(null, [(CredentialA, PrfInputA)], NoPinCall);

        Assert.Empty(result.Output);
        Assert.Equal(Enumerable.Repeat((byte)9, 32), Bytes(api.NativeOutput, 32)); // untouched: not read, not zeroed
    }

    [Fact]
    public void WebAuthn_OpenThroughTheService_PicksTheAnsweringSlot()
    {
        var api = new FakeApi();
        using var answer = api.Assertion(CredentialB, Enumerable.Repeat((byte)7, 32).ToArray(), userVerified: true);
        var service = new Fido2Service(new WebAuthnFido2Keys(api));
        var a = Fido2Slot(CredentialA, PrfInputA);
        var b = Fido2Slot(CredentialB, PrfInputB);

        var opened = service.Open([a, b], null, _ => throw new InvalidOperationException("the PIN delegate was called"));

        Assert.Same(b, opened.Blob);
        Assert.Equal(Enumerable.Repeat((byte)7, 32), opened.Output);
    }

    [Fact]
    public void WebAuthn_NoTerminal_IsRefusedBeforeWindowsIsCalled()
    {
        var api = new FakeApi();
        var service = new Fido2Service(new WebAuthnFido2Keys(api));

        var e = Assert.Throws<Fido2Exception>(() => service.Open([Fido2Slot(CredentialA, PrfInputA)], null, pin: null));

        Assert.Equal(Fido2Failure.NoTerminal, e.Kind);
        Assert.Equal(0, api.VersionCalls);
    }

    // ---- what Windows can't do ----

    [Fact]
    public void WebAuthn_CannotList()
    {
        var keys = new WebAuthnFido2Keys(new FakeApi());

        Assert.False(keys.CanList);
        Assert.Throws<NotSupportedException>(() => keys.Find());
        Assert.Throws<NotSupportedException>(() => keys.FindHolder(CredentialA));
        Assert.Throws<NotSupportedException>(() => keys.SetPin(new Fido2KeyRef("x"), NoPinCall));
    }

    [Fact]
    public void WebAuthn_KeyArgument_IsAlwaysNull()
    {
        var keys = new WebAuthnFido2Keys(new FakeApi());

        Assert.Throws<ArgumentException>(() => keys.MakeCredential(new Fido2KeyRef("x"), UserId, [], NoPinCall));
        Assert.Throws<ArgumentException>(() => keys.GetHmacSecret(new Fido2KeyRef("x"), [(CredentialA, PrfInputA)], NoPinCall));
    }

    // ---- helpers ----

    private static Fido2SlotBlob Fido2Slot(byte[] credentialId, byte[] prfInput) =>
        new(null, YubiKey5Nfc, prfInput, Fido2SlotBlob.TswapRpId, credentialId, requiresPassword: false);

    private static byte[] Aaguid(Guid id)
    {
        var bytes = new byte[16];
        id.TryWriteBytes(bytes, bigEndian: true, out _);
        return bytes;
    }

    private static byte[] Bytes(IntPtr p, uint length)
    {
        var bytes = new byte[length];
        Marshal.Copy(p, bytes, 0, (int)length);
        return bytes;
    }

    private static void AssertCredentialEx(IntPtr p, byte[] id)
    {
        var credential = Marshal.PtrToStructure<WebAuthnCredentialEx>(p);
        Assert.Equal(1u, credential.dwVersion);
        Assert.Equal(id, Bytes(credential.pbId, credential.cbId));
        Assert.Equal("public-key", Marshal.PtrToStringUni(credential.pwszCredentialType));
        // WEBAUTHN_CTAP_TRANSPORT_USB | _NFC: a YubiKey tapped on a reader too (USB only would hide it, and let an NFC
        // enrolment slip past the exclude list); not 0, which may offer hybrid (a phone), and not BLE.
        Assert.Equal(0x3u, credential.dwTransports);
    }

    private static void AssertCredWithSalt(IntPtr list, int index, byte[] id, byte[] prfInput)
    {
        var entry = Marshal.PtrToStructure<WebAuthnCredWithHmacSecretSalt>(list + index * Marshal.SizeOf<WebAuthnCredWithHmacSecretSalt>());
        Assert.Equal(id, Bytes(entry.pbCredID, entry.cbCredID));
        var salt = Marshal.PtrToStructure<WebAuthnHmacSecretSalt>(entry.pHmacSecretSalt);
        Assert.Equal(32u, salt.cbFirst);
        Assert.Equal(Fido2Prf.Salt(prfInput), Bytes(salt.pbFirst, salt.cbFirst)); // hashed by tswap, passed raw
        Assert.Equal(0u, salt.cbSecond);
        Assert.Equal(IntPtr.Zero, salt.pbSecond);
    }

    private static void AssertClientData(IntPtr p, string type)
    {
        var clientData = Marshal.PtrToStructure<WebAuthnClientData>(p);
        Assert.Equal(1u, clientData.dwVersion);
        Assert.Equal("SHA-256", Marshal.PtrToStringUni(clientData.pwszHashAlgId));
        using var json = JsonDocument.Parse(Bytes(clientData.pbClientDataJSON, clientData.cbClientDataJSON));
        Assert.Equal(type, json.RootElement.GetProperty("type").GetString());
        Assert.Equal($"https://{Fido2SlotBlob.TswapRpId}", json.RootElement.GetProperty("origin").GetString());
        Assert.Equal(43, json.RootElement.GetProperty("challenge").GetString()!.Length); // 32 random bytes, base64url
    }

    /// <summary>What make-credential was called with, read from the call's memory while it was live.</summary>
    private sealed record MadeCall(byte[] UserId, List<byte[]> Excluded, uint Conveyance);

    /// <summary>
    /// <c>webauthn.dll</c> as a test double: a version, an HRESULT, and an answer the test builds in native memory
    /// (freed by the <see cref="WebAuthnArena"/> it returns). Records what was called and what was freed.
    /// </summary>
    private sealed class FakeApi : IWebAuthnApi
    {
        public uint Version { get; init; } = 9;
        public int Result { get; init; }
        public Exception? Throw { get; init; }
        public IntPtr Returned { get; private set; }
        public IntPtr NativeOutput { get; private set; }
        public int VersionCalls { get; private set; }
        public int Ceremonies { get; private set; }
        public MadeCall? MadeWith { get; private set; }
        public List<(byte[], byte[])>? AssertedWith { get; private set; }
        public List<IntPtr> FreedAttestations { get; } = [];
        public List<IntPtr> FreedAssertions { get; } = [];

        public uint ApiVersion()
        {
            VersionCalls++;
            if (Throw is not null)
                throw Throw;
            return Version;
        }

        public int MakeCredential(WebAuthnMakeCredentialCall call, out IntPtr attestation)
        {
            Ceremonies++;
            var user = Marshal.PtrToStructure<WebAuthnUserEntityInformation>(call.User);
            var options = Marshal.PtrToStructure<WebAuthnMakeCredentialOptionsV5>(call.Options);
            List<byte[]> excluded = [];
            if (options.pExcludeCredentialList != IntPtr.Zero)
            {
                var list = Marshal.PtrToStructure<WebAuthnCredentialList>(options.pExcludeCredentialList);
                for (var i = 0; i < list.cCredentials; i++)
                {
                    var c = Marshal.PtrToStructure<WebAuthnCredentialEx>(Marshal.ReadIntPtr(list.ppCredentials, i * IntPtr.Size));
                    excluded.Add(Bytes(c.pbId, c.cbId));
                }
            }
            MadeWith = new MadeCall(Bytes(user.pbId, user.cbId), excluded, options.dwAttestationConveyancePreference);
            attestation = Returned;
            return Result;
        }

        public void FreeCredentialAttestation(IntPtr attestation) => FreedAttestations.Add(attestation);

        public int GetAssertion(WebAuthnGetAssertionCall call, out IntPtr assertion)
        {
            Ceremonies++;
            var options = Marshal.PtrToStructure<WebAuthnGetAssertionOptionsV6>(call.Options);
            var values = Marshal.PtrToStructure<WebAuthnHmacSecretSaltValues>(options.pHmacSecretSaltValues);
            List<(byte[], byte[])> asserted = [];
            for (var i = 0; i < values.cCredWithHmacSecretSaltList; i++)
            {
                var entry = Marshal.PtrToStructure<WebAuthnCredWithHmacSecretSalt>(
                    values.pCredWithHmacSecretSaltList + i * Marshal.SizeOf<WebAuthnCredWithHmacSecretSalt>());
                var salt = Marshal.PtrToStructure<WebAuthnHmacSecretSalt>(entry.pHmacSecretSalt);
                asserted.Add((Bytes(entry.pbCredID, entry.cbCredID), Bytes(salt.pbFirst, salt.cbFirst)));
            }
            AssertedWith = asserted;
            assertion = Returned;
            return Result;
        }

        public void FreeAssertion(IntPtr assertion) => FreedAssertions.Add(assertion);

        /// <summary>A WEBAUTHN_CREDENTIAL_ATTESTATION (version 5) as webauthn.dll would return it.</summary>
        public WebAuthnArena Attestation(byte[]? aaguid, byte[] attestationCredentialId, byte[] authDataCredentialId, bool userVerified,
            bool? hmacSecretCreated = true, int? authDataLength = null, uint version = 5, bool residentKey = false, bool prfEnabled = true)
        {
            var arena = new WebAuthnArena();
            var authData = AuthenticatorDataBytes(userVerified, aaguid, authDataCredentialId);
            if (authDataLength is { } length)
                authData = authData[..length];
            var extensions = default(WebAuthnExtensions);
            if (hmacSecretCreated is { } created)
            {
                var extension = new WebAuthnExtension
                {
                    pwszExtensionIdentifier = arena.String("hmac-secret"),
                    cbExtension = 4,
                    pvExtension = arena.Struct(created ? 1 : 0),
                };
                extensions = new WebAuthnExtensions { cExtensions = 1, pExtensions = arena.Struct(extension) };
            }
            Returned = arena.Struct(new WebAuthnCredentialAttestation
            {
                dwVersion = version,
                pwszFormatType = arena.String("packed"),
                cbAuthenticatorData = (uint)authData.Length,
                pbAuthenticatorData = arena.Bytes(authData),
                cbCredentialId = (uint)attestationCredentialId.Length,
                pbCredentialId = arena.Bytes(attestationCredentialId),
                Extensions = extensions,
                bResidentKey = residentKey ? 1 : 0,
                bPrfEnabled = prfEnabled ? 1 : 0,
            });
            return arena;
        }

        /// <summary>A WEBAUTHN_ASSERTION (version 3) for <paramref name="credentialId"/>; no output when null.</summary>
        public WebAuthnArena Assertion(byte[] credentialId, byte[]? output, bool userVerified, uint version = 3, bool nullFirst = false)
        {
            var arena = new WebAuthnArena();
            var authData = AuthenticatorDataBytes(userVerified, null, null);
            var secret = IntPtr.Zero;
            if (output is not null)
            {
                NativeOutput = arena.Bytes(output);
                secret = arena.Struct(new WebAuthnHmacSecretSalt
                {
                    cbFirst = (uint)output.Length,
                    pbFirst = nullFirst ? IntPtr.Zero : NativeOutput,
                });
            }
            Returned = arena.Struct(new WebAuthnAssertion
            {
                dwVersion = version,
                cbAuthenticatorData = (uint)authData.Length,
                pbAuthenticatorData = arena.Bytes(authData),
                Credential = new WebAuthnCredential
                {
                    dwVersion = 1,
                    cbId = (uint)credentialId.Length,
                    pbId = arena.Bytes(credentialId),
                    pwszCredentialType = arena.String("public-key"),
                },
                pHmacSecret = secret,
            });
            return arena;
        }

        /// <summary>rpIdHash | flags (UP, UV when verified, AT with an AAGUID) | signCount [| AAGUID | id length | id | key].</summary>
        private static byte[] AuthenticatorDataBytes(bool userVerified, byte[]? aaguid, byte[]? credentialId)
        {
            var flags = (byte)(0x01 | (userVerified ? 0x04 : 0) | (aaguid is not null ? 0x40 : 0));
            var data = new List<byte>(Enumerable.Repeat((byte)0xAB, 32)) { flags, 0, 0, 0, 1 };
            if (aaguid is not null)
            {
                var id = credentialId ?? [];
                data.AddRange(aaguid);
                data.Add((byte)(id.Length >> 8));
                data.Add((byte)id.Length);
                data.AddRange(id);
                data.AddRange(Encoding.ASCII.GetBytes("cose"));
            }
            return [.. data];
        }
    }
}
