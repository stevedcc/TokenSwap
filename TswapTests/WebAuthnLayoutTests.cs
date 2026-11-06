using System.Runtime.InteropServices;
using TswapCore.Vault.Interop;
using Xunit;

namespace TswapTests;

/// <summary>
/// The webauthn.dll structures, checked against layouts derived by hand from Microsoft's webauthn.h
/// (github.com/microsoft/webauthn, API version 9 header, commit ef82c15) for x64 Windows. The header has no
/// #pragma pack, so the MSVC defaults hold: DWORD/BOOL/LONG are 4 bytes aligned to 4, pointers 8 aligned to 8, a
/// struct is aligned to its largest member and padded to a multiple of it. These blittable structs (uint, int, nint
/// only) lay out the same on Linux x64, so the numbers can be checked here. win-arm64 is also LLP64 with 8-byte
/// pointers, so the same numbers hold there.
/// </summary>
public class WebAuthnLayoutTests
{
    private static int Off<T>(string field) => (int)Marshal.OffsetOf<T>(field);

    [Fact]
    public void Pointers_AreEightBytes() => Assert.Equal(8, IntPtr.Size);

    // WEBAUTHN_RP_ENTITY_INFORMATION: dwVersion@0, pad 4, pwszId@8, pwszName@16, pwszIcon@24; size 32.
    [Fact]
    public void RpEntity()
    {
        Assert.Equal(32, Marshal.SizeOf<WebAuthnRpEntityInformation>());
        Assert.Equal(8, Off<WebAuthnRpEntityInformation>(nameof(WebAuthnRpEntityInformation.pwszId)));
        Assert.Equal(24, Off<WebAuthnRpEntityInformation>(nameof(WebAuthnRpEntityInformation.pwszIcon)));
    }

    // WEBAUTHN_USER_ENTITY_INFORMATION: dwVersion@0, cbId@4, pbId@8, pwszName@16, pwszIcon@24, pwszDisplayName@32;
    // size 40.
    [Fact]
    public void UserEntity()
    {
        Assert.Equal(40, Marshal.SizeOf<WebAuthnUserEntityInformation>());
        Assert.Equal(4, Off<WebAuthnUserEntityInformation>(nameof(WebAuthnUserEntityInformation.cbId)));
        Assert.Equal(8, Off<WebAuthnUserEntityInformation>(nameof(WebAuthnUserEntityInformation.pbId)));
        Assert.Equal(32, Off<WebAuthnUserEntityInformation>(nameof(WebAuthnUserEntityInformation.pwszDisplayName)));
    }

    // WEBAUTHN_COSE_CREDENTIAL_PARAMETER: dwVersion@0, pad 4, pwszCredentialType@8, lAlg@16, tail pad 4; size 24.
    // WEBAUTHN_COSE_CREDENTIAL_PARAMETERS: cCredentialParameters@0, pad 4, pCredentialParameters@8; size 16.
    [Fact]
    public void CoseParameters()
    {
        Assert.Equal(24, Marshal.SizeOf<WebAuthnCoseCredentialParameter>());
        Assert.Equal(8, Off<WebAuthnCoseCredentialParameter>(nameof(WebAuthnCoseCredentialParameter.pwszCredentialType)));
        Assert.Equal(16, Off<WebAuthnCoseCredentialParameter>(nameof(WebAuthnCoseCredentialParameter.lAlg)));
        Assert.Equal(16, Marshal.SizeOf<WebAuthnCoseCredentialParameters>());
        Assert.Equal(8, Off<WebAuthnCoseCredentialParameters>(nameof(WebAuthnCoseCredentialParameters.pCredentialParameters)));
    }

    // WEBAUTHN_CLIENT_DATA: dwVersion@0, cbClientDataJSON@4, pbClientDataJSON@8, pwszHashAlgId@16; size 24.
    [Fact]
    public void ClientData()
    {
        Assert.Equal(24, Marshal.SizeOf<WebAuthnClientData>());
        Assert.Equal(8, Off<WebAuthnClientData>(nameof(WebAuthnClientData.pbClientDataJSON)));
        Assert.Equal(16, Off<WebAuthnClientData>(nameof(WebAuthnClientData.pwszHashAlgId)));
    }

    // WEBAUTHN_CREDENTIAL: dwVersion@0, cbId@4, pbId@8, pwszCredentialType@16; size 24.
    // WEBAUTHN_CREDENTIALS / WEBAUTHN_CREDENTIAL_LIST / WEBAUTHN_EXTENSIONS: count@0, pad 4, pointer@8; size 16.
    // WEBAUTHN_CREDENTIAL_EX: as WEBAUTHN_CREDENTIAL, then dwTransports@24, tail pad 4; size 32.
    [Fact]
    public void Credentials()
    {
        Assert.Equal(24, Marshal.SizeOf<WebAuthnCredential>());
        Assert.Equal(16, Off<WebAuthnCredential>(nameof(WebAuthnCredential.pwszCredentialType)));
        Assert.Equal(16, Marshal.SizeOf<WebAuthnCredentials>());
        Assert.Equal(8, Off<WebAuthnCredentials>(nameof(WebAuthnCredentials.pCredentials)));
        Assert.Equal(32, Marshal.SizeOf<WebAuthnCredentialEx>());
        Assert.Equal(24, Off<WebAuthnCredentialEx>(nameof(WebAuthnCredentialEx.dwTransports)));
        Assert.Equal(16, Marshal.SizeOf<WebAuthnCredentialList>());
        Assert.Equal(8, Off<WebAuthnCredentialList>(nameof(WebAuthnCredentialList.ppCredentials)));
    }

    // WEBAUTHN_EXTENSION: pwszExtensionIdentifier@0, cbExtension@8, pad 4, pvExtension@16; size 24.
    [Fact]
    public void Extensions()
    {
        Assert.Equal(24, Marshal.SizeOf<WebAuthnExtension>());
        Assert.Equal(8, Off<WebAuthnExtension>(nameof(WebAuthnExtension.cbExtension)));
        Assert.Equal(16, Off<WebAuthnExtension>(nameof(WebAuthnExtension.pvExtension)));
        Assert.Equal(16, Marshal.SizeOf<WebAuthnExtensions>());
        Assert.Equal(8, Off<WebAuthnExtensions>(nameof(WebAuthnExtensions.pExtensions)));
    }

    // WEBAUTHN_HMAC_SECRET_SALT: cbFirst@0, pad 4, pbFirst@8, cbSecond@16, pad 4, pbSecond@24; size 32.
    // WEBAUTHN_HMAC_SECRET_SALT_VALUES: pGlobalHmacSalt@0, cCredWithHmacSecretSaltList@8, pad 4,
    // pCredWithHmacSecretSaltList@16; size 24.
    [Fact]
    public void HmacSecretSalt()
    {
        Assert.Equal(32, Marshal.SizeOf<WebAuthnHmacSecretSalt>());
        Assert.Equal(8, Off<WebAuthnHmacSecretSalt>(nameof(WebAuthnHmacSecretSalt.pbFirst)));
        Assert.Equal(16, Off<WebAuthnHmacSecretSalt>(nameof(WebAuthnHmacSecretSalt.cbSecond)));
        Assert.Equal(24, Off<WebAuthnHmacSecretSalt>(nameof(WebAuthnHmacSecretSalt.pbSecond)));
        Assert.Equal(24, Marshal.SizeOf<WebAuthnHmacSecretSaltValues>());
        Assert.Equal(8, Off<WebAuthnHmacSecretSaltValues>(nameof(WebAuthnHmacSecretSaltValues.cCredWithHmacSecretSaltList)));
        Assert.Equal(16, Off<WebAuthnHmacSecretSaltValues>(nameof(WebAuthnHmacSecretSaltValues.pCredWithHmacSecretSaltList)));
    }

    // FIDO2 plan, task 5: one ceremony over every FIDO2 slot, each credential with its own PRF input. Re-confirmed in
    // webauthn.h (ef82c15, byte-identical to master on 2026-11-06):
    //   l.92-96   "#define WEBAUTHN_API_VERSION_4 4 ... WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS : 6"
    //   l.548-556 "typedef struct _WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT { DWORD cbCredID; PBYTE pbCredID;
    //             PWEBAUTHN_HMAC_SECRET_SALT pHmacSecretSalt; // Required }"
    //   l.559-565 "typedef struct _WEBAUTHN_HMAC_SECRET_SALT_VALUES { PWEBAUTHN_HMAC_SECRET_SALT pGlobalHmacSalt;
    //             DWORD cCredWithHmacSecretSaltList; PWEBAUTHN_CRED_WITH_HMAC_SECRET_SALT pCredWithHmacSecretSaltList; }"
    //   l.923-927 "The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6 ...
    //             PWEBAUTHN_HMAC_SECRET_SALT_VALUES pHmacSecretSaltValues;"
    //   l.528-529 "SALT values below by default are converted into RAW Hmac-Secret values as per PRF extension.
    //             - SHA-256(UTF8Encode("WebAuthn PRF") || 0x00 || Value)"
    //   l.861     "#define WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG 0x00100000" (raw salts; tswap leaves it off)
    // The flag's name: the plan says the prose names WEBAUTHN_CTAP_HMAC_SECRET_VALUES_FLAG; at ef82c15 the prose
    // (l.531, l.809) and the definition both say WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG, the defined name,
    // used here. No WEBAUTHN_CTAP_HMAC_SECRET_VALUES_FLAG appears anywhere in that header.
    // WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT: cbCredID@0, pad 4, pbCredID@8, pHmacSecretSalt@16; size 24.
    [Fact]
    public void CredWithHmacSecretSalt()
    {
        Assert.Equal(24, Marshal.SizeOf<WebAuthnCredWithHmacSecretSalt>());
        Assert.Equal(0, Off<WebAuthnCredWithHmacSecretSalt>(nameof(WebAuthnCredWithHmacSecretSalt.cbCredID)));
        Assert.Equal(8, Off<WebAuthnCredWithHmacSecretSalt>(nameof(WebAuthnCredWithHmacSecretSalt.pbCredID)));
        Assert.Equal(16, Off<WebAuthnCredWithHmacSecretSalt>(nameof(WebAuthnCredWithHmacSecretSalt.pHmacSecretSalt)));
    }

    // WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS cut at version 5:
    //   v1  dwVersion@0, dwTimeoutMilliseconds@4, CredentialList@8 (16), Extensions@24 (16),
    //       dwAuthenticatorAttachment@40, bRequireResidentKey@44, dwUserVerificationRequirement@48,
    //       dwAttestationConveyancePreference@52, dwFlags@56, pad 4
    //   v2  pCancellationId@64
    //   v3  pExcludeCredentialList@72
    //   v4  dwEnterpriseAttestation@80, dwLargeBlobSupport@84, bPreferResidentKey@88
    //   v5  bBrowserInPrivateMode@92
    //   size 96 (already a multiple of 8).
    [Fact]
    public void MakeCredentialOptionsV5()
    {
        Assert.Equal(96, Marshal.SizeOf<WebAuthnMakeCredentialOptionsV5>());
        Assert.Equal(8, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.CredentialList)));
        Assert.Equal(24, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.Extensions)));
        Assert.Equal(40, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.dwAuthenticatorAttachment)));
        Assert.Equal(44, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.bRequireResidentKey)));
        Assert.Equal(48, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.dwUserVerificationRequirement)));
        Assert.Equal(52, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.dwAttestationConveyancePreference)));
        Assert.Equal(56, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.dwFlags)));
        Assert.Equal(64, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.pCancellationId)));
        Assert.Equal(72, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.pExcludeCredentialList)));
        Assert.Equal(80, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.dwEnterpriseAttestation)));
        Assert.Equal(88, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.bPreferResidentKey)));
        Assert.Equal(92, Off<WebAuthnMakeCredentialOptionsV5>(nameof(WebAuthnMakeCredentialOptionsV5.bBrowserInPrivateMode)));
    }

    // WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS cut at version 6:
    //   v1  dwVersion@0, dwTimeoutMilliseconds@4, CredentialList@8, Extensions@24, dwAuthenticatorAttachment@40,
    //       dwUserVerificationRequirement@44, dwFlags@48, pad 4
    //   v2  pwszU2fAppId@56, pbU2fAppId@64
    //   v3  pCancellationId@72
    //   v4  pAllowCredentialList@80
    //   v5  dwCredLargeBlobOperation@88, cbCredLargeBlob@92, pbCredLargeBlob@96
    //   v6  pHmacSecretSaltValues@104, bBrowserInPrivateMode@112, tail pad 4
    //   size 120.
    [Fact]
    public void GetAssertionOptionsV6()
    {
        Assert.Equal(120, Marshal.SizeOf<WebAuthnGetAssertionOptionsV6>());
        Assert.Equal(44, Off<WebAuthnGetAssertionOptionsV6>(nameof(WebAuthnGetAssertionOptionsV6.dwUserVerificationRequirement)));
        Assert.Equal(48, Off<WebAuthnGetAssertionOptionsV6>(nameof(WebAuthnGetAssertionOptionsV6.dwFlags)));
        Assert.Equal(56, Off<WebAuthnGetAssertionOptionsV6>(nameof(WebAuthnGetAssertionOptionsV6.pwszU2fAppId)));
        Assert.Equal(72, Off<WebAuthnGetAssertionOptionsV6>(nameof(WebAuthnGetAssertionOptionsV6.pCancellationId)));
        Assert.Equal(80, Off<WebAuthnGetAssertionOptionsV6>(nameof(WebAuthnGetAssertionOptionsV6.pAllowCredentialList)));
        Assert.Equal(88, Off<WebAuthnGetAssertionOptionsV6>(nameof(WebAuthnGetAssertionOptionsV6.dwCredLargeBlobOperation)));
        Assert.Equal(96, Off<WebAuthnGetAssertionOptionsV6>(nameof(WebAuthnGetAssertionOptionsV6.pbCredLargeBlob)));
        Assert.Equal(104, Off<WebAuthnGetAssertionOptionsV6>(nameof(WebAuthnGetAssertionOptionsV6.pHmacSecretSaltValues)));
        Assert.Equal(112, Off<WebAuthnGetAssertionOptionsV6>(nameof(WebAuthnGetAssertionOptionsV6.bBrowserInPrivateMode)));
    }

    // WEBAUTHN_CREDENTIAL_ATTESTATION cut at version 5 (read only through webauthn.dll's own pointer):
    //   v1  dwVersion@0, pad 4, pwszFormatType@8, cbAuthenticatorData@16, pad, pbAuthenticatorData@24,
    //       cbAttestation@32, pad, pbAttestation@40, dwAttestationDecodeType@48, pad, pvAttestationDecode@56,
    //       cbAttestationObject@64, pad, pbAttestationObject@72, cbCredentialId@80, pad, pbCredentialId@88
    //   v2  Extensions@96 (16)
    //   v3  dwUsedTransport@112
    //   v4  bEpAtt@116, bLargeBlobSupported@120, bResidentKey@124
    //   v5  bPrfEnabled@128, tail pad 4
    //   size 136.
    [Fact]
    public void CredentialAttestationV5()
    {
        Assert.Equal(136, Marshal.SizeOf<WebAuthnCredentialAttestation>());
        Assert.Equal(8, Off<WebAuthnCredentialAttestation>(nameof(WebAuthnCredentialAttestation.pwszFormatType)));
        Assert.Equal(16, Off<WebAuthnCredentialAttestation>(nameof(WebAuthnCredentialAttestation.cbAuthenticatorData)));
        Assert.Equal(24, Off<WebAuthnCredentialAttestation>(nameof(WebAuthnCredentialAttestation.pbAuthenticatorData)));
        Assert.Equal(48, Off<WebAuthnCredentialAttestation>(nameof(WebAuthnCredentialAttestation.dwAttestationDecodeType)));
        Assert.Equal(80, Off<WebAuthnCredentialAttestation>(nameof(WebAuthnCredentialAttestation.cbCredentialId)));
        Assert.Equal(88, Off<WebAuthnCredentialAttestation>(nameof(WebAuthnCredentialAttestation.pbCredentialId)));
        Assert.Equal(96, Off<WebAuthnCredentialAttestation>(nameof(WebAuthnCredentialAttestation.Extensions)));
        Assert.Equal(112, Off<WebAuthnCredentialAttestation>(nameof(WebAuthnCredentialAttestation.dwUsedTransport)));
        Assert.Equal(124, Off<WebAuthnCredentialAttestation>(nameof(WebAuthnCredentialAttestation.bResidentKey)));
        Assert.Equal(128, Off<WebAuthnCredentialAttestation>(nameof(WebAuthnCredentialAttestation.bPrfEnabled)));
    }

    // WEBAUTHN_ASSERTION cut at version 3:
    //   v1  dwVersion@0, cbAuthenticatorData@4, pbAuthenticatorData@8, cbSignature@16, pad, pbSignature@24,
    //       Credential@32 (24), cbUserId@56, pad, pbUserId@64
    //   v2  Extensions@72 (16), cbCredLargeBlob@88, pad, pbCredLargeBlob@96, dwCredLargeBlobStatus@104, pad
    //   v3  pHmacSecret@112
    //   size 120.
    [Fact]
    public void AssertionV3()
    {
        Assert.Equal(120, Marshal.SizeOf<WebAuthnAssertion>());
        Assert.Equal(8, Off<WebAuthnAssertion>(nameof(WebAuthnAssertion.pbAuthenticatorData)));
        Assert.Equal(32, Off<WebAuthnAssertion>(nameof(WebAuthnAssertion.Credential)));
        Assert.Equal(56, Off<WebAuthnAssertion>(nameof(WebAuthnAssertion.cbUserId)));
        Assert.Equal(72, Off<WebAuthnAssertion>(nameof(WebAuthnAssertion.Extensions)));
        Assert.Equal(104, Off<WebAuthnAssertion>(nameof(WebAuthnAssertion.dwCredLargeBlobStatus)));
        Assert.Equal(112, Off<WebAuthnAssertion>(nameof(WebAuthnAssertion.pHmacSecret)));
    }

    // Final review (GLM p4a 4): webauthn.dll is not a KnownDLL, so it is loaded from System32 only, never from the
    // application folder.
    [Fact]
    public void WebAuthnImports_LoadFromSystem32Only()
    {
        var imports = typeof(TswapCore.Vault.Interop.WebAuthnNativeMethods)
            .GetMethods(System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public)
            .Where(m => m.GetCustomAttributes(typeof(System.Runtime.InteropServices.LibraryImportAttribute), false).Length > 0)
            .ToList();

        Assert.Equal(7, imports.Count);
        Assert.All(imports, m => Assert.Equal(
            System.Runtime.InteropServices.DllImportSearchPath.System32,
            Assert.IsType<System.Runtime.InteropServices.DefaultDllImportSearchPathsAttribute>(
                Assert.Single(m.GetCustomAttributes(typeof(System.Runtime.InteropServices.DefaultDllImportSearchPathsAttribute), false))).Paths));
    }
}
