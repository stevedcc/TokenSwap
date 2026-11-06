using System.Runtime.InteropServices;

namespace YkSpike;

// The webauthn.dll structures this spike uses, from Microsoft's webauthn.h (github.com/microsoft/webauthn, API version 9
// header, commit ef82c15), each cut at the struct version the spike needs. Blittable on purpose (uint/int/nint only, BOOL
// as int, every pointer as IntPtr) so NativeAOT needs no marshalling code. The x64 offsets and sizes, with their
// derivation, are pinned in spikes/yubikey-sdk.Tests/WebAuthnLayoutTests.cs. Field names follow the header.

/// <summary>webauthn.h constants.</summary>
internal static class WebAuthn
{
    public const uint ApiVersion4 = 4; // first API with GET_ASSERTION_OPTIONS v6 (hmac-secret salt values) and MAKE_CREDENTIAL_OPTIONS v5
    public const uint RpEntityVersion = 1;
    public const uint UserEntityVersion = 1;
    public const uint ClientDataVersion = 1;
    public const uint CoseCredentialParameterVersion = 1;
    public const uint CredentialExVersion = 1;
    public const uint MakeCredentialOptionsVersion5 = 5;
    public const uint GetAssertionOptionsVersion6 = 6;
    public const uint CredentialAttestationVersion2 = 2; // Extensions
    public const uint CredentialAttestationVersion3 = 3; // dwUsedTransport
    public const uint CredentialAttestationVersion5 = 5; // bPrfEnabled
    public const uint AssertionVersion3 = 3; // pHmacSecret

    public const uint CtapTransportUsb = 0x00000001;
    public const int CoseAlgorithmEs256 = -7;
    public const uint AttachmentCrossPlatform = 2;
    public const uint UserVerificationRequired = 1;
    public const uint AttestationConveyanceNone = 1;
    public const uint AttestationConveyanceDirect = 3;

    public const string HashAlgorithmSha256 = "SHA-256";
    public const string CredentialTypePublicKey = "public-key";
    public const string ExtensionHmacSecret = "hmac-secret";
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnRpEntityInformation
{
    public uint dwVersion;
    public IntPtr pwszId;
    public IntPtr pwszName;
    public IntPtr pwszIcon;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnUserEntityInformation
{
    public uint dwVersion;
    public uint cbId;
    public IntPtr pbId;
    public IntPtr pwszName;
    public IntPtr pwszIcon;
    public IntPtr pwszDisplayName;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnCoseCredentialParameter
{
    public uint dwVersion;
    public IntPtr pwszCredentialType;
    public int lAlg; // LONG
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnCoseCredentialParameters
{
    public uint cCredentialParameters;
    public IntPtr pCredentialParameters;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnClientData
{
    public uint dwVersion;
    public uint cbClientDataJSON;
    public IntPtr pbClientDataJSON;
    public IntPtr pwszHashAlgId;
}

// WEBAUTHN_CREDENTIAL (version 1). Embedded in WEBAUTHN_ASSERTION.
[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnCredential
{
    public uint dwVersion;
    public uint cbId;
    public IntPtr pbId;
    public IntPtr pwszCredentialType;
}

// WEBAUTHN_CREDENTIALS (unversioned). Embedded in both option structs.
[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnCredentials
{
    public uint cCredentials;
    public IntPtr pCredentials;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnCredentialEx
{
    public uint dwVersion;
    public uint cbId;
    public IntPtr pbId;
    public IntPtr pwszCredentialType;
    public uint dwTransports;
}

// WEBAUTHN_CREDENTIAL_LIST (unversioned); ppCredentials is an array of PWEBAUTHN_CREDENTIAL_EX.
[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnCredentialList
{
    public uint cCredentials;
    public IntPtr ppCredentials;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnExtension
{
    public IntPtr pwszExtensionIdentifier;
    public uint cbExtension;
    public IntPtr pvExtension;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnExtensions
{
    public uint cExtensions;
    public IntPtr pExtensions;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnHmacSecretSalt
{
    public uint cbFirst;
    public IntPtr pbFirst;
    public uint cbSecond;
    public IntPtr pbSecond;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnHmacSecretSaltValues
{
    public IntPtr pGlobalHmacSalt;
    public uint cCredWithHmacSecretSaltList;
    public IntPtr pCredWithHmacSecretSaltList;
}

// WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS cut at version 5 (API version 4 and later accept it).
[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnMakeCredentialOptionsV5
{
    public uint dwVersion;
    public uint dwTimeoutMilliseconds;
    public WebAuthnCredentials CredentialList;
    public WebAuthnExtensions Extensions;
    public uint dwAuthenticatorAttachment;
    public int bRequireResidentKey; // BOOL
    public uint dwUserVerificationRequirement;
    public uint dwAttestationConveyancePreference;
    public uint dwFlags;
    // v2
    public IntPtr pCancellationId; // GUID*
    // v3
    public IntPtr pExcludeCredentialList; // PWEBAUTHN_CREDENTIAL_LIST
    // v4
    public uint dwEnterpriseAttestation;
    public uint dwLargeBlobSupport;
    public int bPreferResidentKey; // BOOL
    // v5
    public int bBrowserInPrivateMode; // BOOL
}

// WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS cut at version 6.
[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnGetAssertionOptionsV6
{
    public uint dwVersion;
    public uint dwTimeoutMilliseconds;
    public WebAuthnCredentials CredentialList;
    public WebAuthnExtensions Extensions;
    public uint dwAuthenticatorAttachment;
    public uint dwUserVerificationRequirement;
    public uint dwFlags;
    // v2
    public IntPtr pwszU2fAppId;
    public IntPtr pbU2fAppId; // BOOL*
    // v3
    public IntPtr pCancellationId; // GUID*
    // v4
    public IntPtr pAllowCredentialList;
    // v5
    public uint dwCredLargeBlobOperation;
    public uint cbCredLargeBlob;
    public IntPtr pbCredLargeBlob;
    // v6
    public IntPtr pHmacSecretSaltValues;
    public int bBrowserInPrivateMode; // BOOL
}

// WEBAUTHN_CREDENTIAL_ATTESTATION cut at version 5. Only read through the pointer webauthn.dll allocates (at its own,
// possibly later, version), so later fields need not be declared; check dwVersion before reading a later field.
[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnCredentialAttestation
{
    public uint dwVersion;
    public IntPtr pwszFormatType;
    public uint cbAuthenticatorData;
    public IntPtr pbAuthenticatorData;
    public uint cbAttestation;
    public IntPtr pbAttestation;
    public uint dwAttestationDecodeType;
    public IntPtr pvAttestationDecode;
    public uint cbAttestationObject;
    public IntPtr pbAttestationObject;
    public uint cbCredentialId;
    public IntPtr pbCredentialId;
    // v2
    public WebAuthnExtensions Extensions;
    // v3
    public uint dwUsedTransport;
    // v4
    public int bEpAtt; // BOOL
    public int bLargeBlobSupported; // BOOL
    public int bResidentKey; // BOOL
    // v5
    public int bPrfEnabled; // BOOL
}

// WEBAUTHN_ASSERTION cut at version 3; read only through webauthn.dll's pointer, as above.
[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnAssertion
{
    public uint dwVersion;
    public uint cbAuthenticatorData;
    public IntPtr pbAuthenticatorData;
    public uint cbSignature;
    public IntPtr pbSignature;
    public WebAuthnCredential Credential;
    public uint cbUserId;
    public IntPtr pbUserId;
    // v2
    public WebAuthnExtensions Extensions;
    public uint cbCredLargeBlob;
    public IntPtr pbCredLargeBlob;
    public uint dwCredLargeBlobStatus;
    // v3
    public IntPtr pHmacSecret; // PWEBAUTHN_HMAC_SECRET_SALT
}
