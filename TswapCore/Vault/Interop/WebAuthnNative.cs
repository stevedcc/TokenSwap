using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TswapCore.Vault.Interop;

// The webauthn.dll structures tswap uses (FIDO2 plan, task 5; ported from the Windows gate spike, 1e3d56b), from
// Microsoft's webauthn.h (github.com/microsoft/webauthn, API version 9 header, commit ef82c15), each cut at the struct
// version tswap needs. Blittable on purpose (uint/int/nint only, BOOL as int, every pointer as IntPtr) so NativeAOT
// needs no marshalling code. The x64 offsets and sizes, with their derivation, are pinned in
// TswapTests/WebAuthnLayoutTests.cs (run on every OS: these structs lay out the same on Linux x64). Field names follow
// the header.

/// <summary>webauthn.h constants.</summary>
internal static class WebAuthn
{
    /// <summary>The first API with GET_ASSERTION_OPTIONS v6 (hmac-secret salt values) and MAKE_CREDENTIAL_OPTIONS v5.</summary>
    public const uint ApiVersion4 = 4;
    public const uint RpEntityVersion = 1;
    public const uint UserEntityVersion = 1;
    public const uint ClientDataVersion = 1;
    public const uint CoseCredentialParameterVersion = 1;
    public const uint CredentialExVersion = 1;
    public const uint MakeCredentialOptionsVersion5 = 5;
    public const uint GetAssertionOptionsVersion6 = 6;
    public const uint CredentialAttestationVersion2 = 2; // Extensions
    public const uint AssertionVersion3 = 3; // pHmacSecret

    public const uint CtapTransportUsb = 0x00000001;
    public const uint CtapTransportNfc = 0x00000002;
    public const int CoseAlgorithmEs256 = -7;
    public const uint AttachmentCrossPlatform = 2;
    public const uint UserVerificationRequired = 1;
    public const uint AttestationConveyanceDirect = 3;

    /// <summary>
    /// <c>WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG</c>: the salts are raw hmac-secret salts. tswap sets it at every
    /// assertion and hashes each PRF input itself (<c>Fido2Prf.Salt</c>): the header added this flag together with the
    /// default PRF conversion (Feb 2022, API still 4), so an earlier API-4 DLL may pass salts raw either way.
    /// </summary>
    public const uint AuthenticatorHmacSecretValuesFlag = 0x00100000;

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

// WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT: one allowed credential's PRF input (the list is part of
// WEBAUTHN_HMAC_SECRET_SALT_VALUES, GET_ASSERTION_OPTIONS v6, API 4).
[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnCredWithHmacSecretSalt
{
    public uint cbCredID;
    public IntPtr pbCredID;
    public IntPtr pHmacSecretSalt; // PWEBAUTHN_HMAC_SECRET_SALT
}

[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnHmacSecretSaltValues
{
    public IntPtr pGlobalHmacSalt;
    public uint cCredWithHmacSecretSaltList;
    public IntPtr pCredWithHmacSecretSaltList; // WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT[]
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

/// <summary>
/// Native memory for one <c>webauthn.dll</c> call: zero-filled blocks, each zeroed again and freed on
/// <see cref="Dispose"/> (the PRF inputs and the user id live here). Pure memory: no P/Invoke.
/// </summary>
internal sealed unsafe class WebAuthnArena : IDisposable
{
    private readonly List<(IntPtr Pointer, nuint Size)> _blocks = [];

    public IntPtr Alloc(int size)
    {
        var bytes = (nuint)Math.Max(size, 1);
        var p = (IntPtr)NativeMemory.AllocZeroed(bytes);
        _blocks.Add((p, bytes));
        return p;
    }

    public IntPtr Bytes(ReadOnlySpan<byte> bytes)
    {
        var p = Alloc(bytes.Length);
        bytes.CopyTo(new Span<byte>((void*)p, bytes.Length));
        return p;
    }

    /// <summary>A NUL-terminated UTF-16 string (LPCWSTR).</summary>
    public IntPtr String(string text)
    {
        var p = Alloc((text.Length + 1) * sizeof(char));
        text.AsSpan().CopyTo(new Span<char>((void*)p, text.Length));
        return p;
    }

    public IntPtr Struct<T>(T value) where T : unmanaged
    {
        var p = Alloc(sizeof(T));
        *(T*)p = value;
        return p;
    }

    public IntPtr Array<T>(ReadOnlySpan<T> items) where T : unmanaged
    {
        var p = Alloc(items.Length * sizeof(T));
        items.CopyTo(new Span<T>((void*)p, items.Length));
        return p;
    }

    public void Dispose()
    {
        foreach (var (pointer, size) in _blocks)
        {
            NativeMemory.Clear((void*)pointer, size);
            NativeMemory.Free((void*)pointer);
        }
        _blocks.Clear();
    }
}

/// <summary>The P/Invokes into <c>webauthn.dll</c> (and the window handle for its dialog). Windows only.</summary>
[SupportedOSPlatform("windows")]
internal static unsafe partial class WebAuthnNativeMethods
{
    [LibraryImport("webauthn.dll")]
    internal static partial uint WebAuthNGetApiVersionNumber();

    [LibraryImport("webauthn.dll")]
    internal static partial int WebAuthNAuthenticatorMakeCredential(
        IntPtr hWnd, IntPtr pRpInformation, IntPtr pUserInformation, IntPtr pPubKeyCredParams, IntPtr pClientData,
        IntPtr pOptions, IntPtr* ppAttestation);

    [LibraryImport("webauthn.dll")]
    internal static partial void WebAuthNFreeCredentialAttestation(IntPtr pAttestation);

    [LibraryImport("webauthn.dll")]
    internal static partial int WebAuthNAuthenticatorGetAssertion(
        IntPtr hWnd, IntPtr pwszRpId, IntPtr pClientData, IntPtr pOptions, IntPtr* ppAssertion);

    [LibraryImport("webauthn.dll")]
    internal static partial void WebAuthNFreeAssertion(IntPtr pAssertion);

    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr GetConsoleWindow();

    [LibraryImport("user32.dll")]
    internal static partial IntPtr GetForegroundWindow();

    /// <summary>The window Windows' security key dialog belongs to: the console's, else the foreground window.</summary>
    internal static IntPtr Window()
    {
        var hwnd = GetConsoleWindow();
        return hwnd != IntPtr.Zero ? hwnd : GetForegroundWindow();
    }
}
