using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace YkSpike;

/// <summary>
/// Task 4: FIDO2 PRF through webauthn.dll. Asserts the Linux-made credential with the PRF input (not the raw salt), so
/// Windows applies SHA-256("WebAuthn PRF" || 0x00 || input) itself; output_h must equal the Linux SDK run's output_h.
/// Struct layouts follow Microsoft's webauthn.h (API version 9 header), cut at the struct version this spike needs.
/// </summary>
public static unsafe partial class Fido2Windows
{
    // webauthn.h constants.
    private const uint ApiVersionWithHmacSecretSaltValues = 4; // WEBAUTHN_API_VERSION_4: GET_ASSERTION_OPTIONS v6, ASSERTION v3
    private const uint ClientDataVersion = 1; // WEBAUTHN_CLIENT_DATA_CURRENT_VERSION
    private const uint CredentialExVersion = 1; // WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION
    private const uint GetAssertionOptionsVersion6 = 6; // first version with pHmacSecretSaltValues
    private const uint AssertionVersion3 = 3; // first version with pHmacSecret
    private const uint CtapTransportUsb = 0x00000001;
    private const uint AttachmentCrossPlatform = 2;
    private const uint UserVerificationDiscouraged = 3;
    private const uint TimeoutMilliseconds = 60_000;

    public static void Enroll(string outPath) =>
        throw new PlatformNotSupportedException("enrol on Linux; the cross-OS check uses the Linux credential");

    [SupportedOSPlatform("windows")]
    public static void Assert(Fido2.Cred cred)
    {
        var api = WebAuthNGetApiVersionNumber();
        Report.Line("webauthn_api", api);
        if (api < ApiVersionWithHmacSecretSaltValues)
            throw new PlatformNotSupportedException(
                $"webauthn.dll API version {api} has no hmac-secret salt values (needs {ApiVersionWithHmacSecretSaltValues} or later)");

        var credentialId = Fido2.FromBase64Url(cred.credential_id);
        var prfInput = Encoding.UTF8.GetBytes(Fido2.PrfInput);
        var clientDataJson = Encoding.UTF8.GetBytes(
            $$"""{"type":"webauthn.get","challenge":"{{Fido2.Base64Url(RandomNumberGenerator.GetBytes(32))}}","origin":"https://{{cred.rp_id}}"}""");

        var rpId = IntPtr.Zero;
        var hashAlg = IntPtr.Zero;
        var credType = IntPtr.Zero;
        WebAuthnAssertion* assertion = null;
        fixed (byte* pCredId = credentialId)
        fixed (byte* pPrfInput = prfInput)
        fixed (byte* pClientDataJson = clientDataJson)
        {
            try
            {
                rpId = Marshal.StringToHGlobalUni(cred.rp_id);
                hashAlg = Marshal.StringToHGlobalUni("SHA-256"); // WEBAUTHN_HASH_ALGORITHM_SHA_256
                credType = Marshal.StringToHGlobalUni("public-key"); // WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY

                var clientData = new WebAuthnClientData
                {
                    dwVersion = ClientDataVersion,
                    cbClientDataJSON = (uint)clientDataJson.Length,
                    pbClientDataJSON = (IntPtr)pClientDataJson,
                    pwszHashAlgId = hashAlg,
                };
                var credential = new WebAuthnCredentialEx
                {
                    dwVersion = CredentialExVersion,
                    cbId = (uint)credentialId.Length,
                    pbId = (IntPtr)pCredId,
                    pwszCredentialType = credType,
                    dwTransports = CtapTransportUsb,
                };
                var pCredential = &credential;
                var allowList = new WebAuthnCredentialList { cCredentials = 1, ppCredentials = (IntPtr)(&pCredential) };
                var salt = new WebAuthnHmacSecretSalt
                {
                    cbFirst = (uint)prfInput.Length,
                    pbFirst = (IntPtr)pPrfInput,
                    cbSecond = 0,
                    pbSecond = IntPtr.Zero,
                };
                var saltValues = new WebAuthnHmacSecretSaltValues
                {
                    pGlobalHmacSalt = (IntPtr)(&salt),
                    cCredWithHmacSecretSaltList = 0,
                    pCredWithHmacSecretSaltList = IntPtr.Zero,
                };
                var options = new WebAuthnGetAssertionOptionsV6
                {
                    dwVersion = GetAssertionOptionsVersion6,
                    dwTimeoutMilliseconds = TimeoutMilliseconds,
                    CredentialList = default, // ignored when pAllowCredentialList is set
                    Extensions = default,
                    dwAuthenticatorAttachment = AttachmentCrossPlatform,
                    dwUserVerificationRequirement = UserVerificationDiscouraged,
                    dwFlags = 0, // no WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG: Windows applies the PRF transform
                    pwszU2fAppId = IntPtr.Zero,
                    pbU2fAppId = IntPtr.Zero,
                    pCancellationId = IntPtr.Zero,
                    pAllowCredentialList = (IntPtr)(&allowList),
                    dwCredLargeBlobOperation = 0,
                    cbCredLargeBlob = 0,
                    pbCredLargeBlob = IntPtr.Zero,
                    pHmacSecretSaltValues = (IntPtr)(&saltValues),
                    bBrowserInPrivateMode = 0,
                };

                var hwnd = GetConsoleWindow();
                if (hwnd == IntPtr.Zero)
                    hwnd = GetForegroundWindow();

                Console.Error.WriteLine("(Windows will show its security key dialog; touch your YubiKey)");
                var hr = WebAuthNAuthenticatorGetAssertion(hwnd, rpId, &clientData, &options, &assertion);
                if (hr < 0)
                {
                    var name = Marshal.PtrToStringUni(WebAuthNGetErrorName(hr)) ?? "?";
                    Report.Line("error", $"hresult 0x{hr:X8} {name}");
                    return;
                }
                if (assertion == null)
                {
                    Report.Line("error", "no assertion returned");
                    return;
                }

                Report.Line("assertion_version", assertion->dwVersion);
                if (assertion->cbAuthenticatorData > 32)
                {
                    var flags = ((byte*)assertion->pbAuthenticatorData)[32];
                    Report.Line("uv_flag", $"{(flags & 0x04) != 0} (the key's own user-verified flag; False = touch only)");
                }
                else
                {
                    Report.Line("uv_flag", $"unknown (authenticator data only {assertion->cbAuthenticatorData} bytes)");
                }

                if (assertion->dwVersion < AssertionVersion3 || assertion->pHmacSecret == IntPtr.Zero)
                {
                    Report.Line("error", "no hmac-secret output in the assertion");
                }
                else
                {
                    var secret = (WebAuthnHmacSecretSalt*)assertion->pHmacSecret;
                    var output = new ReadOnlySpan<byte>((void*)secret->pbFirst, (int)secret->cbFirst);
                    Report.Line("output_bytes", output.Length);
                    Report.Line("output_h", Report.Hash16(output));
                }
            }
            finally
            {
                if (assertion != null)
                    WebAuthNFreeAssertion(assertion);
                Marshal.FreeHGlobal(rpId);
                Marshal.FreeHGlobal(hashAlg);
                Marshal.FreeHGlobal(credType);
            }
        }

        Console.Error.Write("Did Windows ask for a PIN? (y/n) ");
        var answer = Console.ReadLine()?.Trim();
        Report.Line("pin_asked", answer is { Length: > 0 } && (answer[0] == 'y' || answer[0] == 'Y'));
    }

    // WEBAUTHN_CLIENT_DATA (version 1): 4 fields.
    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnClientData
    {
        public uint dwVersion;
        public uint cbClientDataJSON;
        public IntPtr pbClientDataJSON;
        public IntPtr pwszHashAlgId;
    }

    // WEBAUTHN_CREDENTIAL (version 1): 4 fields. Embedded in WEBAUTHN_ASSERTION.
    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnCredential
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        public IntPtr pwszCredentialType;
    }

    // WEBAUTHN_CREDENTIALS (unversioned): 2 fields. Embedded in the options (CredentialList, unused here).
    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnCredentials
    {
        public uint cCredentials;
        public IntPtr pCredentials;
    }

    // WEBAUTHN_CREDENTIAL_EX (version 1): 5 fields.
    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnCredentialEx
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        public IntPtr pwszCredentialType;
        public uint dwTransports;
    }

    // WEBAUTHN_CREDENTIAL_LIST (unversioned): 2 fields; ppCredentials is an array of PWEBAUTHN_CREDENTIAL_EX.
    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnCredentialList
    {
        public uint cCredentials;
        public IntPtr ppCredentials;
    }

    // WEBAUTHN_EXTENSIONS (unversioned): 2 fields. Embedded in the options and the assertion.
    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnExtensions
    {
        public uint cExtensions;
        public IntPtr pExtensions;
    }

    // WEBAUTHN_HMAC_SECRET_SALT (unversioned): 4 fields.
    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnHmacSecretSalt
    {
        public uint cbFirst;
        public IntPtr pbFirst;
        public uint cbSecond;
        public IntPtr pbSecond;
    }

    // WEBAUTHN_HMAC_SECRET_SALT_VALUES (unversioned): 3 fields.
    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnHmacSecretSaltValues
    {
        public IntPtr pGlobalHmacSalt;
        public uint cCredWithHmacSecretSaltList;
        public IntPtr pCredWithHmacSecretSaltList;
    }

    // WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS cut at version 6: 16 fields (v1: 7, v2: +2, v3: +1, v4: +1, v5: +3, v6: +2).
    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnGetAssertionOptionsV6
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

    // WEBAUTHN_ASSERTION cut at version 3: 13 fields (v1: 8, v2: +4, v3: +1). Only read through a pointer that
    // webauthn.dll allocated (at its own, possibly later, version), so the later fields need not be declared.
    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnAssertion
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

    [LibraryImport("webauthn.dll")]
    private static partial uint WebAuthNGetApiVersionNumber();

    [LibraryImport("webauthn.dll")]
    private static partial int WebAuthNAuthenticatorGetAssertion(
        IntPtr hWnd, IntPtr pwszRpId, WebAuthnClientData* pClientData, WebAuthnGetAssertionOptionsV6* pOptions,
        WebAuthnAssertion** ppAssertion);

    [LibraryImport("webauthn.dll")]
    private static partial void WebAuthNFreeAssertion(WebAuthnAssertion* pAssertion);

    [LibraryImport("webauthn.dll")]
    private static partial IntPtr WebAuthNGetErrorName(int hr);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetConsoleWindow();

    [LibraryImport("user32.dll")]
    private static partial IntPtr GetForegroundWindow();
}
