using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace YkSpike;

/// <summary>
/// FIDO2 through webauthn.dll (the "Windows gate"): make a non-discoverable credential with hmac-secret and user
/// verification required, then assert it twice with user verification required and the PRF input (not the raw salt), so
/// Windows applies SHA-256("WebAuthn PRF" || 0x00 || input) itself. output_h must equal the Linux/macOS SDK run's
/// <c>fido2-assert --uv</c> output_h for the same credential. Structures: WebAuthnNative.cs.
/// </summary>
public static unsafe partial class Fido2Windows
{
    private const uint TimeoutMilliseconds = 120_000;

    [SupportedOSPlatform("windows")]
    public static void Enroll(string outPath, bool directAttestation)
    {
        CheckApi();
        var userId = RandomNumberGenerator.GetBytes(16);
        var clientDataJson = ClientDataJson("webauthn.create", Fido2.RpId);
        var hmacSecretOn = 1; // BOOL TRUE: the hmac-secret make-credential input
        var conveyance = directAttestation ? WebAuthn.AttestationConveyanceDirect : WebAuthn.AttestationConveyanceNone;
        Report.Line("attestation_requested", directAttestation ? "direct" : "none");

        using var strings = new NativeStrings();
        WebAuthnCredentialAttestation* attestation = null;
        fixed (byte* pUserId = userId)
        fixed (byte* pClientDataJson = clientDataJson)
        {
            try
            {
                var rp = new WebAuthnRpEntityInformation
                {
                    dwVersion = WebAuthn.RpEntityVersion,
                    pwszId = strings.Add(Fido2.RpId),
                    pwszName = strings.Add("tswap yk-spike"),
                    pwszIcon = IntPtr.Zero,
                };
                var user = new WebAuthnUserEntityInformation
                {
                    dwVersion = WebAuthn.UserEntityVersion,
                    cbId = (uint)userId.Length,
                    pbId = (IntPtr)pUserId,
                    pwszName = strings.Add("yk-spike"),
                    pwszIcon = IntPtr.Zero,
                    pwszDisplayName = strings.Add("yk-spike"),
                };
                var es256 = new WebAuthnCoseCredentialParameter
                {
                    dwVersion = WebAuthn.CoseCredentialParameterVersion,
                    pwszCredentialType = strings.Add(WebAuthn.CredentialTypePublicKey),
                    lAlg = WebAuthn.CoseAlgorithmEs256,
                };
                var pubKeyParams = new WebAuthnCoseCredentialParameters { cCredentialParameters = 1, pCredentialParameters = (IntPtr)(&es256) };
                var clientData = new WebAuthnClientData
                {
                    dwVersion = WebAuthn.ClientDataVersion,
                    cbClientDataJSON = (uint)clientDataJson.Length,
                    pbClientDataJSON = (IntPtr)pClientDataJson,
                    pwszHashAlgId = strings.Add(WebAuthn.HashAlgorithmSha256),
                };
                var hmacSecret = new WebAuthnExtension
                {
                    pwszExtensionIdentifier = strings.Add(WebAuthn.ExtensionHmacSecret),
                    cbExtension = sizeof(int),
                    pvExtension = (IntPtr)(&hmacSecretOn),
                };
                var options = new WebAuthnMakeCredentialOptionsV5
                {
                    dwVersion = WebAuthn.MakeCredentialOptionsVersion5,
                    dwTimeoutMilliseconds = TimeoutMilliseconds,
                    CredentialList = default, // no exclude list
                    Extensions = new WebAuthnExtensions { cExtensions = 1, pExtensions = (IntPtr)(&hmacSecret) },
                    dwAuthenticatorAttachment = WebAuthn.AttachmentCrossPlatform,
                    bRequireResidentKey = 0, // non-discoverable: nothing is stored on the key
                    dwUserVerificationRequirement = WebAuthn.UserVerificationRequired,
                    dwAttestationConveyancePreference = conveyance,
                    dwFlags = 0,
                    pCancellationId = IntPtr.Zero,
                    pExcludeCredentialList = IntPtr.Zero,
                    dwEnterpriseAttestation = 0,
                    dwLargeBlobSupport = 0,
                    bPreferResidentKey = 0,
                    bBrowserInPrivateMode = 0,
                };

                Console.Error.WriteLine("(Windows will show its security key dialog: enter your FIDO2 PIN, then touch your YubiKey)");
                var hr = WebAuthNAuthenticatorMakeCredential(Window(), &rp, &user, &pubKeyParams, &clientData, &options, &attestation);
                if (hr < 0)
                    throw Failure("WebAuthNAuthenticatorMakeCredential", hr);
                if (attestation == null)
                    throw new InvalidOperationException("WebAuthNAuthenticatorMakeCredential returned no attestation");

                Report.Line("attestation_version", attestation->dwVersion);
                Report.Line("attestation_format", Marshal.PtrToStringUni(attestation->pwszFormatType) ?? "(null)");
                if (attestation->dwVersion >= WebAuthn.CredentialAttestationVersion3)
                    Report.Line("used_transport", $"0x{attestation->dwUsedTransport:X}");
                Report.Line("hmac_secret_created", attestation->dwVersion >= WebAuthn.CredentialAttestationVersion2
                    ? HmacSecretOutput(attestation->Extensions)
                    : $"unknown (attestation version {attestation->dwVersion} has no extensions)");
                if (attestation->dwVersion >= WebAuthn.CredentialAttestationVersion5)
                    Report.Line("prf_enabled", attestation->bPrfEnabled != 0);

                var authData = new ReadOnlySpan<byte>((void*)attestation->pbAuthenticatorData, (int)attestation->cbAuthenticatorData);
                var parsed = AuthenticatorDataInfo.Parse(authData);
                Report.Line("uv_flag", $"{parsed.UserVerified} (the key's own user-verified flag)");
                Fido2.ReportAaguid(parsed);
                if (parsed.AaguidIsZero && !directAttestation)
                    Report.Line("aaguid_note",
                        "webauthn.dll zeroed the AAGUID under attestation \"none\"; rerun with: fido2-enroll --attestation direct --out cred-windows-direct.json");

                var credentialId = new ReadOnlySpan<byte>((void*)attestation->pbCredentialId, (int)attestation->cbCredentialId).ToArray();
                Report.Line("credential_id_bytes", credentialId.Length);
                Report.Line("credential_id_matches_auth_data", parsed.CredentialId is { } id && id.AsSpan().SequenceEqual(credentialId));
                Fido2.SaveCred(outPath, credentialId);
            }
            finally
            {
                if (attestation != null)
                    WebAuthNFreeCredentialAttestation(attestation);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    public static void Assert(Fido2.Cred cred)
    {
        CheckApi();
        var credentialId = Fido2.FromBase64Url(cred.credential_id);
        var first = AssertOnce(cred.rp_id, credentialId, out var uv1);
        var second = AssertOnce(cred.rp_id, credentialId, out var uv2);
        try
        {
            Report.Line("uv_flag", $"{uv1},{uv2} (the key's own user-verified flag; must be True)");
            Report.Line("output_bytes", first.Length);
            Report.Line("output_h_1", Report.Hash16(first));
            Report.Line("output_h_2", Report.Hash16(second));
            Report.Line("output_h", Report.Hash16(first));
            Report.Line("deterministic", first.AsSpan().SequenceEqual(second));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
    }

    /// <summary>One get-assertion with user verification required and the PRF input as the global salt.</summary>
    [SupportedOSPlatform("windows")]
    private static byte[] AssertOnce(string rpIdText, byte[] credentialId, out bool userVerified)
    {
        var prfInput = Encoding.UTF8.GetBytes(Fido2.PrfInput);
        var clientDataJson = ClientDataJson("webauthn.get", rpIdText);
        using var strings = new NativeStrings();
        WebAuthnAssertion* assertion = null;
        fixed (byte* pCredId = credentialId)
        fixed (byte* pPrfInput = prfInput)
        fixed (byte* pClientDataJson = clientDataJson)
        {
            try
            {
                var rpId = strings.Add(rpIdText);
                var clientData = new WebAuthnClientData
                {
                    dwVersion = WebAuthn.ClientDataVersion,
                    cbClientDataJSON = (uint)clientDataJson.Length,
                    pbClientDataJSON = (IntPtr)pClientDataJson,
                    pwszHashAlgId = strings.Add(WebAuthn.HashAlgorithmSha256),
                };
                var credential = new WebAuthnCredentialEx
                {
                    dwVersion = WebAuthn.CredentialExVersion,
                    cbId = (uint)credentialId.Length,
                    pbId = (IntPtr)pCredId,
                    pwszCredentialType = strings.Add(WebAuthn.CredentialTypePublicKey),
                    dwTransports = WebAuthn.CtapTransportUsb,
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
                    dwVersion = WebAuthn.GetAssertionOptionsVersion6,
                    dwTimeoutMilliseconds = TimeoutMilliseconds,
                    CredentialList = default, // ignored when pAllowCredentialList is set
                    Extensions = default,
                    dwAuthenticatorAttachment = WebAuthn.AttachmentCrossPlatform,
                    dwUserVerificationRequirement = WebAuthn.UserVerificationRequired,
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

                Console.Error.WriteLine("(Windows will show its security key dialog: enter your FIDO2 PIN, then touch your YubiKey)");
                var hr = WebAuthNAuthenticatorGetAssertion(Window(), rpId, &clientData, &options, &assertion);
                if (hr < 0)
                    throw Failure("WebAuthNAuthenticatorGetAssertion", hr);
                if (assertion == null)
                    throw new InvalidOperationException("WebAuthNAuthenticatorGetAssertion returned no assertion");

                Report.Line("assertion_version", assertion->dwVersion);
                var authData = new ReadOnlySpan<byte>((void*)assertion->pbAuthenticatorData, (int)assertion->cbAuthenticatorData);
                userVerified = AuthenticatorDataInfo.Parse(authData).UserVerified;
                if (assertion->dwVersion < WebAuthn.AssertionVersion3 || assertion->pHmacSecret == IntPtr.Zero)
                    throw new InvalidOperationException("no hmac-secret output in the assertion");
                var secret = (WebAuthnHmacSecretSalt*)assertion->pHmacSecret;
                return new ReadOnlySpan<byte>((void*)secret->pbFirst, (int)secret->cbFirst).ToArray();
            }
            finally
            {
                if (assertion != null)
                    WebAuthNFreeAssertion(assertion);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CheckApi()
    {
        var api = WebAuthNGetApiVersionNumber();
        Report.Line("webauthn_api", api);
        if (api < WebAuthn.ApiVersion4)
            throw new PlatformNotSupportedException(
                $"webauthn.dll API version {api} has no hmac-secret salt values (needs {WebAuthn.ApiVersion4} or later)");
    }

    /// <summary>The hmac-secret make-credential output: a BOOL, TRUE when the credential was made with hmac-secret.</summary>
    private static string HmacSecretOutput(WebAuthnExtensions extensions)
    {
        var list = (WebAuthnExtension*)extensions.pExtensions;
        for (var i = 0; i < extensions.cExtensions; i++)
        {
            if (Marshal.PtrToStringUni(list[i].pwszExtensionIdentifier) != WebAuthn.ExtensionHmacSecret)
                continue;
            if (list[i].cbExtension < sizeof(int) || list[i].pvExtension == IntPtr.Zero)
                return $"unknown (hmac-secret output of {list[i].cbExtension} bytes)";
            return (*(int*)list[i].pvExtension != 0).ToString();
        }
        return $"not returned ({extensions.cExtensions} extension outputs, none hmac-secret)";
    }

    private static byte[] ClientDataJson(string type, string rpId) => Encoding.UTF8.GetBytes(
        $$"""{"type":"{{type}}","challenge":"{{Fido2.Base64Url(RandomNumberGenerator.GetBytes(32))}}","origin":"https://{{rpId}}","crossOrigin":false}""");

    [SupportedOSPlatform("windows")]
    private static IntPtr Window()
    {
        var hwnd = GetConsoleWindow();
        return hwnd != IntPtr.Zero ? hwnd : GetForegroundWindow();
    }

    [SupportedOSPlatform("windows")]
    private static InvalidOperationException Failure(string call, int hr)
    {
        var name = Marshal.PtrToStringUni(WebAuthNGetErrorName(hr)) ?? "?";
        return new InvalidOperationException(
            $"{call} failed: hresult 0x{hr:X8} {name} (a cancelled dialog, a wrong PIN or a timeout all end here; the spike never retries)");
    }

    /// <summary>UTF-16 strings in unmanaged memory for one call; freed together.</summary>
    private sealed class NativeStrings : IDisposable
    {
        private readonly List<IntPtr> _all = [];

        public IntPtr Add(string text)
        {
            var p = Marshal.StringToHGlobalUni(text);
            _all.Add(p);
            return p;
        }

        public void Dispose()
        {
            foreach (var p in _all)
                Marshal.FreeHGlobal(p);
            _all.Clear();
        }
    }

    [LibraryImport("webauthn.dll")]
    private static partial uint WebAuthNGetApiVersionNumber();

    [LibraryImport("webauthn.dll")]
    private static partial int WebAuthNAuthenticatorMakeCredential(
        IntPtr hWnd, WebAuthnRpEntityInformation* pRpInformation, WebAuthnUserEntityInformation* pUserInformation,
        WebAuthnCoseCredentialParameters* pPubKeyCredParams, WebAuthnClientData* pClientData,
        WebAuthnMakeCredentialOptionsV5* pOptions, WebAuthnCredentialAttestation** ppAttestation);

    [LibraryImport("webauthn.dll")]
    private static partial void WebAuthNFreeCredentialAttestation(WebAuthnCredentialAttestation* pAttestation);

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
