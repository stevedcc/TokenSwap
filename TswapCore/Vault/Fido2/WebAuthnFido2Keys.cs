using System.Buffers.Text;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using TswapCore.Keyring;
using TswapCore.Vault.Interop;

namespace TswapCore.Vault.Fido2;

/// <summary>
/// <c>webauthn.dll</c> as the FIDO2 device on Windows (FIDO2 plan, task 5; ported from the Windows gate spike, 1e3d56b,
/// which the owner ran under NativeAOT on 2026-11-06). Windows' security key dialog picks the key and asks for its PIN
/// (creating one when the key has none), so keys can't be listed (<see cref="CanList"/> false), every <c>key</c>
/// argument is null, the PIN delegate is never called, and <see cref="Find"/>, <see cref="FindHolder"/> and
/// <see cref="SetPin"/> throw <see cref="NotSupportedException"/>.
///
/// <para><b>Make-credential</b>: cross-platform, user verification required, non-discoverable
/// (<c>bRequireResidentKey = 0</c>, <c>bPreferResidentKey = 0</c>), <c>hmac-secret</c> on, ES256, relying party
/// <see cref="Fido2SlotBlob.TswapRpId"/>, the caller's 16-byte user id named <c>tswap</c> with no display name, the
/// vault's FIDO2 credentials as the exclude list, and direct attestation (under "none" Windows zeroes the AAGUID). The
/// AAGUID and credential id come from the attested credential data; a credential id that differs from the
/// attestation's is refused.</para>
///
/// <para><b>The assertion</b> allows every credential passed, each with its own salt in
/// <c>pCredWithHmacSecretSaltList</c>: tswap applies the PRF transform itself (<see cref="Fido2Prf.Salt"/>, the SDK
/// path's function) and sets <c>WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG</c> so Windows passes that salt raw.
/// Why not let Windows hash it: webauthn.h gained the PRF default conversion and the flag together (Feb 2022) while the
/// API version stayed 4, so an earlier API-4 <c>webauthn.dll</c> may pass a salt raw and would silently give a wrong
/// KEK; with the flag and tswap's own hash, both DLL generations send the key the same salt as Linux and macOS (a DLL
/// that rejects the flag fails loudly, never with a wrong KEK). The credential Windows answers with says which slot it
/// was. Windows' copy of the output is zeroed before it is freed.</para>
///
/// <para><b>Failures</b> are <see cref="Fido2DeviceException"/>s only: an HRESULT becomes a kind and its winerror.h
/// name (<see cref="FromHResult"/>); an API below version 4 is <see cref="Fido2Failure.Unsupported"/> with the version
/// number as the detail, checked at every operation before anything is shown.</para>
/// </summary>
public sealed class WebAuthnFido2Keys : IFido2Keys
{
    private readonly IWebAuthnApi _api;

    [SupportedOSPlatform("windows")]
    public WebAuthnFido2Keys()
        : this(new WindowsWebAuthnApi())
    {
    }

    internal WebAuthnFido2Keys(IWebAuthnApi api) => _api = api;

    public bool CanList => false;

    public IReadOnlyList<Fido2KeyInfo> Find() => throw NotOnWindows();

    public Fido2KeyInfo? FindHolder(byte[] credentialId) => throw NotOnWindows();

    public void SetPin(Fido2KeyRef key, Fido2DevicePin newPin) => throw NotOnWindows();

    public Fido2Made MakeCredential(Fido2KeyRef? key, byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds, Fido2DevicePin pin)
    {
        RequireNoKey(key);
        ArgumentNullException.ThrowIfNull(pin); // never called: Windows' dialog asks for the PIN
        return Guarded(() =>
        {
            RequireApi();
            using var call = BuildMakeCredential(userId, excludeCredentialIds);
            var hr = _api.MakeCredential(call, out var attestation);
            try
            {
                if (hr < 0)
                    throw FromHResult(hr, atAssertion: false);
                if (attestation == IntPtr.Zero)
                    throw new Fido2DeviceException(Fido2Failure.Other, null, "NoAttestation");
                return ReadAttestation(attestation);
            }
            finally
            {
                if (attestation != IntPtr.Zero)
                    _api.FreeCredentialAttestation(attestation);
            }
        });
    }

    public Fido2Output GetHmacSecret(Fido2KeyRef? key, IReadOnlyList<(byte[] CredentialId, byte[] PrfInput)> allowed, Fido2DevicePin pin)
    {
        RequireNoKey(key);
        ArgumentNullException.ThrowIfNull(pin); // never called: Windows' dialog asks for the PIN
        if (allowed.Count == 0)
            throw new ArgumentException("The assertion needs at least one credential", nameof(allowed));
        return Guarded(() =>
        {
            RequireApi();
            using var call = BuildGetAssertion(allowed);
            var hr = _api.GetAssertion(call, out var assertion);
            try
            {
                if (hr < 0)
                    throw FromHResult(hr, atAssertion: true);
                if (assertion == IntPtr.Zero)
                    throw new Fido2DeviceException(Fido2Failure.Other, null, "NoAssertion");
                return ReadAssertion(assertion);
            }
            finally
            {
                if (assertion != IntPtr.Zero)
                    _api.FreeAssertion(assertion);
            }
        });
    }

    private const uint TimeoutMilliseconds = 120_000;

    /// <summary>The make-credential user name; no display name (small user entity, plan "Global Constraints").</summary>
    internal const string UserName = "tswap";

    /// <summary>The relying party's name, which Windows' dialog may show.</summary>
    internal const string RpName = "tswap";

    /// <summary>tswap's make-credential (see the class summary), in native memory the returned call owns.</summary>
    internal static WebAuthnMakeCredentialCall BuildMakeCredential(byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds)
    {
        if (userId.Length != Fido2Service.UserIdSize)
            throw new ArgumentException($"The user id is {Fido2Service.UserIdSize} bytes", nameof(userId));

        var call = new WebAuthnMakeCredentialCall();
        var arena = call.Arena;
        call.Rp = arena.Struct(new WebAuthnRpEntityInformation
        {
            dwVersion = WebAuthn.RpEntityVersion,
            pwszId = arena.String(Fido2SlotBlob.TswapRpId),
            pwszName = arena.String(RpName),
        });
        call.User = arena.Struct(new WebAuthnUserEntityInformation
        {
            dwVersion = WebAuthn.UserEntityVersion,
            cbId = (uint)userId.Length,
            pbId = arena.Bytes(userId),
            pwszName = arena.String(UserName),
        });
        call.PubKeyCredParams = arena.Struct(new WebAuthnCoseCredentialParameters
        {
            cCredentialParameters = 1,
            pCredentialParameters = arena.Struct(new WebAuthnCoseCredentialParameter
            {
                dwVersion = WebAuthn.CoseCredentialParameterVersion,
                pwszCredentialType = arena.String(WebAuthn.CredentialTypePublicKey),
                lAlg = WebAuthn.CoseAlgorithmEs256,
            }),
        });
        call.ClientData = ClientData(arena, "webauthn.create");

        // The hmac-secret make-credential input: a BOOL TRUE (webauthn.h, WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET).
        var hmacSecret = arena.Struct(new WebAuthnExtension
        {
            pwszExtensionIdentifier = arena.String(WebAuthn.ExtensionHmacSecret),
            cbExtension = sizeof(int),
            pvExtension = arena.Struct(1),
        });
        call.Options = arena.Struct(new WebAuthnMakeCredentialOptionsV5
        {
            dwVersion = WebAuthn.MakeCredentialOptionsVersion5,
            dwTimeoutMilliseconds = TimeoutMilliseconds,
            Extensions = new WebAuthnExtensions { cExtensions = 1, pExtensions = hmacSecret },
            dwAuthenticatorAttachment = WebAuthn.AttachmentCrossPlatform,
            bRequireResidentKey = 0,
            dwUserVerificationRequirement = WebAuthn.UserVerificationRequired,
            dwAttestationConveyancePreference = WebAuthn.AttestationConveyanceDirect,
            dwFlags = 0,
            pExcludeCredentialList = excludeCredentialIds.Count == 0 ? IntPtr.Zero : CredentialList(arena, excludeCredentialIds),
            bPreferResidentKey = 0,
        });
        return call;
    }

    /// <summary>
    /// The user-verified assertion over every credential in <paramref name="allowed"/>, each with
    /// <see cref="Fido2Prf.Salt"/> of its PRF input as its own salt (<c>pCredWithHmacSecretSaltList</c>; no global salt)
    /// and <c>WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG</c> so Windows passes the salts raw (see the class summary).
    /// In native memory the returned call owns.
    /// </summary>
    internal static WebAuthnGetAssertionCall BuildGetAssertion(IReadOnlyList<(byte[] CredentialId, byte[] PrfInput)> allowed)
    {
        var call = new WebAuthnGetAssertionCall();
        var arena = call.Arena;
        call.RpId = arena.String(Fido2SlotBlob.TswapRpId);
        call.ClientData = ClientData(arena, "webauthn.get");

        var salts = new WebAuthnCredWithHmacSecretSalt[allowed.Count];
        for (var i = 0; i < allowed.Count; i++)
        {
            var (credentialId, prfInput) = allowed[i];
            var salt = Fido2Prf.Salt(prfInput);
            salts[i] = new WebAuthnCredWithHmacSecretSalt
            {
                cbCredID = (uint)credentialId.Length,
                pbCredID = arena.Bytes(credentialId),
                pHmacSecretSalt = arena.Struct(new WebAuthnHmacSecretSalt
                {
                    cbFirst = (uint)salt.Length,
                    pbFirst = arena.Bytes(salt),
                }),
            };
            CryptographicOperations.ZeroMemory(salt);
        }
        var saltValues = arena.Struct(new WebAuthnHmacSecretSaltValues
        {
            pGlobalHmacSalt = IntPtr.Zero,
            cCredWithHmacSecretSaltList = (uint)salts.Length,
            pCredWithHmacSecretSaltList = arena.Array<WebAuthnCredWithHmacSecretSalt>(salts),
        });

        call.Options = arena.Struct(new WebAuthnGetAssertionOptionsV6
        {
            dwVersion = WebAuthn.GetAssertionOptionsVersion6,
            dwTimeoutMilliseconds = TimeoutMilliseconds,
            dwAuthenticatorAttachment = WebAuthn.AttachmentCrossPlatform,
            dwUserVerificationRequirement = WebAuthn.UserVerificationRequired,
            dwFlags = WebAuthn.AuthenticatorHmacSecretValuesFlag, // the salts are hashed already: pass them raw
            pAllowCredentialList = CredentialList(arena, [.. allowed.Select(a => a.CredentialId)]),
            pHmacSecretSaltValues = saltValues,
        });
        return call;
    }

    /// <summary>
    /// A WEBAUTHN_CREDENTIAL_LIST of public-key credentials over USB or NFC: a YubiKey tapped on a reader is offered too
    /// (USB only would hide it at unlock and let an NFC enrolment pass the exclude list, the only duplicate check on
    /// Windows). Not 0 ("no transport restrictions", webauthn.h l.335), which with cross-platform attachment may offer
    /// hybrid sign-in with a phone, a dead end for these non-discoverable credentials; not BLE.
    /// </summary>
    private static IntPtr CredentialList(WebAuthnArena arena, IReadOnlyList<byte[]> ids)
    {
        var type = arena.String(WebAuthn.CredentialTypePublicKey);
        var pointers = new IntPtr[ids.Count];
        for (var i = 0; i < ids.Count; i++)
            pointers[i] = arena.Struct(new WebAuthnCredentialEx
            {
                dwVersion = WebAuthn.CredentialExVersion,
                cbId = (uint)ids[i].Length,
                pbId = arena.Bytes(ids[i]),
                pwszCredentialType = type,
                dwTransports = WebAuthn.CtapTransportUsb | WebAuthn.CtapTransportNfc,
            });
        return arena.Struct(new WebAuthnCredentialList { cCredentials = (uint)ids.Count, ppCredentials = arena.Array<IntPtr>(pointers) });
    }

    /// <summary>
    /// The client data Windows hashes: a random challenge (nothing checks the signature or attestation) and the
    /// relying party's origin.
    /// </summary>
    private static IntPtr ClientData(WebAuthnArena arena, string type)
    {
        var challenge = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        var json = Encoding.UTF8.GetBytes(
            $$"""{"type":"{{type}}","challenge":"{{challenge}}","origin":"https://{{Fido2SlotBlob.TswapRpId}}","crossOrigin":false}""");
        return arena.Struct(new WebAuthnClientData
        {
            dwVersion = WebAuthn.ClientDataVersion,
            cbClientDataJSON = (uint)json.Length,
            pbClientDataJSON = arena.Bytes(json),
            pwszHashAlgId = arena.String(WebAuthn.HashAlgorithmSha256),
        });
    }

    /// <summary>
    /// Reads a WEBAUTHN_CREDENTIAL_ATTESTATION: the credential id (which must equal the attested credential data's), the
    /// AAGUID from the attested credential data, and the UV flag. A credential the extension output says was made
    /// without <c>hmac-secret</c> is refused; when Windows reports no output, the first assertion tells.
    /// </summary>
    private static unsafe Fido2Made ReadAttestation(IntPtr pointer)
    {
        var attestation = (WebAuthnCredentialAttestation*)pointer;
        var authData = AuthenticatorData.Parse(
            new ReadOnlySpan<byte>((void*)attestation->pbAuthenticatorData, (int)attestation->cbAuthenticatorData));
        if (authData.Aaguid is null || authData.CredentialId is null)
            throw new Fido2DeviceException(Fido2Failure.Other, null, "NoAttestedCredentialData");

        var credentialId = new ReadOnlySpan<byte>((void*)attestation->pbCredentialId, (int)attestation->cbCredentialId).ToArray();
        if (!credentialId.AsSpan().SequenceEqual(authData.CredentialId))
            throw new Fido2DeviceException(Fido2Failure.Other, null, "CredentialIdMismatch");
        if (attestation->dwVersion >= WebAuthn.CredentialAttestationVersion2 && HmacSecretCreated(attestation->Extensions) == false)
            throw new Fido2DeviceException(Fido2Failure.Other, null, "HmacSecretNotCreated");

        return new Fido2Made(credentialId, new Guid(authData.Aaguid, bigEndian: true), Serial: null, authData.UserVerified);
    }

    /// <summary>The hmac-secret make-credential output (a BOOL), or null when Windows returned none.</summary>
    private static unsafe bool? HmacSecretCreated(WebAuthnExtensions extensions)
    {
        var list = (WebAuthnExtension*)extensions.pExtensions;
        for (var i = 0; list != null && i < extensions.cExtensions; i++)
        {
            if (Marshal.PtrToStringUni(list[i].pwszExtensionIdentifier) != WebAuthn.ExtensionHmacSecret)
                continue;
            if (list[i].cbExtension < sizeof(int) || list[i].pvExtension == IntPtr.Zero)
                return null;
            return *(int*)list[i].pvExtension != 0;
        }
        return null;
    }

    /// <summary>
    /// Reads a WEBAUTHN_ASSERTION: the credential that answered, the UV flag, and the hmac-secret output (empty when
    /// Windows returned none: the service refuses a missing output). Windows' copy of the output is zeroed here.
    /// </summary>
    private static unsafe Fido2Output ReadAssertion(IntPtr pointer)
    {
        var assertion = (WebAuthnAssertion*)pointer;
        var authData = AuthenticatorData.Parse(
            new ReadOnlySpan<byte>((void*)assertion->pbAuthenticatorData, (int)assertion->cbAuthenticatorData));
        var credentialId = new ReadOnlySpan<byte>((void*)assertion->Credential.pbId, (int)assertion->Credential.cbId).ToArray();

        byte[] output = [];
        if (assertion->dwVersion >= WebAuthn.AssertionVersion3 && assertion->pHmacSecret != IntPtr.Zero)
        {
            var secret = (WebAuthnHmacSecretSalt*)assertion->pHmacSecret;
            if (secret->pbFirst != IntPtr.Zero)
            {
                var first = new Span<byte>((void*)secret->pbFirst, (int)secret->cbFirst);
                output = first.ToArray();
                CryptographicOperations.ZeroMemory(first);
            }
            if (secret->pbSecond != IntPtr.Zero)
                CryptographicOperations.ZeroMemory(new Span<byte>((void*)secret->pbSecond, (int)secret->cbSecond));
        }
        return new Fido2Output(credentialId, output, authData.UserVerified);
    }

    private void RequireApi()
    {
        var version = _api.ApiVersion();
        if (version < WebAuthn.ApiVersion4)
            throw new Fido2DeviceException(Fido2Failure.Unsupported, null, version.ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// Runs <paramref name="operation"/>; anything but a <see cref="Fido2DeviceException"/> becomes one: no
    /// <c>webauthn.dll</c> (Windows before 10 1903) or no such export is <see cref="Fido2Failure.Unsupported"/> with no
    /// version, malformed authenticator data is <see cref="Fido2Failure.Other"/>.
    /// </summary>
    private static T Guarded<T>(Func<T> operation)
    {
        try
        {
            return operation();
        }
        catch (Fido2DeviceException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw e switch
            {
                DllNotFoundException or EntryPointNotFoundException => new Fido2DeviceException(Fido2Failure.Unsupported, null, null),
                FormatException => new Fido2DeviceException(Fido2Failure.Other, null, "MalformedAuthenticatorData"),
                _ => new Fido2DeviceException(Fido2Failure.Other, null, e.GetType().Name),
            };
        }
    }

    // HRESULTs (winerror.h). webauthn.h's WebAuthNGetErrorName comment (ef82c15, l.1348-1362) lists every one it maps:
    //   InvalidStateError - NTE_EXISTS; ConstraintError - HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED), NTE_NOT_SUPPORTED,
    //   NTE_TOKEN_KEYSET_STORAGE_FULL; NotSupportedError - NTE_INVALID_PARAMETER; NotAllowedError - NTE_DEVICE_NOT_FOUND,
    //   NTE_NOT_FOUND, HRESULT_FROM_WIN32(ERROR_CANCELLED), NTE_USER_CANCELLED, HRESULT_FROM_WIN32(ERROR_TIMEOUT).
    // The rest below are not in that list (busy and the PIN class, which Windows' dialog normally handles itself): mapped
    // in case webauthn.dll passes them through, unconfirmed by Microsoft's documentation.
    private const int NteExists = unchecked((int)0x8009000F);
    private const int NteNotFound = unchecked((int)0x80090011);
    private const int NteTokenKeysetStorageFull = unchecked((int)0x80090023);
    private const int NteInvalidParameter = unchecked((int)0x80090027);
    private const int NteNotSupported = unchecked((int)0x80090029);
    private const int NteIncorrectPassword = unchecked((int)0x80090033);
    private const int NteDeviceNotFound = unchecked((int)0x80090035);
    private const int NteUserCancelled = unchecked((int)0x80090036);
    private const int ScardWWrongChv = unchecked((int)0x8010006B);
    private const int ScardWChvBlocked = unchecked((int)0x8010006C);
    private const int Win32NotSupported = unchecked((int)0x80070032); // HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)
    private const int Win32Busy = unchecked((int)0x800700AA); // HRESULT_FROM_WIN32(ERROR_BUSY)
    private const int Win32Cancelled = unchecked((int)0x800704C7); // HRESULT_FROM_WIN32(ERROR_CANCELLED)
    private const int Win32Timeout = unchecked((int)0x800705B4); // HRESULT_FROM_WIN32(ERROR_TIMEOUT)

    /// <summary>
    /// A failed HRESULT as a failure: the kind, and its winerror.h name as the detail (<c>HRESULT 0x...</c> for one
    /// without a name here). PIN results carry no count (Windows' dialog doesn't report one). NTE_NOT_FOUND is
    /// <see cref="Fido2Failure.NoCredential"/> only <paramref name="atAssertion"/> (credentials were asked for); at
    /// make-credential it is <see cref="Fido2Failure.Other"/>. No HRESULT is mapped to
    /// <see cref="Fido2Failure.PinNeedsReinsert"/>: none is known to mean CTAP2_ERR_PIN_AUTH_BLOCKED.
    /// </summary>
    internal static Fido2DeviceException FromHResult(int hr, bool atAssertion)
    {
        var (kind, name) = hr switch
        {
            NteExists => (Fido2Failure.CredentialExcluded, "NTE_EXISTS"),
            NteNotFound => (atAssertion ? Fido2Failure.NoCredential : Fido2Failure.Other, "NTE_NOT_FOUND"),
            NteDeviceNotFound => (Fido2Failure.NotPluggedIn, "NTE_DEVICE_NOT_FOUND"),
            NteUserCancelled => (Fido2Failure.Cancelled, "NTE_USER_CANCELLED"),
            Win32Cancelled => (Fido2Failure.Cancelled, "ERROR_CANCELLED"),
            Win32Timeout => (Fido2Failure.TimedOut, "ERROR_TIMEOUT"),
            NteInvalidParameter => (Fido2Failure.Other, "NTE_INVALID_PARAMETER"),
            NteNotSupported => (Fido2Failure.Other, "NTE_NOT_SUPPORTED"),
            Win32NotSupported => (Fido2Failure.Other, "ERROR_NOT_SUPPORTED"),
            NteTokenKeysetStorageFull => (Fido2Failure.Other, "NTE_TOKEN_KEYSET_STORAGE_FULL"),
            Win32Busy => (Fido2Failure.Busy, "ERROR_BUSY"),
            NteIncorrectPassword => (Fido2Failure.PinWrong, "NTE_INCORRECT_PASSWORD"),
            ScardWWrongChv => (Fido2Failure.PinWrong, "SCARD_W_WRONG_CHV"),
            ScardWChvBlocked => (Fido2Failure.PinBlocked, "SCARD_W_CHV_BLOCKED"),
            _ => (Fido2Failure.Other, $"HRESULT 0x{hr:X8}"),
        };
        return new Fido2DeviceException(kind, null, name);
    }

    private static void RequireNoKey(Fido2KeyRef? key)
    {
        if (key is not null)
            throw new ArgumentException("Windows' dialog picks the key; pass no key", nameof(key));
    }

    private static NotSupportedException NotOnWindows() =>
        new("Windows' dialog picks the key: keys can't be listed, probed or given a PIN through webauthn.dll");
}

/// <summary>One make-credential's arguments in native memory (<see cref="Arena"/>, zeroed and freed on dispose).</summary>
internal sealed class WebAuthnMakeCredentialCall : IDisposable
{
    public WebAuthnArena Arena { get; } = new();
    public IntPtr Rp { get; set; }
    public IntPtr User { get; set; }
    public IntPtr PubKeyCredParams { get; set; }
    public IntPtr ClientData { get; set; }
    public IntPtr Options { get; set; }

    public void Dispose() => Arena.Dispose();
}

/// <summary>One assertion's arguments in native memory (<see cref="Arena"/>, zeroed and freed on dispose).</summary>
internal sealed class WebAuthnGetAssertionCall : IDisposable
{
    public WebAuthnArena Arena { get; } = new();
    public IntPtr RpId { get; set; }
    public IntPtr ClientData { get; set; }
    public IntPtr Options { get; set; }

    public void Dispose() => Arena.Dispose();
}

/// <summary><c>webauthn.dll</c> as <see cref="WebAuthnFido2Keys"/> calls it (a seam for tests).</summary>
internal interface IWebAuthnApi
{
    /// <summary><c>WebAuthNGetApiVersionNumber</c>.</summary>
    uint ApiVersion();

    /// <summary><c>WebAuthNAuthenticatorMakeCredential</c>: the HRESULT, and the attestation (zero when none).</summary>
    int MakeCredential(WebAuthnMakeCredentialCall call, out IntPtr attestation);

    void FreeCredentialAttestation(IntPtr attestation);

    /// <summary><c>WebAuthNAuthenticatorGetAssertion</c>: the HRESULT, and the assertion (zero when none).</summary>
    int GetAssertion(WebAuthnGetAssertionCall call, out IntPtr assertion);

    void FreeAssertion(IntPtr assertion);
}

/// <summary>The real <c>webauthn.dll</c>, its dialog owned by the console window (else the foreground window).</summary>
[SupportedOSPlatform("windows")]
internal sealed unsafe class WindowsWebAuthnApi : IWebAuthnApi
{
    public uint ApiVersion() => WebAuthnNativeMethods.WebAuthNGetApiVersionNumber();

    public int MakeCredential(WebAuthnMakeCredentialCall call, out IntPtr attestation)
    {
        IntPtr result = IntPtr.Zero;
        var hr = WebAuthnNativeMethods.WebAuthNAuthenticatorMakeCredential(
            WebAuthnNativeMethods.Window(), call.Rp, call.User, call.PubKeyCredParams, call.ClientData, call.Options, &result);
        attestation = result;
        return hr;
    }

    public void FreeCredentialAttestation(IntPtr attestation) => WebAuthnNativeMethods.WebAuthNFreeCredentialAttestation(attestation);

    public int GetAssertion(WebAuthnGetAssertionCall call, out IntPtr assertion)
    {
        IntPtr result = IntPtr.Zero;
        var hr = WebAuthnNativeMethods.WebAuthNAuthenticatorGetAssertion(
            WebAuthnNativeMethods.Window(), call.RpId, call.ClientData, call.Options, &result);
        assertion = result;
        return hr;
    }

    public void FreeAssertion(IntPtr assertion) => WebAuthnNativeMethods.WebAuthNFreeAssertion(assertion);
}
