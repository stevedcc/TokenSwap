namespace TswapCore.Vault.Fido2;

/// <summary>
/// The FIDO2 device seam (FIDO2 plan, task 3): one call per operation, no texts. <see cref="Fido2Service"/> sits on
/// top and composes every message. Implementations: Yubico's SDK on Linux and macOS (<see cref="CanList"/> true, keys
/// addressed by <see cref="Fido2KeyRef"/>), <c>webauthn.dll</c> on Windows (<see cref="CanList"/> false: Windows'
/// dialog picks the key and asks for the PIN, every <c>key</c> argument is null, and <see cref="Find"/>,
/// <see cref="FindHolder"/> and <see cref="SetPin"/> throw <see cref="NotSupportedException"/>), and a fake for tests.
///
/// <para><b>Failures</b> are <see cref="Fido2DeviceException"/>s: a <see cref="Fido2Failure"/>, the PIN tries left
/// when the key reported them, and a status name (never the SDK's prose). A <see cref="Fido2DeviceException"/> thrown
/// by a <see cref="Fido2DevicePin"/> (the person cancelled at the prompt, or a second PIN request was refused) must
/// propagate out of the operation unchanged, without the PIN being sent to the key.</para>
///
/// <para><b>Every credential</b> is non-discoverable (<c>rk = false</c>), needs user verification (PIN and touch),
/// has <c>hmac-secret</c> on and the relying-party id <see cref="Keyring.Fido2SlotBlob.TswapRpId"/>.</para>
/// </summary>
public interface IFido2Keys
{
    /// <summary>Whether keys can be listed and addressed (false on Windows: the dialog picks the key).</summary>
    bool CanList { get; }

    /// <summary>
    /// Every plugged-in FIDO2 key, read fresh from the key: keys without a serial are listed too. Only when
    /// <see cref="CanList"/>.
    /// </summary>
    IReadOnlyList<Fido2KeyInfo> Find();

    /// <summary>
    /// Makes a credential on <paramref name="key"/> (null on Windows). <paramref name="userId"/> is 16 random bytes
    /// made by the caller (name <c>tswap</c>, no display name); it is not stored, and a non-discoverable credential
    /// never returns it. A key holding one of <paramref name="excludeCredentialIds"/> refuses with
    /// <see cref="Fido2Failure.CredentialExcluded"/>. <paramref name="pin"/> is called at most once.
    /// </summary>
    Fido2Made MakeCredential(Fido2KeyRef? key, byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds, Fido2DevicePin pin);

    /// <summary>
    /// A user-verified assertion with the <c>hmac-secret</c> extension over <paramref name="allowed"/>: the SDK path
    /// is called with one entry (the located slot) and sends the key <c>Fido2Prf.Salt(PrfInput)</c>; the Windows path
    /// with every FIDO2 slot of the vault, passing <c>Fido2Prf.Salt</c> of each PRF input to <c>webauthn.dll</c>
    /// raw (<c>WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG</c>), so the key gets the same salt. Returns which credential answered and its output (the caller zeroes the output).
    /// <paramref name="pin"/> is called at most once.
    /// </summary>
    Fido2Output GetHmacSecret(Fido2KeyRef? key, IReadOnlyList<(byte[] CredentialId, byte[] PrfInput)> allowed, Fido2DevicePin pin);

    /// <summary>
    /// A silent assertion (user presence off: no PIN, no touch) for <paramref name="credentialId"/> on every
    /// plugged-in key, serial or not: the key that holds it, or null when none does. Only when <see cref="CanList"/>.
    /// </summary>
    Fido2KeyInfo? FindHolder(byte[] credentialId);

    /// <summary>
    /// Sets the FIDO2 PIN of a key that has none (<paramref name="newPin"/> is called once, with no retries). Only when
    /// <see cref="CanList"/>.
    /// </summary>
    void SetPin(Fido2KeyRef key, Fido2DevicePin newPin);

    /// <summary>
    /// Brief T19, item 3: whether libfido2 (security keys other than YubiKeys, Linux and macOS) is available:
    /// <see cref="Libfido2.CompositeFido2Keys"/> returns its loaded status, loading it if needed; null on Windows
    /// (<c>webauthn.dll</c> talks to every brand) and in the SDK-only and fake backends unless a test sets it.
    /// <see cref="Fido2Service"/> reads it only for its two "needs libfido2" hints.
    /// </summary>
    Libfido2.Libfido2Status? OtherBrands => null;
}

/// <summary>An opaque handle to a plugged-in key (the SDK's device path), valid for this process only.</summary>
public sealed record Fido2KeyRef(string Id);

/// <summary>
/// A plugged-in key as <see cref="IFido2Keys.Find"/> read it: its handle, serial (null when the key reports none),
/// AAGUID (model), whether a FIDO2 PIN is set (what enrolment checks) and the PIN tries left (null when unknown).
/// </summary>
public sealed record Fido2KeyInfo(Fido2KeyRef Key, int? Serial, Guid Aaguid, bool PinSet, int? PinRetries, string? Product = null);

/// <summary>
/// A credential make-credential returned: its id, the AAGUID from the attested credential data (zero on Windows when
/// it reported none), the key's serial when the device layer knows it, and whether the key verified the user.
/// </summary>
public sealed record Fido2Made(byte[] CredentialId, Guid Aaguid, int? Serial, bool UserVerified);

/// <summary>
/// An assertion's result: the credential that answered, its <c>hmac-secret</c> output (32 bytes from a key that
/// follows the spec; the caller zeroes it) and whether the key verified the user.
/// </summary>
public sealed record Fido2Output(byte[] CredentialId, byte[] Output, bool UserVerified);

/// <summary>
/// What the device layer calls for a PIN, with the tries left when the key reported them. No names, no texts:
/// <see cref="Fido2Service"/> builds it from the caller's <see cref="Fido2Pin"/>. The device zeroes the returned
/// bytes after use. It may throw <see cref="Fido2DeviceException"/> (cancelled at the prompt, or a second request
/// in one operation), which the device lets through.
/// </summary>
public delegate byte[] Fido2DevicePin(int? retriesLeft);
