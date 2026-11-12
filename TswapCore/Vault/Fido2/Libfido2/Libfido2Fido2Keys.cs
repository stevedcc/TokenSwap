using System.Globalization;
using System.Security.Cryptography;
using TswapCore.Keyring;

namespace TswapCore.Vault.Fido2.Libfido2;

/// <summary>
/// libfido2 as a FIDO2 device on Linux and macOS (brief T19, item 2), for security keys of any brand: libfido2 does the
/// HID framing, CBOR, PIN protocol and <c>hmac-secret</c> key agreement; this class only maps <see cref="IFido2Keys"/>
/// onto its calls (<see cref="ILibfido2"/>). Yubico devices (USB vendor <c>0x1050</c>) are skipped: they stay on
/// <see cref="SdkFido2Keys"/>, so no key is listed twice. Keys are addressed by their device path.
///
/// <para><b>Parity with <see cref="SdkFido2Keys"/>:</b> make-credential and the assertion send the same CTAP2
/// parameters (relying party <see cref="Fido2SlotBlob.TswapRpId"/>, user <see cref="SdkFido2Keys.UserName"/>, ES256,
/// <c>rk</c> off, <c>hmac-secret</c>, the salt <see cref="Fido2Prf.Salt"/> of the PRF input), so a slot made by either
/// backend opens on the other. Options are <see cref="FidoOpt"/>s: off is <see cref="FidoOpt.False"/>, never 0.</para>
///
/// <para><b>Failures</b> are <see cref="Fido2DeviceException"/>s only, the detail a <c>FIDO_ERR_*</c> name
/// (<see cref="Libfido2Errors.Name"/>); <c>fido_strerr</c>'s prose goes to <c>-v</c> only. Every <c>fido_*</c> object
/// is freed in a <c>finally</c>. tswap zeroes its own buffers (the PIN, the salt); libfido2's copies inside its objects
/// are freed by its <c>*_free</c> calls, and whether libfido2 zeroes them is its behaviour, not verified here.</para>
/// </summary>
public sealed class Libfido2Fido2Keys : IFido2Keys
{
    /// <summary>Yubico's USB vendor id: such keys are the SDK backend's.</summary>
    public const short YubicoVendorId = 0x1050;

    /// <summary>The most devices one listing reads.</summary>
    public const int MaxDevices = 64;

    private const int ClientDataHashSize = 32;
    private const string HmacSecretExtension = "hmac-secret";
    private const string ClientPinOption = "clientPin";

    private readonly ILibfido2 _fido;
    private readonly TextWriter? _notices;
    private readonly TextWriter? _verbose;
    private readonly bool _linux;
    private readonly bool _includeYubico;

    /// <param name="notices">Where a plugged-in key left out of a listing is said: stderr.</param>
    /// <param name="verbose">Where <c>fido_strerr</c>'s text for a failure goes (<c>-v</c>).</param>
    public Libfido2Fido2Keys(ILibfido2 fido, TextWriter? notices = null, TextWriter? verbose = null)
        : this(fido, notices, verbose, OperatingSystem.IsLinux(), includeYubico: false)
    {
    }

    /// <param name="linux">Whether a key that can't be opened gets <see cref="Fido2Texts.NoDeviceAccess"/>.</param>
    /// <param name="includeYubico">Test only (the owner's cross-check C4): lists Yubico devices too.</param>
    internal Libfido2Fido2Keys(ILibfido2 fido, TextWriter? notices, TextWriter? verbose, bool linux, bool includeYubico)
    {
        _fido = fido;
        _notices = notices;
        _verbose = verbose;
        _linux = linux;
        _includeYubico = includeYubico;
    }

    public bool CanList => true;

    /// <summary>The longest <see cref="Fido2KeyInfo.Product"/>.</summary>
    public const int MaxProductLength = 64;

    /// <summary>
    /// A key's name from its USB strings (brief T19, item 4), which come from the device and so are untrusted: every
    /// control character dropped (<see cref="char.IsControl(char)"/>, which removes ESC and so any terminal escape
    /// sequence) and every Unicode format character (<see cref="UnicodeCategory.Format"/>: bidi overrides such as
    /// U+202E, isolates, zero-width characters; review F6), each trimmed; the product alone when it already starts with
    /// the manufacturer (ignoring case), else "manufacturer product"; at most <see cref="MaxProductLength"/>
    /// characters, never cutting a surrogate pair; null when nothing is left.
    /// </summary>
    internal static string? ProductName(string? manufacturer, string? product)
    {
        var maker = Clean(manufacturer);
        var model = Clean(product);
        var name = maker.Length == 0 ? model
            : model.Length == 0 ? maker
            : model.StartsWith(maker, StringComparison.OrdinalIgnoreCase) ? model
            : $"{maker} {model}";
        if (name.Length > MaxProductLength)
        {
            // Never keep half of a surrogate pair (review F6): a high surrogate at the cap goes with its pair.
            var cut = char.IsHighSurrogate(name[MaxProductLength - 1]) ? MaxProductLength - 1 : MaxProductLength;
            name = name[..cut].TrimEnd();
        }
        return name.Length == 0 ? null : name;

        static string Clean(string? text) => text is null ? ""
            : string.Concat(text.Where(c => !char.IsControl(c) && char.GetUnicodeCategory(c) != UnicodeCategory.Format)).Trim();
    }

    /// <summary>
    /// Every listed device (Yubico's left out) whose CBOR info could be read, opened only for that: the AAGUID, whether
    /// a PIN is set, and only then the retries. One without <c>hmac-secret</c> is left out with a notice; one that can't
    /// be read is left out with a notice (<see cref="Fido2Texts.LeftOut"/>), unless none could be read: then that
    /// failure is thrown (<c>SdkFido2Devices.ReadEach</c>'s rule).
    /// </summary>
    public IReadOnlyList<Fido2KeyInfo> Find()
    {
        List<Fido2KeyInfo> keys = [];
        List<string> notes = [];
        Fido2DeviceException? first = null;
        foreach (var device in Listed())
        {
            try
            {
                var (key, hmacSecret) = WithDevice(device.Path, operation: false, dev => Read(device, dev));
                if (hmacSecret)
                    keys.Add(key);
                else
                    notes.Add(Fido2Texts.KeyLeftOut("HmacSecretUnsupported"));
            }
            catch (Fido2DeviceException e)
            {
                first ??= e;
                notes.Add(Fido2Texts.LeftOut(e, _linux));
            }
        }
        if (keys.Count == 0 && first is not null)
            throw first;
        foreach (var note in notes)
            _notices?.WriteLine(note);
        return keys;
    }

    public Fido2Made MakeCredential(Fido2KeyRef? key, byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds, Fido2DevicePin pin)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (userId.Length != Fido2Service.UserIdSize)
            throw new ArgumentException($"The user id is {Fido2Service.UserIdSize} bytes", nameof(userId));
        return WithDevice(key.Id, operation: true, dev =>
        {
            RequirePinAndHmacSecret(key.Id, dev);
            var cred = Allocated(_fido.CredNew());
            try
            {
                Check(_fido.CredSetType(cred, Libfido2Params.CoseEs256));
                Check(_fido.CredSetClientDataHash(cred, RandomNumberGenerator.GetBytes(ClientDataHashSize)));
                Check(_fido.CredSetRp(cred, Fido2SlotBlob.TswapRpId, null));
                Check(_fido.CredSetUser(cred, userId, SdkFido2Keys.UserName, null, null));
                Check(_fido.CredSetExtensions(cred, Libfido2Params.ExtHmacSecret));
                Check(_fido.CredSetRk(cred, FidoOpt.False));
                foreach (var id in excludeCredentialIds)
                    Check(_fido.CredExclude(cred, id));

                var result = Libfido2Pin.Send(pin(null), p => _fido.DevMakeCred(dev, cred, p));
                if (result != Libfido2Errors.Ok)
                    throw Error(result, dev);

                var credentialId = _fido.CredId(cred);
                if (credentialId.Length == 0)
                    throw new Fido2DeviceException(Fido2Failure.Other, null, "NoCredentialId");
                return new Fido2Made(credentialId, Fido2Aaguid.ToGuid(_fido.CredAaguid(cred)), Serial: null,
                    UserVerified: (_fido.CredFlags(cred) & Libfido2Params.FlagUserVerified) != 0);
            }
            finally
            {
                _fido.CredFree(cred);
            }
        });
    }

    public Fido2Output GetHmacSecret(Fido2KeyRef? key, IReadOnlyList<(byte[] CredentialId, byte[] PrfInput)> allowed, Fido2DevicePin pin)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (allowed.Count != 1)
            throw new ArgumentException("On Linux and macOS the assertion is for the one located slot", nameof(allowed));
        var (credentialId, prfInput) = allowed[0];
        return WithDevice(key.Id, operation: true, dev =>
        {
            RequirePinAndHmacSecret(key.Id, dev);
            // The salt first (review F3): nothing between allocating the fido_assert_t and its try can throw.
            var salt = Fido2Prf.Salt(prfInput);
            nint assert;
            try
            {
                assert = Allocated(_fido.AssertNew());
            }
            catch
            {
                CryptographicOperations.ZeroMemory(salt);
                throw;
            }
            try
            {
                Check(_fido.AssertSetRp(assert, Fido2SlotBlob.TswapRpId));
                Check(_fido.AssertSetClientDataHash(assert, RandomNumberGenerator.GetBytes(ClientDataHashSize)));
                Check(_fido.AssertAllowCred(assert, credentialId));
                Check(_fido.AssertSetExtensions(assert, Libfido2Params.ExtHmacSecret));
                Check(_fido.AssertSetHmacSalt(assert, salt));
                CryptographicOperations.ZeroMemory(salt); // libfido2 has its own copy now
                Check(_fido.AssertSetUp(assert, FidoOpt.True));

                var result = Libfido2Pin.Send(pin(null), p => _fido.DevGetAssert(dev, assert, p));
                if (result != Libfido2Errors.Ok)
                    throw Error(result, dev);
                if (_fido.AssertCount(assert) < 1)
                    throw new Fido2DeviceException(Fido2Failure.Other, null, "NoAssertion");

                // Read straight into the array the caller gets (and zeroes): no intermediate managed copy.
                var output = _fido.AssertHmacSecret(assert, 0);
                if (output.Length != Fido2Service.OutputSize)
                {
                    // Review F4: one salt gives exactly 32 bytes; anything else is refused here, zeroed.
                    CryptographicOperations.ZeroMemory(output);
                    throw new Fido2DeviceException(Fido2Failure.Other, null, "BadHmacSecretLength");
                }
                var answered = _fido.AssertId(assert, 0);
                // CTAP 2 lets a key leave the credential out when one was allowed: it is the allowed one.
                if (answered.Length == 0)
                    answered = (byte[])credentialId.Clone();
                return new Fido2Output(answered, output, (_fido.AssertFlags(assert, 0) & Libfido2Params.FlagUserVerified) != 0);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(salt);
                _fido.AssertFree(assert);
            }
        });
    }

    /// <summary>
    /// The silent probe on every listed device (Yubico's left out): an assertion for <paramref name="credentialId"/>
    /// with <c>up</c> <see cref="FidoOpt.False"/>, no extensions and no PIN, so the key neither blinks nor asks.
    /// <c>FIDO_ERR_NO_CREDENTIALS</c> and <c>FIDO_ERR_INVALID_CREDENTIAL</c> mean "doesn't hold it"; anything else but
    /// <c>FIDO_OK</c> is a failure, which counts only when no device holds it (<c>SdkFido2Devices.FirstHolder</c>).
    /// </summary>
    public Fido2KeyInfo? FindHolder(byte[] credentialId) =>
        SdkFido2Devices.FirstHolder(Listed(), device => Probe(device.Path, credentialId),
            device => WithDevice(device.Path, operation: false, dev => Read(device, dev)).Key);

    public void SetPin(Fido2KeyRef key, Fido2DevicePin newPin) =>
        WithDevice(key.Id, operation: true, dev =>
        {
            if (Read(new Listing(key.Id, null), dev).Key.PinSet)
                throw new Fido2DeviceException(Fido2Failure.Other, null, "PinAlreadySet");
            var result = Libfido2Pin.Send(newPin(null), p => _fido.DevSetPin(dev, p));
            return result == Libfido2Errors.Ok ? true : throw Error(result, dev);
        });

    private bool Probe(string path, byte[] credentialId) => WithDevice(path, operation: false, dev =>
    {
        var assert = Allocated(_fido.AssertNew());
        try
        {
            Check(_fido.AssertSetRp(assert, Fido2SlotBlob.TswapRpId));
            Check(_fido.AssertSetClientDataHash(assert, RandomNumberGenerator.GetBytes(ClientDataHashSize)));
            Check(_fido.AssertAllowCred(assert, credentialId));
            Check(_fido.AssertSetUp(assert, FidoOpt.False));
            return _fido.DevGetAssert(dev, assert, 0) switch
            {
                Libfido2Errors.Ok => true,
                Libfido2Errors.NoCredentials or Libfido2Errors.InvalidCredential => false,
                var failed => throw Error(failed, dev),
            };
        }
        finally
        {
            _fido.AssertFree(assert);
        }
    });

    /// <summary>A listed device: its path and its <see cref="ProductName"/>.</summary>
    private sealed record Listing(string Path, string? Product);

    /// <summary>The listed devices, Yubico's left out unless the test-only flag says otherwise.</summary>
    private List<Listing> Listed()
    {
        var list = Allocated(_fido.DevInfoNew(MaxDevices));
        try
        {
            Check(_fido.DevInfoManifest(list, MaxDevices, out var found));
            List<Listing> devices = [];
            for (nuint i = 0; i < found && i < MaxDevices; i++)
            {
                var info = _fido.DevInfoPtr(list, i);
                if (info == 0 || (!_includeYubico && _fido.DevInfoVendor(info) == YubicoVendorId))
                    continue;
                if (_fido.DevInfoPath(info) is { Length: > 0 } path)
                    devices.Add(new Listing(path,
                        ProductName(_fido.DevInfoManufacturerString(info), _fido.DevInfoProductString(info))));
            }
            return devices;
        }
        finally
        {
            _fido.DevInfoFree(list, MaxDevices);
        }
    }

    /// <summary>
    /// Opens <paramref name="path"/> for <paramref name="action"/>, then closes and frees it. A failed open is
    /// <c>OpenFailed:&lt;FIDO_ERR name&gt;</c>, or, for an <paramref name="operation"/> on a key no longer listed,
    /// <see cref="Fido2Failure.NotPluggedIn"/>.
    /// </summary>
    private T WithDevice<T>(string path, bool operation, Func<nint, T> action)
    {
        var dev = Allocated(_fido.DevNew());
        try
        {
            var opened = _fido.DevOpen(dev, path);
            if (opened != Libfido2Errors.Ok)
            {
                Verbose(opened);
                var detail = Fido2Texts.OpenFailedPrefix + Libfido2Errors.Name(opened);
                throw operation && !StillListed(path)
                    ? new Fido2DeviceException(Fido2Failure.NotPluggedIn, null, detail)
                    : new Fido2DeviceException(Fido2Failure.Other, null, detail);
            }
            try
            {
                return action(dev);
            }
            finally
            {
                _fido.DevClose(dev);
            }
        }
        finally
        {
            _fido.DevFree(dev);
        }
    }

    private bool StillListed(string path)
    {
        try
        {
            return Listed().Any(d => d.Path == path);
        }
        catch (Fido2DeviceException)
        {
            return true; // can't tell: keep the open failure
        }
    }

    /// <summary>The key's CBOR info (no PIN, no touch): its listing entry and whether it has <c>hmac-secret</c>.</summary>
    private (Fido2KeyInfo Key, bool HmacSecret) Read(Listing device, nint dev)
    {
        var info = Allocated(_fido.CborInfoNew());
        Guid aaguid;
        bool hmacSecret, pinSet;
        try
        {
            Check(_fido.DevGetCborInfo(dev, info));
            aaguid = Fido2Aaguid.ToGuid(_fido.CborInfoAaguid(info));
            hmacSecret = _fido.CborInfoExtensions(info).Contains(HmacSecretExtension, StringComparer.Ordinal);
            pinSet = _fido.CborInfoOptions(info).Any(o => o.Name == ClientPinOption && o.Value);
        }
        finally
        {
            _fido.CborInfoFree(info);
        }
        // fido_dev_get_retry_count fails without a PIN, so it is asked only with one.
        int? retries = pinSet && _fido.DevGetRetryCount(dev, out var left) == Libfido2Errors.Ok ? left : null;
        return (new Fido2KeyInfo(new Fido2KeyRef(device.Path), null, aaguid, pinSet, retries, device.Product), hmacSecret);
    }

    /// <summary>As on the SDK path: a key without a PIN, or without <c>hmac-secret</c>, is refused before the PIN is asked.</summary>
    private void RequirePinAndHmacSecret(string path, nint dev)
    {
        var (key, hmacSecret) = Read(new Listing(path, null), dev);
        if (!key.PinSet)
            throw new Fido2DeviceException(Fido2Failure.NoPin, null, "PinNotSet");
        if (!hmacSecret)
            throw new Fido2DeviceException(Fido2Failure.Other, null, "HmacSecretUnsupported");
    }

    private void Check(int result)
    {
        if (result != Libfido2Errors.Ok)
            throw Error(result, 0);
    }

    private static nint Allocated(nint handle) =>
        handle != 0 ? handle : throw new Fido2DeviceException(Fido2Failure.Other, null, "OutOfMemory");

    /// <summary>
    /// A libfido2 error as a failure. A refused PIN (<c>PIN_INVALID</c>, <c>PIN_AUTH_BLOCKED</c>) reads the tries left on
    /// the still-open <paramref name="dev"/> (null when that fails); none left is <see cref="Fido2Failure.PinBlocked"/>.
    /// </summary>
    private Fido2DeviceException Error(int result, nint dev)
    {
        Verbose(result);
        var name = Libfido2Errors.Name(result);
        if (result is Libfido2Errors.PinInvalid or Libfido2Errors.PinAuthBlocked)
        {
            int? retries = dev != 0 && _fido.DevGetRetryCount(dev, out var left) == Libfido2Errors.Ok ? left : null;
            var kind = retries == 0 ? Fido2Failure.PinBlocked
                : result == Libfido2Errors.PinInvalid ? Fido2Failure.PinWrong
                : Fido2Failure.PinNeedsReinsert;
            return new Fido2DeviceException(kind, retries, name);
        }
        return new Fido2DeviceException(Kind(result), null, name);
    }

    internal static Fido2Failure Kind(int result) => result switch
    {
        Libfido2Errors.PinBlocked => Fido2Failure.PinBlocked,
        Libfido2Errors.PinNotSet => Fido2Failure.NoPin,
        Libfido2Errors.NoCredentials or Libfido2Errors.InvalidCredential => Fido2Failure.NoCredential,
        Libfido2Errors.CredentialExcluded => Fido2Failure.CredentialExcluded,
        Libfido2Errors.ActionTimeout or Libfido2Errors.UserActionTimeout => Fido2Failure.TimedOut,
        Libfido2Errors.OperationDenied or Libfido2Errors.KeepaliveCancel => Fido2Failure.Cancelled,
        Libfido2Errors.ChannelBusy => Fido2Failure.Busy,
        Libfido2Errors.UnsupportedExtension or Libfido2Errors.UnsupportedOption => Fido2Failure.Unsupported,
        _ => Fido2Failure.Other,
    };

    private void Verbose(int result) => _verbose?.WriteLine($"libfido2: {Libfido2Errors.Name(result)}: {_fido.StrErr(result)}");
}
