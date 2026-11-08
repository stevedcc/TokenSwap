using System.Formats.Cbor;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Security.Cryptography;
using TswapCore.Keyring;
using Yubico.Core.Iso7816;
using Yubico.PlatformInterop;
using Yubico.YubiKey;
using Yubico.YubiKey.Fido2;
using Yubico.YubiKey.Fido2.Commands;
using SdkFido2Exception = Yubico.YubiKey.Fido2.Fido2Exception;

namespace TswapCore.Vault.Fido2;

/// <summary>
/// Yubico's .NET SDK (<c>Yubico.YubiKey</c> 1.18.1) as the FIDO2 device on Linux and macOS (FIDO2 plan, task 4).
/// Keys are listed and addressed (<see cref="CanList"/>), with or without a serial.
///
/// <para><b>The PIN</b> is asked once per operation (<see cref="SdkPinCollector"/>) and verified explicitly, one try,
/// for a PIN token with the operation's permission and the relying party <see cref="Fido2SlotBlob.TswapRpId"/>
/// (<see cref="TokenRequest"/>); a refused PIN stops the operation (<see cref="PinRefused"/>). The PIN bytes are zeroed
/// as soon as the SDK has them. The session's <c>KeyCollector</c> is the same collector: it never answers a retry.</para>
///
/// <para><b>The ceremony</b> (make-credential, the user-verified assertion) is sent as the raw CTAP command under that
/// token (<see cref="SdkFido2Session"/>), not through <c>Fido2Session.MakeCredential</c>/<c>GetAssertions</c>: those
/// drop the CTAP status of most failures (they throw an SDK exception with a message only, e.g. for
/// <c>CredentialExcluded</c>), report a refused touch as a timeout, and on a rejected token fetch a new one, trying
/// the key's built-in UV (a fingerprint) before the PIN. The raw command answers with its status, which
/// <see cref="FromStatus"/> maps.</para>
///
/// <para><b>Failures</b> are <see cref="Fido2DeviceException"/>s only (<see cref="Classify"/>): the detail is a status
/// name, never the SDK's text.</para>
/// </summary>
public sealed class SdkFido2Keys : IFido2Keys
{
    private readonly ISdkFido2Devices _devices;

    /// <param name="notices">Where a plugged-in key left out of a listing (it couldn't be read) is said: stderr.</param>
    public SdkFido2Keys(TextWriter? notices = null)
        : this(new SdkFido2Devices(notices))
    {
    }

    internal SdkFido2Keys(ISdkFido2Devices devices) => _devices = devices;

    public bool CanList => true;

    public IReadOnlyList<Fido2KeyInfo> Find() => Guarded(null, _devices.Find);

    public Fido2KeyInfo? FindHolder(byte[] credentialId) => Guarded(null, () => _devices.FindHolder(credentialId));

    public Fido2Made MakeCredential(Fido2KeyRef? key, byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds, Fido2DevicePin pin)
    {
        ArgumentNullException.ThrowIfNull(key);
        var parameters = BuildMakeCredentialParameters(userId, excludeCredentialIds);
        return Verified(key, pin, PinUvAuthTokenPermissions.MakeCredential, session => session.MakeCredential(parameters));
    }

    public Fido2Output GetHmacSecret(Fido2KeyRef? key, IReadOnlyList<(byte[] CredentialId, byte[] PrfInput)> allowed, Fido2DevicePin pin)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (allowed.Count != 1)
            throw new ArgumentException("On Linux and macOS the assertion is for the one located slot", nameof(allowed));
        var parameters = BuildAssertionParameters(allowed[0].CredentialId, allowed[0].PrfInput);
        return Verified(key, pin, PinUvAuthTokenPermissions.GetAssertion, session => session.GetAssertion(parameters));
    }

    public void SetPin(Fido2KeyRef key, Fido2DevicePin newPin)
    {
        var collector = new SdkPinCollector(newPin);
        Guarded(collector, () =>
        {
            using var session = _devices.Open(key, collector);
            if (session.PinSet)
                throw new Fido2DeviceException(Fido2Failure.Other, null, "PinAlreadySet");
            var bytes = collector.TakePin(null);
            try
            {
                if (!session.TrySetPin(bytes))
                    throw new Fido2DeviceException(Fido2Failure.Other, null, "PinAlreadySet");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
            return true;
        });
    }

    /// <summary>
    /// Opens <paramref name="key"/>, verifies the PIN once for a token with <paramref name="permission"/>, then runs
    /// <paramref name="operation"/> under it. A key without a PIN, or without <c>hmac-secret</c>, is refused before
    /// the PIN is asked for.
    /// </summary>
    private T Verified<T>(Fido2KeyRef key, Fido2DevicePin pin, PinUvAuthTokenPermissions permission, Func<IFido2SdkSession, T> operation)
    {
        var collector = new SdkPinCollector(pin);
        return Guarded(collector, () =>
        {
            using var session = _devices.Open(key, collector);
            if (!session.PinSet)
                throw new Fido2DeviceException(Fido2Failure.NoPin, null, "PinNotSet");
            if (!session.HmacSecretSupported)
                throw new Fido2DeviceException(Fido2Failure.Other, null, "HmacSecretUnsupported");

            var (permissions, rpId) = TokenRequest(session.PinUvAuthTokenSupported, permission);
            var bytes = collector.TakePin(null);
            bool verified;
            int? retriesLeft;
            bool? reinsert;
            try
            {
                verified = session.TryVerifyPin(bytes, permissions, rpId, out retriesLeft, out reinsert);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
            if (!verified)
                throw PinRefused(retriesLeft, reinsert);
            return operation(session);
        });
    }

    /// <summary>
    /// Runs <paramref name="operation"/>; anything but a <see cref="Fido2DeviceException"/> becomes one. A refusal the
    /// collector captured (the SDK asked it for a PIN, a retry, a fingerprint) wins over whatever the operation then
    /// threw, a <see cref="Fido2DeviceException"/> included, and is rethrown unchanged.
    /// </summary>
    private static T Guarded<T>(SdkPinCollector? collector, Func<T> operation)
    {
        try
        {
            return operation();
        }
        catch (Exception e)
        {
            collector?.ThrowIfCaptured();
            if (e is Fido2DeviceException)
                throw;
            throw Classify(e);
        }
    }

    /// <summary>
    /// The PIN token to ask for: with <paramref name="permission"/> and the relying party on a key with
    /// <c>pinUvAuthToken</c> (CTAP 2.1); a plain PIN token otherwise (CTAP 2.0, where a relying party can't be named:
    /// the SDK refuses one there).
    /// </summary>
    internal static (PinUvAuthTokenPermissions? Permissions, string? RpId) TokenRequest(bool pinUvAuthTokenSupported, PinUvAuthTokenPermissions permission) =>
        pinUvAuthTokenSupported ? (permission, Fido2SlotBlob.TswapRpId) : (null, null);

    /// <summary>The make-credential user name; no display name (small user entity, plan "Global Constraints").</summary>
    internal const string UserName = "tswap";

    /// <summary>
    /// tswap's make-credential: relying party <see cref="Fido2SlotBlob.TswapRpId"/>, the caller's 16-byte user id named
    /// <see cref="UserName"/>, ES256 only (the constructor's one algorithm), <c>rk = false</c>, <c>hmac-secret</c> on and
    /// the vault's FIDO2 credentials excluded. User verification is the PIN token's (<c>pinUvAuthParam</c>, added by
    /// <see cref="SdkFido2Session"/>), never the <c>uv</c> option, which a key without built-in UV refuses
    /// (<c>CTAP2_ERR_UNSUPPORTED_OPTION</c>). The client data hash is random: nothing checks the attestation.
    /// </summary>
    internal static MakeCredentialParameters BuildMakeCredentialParameters(byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds)
    {
        if (userId.Length != Fido2Service.UserIdSize)
            throw new ArgumentException($"The user id is {Fido2Service.UserIdSize} bytes", nameof(userId));
        var user = new UserEntity(userId.ToArray()) { Name = UserName };
        var parameters = new MakeCredentialParameters(new RelyingParty(Fido2SlotBlob.TswapRpId), user)
        {
            ClientDataHash = RandomNumberGenerator.GetBytes(ClientDataHashSize),
        };
        parameters.AddOption(AuthenticatorOptions.rk, false);
        parameters.AddExtension(Extensions.HmacSecret, true);
        foreach (var id in excludeCredentialIds)
            parameters.ExcludeCredential(new CredentialId { Id = id.ToArray() });
        return parameters;
    }

    /// <summary>
    /// The user-verified assertion for one slot: its credential, user presence left on (a touch), and the
    /// <c>hmac-secret</c> salt <see cref="Fido2Prf.Salt"/> of the slot's PRF input (the same function the Windows path uses).
    /// </summary>
    internal static GetAssertionParameters BuildAssertionParameters(byte[] credentialId, byte[] prfInput)
    {
        var parameters = new GetAssertionParameters(new RelyingParty(Fido2SlotBlob.TswapRpId), RandomNumberGenerator.GetBytes(ClientDataHashSize));
        parameters.AllowCredential(new CredentialId { Id = credentialId.ToArray() });
        parameters.RequestHmacSecretExtension(Fido2Prf.Salt(prfInput));
        return parameters;
    }

    /// <summary>
    /// The silent probe (<see cref="FindHolder"/>): an assertion for <paramref name="credentialId"/> with user presence
    /// off and no PIN token, so the key neither blinks nor asks; it answers whether it holds the credential.
    /// </summary>
    internal static GetAssertionParameters BuildProbeParameters(byte[] credentialId)
    {
        var parameters = new GetAssertionParameters(new RelyingParty(Fido2SlotBlob.TswapRpId), RandomNumberGenerator.GetBytes(ClientDataHashSize));
        parameters.AllowCredential(new CredentialId { Id = credentialId.ToArray() });
        parameters.AddOption(AuthenticatorOptions.up, false);
        return parameters;
    }

    /// <summary>
    /// The probe's answer: the key holds the credential (true), doesn't (false), or failed (thrown), a CTAPHID error
    /// frame included (<see cref="Status"/>): a busy key is never taken for the holder.
    /// </summary>
    internal static bool ProbeHolds(ResponseApdu answer) => Status(answer) switch
    {
        CtapStatus.Ok => true,
        CtapStatus.NoCredentials or InvalidCredential => false,
        var status => throw FromStatus(status),
    };

    /// <summary>A ceremony's answer (make-credential, the assertion): anything but a CTAP <c>Ok</c> throws.</summary>
    internal static void RequireOk(ResponseApdu answer)
    {
        if (Status(answer) is not CtapStatus.Ok and var status)
            throw FromStatus(status);
    }

    /// <summary>
    /// The CTAP status of an answer, as <c>Fido2Response</c> reads it (the status word's low byte), after ruling out a
    /// CTAPHID error frame. The SDK's <c>FidoTransform</c> turns one (ERR_CHANNEL_BUSY when another process is
    /// mid-transaction on the shared hidraw node, ERR_MSG_TIMEOUT, ...) into status word 0x6F00 (0x6900, 0x6A00, 0x6700
    /// for errors 1 to 3) with the error byte as data, whose low byte <c>Fido2Response</c> reads as <c>Ok</c>. A CTAP2
    /// answer is 0x9000 or 0x6F00 | status, so a status word other than 0x9000 with a zero low byte is that frame.
    /// </summary>
    private static CtapStatus Status(ResponseApdu answer)
    {
        var word = (ushort)answer.SW;
        if (word != SuccessWord && (word & 0xFF) == 0)
            throw CtapHidError(answer.Data.Length == 1 ? answer.Data.Span[0] : null);
        return (CtapStatus)(word & 0xFF);
    }

    private const ushort SuccessWord = 0x9000;

    /// <summary>A CTAPHID error (its code, when the frame carried one) as a failure.</summary>
    private static Fido2DeviceException CtapHidError(byte? code) => code switch
    {
        0x06 => new(Fido2Failure.Busy, null, "ChannelBusy"),
        0x05 => new(Fido2Failure.TimedOut, null, "MessageTimeout"),
        { } other => new(Fido2Failure.Other, null, $"CtapHidError0x{other:X2}"),
        null => new(Fido2Failure.Other, null, "CtapHidError"),
    };

    /// <summary>
    /// A GetAssertion answer's CBOR with the credential (key 1) filled in as <paramref name="requestedId"/> when the key
    /// left it out, which CTAP allows when the allow list held one credential; the SDK's <c>GetAssertionData</c> needs
    /// it. An answer with a credential is returned unchanged.
    /// </summary>
    internal static ReadOnlyMemory<byte> WithCredential(ReadOnlyMemory<byte> answer, byte[] requestedId)
    {
        var reader = new CborReader(answer, CborConformanceMode.Ctap2Canonical);
        var count = reader.ReadStartMap() ?? throw new Fido2DeviceException(Fido2Failure.Other, null, "MalformedAssertion");
        List<(int Key, ReadOnlyMemory<byte> Value)> entries = [];
        for (var i = 0; i < count; i++)
        {
            var key = reader.ReadInt32();
            if (key == CredentialKey)
                return answer;
            entries.Add((key, reader.ReadEncodedValue()));
        }

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(count + 1);
        writer.WriteInt32(CredentialKey);
        writer.WriteStartMap(2);
        writer.WriteTextString("id");
        writer.WriteByteString(requestedId);
        writer.WriteTextString("type");
        writer.WriteTextString("public-key");
        writer.WriteEndMap();
        foreach (var (key, value) in entries)
        {
            writer.WriteInt32(key);
            writer.WriteEncodedValue(value.Span);
        }
        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>The GetAssertion answer's <c>credential</c> member (CTAP 2.1, authenticatorGetAssertion response).</summary>
    private const int CredentialKey = 1;

    private const int ClientDataHashSize = 32;

    /// <summary>CTAP2_ERR_INVALID_CREDENTIAL (0x22), which the SDK's <see cref="CtapStatus"/> doesn't name.</summary>
    private const CtapStatus InvalidCredential = (CtapStatus)0x22;

    /// <summary>
    /// A PIN the key refused (the SDK's <c>TryVerifyPin</c> returned false, with what the key reported): none left is
    /// blocked, a required power cycle (three wrong in a row, <c>CTAP2_ERR_PIN_AUTH_BLOCKED</c>) needs a re-insert,
    /// otherwise wrong with the tries left.
    /// </summary>
    internal static Fido2DeviceException PinRefused(int? retriesLeft, bool? reinsertRequired) =>
        retriesLeft == 0 ? new Fido2DeviceException(Fido2Failure.PinBlocked, retriesLeft, "PinBlocked")
        : reinsertRequired == true ? new Fido2DeviceException(Fido2Failure.PinNeedsReinsert, retriesLeft, "PinAuthBlocked")
        : new Fido2DeviceException(Fido2Failure.PinWrong, retriesLeft, "PinInvalid");

    /// <summary>A CTAP status other than <c>Ok</c> as a failure; the detail is the status name.</summary>
    internal static Fido2DeviceException FromStatus(CtapStatus status)
    {
        var kind = status switch
        {
            CtapStatus.PinInvalid => Fido2Failure.PinWrong,
            CtapStatus.PinBlocked => Fido2Failure.PinBlocked,
            // CTAP2_ERR_PIN_AUTH_BLOCKED, 0x34.
            CtapStatus.PowerCycleRequired => Fido2Failure.PinNeedsReinsert,
            CtapStatus.NoCredentials or InvalidCredential => Fido2Failure.NoCredential,
            CtapStatus.OperationDenied or CtapStatus.KeepAliveCancel => Fido2Failure.Cancelled,
            CtapStatus.ActionTimeout or CtapStatus.UserActionTimeout => Fido2Failure.TimedOut,
            CtapStatus.CredentialExcluded => Fido2Failure.CredentialExcluded,
            CtapStatus.PinNotSet => Fido2Failure.NoPin,
            CtapStatus.ChannelBusy => Fido2Failure.Busy,
            _ => Fido2Failure.Other,
        };
        return new Fido2DeviceException(kind, null, StatusName(status));
    }

    private static string StatusName(CtapStatus status) =>
        status == InvalidCredential ? "InvalidCredential"
        : Enum.IsDefined(status) ? status.ToString()
        : $"0x{(byte)status:X2}";

    // The SDK's messages (Yubico.NET.SDK 1.18.1, Resources/ExceptionMessages.resx of Yubico.YubiKey and Yubico.Core),
    // matched only to pick a kind; none of them reaches the person.
    private const string NoMoreRetriesMessage = "There are no more retries remaining.";
    private const string NoPinMessage = "The YubiKey does not have a PIN set.";
    private const string RegistryEntryNotFoundMessage = "No IOKit registry entry was found for the device.";
    private const string LinuxHidOpenFailedMessage = "Could not open HID node on Linux.";
    private const string HidrawFailedMessage = "A HIDRAW operation failed.";

    /// <summary>
    /// Any exception from the SDK (or the platform under it) as a <see cref="Fido2DeviceException"/>; one already is
    /// passes through unchanged. The detail is a status or type name, never the exception's message.
    /// </summary>
    internal static Fido2DeviceException Classify(Exception e) => e switch
    {
        Fido2DeviceException mine => mine,
        // Status Ok in an exception: a CTAPHID error frame the SDK read as a CTAP status (see Status); its code is gone.
        SdkFido2Exception { Status: CtapStatus.Ok } => CtapHidError(null),
        SdkFido2Exception { Status: { } status } => FromStatus(status),
        // Fido2Session's high-level calls: a refused or missed touch, a cancelled collector, no tries left, no PIN.
        TimeoutException => new(Fido2Failure.TimedOut, null, nameof(TimeoutException)),
        OperationCanceledException => new(Fido2Failure.Cancelled, null, nameof(OperationCanceledException)),
        SecurityException { Message: NoMoreRetriesMessage } => new(Fido2Failure.PinBlocked, null, "PinBlocked"),
        InvalidOperationException { Message: NoPinMessage } => new(Fido2Failure.NoPin, null, "PinNotSet"),
        // macOS: another program holds the key's HID device (MacOSHidIOReportConnection, kIOReturnExclusiveAccess).
        PlatformApiException p when YubicoOtpKeys.IsMacExclusiveAccess(p) => new(Fido2Failure.Busy, null, "ExclusiveAccess"),
        PlatformApiException { Message: RegistryEntryNotFoundMessage } => new(Fido2Failure.NotPluggedIn, null, "RegistryEntryNotFound"),
        PlatformApiException { Message: LinuxHidOpenFailedMessage } => new(Fido2Failure.Other, null, "HidOpenFailed"),
        PlatformApiException { Message: HidrawFailedMessage } => new(Fido2Failure.Other, null, "HidrawFailed"),
        UnauthorizedAccessException => new(Fido2Failure.Other, null, "AccessDenied"),
        _ => new(Fido2Failure.Other, null, e.GetType().Name),
    };
}

/// <summary>
/// One operation's PIN source, and the SDK session's <c>KeyCollector</c>: the <see cref="Fido2DevicePin"/> is called at
/// most once (<see cref="TakePin"/>); the collector answers a first <c>VerifyFido2Pin</c> through it, refuses a retry
/// (the key rejected the PIN: <see cref="Fido2Failure.PinWrong"/> with the tries it reported), a second PIN request,
/// a fingerprint (cancelled at once: tswap verifies with the PIN) and any other entry, and lets touch notices pass.
/// A refusal is captured, the SDK is told "no" (false), and the operation rethrows it afterwards
/// (<see cref="ThrowIfCaptured"/>): an exception can't cross the SDK, which calls the collector from its own task.
/// </summary>
internal sealed class SdkPinCollector(Fido2DevicePin pin)
{
    private readonly Lock _gate = new();
    private bool _asked;
    private Fido2DeviceException? _captured;

    /// <summary>The PIN from the delegate, once; a second request throws. The caller zeroes the bytes.</summary>
    public byte[] TakePin(int? retriesLeft)
    {
        lock (_gate)
        {
            if (_asked)
                throw new Fido2DeviceException(Fido2Failure.Other, retriesLeft, "PinRequestedTwice");
            _asked = true;
        }
        return pin(retriesLeft);
    }

    public bool Collect(KeyEntryData data)
    {
        switch (data.Request)
        {
            case KeyEntryRequest.VerifyFido2Pin when data.IsRetry:
                Capture(new Fido2DeviceException(Fido2Failure.PinWrong, data.RetriesRemaining, "PinInvalid"));
                return false;
            case KeyEntryRequest.VerifyFido2Pin:
                byte[] bytes;
                try
                {
                    bytes = TakePin(data.RetriesRemaining);
                }
                catch (Fido2DeviceException e)
                {
                    Capture(e);
                    return false;
                }
                try
                {
                    data.SubmitValue(bytes);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
                return true;
            case KeyEntryRequest.VerifyFido2Uv:
                data.SignalUserCancel?.Invoke();
                return false;
            case KeyEntryRequest.TouchRequest or KeyEntryRequest.Release:
                return true;
            default:
                return false;
        }
    }

    /// <summary>Rethrows the first refusal the collector captured, unchanged; nothing when there was none.</summary>
    public void ThrowIfCaptured()
    {
        Fido2DeviceException? captured;
        lock (_gate)
            captured = _captured;
        if (captured is not null)
            ExceptionDispatchInfo.Throw(captured);
    }

    private void Capture(Fido2DeviceException e)
    {
        lock (_gate)
            _captured ??= e;
    }
}

/// <summary>The plugged-in keys as <see cref="SdkFido2Keys"/> reaches them (a seam for tests).</summary>
internal interface ISdkFido2Devices
{
    IReadOnlyList<Fido2KeyInfo> Find();

    Fido2KeyInfo? FindHolder(byte[] credentialId);

    /// <summary>A session on <paramref name="key"/> whose <c>KeyCollector</c> is <paramref name="collector"/>.</summary>
    IFido2SdkSession Open(Fido2KeyRef key, SdkPinCollector collector);
}

/// <summary>One opened key: the parts of a <c>Fido2Session</c> tswap uses (a seam for tests).</summary>
internal interface IFido2SdkSession : IDisposable
{
    bool PinSet { get; }

    bool HmacSecretSupported { get; }

    /// <summary>The key's <c>pinUvAuthToken</c> option: PIN tokens with permissions and a relying party (CTAP 2.1).</summary>
    bool PinUvAuthTokenSupported { get; }

    /// <summary>One PIN verification (<c>Fido2Session.TryVerifyPin</c> with the PIN given): no retry, no collector.</summary>
    bool TryVerifyPin(byte[] pin, PinUvAuthTokenPermissions? permissions, string? rpId, out int? retriesLeft, out bool? reinsertRequired);

    /// <summary>The raw make-credential under the session's PIN token; a CTAP status other than Ok throws.</summary>
    Fido2Made MakeCredential(MakeCredentialParameters parameters);

    /// <summary>The raw assertion under the session's PIN token, <c>hmac-secret</c> encoded; a status other than Ok throws.</summary>
    Fido2Output GetAssertion(GetAssertionParameters parameters);

    /// <summary>Sets the first PIN (<c>Fido2Session.TrySetPin</c> with the PIN given); false when the key has one.</summary>
    bool TrySetPin(byte[] newPin);
}
