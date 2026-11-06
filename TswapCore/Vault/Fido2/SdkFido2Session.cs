using Yubico.Core.Iso7816;
using Yubico.YubiKey;
using Yubico.YubiKey.Fido2;
using Yubico.YubiKey.Fido2.Commands;

namespace TswapCore.Vault.Fido2;

/// <summary>
/// The plugged-in keys through Yubico's SDK: every key the SDK sees over its FIDO HID interface, serial or not
/// (<c>YubiKeyDevice.FindByTransport(Transport.HidFido)</c>). The SDK's device listing hands back the same device object
/// for a key while it stays plugged in, so a <see cref="Fido2KeyRef"/> is a handle to that object, valid for this
/// process: a key unplugged since it was listed is not plugged in, even when plugged in again.
/// </summary>
internal sealed class SdkFido2Devices(TextWriter? notices = null) : ISdkFido2Devices
{
    private readonly Lock _gate = new();
    private readonly Dictionary<IYubiKeyDevice, Fido2KeyRef> _refs = new(ReferenceEqualityComparer.Instance);
    private int _next;

    /// <summary>
    /// Every key that can be read (<see cref="ReadEach"/>); one that can't is left out, said on
    /// <paramref name="notices"/> (stderr) with its problem.
    /// </summary>
    public IReadOnlyList<Fido2KeyInfo> Find() => ReadEach(Listed(), Read, e => notices?.WriteLine(Fido2Texts.KeyLeftOut(e.Detail ?? e.Kind.ToString())));

    /// <summary>
    /// The silent probe on every plugged-in key (<see cref="SdkFido2Keys.BuildProbeParameters"/>, sent as the raw
    /// GetAssertion command: no PIN token, user presence off), through <see cref="FirstHolder"/>.
    /// </summary>
    public Fido2KeyInfo? FindHolder(byte[] credentialId) => FirstHolder(Listed(), device =>
    {
        using var connection = device.Connect(YubiKeyApplication.Fido2);
        return SdkFido2Keys.ProbeHolds(SdkAnswer.Of(connection, new GetAssertionCommand(SdkFido2Keys.BuildProbeParameters(credentialId))));
    }, Read);

    /// <summary>
    /// The listing's loop: each device read with <paramref name="read"/>; a device that can't be read is left out and
    /// passed to <paramref name="leftOut"/>. When none could be read and one failed, that failure is thrown.
    /// </summary>
    internal static IReadOnlyList<Fido2KeyInfo> ReadEach<TDevice>(IEnumerable<TDevice> devices, Func<TDevice, Fido2KeyInfo> read,
        Action<Fido2DeviceException>? leftOut)
    {
        List<Fido2KeyInfo> keys = [];
        List<Fido2DeviceException> failures = [];
        foreach (var device in devices)
        {
            try
            {
                keys.Add(read(device));
            }
            catch (Exception e)
            {
                failures.Add(SdkFido2Keys.Classify(e));
            }
        }
        if (keys.Count == 0 && failures.Count > 0)
            throw failures[0];
        foreach (var failure in failures)
            leftOut?.Invoke(failure);
        return keys;
    }

    /// <summary>
    /// The probe's loop: the first device <paramref name="holds"/> says holds the credential wins (read with
    /// <paramref name="read"/>); when none does, a device that failed to answer makes the probe fail (it might have been
    /// the holder), otherwise none.
    /// </summary>
    internal static Fido2KeyInfo? FirstHolder<TDevice>(IEnumerable<TDevice> devices, Func<TDevice, bool> holds, Func<TDevice, Fido2KeyInfo> read)
    {
        Fido2DeviceException? failure = null;
        foreach (var device in devices)
        {
            try
            {
                if (holds(device))
                    return read(device);
            }
            catch (Exception e)
            {
                failure ??= SdkFido2Keys.Classify(e);
            }
        }
        return failure is null ? null : throw failure;
    }

    public IFido2SdkSession Open(Fido2KeyRef key, SdkPinCollector collector)
    {
        var device = Listed().FirstOrDefault(d => RefFor(d) == key)
            ?? throw new Fido2DeviceException(Fido2Failure.NotPluggedIn, null, "NotListed");
        return new SdkFido2Session(device, collector);
    }

    private static IReadOnlyList<IYubiKeyDevice> Listed()
    {
        YubicoSdk.EnsureInitialized();
        return [.. YubiKeyDevice.FindByTransport(Transport.HidFido)];
    }

    private Fido2KeyRef RefFor(IYubiKeyDevice device)
    {
        lock (_gate)
        {
            if (!_refs.TryGetValue(device, out var key))
            {
                key = new Fido2KeyRef($"fido2-{++_next}");
                _refs.Add(device, key);
            }
            return key;
        }
    }

    /// <summary>
    /// What <see cref="IFido2Keys.Find"/> reports for <paramref name="device"/>, read from the key (GetInfo, and the PIN
    /// retries when a PIN is set): no PIN, no touch.
    /// </summary>
    private Fido2KeyInfo Read(IYubiKeyDevice device)
    {
        using var session = new Fido2Session(device);
        var info = session.AuthenticatorInfo;
        var pinSet = info.GetOptionValue(AuthenticatorOptions.clientPin) == OptionValue.True;
        int? retries = pinSet ? PinRetries(session.Connection) : null;
        return new Fido2KeyInfo(RefFor(device), device.SerialNumber, SdkFido2Session.ToGuid(info.Aaguid), pinSet, retries);
    }

    /// <summary>The PIN tries left (ClientPin getPINRetries), a CTAPHID error frame refused as for the ceremonies.</summary>
    private static int PinRetries(IYubiKeyConnection connection)
    {
        var answer = SdkAnswer.Of(connection, new GetPinRetriesCommand());
        SdkFido2Keys.RequireOk(answer);
        return new GetPinRetriesResponse(answer).GetData().retriesRemaining;
    }
}

/// <summary>
/// A <c>Fido2Session</c> on one key, with tswap's <see cref="SdkPinCollector"/> as its <c>KeyCollector</c>. The PIN is
/// verified through the session (it keeps the PIN protocol and the token); make-credential and the assertion are then
/// sent as raw commands signed with that token, so their CTAP status comes back as the key gave it
/// (<see cref="SdkFido2Keys.FromStatus"/>).
/// </summary>
internal sealed class SdkFido2Session(IYubiKeyDevice device, SdkPinCollector collector) : IFido2SdkSession
{
    private readonly Fido2Session _session = new(device) { KeyCollector = collector.Collect };

    public bool PinSet => _session.AuthenticatorInfo.GetOptionValue(AuthenticatorOptions.clientPin) == OptionValue.True;

    public bool HmacSecretSupported => _session.AuthenticatorInfo.IsExtensionSupported(Extensions.HmacSecret);

    public bool PinUvAuthTokenSupported => _session.AuthenticatorInfo.GetOptionValue(AuthenticatorOptions.pinUvAuthToken) == OptionValue.True;

    public bool TryVerifyPin(byte[] pin, PinUvAuthTokenPermissions? permissions, string? rpId, out int? retriesLeft, out bool? reinsertRequired) =>
        _session.TryVerifyPin(pin, permissions, rpId, out retriesLeft, out reinsertRequired);

    public Fido2Made MakeCredential(MakeCredentialParameters parameters)
    {
        parameters.Protocol = _session.AuthProtocol.Protocol;
        parameters.PinUvAuthParam = Authorise(parameters.ClientDataHash);
        var answer = SdkAnswer.Of(_session.Connection, new MakeCredentialCommand(parameters));
        SdkFido2Keys.RequireOk(answer);
        var data = new MakeCredentialData(answer.Data).AuthenticatorData;
        var credentialId = data.CredentialId?.Id.ToArray()
            ?? throw new Fido2DeviceException(Fido2Failure.Other, null, "NoCredentialId");
        var aaguid = data.Aaguid is { } bytes ? ToGuid(bytes) : Guid.Empty;
        return new Fido2Made(credentialId, aaguid, device.SerialNumber, data.UserVerification);
    }

    public Fido2Output GetAssertion(GetAssertionParameters parameters)
    {
        parameters.Protocol = _session.AuthProtocol.Protocol;
        parameters.PinUvAuthParam = Authorise(parameters.ClientDataHash);
        parameters.EncodeHmacSecretExtension(_session.AuthProtocol);
        var answer = SdkAnswer.Of(_session.Connection, new GetAssertionCommand(parameters));
        SdkFido2Keys.RequireOk(answer);
        var requested = parameters.AllowList is [var only] ? only.Id.ToArray()
            : throw new ArgumentException("The assertion is for one credential", nameof(parameters));
        using var data = new GetAssertionData(SdkFido2Keys.WithCredential(answer.Data, requested));
        // Decrypted with the session's shared secret into a new array: the caller's to zero.
        var output = data.AuthenticatorData.GetHmacSecretExtension(_session.AuthProtocol);
        return new Fido2Output(data.CredentialId.Id.ToArray(), output, data.AuthenticatorData.UserVerification);
    }

    public bool TrySetPin(byte[] newPin)
    {
        try
        {
            return _session.TrySetPin(newPin);
        }
        catch (ArgumentException)
        {
            // Fido2Session.VerifyPinLengthRequirements: shorter than the key's minimum, or longer than 63 bytes.
            throw new Fido2DeviceException(Fido2Failure.Other, null, "PinPolicyViolation");
        }
    }

    public void Dispose() => _session.Dispose();

    /// <summary>The <c>pinUvAuthParam</c> over <paramref name="clientDataHash"/> with the token the PIN verification got.</summary>
    private byte[] Authorise(ReadOnlyMemory<byte> clientDataHash)
    {
        var token = _session.AuthToken ?? throw new Fido2DeviceException(Fido2Failure.Other, null, "NoPinToken");
        return _session.AuthProtocol.AuthenticateUsingPinToken(token, clientDataHash);
    }

    /// <summary>An AAGUID as the key sends it (16 bytes, big-endian), as tswap stores it; anything else is empty.</summary>
    internal static Guid ToGuid(ReadOnlyMemory<byte> aaguid) =>
        aaguid.Length == AuthenticatorInfo.AaguidLength ? new Guid(aaguid.Span, bigEndian: true) : Guid.Empty;
}

/// <summary>
/// Sends a command and keeps the raw answer: the typed responses hide it, and their CTAP status can't tell a CTAPHID
/// error frame from success (<see cref="SdkFido2Keys.RequireOk"/>). The FIDO pipeline (<c>FidoTransform</c>) ignores the
/// command's type, so the wrapper changes nothing on the wire.
/// </summary>
internal sealed class SdkAnswer<TResponse>(IYubiKeyCommand<TResponse> inner) : IYubiKeyCommand<TResponse>
    where TResponse : IYubiKeyResponse
{
    public ResponseApdu? Answer { get; private set; }

    public YubiKeyApplication Application => inner.Application;

    public CommandApdu CreateCommandApdu() => inner.CreateCommandApdu();

    public TResponse CreateResponseForApdu(ResponseApdu responseApdu)
    {
        Answer = responseApdu;
        return inner.CreateResponseForApdu(responseApdu);
    }
}

internal static class SdkAnswer
{
    /// <summary>The raw answer to <paramref name="command"/> on <paramref name="connection"/>.</summary>
    public static ResponseApdu Of<TResponse>(IYubiKeyConnection connection, IYubiKeyCommand<TResponse> command)
        where TResponse : IYubiKeyResponse
    {
        var capture = new SdkAnswer<TResponse>(command);
        connection.SendCommand(capture);
        return capture.Answer ?? throw new Fido2DeviceException(Fido2Failure.Other, null, "NoAnswer");
    }
}
