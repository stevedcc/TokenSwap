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
internal sealed class SdkFido2Devices : ISdkFido2Devices
{
    private readonly Lock _gate = new();
    private readonly Dictionary<IYubiKeyDevice, Fido2KeyRef> _refs = new(ReferenceEqualityComparer.Instance);
    private int _next;

    public IReadOnlyList<Fido2KeyInfo> Find() => [.. Listed().Select(Read)];

    /// <summary>
    /// The silent probe on every plugged-in key (<see cref="SdkFido2Keys.BuildProbeParameters"/>, sent as the raw
    /// GetAssertion command: no PIN token, user presence off). The first key holding the credential wins; when none
    /// does, a key that failed to answer makes the probe fail (it might have been the holder), otherwise none.
    /// </summary>
    public Fido2KeyInfo? FindHolder(byte[] credentialId)
    {
        Fido2DeviceException? failure = null;
        foreach (var device in Listed())
        {
            try
            {
                bool holds;
                using (var connection = device.Connect(YubiKeyApplication.Fido2))
                    holds = SdkFido2Keys.ProbeHolds(connection.SendCommand(new GetAssertionCommand(SdkFido2Keys.BuildProbeParameters(credentialId))).CtapStatus);
                if (holds)
                    return Read(device);
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
        int? retries = pinSet ? session.Connection.SendCommand(new GetPinRetriesCommand()).GetData().retriesRemaining : null;
        return new Fido2KeyInfo(RefFor(device), device.SerialNumber, SdkFido2Session.ToGuid(info.Aaguid), pinSet, retries);
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
        var response = _session.Connection.SendCommand(new MakeCredentialCommand(parameters));
        if (response.CtapStatus != CtapStatus.Ok)
            throw SdkFido2Keys.FromStatus(response.CtapStatus);
        var data = response.GetData().AuthenticatorData;
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
        var response = _session.Connection.SendCommand(new GetAssertionCommand(parameters));
        if (response.CtapStatus != CtapStatus.Ok)
            throw SdkFido2Keys.FromStatus(response.CtapStatus);
        using var data = response.GetData();
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
