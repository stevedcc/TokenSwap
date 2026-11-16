namespace TswapCore.Vault.Fido2;

/// <summary>
/// Brief T29: the FIDO2 device layer with every call that talks to a key (<see cref="IFido2Keys.Find"/>,
/// <see cref="IFido2Keys.MakeCredential"/>, <see cref="IFido2Keys.GetHmacSecret"/>, <see cref="IFido2Keys.FindHolder"/>,
/// <see cref="IFido2Keys.SetPin"/>) made under <paramref name="hardwareLock"/>, the same lock as the OTP calls. The PIN
/// delegate runs inside the device call, so a second tswap shows no PIN prompt until the first is done (B7.2).
/// <see cref="IFido2Keys.CanList"/> and <see cref="IFido2Keys.OtherBrands"/> (which only loads libfido2) are
/// forwarded without it. Results are the inner's own records, passed through unchanged (never rebuilt), and
/// exceptions pass through.
/// </summary>
public sealed class LockedFido2Keys(IFido2Keys inner, YubiKeyLock hardwareLock) : IFido2Keys
{
    internal IFido2Keys Inner => inner;
    internal YubiKeyLock Lock => hardwareLock;

    bool IFido2Keys.CanList => inner.CanList;

    Libfido2.Libfido2Status? IFido2Keys.OtherBrands => inner.OtherBrands;

    IReadOnlyList<Fido2KeyInfo> IFido2Keys.Find() => hardwareLock.Run(inner.Find);

    Fido2Made IFido2Keys.MakeCredential(Fido2KeyRef? key, byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds, Fido2DevicePin pin) =>
        hardwareLock.Run(() => inner.MakeCredential(key, userId, excludeCredentialIds, pin));

    Fido2Output IFido2Keys.GetHmacSecret(Fido2KeyRef? key, IReadOnlyList<(byte[] CredentialId, byte[] PrfInput)> allowed, Fido2DevicePin pin) =>
        hardwareLock.Run(() => inner.GetHmacSecret(key, allowed, pin));

    Fido2KeyInfo? IFido2Keys.FindHolder(byte[] credentialId) => hardwareLock.Run(() => inner.FindHolder(credentialId));

    void IFido2Keys.SetPin(Fido2KeyRef key, Fido2DevicePin newPin) => hardwareLock.Run(() => inner.SetPin(key, newPin));
}
