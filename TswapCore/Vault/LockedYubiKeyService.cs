namespace TswapCore.Vault;

/// <summary>
/// Brief T29: <paramref name="inner"/> with every call that can reach a key made under <paramref name="hardwareLock"/>,
/// so concurrent tswap processes (and threads) take turns at the YubiKey. Every member is implemented here and
/// forwards to the same member of the inner service (never a default interface body, which would bypass the inner's
/// own); <see cref="IYubiKeyService.IsSimulated"/> touches no key and is forwarded without the lock. Exceptions pass
/// through unchanged; the lock is released however the call ends.
/// </summary>
public sealed class LockedYubiKeyService(IYubiKeyService inner, YubiKeyLock hardwareLock) : IYubiKeyService
{
    internal IYubiKeyService Inner => inner;
    internal YubiKeyLock Lock => hardwareLock;

    bool IYubiKeyService.IsSimulated => inner.IsSimulated;

    IReadOnlyList<int> IYubiKeyService.ListSerials() => hardwareLock.Run(inner.ListSerials);

    byte[] IYubiKeyService.Challenge(int serial, string challenge) => hardwareLock.Run(() => inner.Challenge(serial, challenge));

    bool? IYubiKeyService.DetectTouchRequirement(int serial) => hardwareLock.Run(() => inner.DetectTouchRequirement(serial));

    YubiKeyResponse IYubiKeyService.ChallengeReportingTouch(int serial, string challenge) =>
        hardwareLock.Run(() => inner.ChallengeReportingTouch(serial, challenge));

    IReadOnlyList<YubiKeyInfo> IYubiKeyService.FindKeys() => hardwareLock.Run(inner.FindKeys);

    string? IYubiKeyService.DescribeUnreachable() => hardwareLock.Run(inner.DescribeUnreachable);

    Slot2State IYubiKeyService.GetSlot2State(int serial) => hardwareLock.Run(() => inner.GetSlot2State(serial));

    void IYubiKeyService.ProgramSlot2(int serial, bool requireTouch) => hardwareLock.Run(() => inner.ProgramSlot2(serial, requireTouch));
}
