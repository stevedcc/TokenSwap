using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TswapCore.Vault.Fido2.Libfido2;

/// <summary>
/// A PIN on its way to libfido2 (brief T19, item 1). The <see cref="Fido2DevicePin"/>'s bytes are UTF-8, as on the SDK
/// path; libfido2 takes a C string. Before anything is sent, a PIN with a <c>0x00</c> byte (libfido2 would silently cut
/// it short) or over <see cref="MaxBytes"/> bytes (CTAP's maximum) is refused. Otherwise it is copied into a pinned
/// buffer of length + 1 with the terminating NUL, and <b>both</b> the caller's array and the whole pinned buffer are
/// zeroed in a <c>finally</c>, whatever the call did.
/// </summary>
public static class Libfido2Pin
{
    /// <summary>CTAP 2's longest PIN, in UTF-8 bytes.</summary>
    public const int MaxBytes = 63;

    /// <summary>
    /// Calls <paramref name="call"/> with the address of a NUL-terminated copy of <paramref name="pin"/>, valid only
    /// during the call; zeroes <paramref name="pin"/> and the copy afterwards (and on a refusal).
    /// </summary>
    public static T Send<T>(byte[] pin, Func<nint, T> call)
    {
        byte[]? buffer = null;
        try
        {
            if (pin.AsSpan().Contains((byte)0) || pin.Length > MaxBytes)
                throw new Fido2DeviceException(Fido2Failure.Other, null, "PinNotSendable");
            buffer = GC.AllocateArray<byte>(pin.Length + 1, pinned: true);
            pin.CopyTo(buffer, 0);
            return call(Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pin);
            if (buffer is not null)
                CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
