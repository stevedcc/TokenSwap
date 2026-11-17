using System.Buffers.Binary;

namespace TswapCore.Keyring;

/// <summary>
/// What a machine slot's hardware blob says it is (brief T36, #350). No slot format records a kind; every blob tswap
/// writes can still be told by its header or its package's layout (<see cref="HardwareSlotKinds.Classify"/>). Display
/// only: no unlock reads it.
/// </summary>
public enum HardwareSlotKind
{
    /// <summary>None of the rules recognises the blob (or it is a YubiKey blob, or empty).</summary>
    NotRecorded,

    /// <summary>A <c>TSTP</c> header with the ECC-primary bit: only the Linux backend writes it.</summary>
    LinuxTpmEcc,

    /// <summary>A Linux sealed-object package (RSA-2048 primary): header-less, or under <c>TSTP 0x01</c>.</summary>
    LinuxTpmRsa,

    /// <summary>A Windows (Platform Crypto Provider) package: header-less, or under <c>TSTP 0x01</c>.</summary>
    WindowsTpm,

    /// <summary>A <c>TSTP</c> blob whose package is neither layout, or whose header is corrupt or newer.</summary>
    TpmPlatformNotRecorded,

    /// <summary>A <c>TSSE</c> header, or a header-less Secure Enclave package.</summary>
    SecureEnclave,
}

/// <summary>Reads a slot's <see cref="HardwareSlotKind"/> from its blob alone; never throws.</summary>
public static class HardwareSlotKinds
{
    /// <summary>
    /// The CNG key name every Windows package starts with (<c>PlatformCryptoProviderInterop.KeyNamePrefix</c>, written
    /// by its <c>WrapCore</c> as the prefix and 32 hex characters; the unlock refuses any other name).
    /// </summary>
    internal static ReadOnlySpan<byte> WindowsKeyNamePrefix => "tswap-vault-key-"u8;

    /// <summary>
    /// <c>TPM2_ALG_KEYEDHASH</c>, the type of the sealed data object whose marshalled <c>TPM2B_PUBLIC</c>
    /// (<c>tpm2_create -u</c>) starts a Linux package (<c>Tpm2ToolsInterop.SealCore</c>).
    /// </summary>
    internal const ushort KeyedHashAlgorithm = 0x0008;

    /// <summary>
    /// The Secure Enclave package after the key's <c>dataRepresentation</c> (<c>AppleSecureEnclaveInterop.Package</c>,
    /// <c>TswapSecureEnclave.swift</c>'s <c>tswap_se_wrap</c>): the ephemeral public key (65 bytes, an uncompressed
    /// point starting <c>0x04</c>), the nonce (12), the AES-GCM ciphertext of the 32-byte <c>KEK_slot</c>
    /// (<c>SecureEnclaveHardwareService.Enrol</c>) and the tag (16).
    /// </summary>
    internal const int SecureEnclaveWrappedKekLength = 65 + 12 + 32 + 16;

    private const byte UncompressedPointMarker = 0x04;

    /// <summary>
    /// The rules, in order: a YubiKey blob or none → <see cref="HardwareSlotKind.NotRecorded"/> (callers name those
    /// first); a <c>TSSE</c> header → <see cref="HardwareSlotKind.SecureEnclave"/>; a <c>TSTP</c> header → ECC by its
    /// bit, else the package's Windows or Linux layout, else <see cref="HardwareSlotKind.TpmPlatformNotRecorded"/>;
    /// a header-less package → Windows, Secure Enclave, Linux by layout, else not recorded.
    /// </summary>
    public static HardwareSlotKind Classify(byte[]? hwBlob)
    {
        if (hwBlob is not { Length: > 0 } || YubiKeySlotKinds.IsYubiKey(hwBlob))
            return HardwareSlotKind.NotRecorded;
        // Whatever its flags: a corrupt or newer TSSE header is marked by SlotPassword.Classify before any label.
        if (SecureEnclaveSlotBlob.HasHeader(hwBlob))
            return HardwareSlotKind.SecureEnclave;
        if (TpmSlotBlob.HasHeader(hwBlob))
        {
            var (_, flags, package, _) = PasswordBlobHeader.Parse(hwBlob, "TPM", TpmSlotBlob.KnownFlags);
            if (package is null)
                return HardwareSlotKind.TpmPlatformNotRecorded;
            if ((flags & TpmSlotBlob.EccPrimary) != 0)
                return HardwareSlotKind.LinuxTpmEcc;
            // Only a TPM writes TSTP, so its package is asked the two TPM layouts only.
            if (IsWindowsTpmPackage(package))
                return HardwareSlotKind.WindowsTpm;
            return IsLinuxTpmPackage(package) ? HardwareSlotKind.LinuxTpmRsa : HardwareSlotKind.TpmPlatformNotRecorded;
        }

        // Header-less. The Secure Enclave rest (exactly 125 bytes, first byte 0x04) and the Linux private part (a
        // big-endian UINT16 equal to the rest's length - 2, so 123 = 0x007B for 125 bytes, and at least 0x0400 when the
        // first byte is 0x04) exclude each other for every input, and a Windows package is told by its fixed key-name
        // bytes. So no blob passes two tests and the order decides nothing today; Secure Enclave is asked before Linux
        // as a defence in depth, because Apple's opaque dataRepresentation is the one first part that could in principle
        // look like a TPM2B_PUBLIC should the Linux test ever be relaxed.
        if (IsWindowsTpmPackage(hwBlob))
            return HardwareSlotKind.WindowsTpm;
        if (IsSecureEnclavePackage(hwBlob))
            return HardwareSlotKind.SecureEnclave;
        return IsLinuxTpmPackage(hwBlob) ? HardwareSlotKind.LinuxTpmRsa : HardwareSlotKind.NotRecorded;
    }

    /// <summary>
    /// The first part and the rest of an <c>int32 LE length | first part | rest</c> package, all three writers' layout;
    /// false when the length is out of range (the unlockers' own check, <c>0 &lt;= n &lt; Length - 4</c>).
    /// </summary>
    private static bool TrySplit(ReadOnlySpan<byte> package, out ReadOnlySpan<byte> first, out ReadOnlySpan<byte> rest)
    {
        first = rest = default;
        if (package.Length < 4)
            return false;
        var n = BinaryPrimitives.ReadInt32LittleEndian(package);
        if (n < 0 || n >= package.Length - 4)
            return false;
        first = package.Slice(4, n);
        rest = package[(4 + n)..];
        return true;
    }

    /// <summary>A Windows package: the first part is the CNG key name, <see cref="WindowsKeyNamePrefix"/> first.</summary>
    internal static bool IsWindowsTpmPackage(ReadOnlySpan<byte> package) =>
        TrySplit(package, out var first, out _) && first.StartsWith(WindowsKeyNamePrefix);

    /// <summary>
    /// A Linux package: a marshalled <c>TPM2B_PUBLIC</c> of a keyed-hash object (big-endian size = the rest of the
    /// part, then <see cref="KeyedHashAlgorithm"/>), then a marshalled <c>TPM2B_PRIVATE</c> (big-endian size = the
    /// rest of the bytes; <c>tpm2_create -r</c> writes it with <c>files_save_private</c>, tpm2-tools' <c>lib/files.c</c>).
    /// </summary>
    internal static bool IsLinuxTpmPackage(ReadOnlySpan<byte> package)
    {
        if (!TrySplit(package, out var first, out var rest))
            return false;
        return first.Length >= 4
               && BinaryPrimitives.ReadUInt16BigEndian(first) == first.Length - 2
               && BinaryPrimitives.ReadUInt16BigEndian(first[2..]) == KeyedHashAlgorithm
               && rest.Length >= 2
               && BinaryPrimitives.ReadUInt16BigEndian(rest) == rest.Length - 2;
    }

    /// <summary>A Secure Enclave package: the rest is the 125-byte wrapped <c>KEK_slot</c>, starting with the point marker.</summary>
    internal static bool IsSecureEnclavePackage(ReadOnlySpan<byte> package) =>
        TrySplit(package, out _, out var rest) && rest.Length == SecureEnclaveWrappedKekLength && rest[0] == UncompressedPointMarker;
}
