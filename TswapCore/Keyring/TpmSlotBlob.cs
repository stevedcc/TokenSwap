namespace TswapCore.Keyring;

/// <summary>
/// The <c>TSTP</c> header of a TPM slot blob (brief T17 ruling 3, issue #261): <c>"TSTP" | version 1 | flags 1</c>,
/// followed by the TPM package exactly as a header-less slot stores it (Linux: the sealed object's public and private
/// parts; Windows: the key name and wrapped key). Flags bit 0 (<see cref="Password"/>) means the slot needs the vault
/// password; bit 1 (<see cref="EccPrimary"/>) means the Linux package was sealed under an ECC P-256 storage primary
/// instead of RSA-2048. These two are the only bits this build knows, on every OS.
///
/// <para>Every new Linux TPM slot has the header, flags <c>0x02</c> or <c>0x03</c>. Windows writes what it always
/// has: its legacy package for a password-free slot, flags <c>0x01</c> for a password slot. A legacy package (no
/// header) and flags <c>0x01</c> mean RSA-2048 on Linux. A legacy package starts with a 4-byte little-endian length;
/// <c>"TSTP"</c> read that way is 0x50545354, larger than any blob, so the two never collide.</para>
///
/// <para>Stripping the header doesn't weaken the slot. A password slot's sealed object still needs the stretched
/// password as its auth value, so the unseal fails. An ECC slot's package read without its header goes through the
/// RSA primary, which isn't its parent, so <c>tpm2_load</c> fails its integrity check. The flags only decide whether
/// tswap asks and which primary it rebuilds.</para>
/// </summary>
public static class TpmSlotBlob
{
    /// <summary>"TSTP": TokenSwap TPM slot.</summary>
    public static ReadOnlySpan<byte> Magic => "TSTP"u8;

    /// <summary>Flags bit 0: the slot needs the vault password.</summary>
    public const byte Password = SlotPassword.PasswordFlag;

    /// <summary>Flags bit 1: the Linux package was sealed under an ECC P-256 storage primary (issue #261).</summary>
    public const byte EccPrimary = 0x02;

    /// <summary>Every flag bit this build knows for <c>TSTP</c>; any other bit needs a newer tswap.</summary>
    internal const byte KnownFlags = Password | EccPrimary;

    /// <summary>True when <paramref name="hwBlob"/> starts with the <c>TSTP</c> magic.</summary>
    public static bool HasHeader(byte[]? hwBlob) => PasswordBlobHeader.HasMagic(hwBlob, Magic);

    /// <summary>
    /// The header with <paramref name="flags"/> (<see cref="Password"/>, <see cref="EccPrimary"/> or both) around
    /// <paramref name="package"/>. Throws <see cref="ArgumentException"/> for flags <c>0x00</c> or a bit this build
    /// doesn't know: it never writes a header that classifies as corrupt or as needing a newer tswap.
    /// </summary>
    public static byte[] Wrap(byte[] package, byte flags)
    {
        if (flags == 0 || (flags & ~KnownFlags) != 0)
            throw new ArgumentException($"Flags 0x{flags:x2} can't be written in a TSTP header", nameof(flags));
        return PasswordBlobHeader.Wrap(Magic, flags, package);
    }

    /// <summary>
    /// Whether <paramref name="hwBlob"/> needs the password, whether its package was sealed under the ECC primary, and
    /// the package. A legacy blob (no magic) is password-free, RSA and returned unchanged. Throws ruling 3's texts for a
    /// newer version, an unknown flag bit or flags <c>0x00</c>, and a "Malformed …" text for a truncated header.
    /// </summary>
    public static (bool Password, bool EccPrimary, byte[] Package) Split(byte[] hwBlob)
    {
        var (flags, package) = PasswordBlobHeader.Split(hwBlob, Magic, "TPM", KnownFlags);
        return ((flags & Password) != 0, (flags & EccPrimary) != 0, package);
    }

    /// <summary>True only for a valid <c>TSTP</c> header with <see cref="EccPrimary"/> set; never throws.</summary>
    public static bool SealedUnderEccPrimary(byte[]? hwBlob)
    {
        if (hwBlob is null || !HasHeader(hwBlob))
            return false;
        var (_, flags, package, _) = PasswordBlobHeader.Parse(hwBlob, "TPM", KnownFlags);
        return package is not null && (flags & EccPrimary) != 0;
    }
}
