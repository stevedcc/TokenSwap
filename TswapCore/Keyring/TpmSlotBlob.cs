namespace TswapCore.Keyring;

/// <summary>
/// The hardware blob of a password TPM slot (brief T17 ruling 3): <c>"TSTP" | version 1 | flags 1
/// (bit 0 = password)</c>, followed by the TPM package exactly as a password-free slot stores it (Linux:
/// the sealed object's public and private parts; Windows: the key name and wrapped key).
///
/// <para>A password-free slot keeps its legacy package, unchanged (Goal 4). That package starts with a
/// 4-byte little-endian length; <c>"TSTP"</c> read that way is 0x50545354, larger than any blob, so the two
/// never collide.</para>
///
/// <para>Stripping the header doesn't weaken the slot: the sealed object's auth value still needs the
/// stretched password, so the unseal fails. The flag only decides whether tswap asks.</para>
/// </summary>
public static class TpmSlotBlob
{
    /// <summary>"TSTP": TokenSwap TPM password slot.</summary>
    public static ReadOnlySpan<byte> Magic => "TSTP"u8;

    /// <summary>True when <paramref name="hwBlob"/> starts with the <c>TSTP</c> magic.</summary>
    public static bool HasHeader(byte[]? hwBlob) => PasswordBlobHeader.HasMagic(hwBlob, Magic);

    /// <summary>A password slot's blob around <paramref name="package"/>; the password bit is always set.</summary>
    public static byte[] Wrap(byte[] package) => PasswordBlobHeader.Wrap(Magic, package);

    /// <summary>
    /// Whether <paramref name="hwBlob"/> is a password slot, and its package. A legacy blob (no magic) is
    /// password-free and returned unchanged. Throws ruling 3's texts for a newer version, unknown flags or
    /// a missing password flag, and a "Malformed …" text for a truncated header.
    /// </summary>
    public static (bool Password, byte[] Package) Split(byte[] hwBlob) => PasswordBlobHeader.Split(hwBlob, Magic, "TPM");
}
