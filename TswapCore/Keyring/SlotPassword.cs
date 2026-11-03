namespace TswapCore.Keyring;

/// <summary>How a slot stands with respect to the vault password (brief T17 ruling 3).</summary>
public enum SlotPasswordKind
{
    /// <summary>No password: a v1 YubiKey blob, a legacy TPM / Secure Enclave blob, a legacy pair slot or a recovery slot.</summary>
    None,

    /// <summary>The slot needs the vault password (its blob's flags are exactly <c>0x01</c>).</summary>
    Password,

    /// <summary>A newer blob version or unknown flag bits: this build can't use the slot.</summary>
    NeedsNewerTswap,

    /// <summary>A password header without the password flag, or a known magic that is truncated or has trailing bytes.</summary>
    Corrupt,
}

/// <summary>
/// Classifies keyring slots by their hardware blob's magic, version and flags (brief T17 ruling 3):
///
/// <list type="bullet">
/// <item><c>TSYK</c> version 1 → None; <c>TSYK</c> version 2, <c>TSTP</c> version 1, <c>TSSE</c> version 1 by
/// flags: exactly <c>0x01</c> → Password, any other bit set → NeedsNewerTswap, <c>0x00</c> → Corrupt.</item>
/// <item>A higher version → NeedsNewerTswap; a known magic that is truncated or has trailing bytes → Corrupt.</item>
/// <item>A legacy blob without magic, no blob at all, or a recovery slot → None.</item>
/// </list>
///
/// <para><see cref="Classify"/> never throws, so every caller decides what each value means for it.
/// <see cref="YubiKeySlotBlob.Decode"/>, <see cref="TpmSlotBlob.Split"/> and
/// <see cref="SecureEnclaveSlotBlob.Split"/> agree with it, and throw <see cref="NeedsNewerTswapText"/> or
/// <see cref="CorruptText"/> without a slot id; the caller, which knows the slot, prefixes <c>Slot &lt;id8&gt;: </c>.</para>
/// </summary>
public static class SlotPassword
{
    /// <summary>Bit 0 of a password header's flags byte.</summary>
    public const byte PasswordFlag = 0x01;

    /// <summary>The text for a blob this build is too old for (all three kinds).</summary>
    public static string NeedsNewerTswapText(int version) =>
        $"needs a newer tswap (blob version {version} or unknown flags); upgrade tswap.";

    /// <summary>The text for a damaged password blob.</summary>
    public const string CorruptText =
        "a password header without the password flag, or a truncated blob or trailing bytes (corrupt); restore config.json from backup.";

    /// <summary>The slot's password standing; never throws.</summary>
    public static SlotPasswordKind Classify(Slot slot)
    {
        if (slot.Kind != SlotKind.Machine || slot.HwBlob is not { } hwBlob)
            return SlotPasswordKind.None;
        if (YubiKeySlotBlob.IsYubiKeyBlob(hwBlob))
            return YubiKeySlotBlob.Parse(hwBlob).Kind;
        if (TpmSlotBlob.HasHeader(hwBlob))
            return PasswordBlobHeader.Parse(hwBlob, "TPM").Kind;
        if (SecureEnclaveSlotBlob.HasHeader(hwBlob))
            return PasswordBlobHeader.Parse(hwBlob, "Secure Enclave").Kind;
        return SlotPasswordKind.None;
    }

    /// <summary>True when the slot needs the vault password: <see cref="Classify"/> is <see cref="SlotPasswordKind.Password"/>.</summary>
    public static bool Requires(Slot slot) => Classify(slot) == SlotPasswordKind.Password;
}

/// <summary>
/// The shared <c>magic(4) | version 1 | flags 1 | package</c> header of a password TPM (<c>TSTP</c>) or
/// Secure Enclave (<c>TSSE</c>) slot blob (brief T17 ruling 3). The package that follows is the backend's
/// blob exactly as a password-free slot stores it.
/// </summary>
internal static class PasswordBlobHeader
{
    public const byte CurrentVersion = 1;
    public const int Size = 4 + 1 + 1;

    public static bool HasMagic(byte[]? hwBlob, ReadOnlySpan<byte> magic) =>
        hwBlob is { Length: >= 4 } && hwBlob.AsSpan(0, 4).SequenceEqual(magic);

    public static byte[] Wrap(ReadOnlySpan<byte> magic, byte[] package)
    {
        if (package.Length == 0)
            throw new ArgumentException("The package must not be empty", nameof(package));
        var bytes = new byte[Size + package.Length];
        magic.CopyTo(bytes);
        bytes[4] = CurrentVersion;
        bytes[5] = SlotPassword.PasswordFlag;
        package.CopyTo(bytes, Size);
        return bytes;
    }

    /// <summary>
    /// Parses a blob that starts with the header's magic. A blob too short for a version byte, flags and a
    /// package keeps a "Malformed … Restore config.json from backup." text; a newer version or unknown flag
    /// bits give <see cref="SlotPassword.NeedsNewerTswapText"/>; flags <c>0x00</c> gives
    /// <see cref="SlotPassword.CorruptText"/>.
    /// </summary>
    public static (SlotPasswordKind Kind, byte[]? Package, string? Error) Parse(byte[] hwBlob, string kindName)
    {
        if (hwBlob.Length < 5)
            return (SlotPasswordKind.Corrupt, null, Malformed(kindName, $"truncated ({hwBlob.Length} bytes)"));
        var version = hwBlob[4];
        if (version > CurrentVersion)
            return (SlotPasswordKind.NeedsNewerTswap, null, SlotPassword.NeedsNewerTswapText(version));
        if (version != CurrentVersion)
            return (SlotPasswordKind.Corrupt, null, Malformed(kindName, $"unknown version {version}"));
        if (hwBlob.Length <= Size)
            return (SlotPasswordKind.Corrupt, null, Malformed(kindName, $"truncated ({hwBlob.Length} bytes)"));
        var flags = hwBlob[5];
        if ((flags & ~SlotPassword.PasswordFlag) != 0)
            return (SlotPasswordKind.NeedsNewerTswap, null, SlotPassword.NeedsNewerTswapText(version));
        if (flags != SlotPassword.PasswordFlag)
            return (SlotPasswordKind.Corrupt, null, SlotPassword.CorruptText);
        return (SlotPasswordKind.Password, hwBlob.AsSpan(Size).ToArray(), null);
    }

    public static (bool Password, byte[] Package) Split(byte[] hwBlob, ReadOnlySpan<byte> magic, string kindName)
    {
        if (!HasMagic(hwBlob, magic))
            return (false, hwBlob);
        var (_, package, error) = Parse(hwBlob, kindName);
        return package is not null ? (true, package) : throw new TswapException(error!);
    }

    private static string Malformed(string kindName, string what) =>
        $"Malformed {kindName} slot blob: {what}. Restore config.json from backup.";
}
