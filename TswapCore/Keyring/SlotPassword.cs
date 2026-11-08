namespace TswapCore.Keyring;

/// <summary>How a slot stands with respect to the vault password (brief T17 ruling 3).</summary>
public enum SlotPasswordKind
{
    /// <summary>
    /// No password: a v1 YubiKey blob, a legacy TPM / Secure Enclave blob, a <c>TSTP</c> header with known flags but
    /// not bit 0 (<c>0x02</c>, an ECC-primary Linux TPM package), a legacy pair slot or a recovery slot.
    /// </summary>
    None,

    /// <summary>
    /// The slot needs the vault password: its blob's flags have bit 0 set and no bit its magic doesn't know (a
    /// <c>TSYK</c> or <c>TSSE</c> blob <c>0x01</c>; a <c>TSTP</c> blob <c>0x01</c> or <c>0x03</c>).
    /// </summary>
    Password,

    /// <summary>A newer blob version or unknown flag bits: this build can't use the slot.</summary>
    NeedsNewerTswap,

    /// <summary>A header with no known flag (<c>0x00</c>), or a known magic that is truncated or has trailing bytes.</summary>
    Corrupt,
}

/// <summary>
/// Classifies keyring slots by their hardware blob's magic, version and flags (brief T17 ruling 3):
///
/// <list type="bullet">
/// <item><c>TSYK</c> version 1 → None; <c>TSYK</c> version 2, <c>TSTP</c> version 1, <c>TSSE</c> version 1 by
/// flags, with the bits each magic knows (<c>TSYK</c> v2 and <c>TSSE</c>: bit 0; <c>TSTP</c>: bits 0 and 1, bit 1 being
/// "sealed under an ECC P-256 primary", issue #261), the same on every OS: a bit the magic doesn't know →
/// NeedsNewerTswap, whatever else is set; else bit 0 → Password; else a known bit → None; <c>0x00</c> → Corrupt. So
/// <c>TSTP</c> <c>0x02</c> is None, <c>0x03</c> Password and <c>0x04</c>–<c>0x06</c> NeedsNewerTswap; <c>TSSE</c>
/// <c>0x02</c> is NeedsNewerTswap.</item>
/// <item><c>TSYK</c> version 3 (a FIDO2 slot, <see cref="Fido2SlotBlob"/>) by its always-present flags byte: <c>0x01</c> →
/// Password, <c>0x00</c> → None; its other checks are <see cref="Fido2SlotBlob.Decode"/>'s (FIDO2 plan, task 2).</item>
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
        "a header with no known flag, or a truncated blob or trailing bytes (corrupt); restore config.json from backup.";

    /// <summary>The slot's password standing; never throws.</summary>
    public static SlotPasswordKind Classify(Slot slot) => Describe(slot).Kind;

    /// <summary>
    /// <see cref="Classify"/> plus, for <see cref="SlotPasswordKind.NeedsNewerTswap"/> and
    /// <see cref="SlotPasswordKind.Corrupt"/>, the text the slot's parser throws (no slot id).
    /// </summary>
    internal static (SlotPasswordKind Kind, string? Error) Describe(Slot slot)
    {
        if (slot.Kind != SlotKind.Machine || slot.HwBlob is not { } hwBlob)
            return (SlotPasswordKind.None, null);
        switch (YubiKeySlotKinds.Classify(hwBlob))
        {
            case YubiKeySlotKind.Otp(var otp):
                return (otp.RequiresPassword ? SlotPasswordKind.Password : SlotPasswordKind.None, null);
            case YubiKeySlotKind.Fido2(var fido2):
                return (fido2.RequiresPassword ? SlotPasswordKind.Password : SlotPasswordKind.None, null);
            case YubiKeySlotKind.NeedsNewerTswap(var error):
                return (SlotPasswordKind.NeedsNewerTswap, error);
            case YubiKeySlotKind.Corrupt(var error):
                return (SlotPasswordKind.Corrupt, error);
        }
        if (TpmSlotBlob.HasHeader(hwBlob))
        {
            var (kind, _, _, error) = PasswordBlobHeader.Parse(hwBlob, "TPM", TpmSlotBlob.KnownFlags);
            return (kind, error);
        }
        if (SecureEnclaveSlotBlob.HasHeader(hwBlob))
        {
            var (kind, _, _, error) = PasswordBlobHeader.Parse(hwBlob, "Secure Enclave", SecureEnclaveSlotBlob.KnownFlags);
            return (kind, error);
        }
        return (SlotPasswordKind.None, null);
    }

    /// <summary>True when the slot needs the vault password: <see cref="Classify"/> is <see cref="SlotPasswordKind.Password"/>.</summary>
    public static bool Requires(Slot slot) => Classify(slot) == SlotPasswordKind.Password;
}

/// <summary>
/// The shared <c>magic(4) | version 1 | flags 1 | package</c> header of a TPM (<c>TSTP</c>) or Secure Enclave
/// (<c>TSSE</c>) slot blob (brief T17 ruling 3). The package that follows is the backend's blob exactly as a
/// header-less slot stores it. Which flag bits are known is the magic's business (<see cref="TpmSlotBlob.KnownFlags"/>,
/// <see cref="SecureEnclaveSlotBlob.KnownFlags"/>); bit 0 is always the password.
/// </summary>
internal static class PasswordBlobHeader
{
    public const byte CurrentVersion = 1;
    public const int Size = 4 + 1 + 1;

    public static bool HasMagic(byte[]? hwBlob, ReadOnlySpan<byte> magic) =>
        hwBlob is { Length: >= 4 } && hwBlob.AsSpan(0, 4).SequenceEqual(magic);

    /// <summary>The header with <paramref name="flags"/> around <paramref name="package"/>; the caller checks the flags.</summary>
    public static byte[] Wrap(ReadOnlySpan<byte> magic, byte flags, byte[] package)
    {
        if (package.Length == 0)
            throw new ArgumentException("The package must not be empty", nameof(package));
        var bytes = new byte[Size + package.Length];
        magic.CopyTo(bytes);
        bytes[4] = CurrentVersion;
        bytes[5] = flags;
        package.CopyTo(bytes, Size);
        return bytes;
    }

    /// <summary>
    /// Parses a blob that starts with the header's magic. A blob too short for a version byte, flags and a
    /// package keeps a "Malformed … Restore config.json from backup." text; a newer version, or a flag bit outside
    /// <paramref name="knownFlags"/> (checked before anything else about the flags), gives
    /// <see cref="SlotPassword.NeedsNewerTswapText"/>; flags <c>0x00</c> gives <see cref="SlotPassword.CorruptText"/>.
    /// Otherwise the kind is Password when bit 0 is set and None when it isn't, with the flags and the package.
    /// </summary>
    public static (SlotPasswordKind Kind, byte Flags, byte[]? Package, string? Error) Parse(byte[] hwBlob, string kindName, byte knownFlags)
    {
        if (hwBlob.Length < 5)
            return (SlotPasswordKind.Corrupt, 0, null, Malformed(kindName, $"truncated ({hwBlob.Length} bytes)"));
        var version = hwBlob[4];
        if (version > CurrentVersion)
            return (SlotPasswordKind.NeedsNewerTswap, 0, null, SlotPassword.NeedsNewerTswapText(version));
        if (version != CurrentVersion)
            return (SlotPasswordKind.Corrupt, 0, null, Malformed(kindName, $"unknown version {version}"));
        if (hwBlob.Length <= Size)
            return (SlotPasswordKind.Corrupt, 0, null, Malformed(kindName, $"truncated ({hwBlob.Length} bytes)"));
        var flags = hwBlob[5];
        if ((flags & ~knownFlags) != 0)
            return (SlotPasswordKind.NeedsNewerTswap, 0, null, SlotPassword.NeedsNewerTswapText(version));
        if (flags == 0)
            return (SlotPasswordKind.Corrupt, 0, null, SlotPassword.CorruptText);
        var kind = (flags & SlotPassword.PasswordFlag) != 0 ? SlotPasswordKind.Password : SlotPasswordKind.None;
        return (kind, flags, hwBlob.AsSpan(Size).ToArray(), null);
    }

    /// <summary>
    /// The header's flags and the package; a blob without <paramref name="magic"/> is returned unchanged with flags
    /// <c>0x00</c>. Throws <see cref="Parse"/>'s text for anything it refuses.
    /// </summary>
    public static (byte Flags, byte[] Package) Split(byte[] hwBlob, ReadOnlySpan<byte> magic, string kindName, byte knownFlags)
    {
        if (!HasMagic(hwBlob, magic))
            return (0, hwBlob);
        var (_, flags, package, error) = Parse(hwBlob, kindName, knownFlags);
        return package is not null ? (flags, package) : throw new TswapException(error!);
    }

    private static string Malformed(string kindName, string what) =>
        $"Malformed {kindName} slot blob: {what}. Restore config.json from backup.";
}
