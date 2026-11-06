using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TswapCore.Keyring;

/// <summary>
/// A YubiKey slot's recorded touch policy (slot 2's "require touch" setting at enrollment).
/// Explicit byte values: <see cref="YubiKeySlotBlob"/> persists this as a raw byte.
/// </summary>
public enum YubiKeyTouchPolicy : byte
{
    /// <summary>Detection failed at enrollment (for example the slot could not be read).</summary>
    Unknown = 0,
    NotRequired = 1,
    Required = 2,
}

/// <summary>
/// The parameters of a one-key YubiKey keyring slot (brief T4 decision 2, issue #184), kept in
/// that slot's v3 hardware blob (<see cref="Slot.HwBlob"/>, issue #154) rather than in per-machine
/// config, so the slot works on any machine that has the vault files and that key.
///
/// <para><b>Layout</b> (fixed binary, 74 bytes):
/// <c>magic "TSYK"(4) || version(1) = 1 || serial(int32, little-endian) || challenge(32) ||
/// salt(32) || touch policy(1)</c>. The magic tells a YubiKey blob apart from a TPM or Secure
/// Enclave blob in the same column; the version byte lets a later layout coexist. Decoding is
/// strict: wrong magic, an unknown version, a short blob, trailing bytes, an unknown touch policy
/// or a non-positive serial give a <see cref="TswapException"/>.</para>
///
/// <para><b>Version 2</b> (brief T17 ruling 3, 75 bytes) is version 1 plus a trailing <c>flags</c> byte
/// (bit 0 = password; other bits must be 0). It is written only for password slots, whose
/// <c>KEK_slot</c> mixes in the stretched vault password (<see cref="YubiKeySlotKek.DeriveV2"/>), so a
/// password-free slot stays byte-identical to version 1. Flags <c>0x00</c> is damage, any other bit
/// needs a newer tswap (<see cref="SlotPassword"/>).</para>
///
/// <para>A YubiKey machine slot <em>without</em> such a blob is a <b>legacy pair slot</b>: its
/// <c>KEK_slot</c> still comes from the two-key XOR scheme and the per-machine config fields
/// (<c>YubiKeySerials</c>, <c>RedundancyXor</c>, <c>UnlockChallenge</c>, <c>MasterKeySalt</c>).
/// See <see cref="YubiKeySlotKek"/> for how this blob's fields become <c>KEK_slot</c>.</para>
/// </summary>
public sealed record YubiKeySlotBlob
{
    public const byte CurrentVersion = 1;

    /// <summary>Brief T17: the version of a password slot's blob (version 1 plus a flags byte).</summary>
    public const byte PasswordVersion = 2;
    public const int ChallengeSize = 32;
    public const int SaltSize = 32;

    private const int MagicSize = 4;
    private const int HeaderSize = MagicSize + 1; // magic + version
    public const int EncodedSize = HeaderSize + 4 + ChallengeSize + SaltSize + 1;

    /// <summary>The size of a version 2 (password) blob: <see cref="EncodedSize"/> plus the flags byte.</summary>
    public const int PasswordEncodedSize = EncodedSize + 1;

    /// <summary>"TSYK": TokenSwap YubiKey slot.</summary>
    public static ReadOnlySpan<byte> Magic => "TSYK"u8;

    public YubiKeySlotBlob(int serial, byte[] challenge, byte[] salt, YubiKeyTouchPolicy touch, bool requiresPassword = false)
    {
        if (challenge.Length != ChallengeSize)
            throw new ArgumentException($"The challenge must be {ChallengeSize} bytes", nameof(challenge));
        if (salt.Length != SaltSize)
            throw new ArgumentException($"The salt must be {SaltSize} bytes", nameof(salt));
        Serial = serial;
        Challenge = (byte[])challenge.Clone();
        Salt = (byte[])salt.Clone();
        Touch = touch;
        RequiresPassword = requiresPassword;
    }

    /// <summary>
    /// Brief T17: the slot's <c>KEK_slot</c> mixes in the stretched vault password
    /// (<see cref="YubiKeySlotKek.DeriveV2"/>); encoded as version 2.
    /// </summary>
    public bool RequiresPassword { get; }

    /// <summary>The enrolled YubiKey's serial number.</summary>
    public int Serial { get; }

    /// <summary>32 random bytes; the key is challenged with <see cref="ChallengeString"/>.</summary>
    public byte[] Challenge { get; }

    /// <summary>32 random bytes, the HKDF salt (<see cref="YubiKeySlotKek"/>).</summary>
    public byte[] Salt { get; }

    public YubiKeyTouchPolicy Touch { get; }

    /// <summary><see cref="Touch"/> as the nullable bool <see cref="Config.RequiresTouch"/> uses.</summary>
    public bool? RequiresTouch => Touch switch
    {
        YubiKeyTouchPolicy.Required => true,
        YubiKeyTouchPolicy.NotRequired => false,
        _ => null,
    };

    /// <summary>
    /// What is sent to the key through <see cref="Vault.IYubiKeyService.Challenge"/>: the challenge
    /// as 64 hex characters, which the YubiKey service sends as exactly 64 bytes, the same shape as
    /// a pair vault's <c>UnlockChallenge</c>.
    /// </summary>
    public string ChallengeString => Convert.ToHexString(Challenge);

    /// <summary>A new slot's parameters: fresh CSPRNG challenge and salt (decision 1).</summary>
    public static YubiKeySlotBlob Create(int serial, bool? requiresTouch) => new(
        serial,
        RandomNumberGenerator.GetBytes(ChallengeSize),
        RandomNumberGenerator.GetBytes(SaltSize),
        ToPolicy(requiresTouch));

    /// <summary>
    /// This blob with its touch policy set (brief T7 item 5: the posture is known only after the
    /// first challenge, which uses this blob's challenge).
    /// </summary>
    public YubiKeySlotBlob WithRequiresTouch(bool? requiresTouch) =>
        new(Serial, Challenge, Salt, ToPolicy(requiresTouch), RequiresPassword);

    /// <summary>This blob as a password slot's (version 2), same serial, challenge, salt and touch policy.</summary>
    public YubiKeySlotBlob WithPassword() => new(Serial, Challenge, Salt, Touch, requiresPassword: true);

    private static YubiKeyTouchPolicy ToPolicy(bool? requiresTouch) => requiresTouch switch
    {
        true => YubiKeyTouchPolicy.Required,
        false => YubiKeyTouchPolicy.NotRequired,
        null => YubiKeyTouchPolicy.Unknown,
    };

    /// <summary>True when <paramref name="hwBlob"/> starts with this format's magic.</summary>
    public static bool IsYubiKeyBlob(byte[]? hwBlob) =>
        hwBlob is { Length: >= MagicSize } && hwBlob.AsSpan(0, MagicSize).SequenceEqual(Magic);

    /// <summary>Version 1 (74 bytes) unless <see cref="RequiresPassword"/>, then version 2 (75 bytes, flags <c>0x01</c>).</summary>
    public byte[] Encode()
    {
        var bytes = new byte[RequiresPassword ? PasswordEncodedSize : EncodedSize];
        var span = bytes.AsSpan();
        Magic.CopyTo(span);
        span[MagicSize] = RequiresPassword ? PasswordVersion : CurrentVersion;
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderSize, 4), Serial);
        Challenge.CopyTo(span.Slice(HeaderSize + 4, ChallengeSize));
        Salt.CopyTo(span.Slice(HeaderSize + 4 + ChallengeSize, SaltSize));
        span[EncodedSize - 1] = (byte)Touch;
        if (RequiresPassword)
            span[PasswordEncodedSize - 1] = SlotPassword.PasswordFlag;
        return bytes;
    }

    /// <summary>
    /// Decodes a version 1 or version 2 blob. A newer version or unknown flag bits throw
    /// <see cref="SlotPassword.NeedsNewerTswapText"/>, flags <c>0x00</c> throws
    /// <see cref="SlotPassword.CorruptText"/>, and every other defect a "Malformed YubiKey slot blob: …"
    /// text (brief T17 ruling 3; <see cref="SlotPassword.Classify"/> agrees).
    /// </summary>
    public static YubiKeySlotBlob Decode(byte[] bytes)
    {
        var (blob, _, error) = Parse(bytes);
        return blob ?? throw new TswapException(error!);
    }

    /// <summary>The blob, or null when <paramref name="bytes"/> don't decode (corrupt, or from a newer tswap).</summary>
    public static YubiKeySlotBlob? TryDecode(byte[] bytes) => Parse(bytes).Blob;

    /// <summary>
    /// Never throws: the blob and its <see cref="SlotPasswordKind"/> (None or Password), or null with the
    /// kind (NeedsNewerTswap or Corrupt) and the error text <see cref="Decode"/> throws.
    /// </summary>
    internal static (YubiKeySlotBlob? Blob, SlotPasswordKind Kind, string? Error) Parse(byte[] bytes)
    {
        if (bytes.Length < HeaderSize)
            return Fail(SlotPasswordKind.Corrupt, Malformed($"truncated ({bytes.Length} bytes)"));
        if (!IsYubiKeyBlob(bytes))
            return Fail(SlotPasswordKind.Corrupt, Malformed("wrong magic"));

        var version = bytes[MagicSize];
        if (version > PasswordVersion)
            return Fail(SlotPasswordKind.NeedsNewerTswap, SlotPassword.NeedsNewerTswapText(version));
        if (version is not (CurrentVersion or PasswordVersion))
            return Fail(SlotPasswordKind.Corrupt, Malformed($"unknown version {version}"));

        var size = version == PasswordVersion ? PasswordEncodedSize : EncodedSize;
        if (bytes.Length < size)
            return Fail(SlotPasswordKind.Corrupt, Malformed($"truncated ({bytes.Length} of {size} bytes)"));
        if (bytes.Length > size)
            return Fail(SlotPasswordKind.Corrupt, Malformed($"{bytes.Length - size} trailing bytes"));

        var requiresPassword = false;
        if (version == PasswordVersion)
        {
            var flags = bytes[PasswordEncodedSize - 1];
            if ((flags & ~SlotPassword.PasswordFlag) != 0)
                return Fail(SlotPasswordKind.NeedsNewerTswap, SlotPassword.NeedsNewerTswapText(version));
            if (flags != SlotPassword.PasswordFlag)
                return Fail(SlotPasswordKind.Corrupt, SlotPassword.CorruptText);
            requiresPassword = true;
        }

        var serial = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(HeaderSize, 4));
        if (serial <= 0)
            return Fail(SlotPasswordKind.Corrupt, Malformed($"invalid serial {serial}"));

        var touch = bytes[EncodedSize - 1];
        if (touch > (byte)YubiKeyTouchPolicy.Required)
            return Fail(SlotPasswordKind.Corrupt, Malformed($"unknown touch policy {touch}"));

        var blob = new YubiKeySlotBlob(
            serial,
            bytes.AsSpan(HeaderSize + 4, ChallengeSize).ToArray(),
            bytes.AsSpan(HeaderSize + 4 + ChallengeSize, SaltSize).ToArray(),
            (YubiKeyTouchPolicy)touch,
            requiresPassword);
        return (blob, requiresPassword ? SlotPasswordKind.Password : SlotPasswordKind.None, null);

        static (YubiKeySlotBlob?, SlotPasswordKind, string?) Fail(SlotPasswordKind kind, string error) => (null, kind, error);
    }

    private static string Malformed(string what) =>
        $"Malformed YubiKey slot blob: {what}. Restore config.json from backup.";
}
