using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TswapCore.Keyring;

/// <summary>
/// A YubiKey slot's recorded touch policy (slot 2's "require touch" setting at enrollment).
/// Explicit byte values: <see cref="YubiKeySlotBlob"/> persists this as a raw byte.
/// </summary>
public enum YubiKeyTouchPolicy : byte
{
    /// <summary>Detection failed at enrollment (for example ykman could not read the slot).</summary>
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
/// <para>A YubiKey machine slot <em>without</em> such a blob is a <b>legacy pair slot</b>: its
/// <c>KEK_slot</c> still comes from the two-key XOR scheme and the per-machine config fields
/// (<c>YubiKeySerials</c>, <c>RedundancyXor</c>, <c>UnlockChallenge</c>, <c>MasterKeySalt</c>).
/// See <see cref="YubiKeySlotKek"/> for how this blob's fields become <c>KEK_slot</c>.</para>
/// </summary>
public sealed record YubiKeySlotBlob
{
    public const byte CurrentVersion = 1;
    public const int ChallengeSize = 32;
    public const int SaltSize = 32;

    private const int MagicSize = 4;
    private const int HeaderSize = MagicSize + 1; // magic + version
    public const int EncodedSize = HeaderSize + 4 + ChallengeSize + SaltSize + 1;

    /// <summary>"TSYK": TokenSwap YubiKey slot.</summary>
    public static ReadOnlySpan<byte> Magic => "TSYK"u8;

    public YubiKeySlotBlob(int serial, byte[] challenge, byte[] salt, YubiKeyTouchPolicy touch)
    {
        if (challenge.Length != ChallengeSize)
            throw new ArgumentException($"The challenge must be {ChallengeSize} bytes", nameof(challenge));
        if (salt.Length != SaltSize)
            throw new ArgumentException($"The salt must be {SaltSize} bytes", nameof(salt));
        Serial = serial;
        Challenge = (byte[])challenge.Clone();
        Salt = (byte[])salt.Clone();
        Touch = touch;
    }

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
    /// as 64 hex characters, which the ykman driver sends as exactly 64 bytes, the same shape as
    /// a pair vault's <c>UnlockChallenge</c>.
    /// </summary>
    public string ChallengeString => Convert.ToHexString(Challenge);

    /// <summary>A new slot's parameters: fresh CSPRNG challenge and salt (decision 1).</summary>
    public static YubiKeySlotBlob Create(int serial, bool? requiresTouch) => new(
        serial,
        RandomNumberGenerator.GetBytes(ChallengeSize),
        RandomNumberGenerator.GetBytes(SaltSize),
        requiresTouch switch
        {
            true => YubiKeyTouchPolicy.Required,
            false => YubiKeyTouchPolicy.NotRequired,
            null => YubiKeyTouchPolicy.Unknown,
        });

    /// <summary>True when <paramref name="hwBlob"/> starts with this format's magic.</summary>
    public static bool IsYubiKeyBlob(byte[]? hwBlob) =>
        hwBlob is { Length: >= MagicSize } && hwBlob.AsSpan(0, MagicSize).SequenceEqual(Magic);

    public byte[] Encode()
    {
        var bytes = new byte[EncodedSize];
        var span = bytes.AsSpan();
        Magic.CopyTo(span);
        span[MagicSize] = CurrentVersion;
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderSize, 4), Serial);
        Challenge.CopyTo(span.Slice(HeaderSize + 4, ChallengeSize));
        Salt.CopyTo(span.Slice(HeaderSize + 4 + ChallengeSize, SaltSize));
        span[EncodedSize - 1] = (byte)Touch;
        return bytes;
    }

    public static YubiKeySlotBlob Decode(byte[] bytes)
    {
        if (bytes.Length < HeaderSize)
            throw Corrupt($"truncated ({bytes.Length} bytes)");
        if (!IsYubiKeyBlob(bytes))
            throw Corrupt("wrong magic");

        var version = bytes[MagicSize];
        if (version > CurrentVersion)
            throw new TswapException(
                $"Unsupported YubiKey slot blob version {version}: this slot was enrolled by a newer tswap " +
                $"(this build reads version {CurrentVersion}); upgrade tswap to use it.");
        if (version != CurrentVersion)
            throw Corrupt($"unknown version {version}");

        if (bytes.Length < EncodedSize)
            throw Corrupt($"truncated ({bytes.Length} of {EncodedSize} bytes)");
        if (bytes.Length > EncodedSize)
            throw Corrupt($"{bytes.Length - EncodedSize} trailing bytes");

        var serial = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(HeaderSize, 4));
        if (serial <= 0)
            throw Corrupt($"invalid serial {serial}");

        var touch = bytes[EncodedSize - 1];
        if (touch > (byte)YubiKeyTouchPolicy.Required)
            throw Corrupt($"unknown touch policy {touch}");

        return new YubiKeySlotBlob(
            serial,
            bytes.AsSpan(HeaderSize + 4, ChallengeSize).ToArray(),
            bytes.AsSpan(HeaderSize + 4 + ChallengeSize, SaltSize).ToArray(),
            (YubiKeyTouchPolicy)touch);
    }

    private static TswapException Corrupt(string what) => new(
        $"Malformed YubiKey slot blob: {what}. Restore config.json from backup.");
}
