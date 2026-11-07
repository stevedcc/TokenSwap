using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TswapCore.Keyring;

/// <summary>
/// The parameters of a FIDO2 hmac-secret keyring slot, kept in that slot's hardware blob
/// (<see cref="Slot.HwBlob"/>) under the YubiKey magic <c>TSYK</c> with version 3, so a v0.2.x tswap answers
/// "needs a newer tswap" for the slot (<see cref="YubiKeySlotBlob.Parse"/>) and never misreads it.
///
/// <para><b>Layout</b> (little-endian integers):
/// <c>"TSYK"(4) || version 3 (1) || flags (1; bit 0 = password) || PRF version 1 (1) || serial int32 (0 =
/// unknown) || AAGUID (16, RFC 4122 byte order) || PRF input (32) || rpId length (1) || rpId UTF-8 ||
/// credential id length (uint16) || credential id (16..1023)</c>. Unlike an OTP version 2 blob, the flags
/// byte is always present, so flags <c>0x00</c> is a valid password-free slot.</para>
///
/// <para><b>Decoding is strict</b> (<see cref="Parse"/>): truncation, trailing bytes, a credential id or rp id
/// length out of range, a negative serial, PRF version 0 or an rp id other than <see cref="TswapRpId"/> are
/// corrupt ("Malformed FIDO2 slot blob: …"); unknown flag bits or a PRF version above 1 need a newer tswap
/// (<see cref="NeedsNewerText"/>). So a decoded blob's <see cref="RpId"/> is always <see cref="TswapRpId"/>.</para>
///
/// <para>The key is sent <see cref="Fido2Prf.Salt"/> of <see cref="PrfInput"/>; its output becomes
/// <c>KEK_slot</c> through <see cref="Fido2SlotKek"/>, with <see cref="PrfInput"/> as the HKDF salt.</para>
///
/// <para><b>Equality:</b> this is a record, but <see cref="PrfInput"/> and <see cref="CredentialId"/> are arrays,
/// so the generated <c>Equals</c> compares them by reference: two blobs decoded from the same bytes are not
/// equal. Compare field by field (<c>SequenceEqual</c> for the arrays).</para>
/// </summary>
public sealed record Fido2SlotBlob
{
    /// <summary>The <c>TSYK</c> version of a FIDO2 slot blob (versions 1 and 2 are <see cref="YubiKeySlotBlob"/>'s).</summary>
    public const byte Version = 3;

    /// <summary>The PRF transform this build applies (<see cref="Fido2Prf"/>).</summary>
    public const byte CurrentPrfVersion = 1;

    /// <summary>The relying-party id of every tswap FIDO2 credential.</summary>
    public const string TswapRpId = "tswap.crawford.dev";

    public const int PrfInputSize = 32;
    public const int MinCredentialIdSize = 16;
    public const int MaxCredentialIdSize = 1023;

    private const byte PasswordFlag = 0x01;
    private const int MagicSize = 4;
    private const int AaguidSize = 16;

    /// <summary>magic, version, flags, PRF version, serial, AAGUID and PRF input: everything before the rp id length.</summary>
    private const int FixedSize = MagicSize + 1 + 1 + 1 + 4 + AaguidSize + PrfInputSize;

    /// <summary><see cref="TswapRpId"/> as UTF-8 (a test pins the two equal).</summary>
    internal static ReadOnlySpan<byte> TswapRpIdUtf8 => "tswap.crawford.dev"u8;

    public Fido2SlotBlob(int? serial, Guid aaguid, byte[] prfInput, string rpId, byte[] credentialId, bool requiresPassword)
    {
        if (serial is <= 0)
            throw new ArgumentOutOfRangeException(nameof(serial), serial, "A known serial is positive; pass null when it is unknown");
        if (prfInput.Length != PrfInputSize)
            throw new ArgumentException($"The PRF input must be {PrfInputSize} bytes", nameof(prfInput));
        if (rpId != TswapRpId)
            throw new ArgumentException($"The relying-party id must be {TswapRpId}", nameof(rpId));
        if (credentialId.Length is < MinCredentialIdSize or > MaxCredentialIdSize)
            throw new ArgumentException(
                $"The credential id must be {MinCredentialIdSize} to {MaxCredentialIdSize} bytes", nameof(credentialId));
        Serial = serial;
        Aaguid = aaguid;
        PrfInput = (byte[])prfInput.Clone();
        RpId = rpId;
        CredentialId = (byte[])credentialId.Clone();
        RequiresPassword = requiresPassword;
    }

    /// <summary>The key's serial when it reported one at enrolment; null when unknown (written as 0).</summary>
    public int? Serial { get; }

    /// <summary>The authenticator's model id from its attestation (a Yubico one, <see cref="YubicoAaguids"/>).</summary>
    public Guid Aaguid { get; }

    /// <summary>32 random bytes; the key is sent <see cref="Fido2Prf.Salt"/> of them, and they are the KEK's HKDF salt.</summary>
    public byte[] PrfInput { get; }

    /// <summary>Always <see cref="TswapRpId"/>; readers use this property for the ceremony.</summary>
    public string RpId { get; }

    /// <summary>The non-discoverable credential's id, as make-credential returned it.</summary>
    public byte[] CredentialId { get; }

    /// <summary>The slot's <c>KEK_slot</c> mixes in the stretched vault password (<see cref="Fido2SlotKek.DeriveV2"/>).</summary>
    public bool RequiresPassword { get; }

    /// <summary>The PRF transform the slot was made with; always <see cref="CurrentPrfVersion"/> in this build.</summary>
    public byte PrfVersion => CurrentPrfVersion;

    /// <summary>A new slot's parameters: a fresh CSPRNG PRF input and <see cref="TswapRpId"/>.</summary>
    public static Fido2SlotBlob Create(int? serial, Guid aaguid, byte[] credentialId, bool requiresPassword) =>
        new(serial, aaguid, RandomNumberGenerator.GetBytes(PrfInputSize), TswapRpId, credentialId, requiresPassword);

    /// <summary>"YubiKey N" when the serial is known, else the model's name, else a generic description.</summary>
    public static string DisplayName(int? serial, Guid aaguid) =>
        serial is { } known ? $"YubiKey {known}"
        : YubicoAaguids.ModelName(aaguid) ?? "the YubiKey this slot was made with";

    /// <summary>The text for a blob this build is too old for; <paramref name="what"/> names the newer part.</summary>
    public static string NeedsNewerText(string what) => $"needs a newer tswap ({what}); upgrade tswap.";

    public byte[] Encode()
    {
        var bytes = new byte[FixedSize + 1 + TswapRpIdUtf8.Length + 2 + CredentialId.Length];
        var span = bytes.AsSpan();
        var offset = 0;
        YubiKeySlotBlob.Magic.CopyTo(span);
        offset += MagicSize;
        span[offset++] = Version;
        span[offset++] = RequiresPassword ? PasswordFlag : (byte)0;
        span[offset++] = PrfVersion;
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(offset, 4), Serial ?? 0);
        offset += 4;
        Aaguid.TryWriteBytes(span.Slice(offset, AaguidSize), bigEndian: true, out _);
        offset += AaguidSize;
        PrfInput.CopyTo(span.Slice(offset, PrfInputSize));
        offset += PrfInputSize;
        span[offset++] = (byte)TswapRpIdUtf8.Length;
        TswapRpIdUtf8.CopyTo(span.Slice(offset));
        offset += TswapRpIdUtf8.Length;
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), (ushort)CredentialId.Length);
        offset += 2;
        CredentialId.CopyTo(span.Slice(offset));
        return bytes;
    }

    /// <summary>Decodes a version 3 blob, or throws the <see cref="TswapException"/> text <see cref="Parse"/> gives.</summary>
    public static Fido2SlotBlob Decode(byte[] bytes)
    {
        var (blob, _, error) = Parse(bytes);
        return blob ?? throw new TswapException(error!);
    }

    /// <summary>
    /// Never throws: the blob and its <see cref="SlotPasswordKind"/> (None or Password), or null with the kind
    /// (NeedsNewerTswap or Corrupt) and the error text <see cref="Decode"/> throws. The header bytes (version,
    /// flags, PRF version) are checked as soon as they are read, so a newer layout says "needs a newer tswap"
    /// rather than "malformed".
    /// </summary>
    internal static (Fido2SlotBlob? Blob, SlotPasswordKind Kind, string? Error) Parse(byte[] bytes)
    {
        if (!YubiKeySlotBlob.IsYubiKeyBlob(bytes))
            return Corrupt(bytes.Length < MagicSize ? $"truncated ({bytes.Length} bytes)" : "wrong magic");
        if (bytes.Length < MagicSize + 1)
            return Corrupt($"truncated ({bytes.Length} bytes)");

        var version = bytes[MagicSize];
        if (version > Version)
            return Fail(SlotPasswordKind.NeedsNewerTswap, SlotPassword.NeedsNewerTswapText(version));
        if (version != Version)
            return Corrupt($"version {version} is not a FIDO2 slot's");

        if (bytes.Length < MagicSize + 2)
            return Corrupt($"truncated ({bytes.Length} bytes, no flags)");
        var flags = bytes[MagicSize + 1];
        if ((flags & ~PasswordFlag) != 0)
            return Fail(SlotPasswordKind.NeedsNewerTswap, NeedsNewerText($"FIDO2 slot flags 0x{flags:X2}"));

        if (bytes.Length < MagicSize + 3)
            return Corrupt($"truncated ({bytes.Length} bytes, no PRF version)");
        var prfVersion = bytes[MagicSize + 2];
        if (prfVersion > CurrentPrfVersion)
            return Fail(SlotPasswordKind.NeedsNewerTswap, NeedsNewerText($"FIDO2 slot PRF version {prfVersion}"));
        if (prfVersion == 0)
            return Corrupt("PRF version 0");

        if (bytes.Length < FixedSize + 1)
            return Corrupt($"truncated ({bytes.Length} bytes, short of the fixed fields)");
        var offset = MagicSize + 3;
        var serial = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset, 4));
        if (serial < 0)
            return Corrupt($"invalid serial {serial}");
        offset += 4;
        var aaguid = new Guid(bytes.AsSpan(offset, AaguidSize), bigEndian: true);
        offset += AaguidSize;
        var prfInput = bytes.AsSpan(offset, PrfInputSize);
        offset += PrfInputSize;

        var rpIdLength = bytes[offset++];
        if (rpIdLength == 0)
            return Corrupt("empty relying-party id");
        if (bytes.Length < offset + rpIdLength)
            return Corrupt($"truncated ({bytes.Length} bytes, in the relying-party id)");
        if (!bytes.AsSpan(offset, rpIdLength).SequenceEqual(TswapRpIdUtf8))
            return Corrupt($"relying-party id is not {TswapRpId}");
        offset += rpIdLength;

        if (bytes.Length < offset + 2)
            return Corrupt($"truncated ({bytes.Length} bytes, no credential id length)");
        var credentialIdLength = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
        offset += 2;
        if (credentialIdLength is < MinCredentialIdSize or > MaxCredentialIdSize)
            return Corrupt($"credential id length {credentialIdLength} (expected {MinCredentialIdSize} to {MaxCredentialIdSize})");
        var size = offset + credentialIdLength;
        if (bytes.Length < size)
            return Corrupt($"truncated ({bytes.Length} of {size} bytes)");
        if (bytes.Length > size)
            return Corrupt($"{bytes.Length - size} trailing bytes");

        var requiresPassword = flags == PasswordFlag;
        var blob = new Fido2SlotBlob(
            serial == 0 ? null : serial,
            aaguid,
            prfInput.ToArray(),
            TswapRpId,
            bytes.AsSpan(offset, credentialIdLength).ToArray(),
            requiresPassword);
        return (blob, requiresPassword ? SlotPasswordKind.Password : SlotPasswordKind.None, null);

        static (Fido2SlotBlob?, SlotPasswordKind, string?) Fail(SlotPasswordKind kind, string error) => (null, kind, error);

        static (Fido2SlotBlob?, SlotPasswordKind, string?) Corrupt(string what) =>
            (null, SlotPasswordKind.Corrupt, $"Malformed FIDO2 slot blob: {what}. Restore config.json from backup.");
    }
}
