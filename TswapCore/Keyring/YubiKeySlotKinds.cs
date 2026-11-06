namespace TswapCore.Keyring;

/// <summary>
/// What a slot's hardware blob is, as far as YubiKeys go (<see cref="YubiKeySlotKinds.Classify"/>): an OTP
/// challenge-response slot (<c>TSYK</c> version 1 or 2), a FIDO2 hmac-secret slot (<c>TSYK</c> version 3), a
/// <c>TSYK</c> blob this build can't use or can't read, or not a YubiKey blob at all.
/// </summary>
public abstract record YubiKeySlotKind
{
    private YubiKeySlotKind()
    {
    }

    /// <summary>An OTP (HMAC-SHA1 challenge-response) slot.</summary>
    public sealed record Otp(YubiKeySlotBlob Blob) : YubiKeySlotKind;

    /// <summary>A FIDO2 hmac-secret slot.</summary>
    public sealed record Fido2(Fido2SlotBlob Blob) : YubiKeySlotKind;

    /// <summary>A newer blob version, PRF version or flag bits than this build knows; <see cref="Error"/> says which.</summary>
    public sealed record NeedsNewerTswap(string Error) : YubiKeySlotKind;

    /// <summary>A damaged <c>TSYK</c> blob; <see cref="Error"/> is the "Malformed … Restore config.json from backup." text.</summary>
    public sealed record Corrupt(string Error) : YubiKeySlotKind;

    /// <summary>Not a <c>TSYK</c> blob (a TPM or Secure Enclave blob, or none at all).</summary>
    public sealed record None : YubiKeySlotKind;
}

/// <summary>Routes a <c>TSYK</c> blob to its parser by the version byte; never throws.</summary>
public static class YubiKeySlotKinds
{
    private const int VersionOffset = 4;

    /// <summary>True when <paramref name="hwBlob"/> starts with the <c>TSYK</c> magic, whatever its version.</summary>
    public static bool IsYubiKey(byte[]? hwBlob) => YubiKeySlotBlob.IsYubiKeyBlob(hwBlob);

    /// <summary>
    /// Versions 1–2 go to <see cref="YubiKeySlotBlob.Parse"/>, 3 to <see cref="Fido2SlotBlob.Parse"/>; a
    /// greater version needs a newer tswap; version 0, or a blob too short to hold a version, is corrupt.
    /// </summary>
    public static YubiKeySlotKind Classify(byte[]? hwBlob)
    {
        if (!IsYubiKey(hwBlob))
            return new YubiKeySlotKind.None();
        if (hwBlob!.Length <= VersionOffset)
            return new YubiKeySlotKind.Corrupt(MalformedYubiKey($"truncated ({hwBlob.Length} bytes)"));

        var version = hwBlob[VersionOffset];
        switch (version)
        {
            case 0:
                return new YubiKeySlotKind.Corrupt(MalformedYubiKey($"unknown version {version}"));
            case YubiKeySlotBlob.CurrentVersion or YubiKeySlotBlob.PasswordVersion:
            {
                var (blob, kind, error) = YubiKeySlotBlob.Parse(hwBlob);
                return blob is not null ? new YubiKeySlotKind.Otp(blob) : Failure(kind, error!);
            }
            case Fido2SlotBlob.Version:
            {
                var (blob, kind, error) = Fido2SlotBlob.Parse(hwBlob);
                return blob is not null ? new YubiKeySlotKind.Fido2(blob) : Failure(kind, error!);
            }
            default:
                return new YubiKeySlotKind.NeedsNewerTswap(SlotPassword.NeedsNewerTswapText(version));
        }
    }

    private static YubiKeySlotKind Failure(SlotPasswordKind kind, string error) =>
        kind == SlotPasswordKind.NeedsNewerTswap
            ? new YubiKeySlotKind.NeedsNewerTswap(error)
            : new YubiKeySlotKind.Corrupt(error);

    private static string MalformedYubiKey(string what) =>
        $"Malformed YubiKey slot blob: {what}. Restore config.json from backup.";
}
