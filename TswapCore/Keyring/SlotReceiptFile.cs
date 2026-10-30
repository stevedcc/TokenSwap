using System.Text.Json;
using System.Text.Json.Serialization;

namespace TswapCore.Keyring;

/// <summary>
/// Wire format of the receipt <c>tswap slot accept</c> writes (brief T5 decision 1, issue #190):
/// the finished new slot, carried back to the approving machine, which adds it to its own keyring
/// with <c>tswap slot merge</c>. JSON for the same reasons as <see cref="SlotApproveFile"/>: a
/// small, hand-carried artifact whose fields, not its bytes, feed the slot's AEAD.
///
/// <para>A receipt holds no secret: <see cref="Wrapped"/> is AEAD ciphertext under the joiner's
/// own <c>KEK_slot</c>, bound to (format version, vault id, k, slot id), and <see cref="HwBlob"/>
/// is the joiner's hardware blob (a <see cref="YubiKeySlotBlob"/> or an opaque TPM/Secure Enclave
/// blob), useless without that hardware.</para>
///
/// <para><b>Strict:</b> unknown members are refused (<see cref="JsonUnmappedMemberHandling.Disallow"/>),
/// as is anything after the JSON value. <see cref="ReceiptFormatVersion"/> is also what tells
/// <c>slot merge</c> that a file is a receipt rather than another copy's <c>config.json</c>. The
/// approve file's slot id is <see cref="SlotId"/> itself: accept refuses an approve file whose slot
/// id differs from its pending request, so the two are always equal and only one is carried.</para>
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record SlotReceiptFile(
    int ReceiptFormatVersion,
    byte KeyringFormatVersion,
    string? VaultId,
    byte K,
    string? SlotId,
    string? PublicKey,
    string? Wrapped,
    SlotKind Kind,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? HwBlob = null);

/// <summary>A decoded receipt: the keyring header it belongs to and the finished slot.</summary>
public sealed record SlotReceipt(byte KeyringFormatVersion, byte[] VaultId, byte K, Slot Slot);

/// <summary>Reads and writes <see cref="SlotReceiptFile"/>.</summary>
public static class SlotReceiptCodec
{
    /// <summary>The receipt format this build writes and reads (<c>ReceiptFormatVersion</c>).</summary>
    public const int CurrentFormatVersion = 1;

    /// <summary>
    /// Largest receipt this build reads, in characters. A real one is well under 1 KiB (a
    /// TPM blob is the largest part, see <see cref="KeyringFormat.MaxHwBlobSize"/>); this only
    /// stops a huge file from being parsed at all.
    /// </summary>
    public const int MaxFileSize = 16 * 1024;

    /// <summary>
    /// Largest wrapped slot accepted. A machine slot's wrap is 92 bytes (nonce, tag and the
    /// 64-byte <see cref="SlotSecretPayload"/>); the limit leaves room without allowing junk.
    /// </summary>
    public const int MaxWrappedSize = 1024;

    public static string Serialize(SlotReceipt receipt) =>
        JsonSerializer.Serialize(new SlotReceiptFile(
            CurrentFormatVersion,
            receipt.KeyringFormatVersion,
            Convert.ToBase64String(receipt.VaultId),
            receipt.K,
            Convert.ToBase64String(receipt.Slot.SlotId),
            Convert.ToBase64String(receipt.Slot.PublicKey),
            Convert.ToBase64String(receipt.Slot.Wrapped),
            receipt.Slot.Kind,
            receipt.Slot.HwBlob is { Length: > 0 } hwBlob ? Convert.ToBase64String(hwBlob) : null),
            TswapJsonContext.Default.SlotReceiptFile);

    /// <summary>
    /// Decodes and validates a receipt. Throws <see cref="TswapException"/> for anything a
    /// keyring could not hold or that a real accept never writes: another receipt version, a
    /// keyring version other than <see cref="KeyringFormat.KeyringFormatVersion"/> (a version 2
    /// keyring has no hardware blob column and takes no new slots), wrong-length ids or keys, a
    /// non-machine slot, a missing or oversize hardware blob, a malformed YubiKey blob, unknown
    /// members or trailing data.
    /// </summary>
    public static SlotReceipt Deserialize(string json)
    {
        if (json.Length > MaxFileSize)
            throw new TswapException($"Slot receipt is too large ({json.Length} characters; a receipt is at most {MaxFileSize}).");

        SlotReceiptFile? file;
        try
        {
            file = JsonSerializer.Deserialize(json, TswapJsonContext.Default.SlotReceiptFile);
        }
        catch (JsonException ex)
        {
            throw new TswapException($"Slot receipt is not valid JSON: {ex.Message}");
        }

        if (file == null)
            throw new TswapException("Slot receipt is empty or invalid.");
        if (file.ReceiptFormatVersion != CurrentFormatVersion)
            throw new TswapException(
                $"Unsupported slot receipt format version {file.ReceiptFormatVersion} " +
                $"(this build supports {CurrentFormatVersion}). Use a matching tswap version on both machines.");
        if (file.KeyringFormatVersion != KeyringFormat.KeyringFormatVersion)
            throw new TswapException(
                $"Unsupported keyring format version {file.KeyringFormatVersion} in slot receipt " +
                $"(a receipt carries a version {KeyringFormat.KeyringFormatVersion} slot).");
        if (file.Kind != SlotKind.Machine)
            throw new TswapException("Malformed slot receipt: a receipt carries a machine slot, nothing else.");

        var vaultId = SlotEnrollmentFileCodec.DecodeFixed(Required(file.VaultId, "vault id"), KeyringFormat.VaultIdSize, "receipt's vault id");
        var slotId = SlotEnrollmentFileCodec.DecodeFixed(Required(file.SlotId, "slot id"), KeyringFormat.SlotIdSize, "receipt's slot id");
        var publicKey = SlotEnrollmentFileCodec.DecodeFixed(Required(file.PublicKey, "public key"), SlotKeyPair.KeySize, "receipt's public key");
        var wrapped = SlotEnrollmentFileCodec.DecodeVariable(Required(file.Wrapped, "wrapped slot"), "receipt's wrapped slot");
        if (wrapped.Length == 0 || wrapped.Length > MaxWrappedSize)
            throw new TswapException(
                $"Malformed slot receipt: the wrapped slot is {wrapped.Length} bytes (expected 1 to {MaxWrappedSize}).");

        if (file.HwBlob == null)
            throw new TswapException("Malformed slot receipt: the slot has no hardware blob, so no device could open it.");
        var hwBlob = ValidateHwBlob(SlotEnrollmentFileCodec.DecodeVariable(file.HwBlob, "receipt's hardware blob"), "slot receipt");

        return new SlotReceipt(file.KeyringFormatVersion, vaultId, file.K,
            new Slot(slotId, publicKey, wrapped, SlotKind.Machine, hwBlob));
    }

    /// <summary>
    /// The hardware blob rules every slot arriving from another machine must meet (T2's hardening,
    /// shared with <c>slot merge</c>): not empty, at most <see cref="KeyringFormat.MaxHwBlobSize"/>
    /// bytes, and a blob with the YubiKey magic must decode strictly. Returns the blob.
    /// </summary>
    public static byte[] ValidateHwBlob(byte[] hwBlob, string what)
    {
        if (hwBlob.Length == 0)
            throw new TswapException($"Malformed {what}: the slot has no hardware blob, so no device could open it.");
        if (hwBlob.Length > KeyringFormat.MaxHwBlobSize)
            throw new TswapException(
                $"Malformed {what}: a slot's hardware blob is {hwBlob.Length} bytes, more than the {KeyringFormat.MaxHwBlobSize}-byte limit.");
        if (YubiKeySlotBlob.IsYubiKeyBlob(hwBlob))
            YubiKeySlotBlob.Decode(hwBlob);
        return hwBlob;
    }

    private static string Required(string? value, string what) =>
        value ?? throw new TswapException($"Malformed slot receipt: the {what} is missing.");
}
