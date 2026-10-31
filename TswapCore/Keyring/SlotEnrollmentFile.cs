using System.Text.Json;
using System.Text.Json.Serialization;

namespace TswapCore.Keyring;

/// <summary>
/// Wire format for <c>tswap slot request</c>'s output file (issue #121). Hand-carried by the
/// user (scp/USB/paste) to an already-enrolled machine, which reads it in <c>tswap slot
/// approve</c>.
///
/// <para><b>Encoding: JSON, not fixed-binary — a deliberate departure from
/// <see cref="KeyringCodec"/>/<see cref="SlotPayloadWrap"/>'s AAD, and worth explaining.</b> Those
/// formats are fixed-binary because their own bytes directly feed an AEAD's associated data or
/// are stored indefinitely on disk, where an incidental JSON reordering could silently corrupt
/// every derived computation with no diagnosable cause (see <see cref="KeyringFormat"/>'s doc
/// comment). This file is neither: it is a small, transient, one-shot, human-handled artifact
/// (the user looks at it, moves it, and discards it) that never itself feeds an AAD computation —
/// its *fields*, once parsed into plain byte arrays, are what feed <see cref="SlotPayloadWrap"/>'s
/// AAD, identically regardless of whether they arrived via JSON or a bespoke binary layout. JSON
/// keeps this format easy to inspect, debug, and hand-edit if something goes wrong mid-enrollment,
/// at zero cost to the actual cryptographic binding. <see cref="SlotEnrollmentFileCodec"/> still
/// version-checks this format explicitly (see <see cref="CurrentFormatVersion"/>) — the "add a
/// version-compatibility check for any new persisted wire format" bar applies regardless of
/// encoding choice.</para>
///
/// <para><b>Fields:</b> <see cref="SlotId"/> (base64, <see cref="KeyringFormat.SlotIdSize"/>
/// bytes) is chosen here, at request time, by the new machine — not by the approving machine —
/// specifically so it can be persisted locally (see <c>Config.PendingSlotId</c>) and carried
/// through unchanged into the finalized <see cref="SlotKind.Machine"/> slot that <c>slot
/// accept</c> eventually writes. <see cref="PublicKey"/> (base64, <see cref="SlotKeyPair.KeySize"/>
/// bytes) is that same slot's long-lived X25519 public key (<see cref="SlotKeyPair.Generate"/>) —
/// the private half never leaves the requesting machine in this file.</para>
///
/// <para><b>Version 2 (brief T4 decision 6):</b> <see cref="HwBlob"/> is the requested slot's
/// <see cref="YubiKeySlotBlob"/> (base64): <c>slot request</c> enrolls one YubiKey, <c>slot
/// approve</c> copies the blob into the approve file and <c>slot accept</c> writes it into the
/// new machine slot. A version 1 request (an older tswap's YubiKey pair enrollment, no blob) is
/// refused with a message saying to run <c>slot request</c> again; it is never treated as a pair
/// slot. <c>slot approve</c> refuses a version 2 request without a blob.</para>
///
/// <para><b><see cref="Backend"/> (brief T5 decision 2, issue #152):</b> null (omitted) for the
/// one-YubiKey request, whose <see cref="HwBlob"/> is a <see cref="YubiKeySlotBlob"/>;
/// <c>"tpm"</c> or <c>"secure-enclave"</c> for <c>slot request --tpm</c>/<c>--secure-enclave</c>,
/// whose <see cref="HwBlob"/> is that backend's opaque sealed/wrapped <c>KEK_slot</c>. An optional
/// field rather than a format version bump: a YubiKey request is byte-for-byte what version 2
/// always was, and an older tswap reading a TPM request fails safely on the blob (wrong YubiKey
/// magic). The name is informational for the approver; accept checks the blob byte for byte
/// against its own pending copy.</para>
/// </summary>
public sealed record SlotRequestFile(int FormatVersion, string SlotId, string PublicKey,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? HwBlob = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] HardwareBackend? Backend = null)
{
    /// <summary>Current format version this build writes and requires on read.</summary>
    public const int CurrentFormatVersion = 2;

    /// <summary>The pair-enrollment request format made by tswap before brief T4.</summary>
    public const int PairFormatVersion = 1;
}

/// <summary>
/// One existing keyring slot, verbatim, as carried inside a <see cref="SlotApproveFile"/> (design
/// decision: the approve file propagates the *entire* current slot list, not just the new slot's
/// material — see this issue's PR body). Every field here is the base64/raw form of the
/// corresponding <see cref="Slot"/> field; <see cref="SlotEnrollmentFileCodec"/> round-trips
/// these back into real <see cref="Slot"/> instances at <c>slot accept</c> time.
///
/// <para><see cref="HwBlob"/> (issue #154): the slot's <see cref="Slot.HwBlob"/>, base64, so a
/// TPM/Secure Enclave machine slot is copied whole into the accepting machine's keyring. Omitted
/// from the JSON when null (YubiKey and recovery slots, and every approve file written before
/// this field), which older readers ignore.</para>
/// </summary>
public sealed record SlotDto(string SlotId, string PublicKey, string Wrapped, SlotKind Kind,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? HwBlob = null);

/// <summary>
/// Wire format for <c>tswap slot approve</c>'s output file (issue #121). Hand-carried back to the
/// requesting machine, which reads it in <c>tswap slot accept</c>.
///
/// <para>Carries everything <see cref="SlotPayloadWrap.BuildAad"/> needs to be reconstructed
/// identically on the accepting machine (<see cref="KeyringFormatVersion"/>,
/// <see cref="VaultId"/>, <see cref="K"/>, <see cref="NewSlotId"/> — the last echoed straight from
/// the <see cref="SlotRequestFile"/> this approve file answers), plus:</para>
/// <list type="bullet">
/// <item><see cref="ExistingSlots"/> — the approving machine's <em>entire</em> current slot list
/// (design decision, this issue's PR body §3: keeps every machine's local keyring a reasonably
/// accurate, if manually-propagated, picture of the fleet — "no merge engine, no revocation/sync
/// in v0" is an accepted limitation, not a data-loss risk, since nothing here is ever destructive
/// to the approving machine's own copy).</item>
/// <item><see cref="NewSlotPublicKey"/> — the requester's long-term public key, echoed back so
/// <c>slot accept</c> can cross-check it against what this machine itself generated at <c>slot
/// request</c> time (<c>Config.PendingSlotPublicKey</c>), catching a mismatched/wrong-pair file
/// before any cryptography is attempted.</item>
/// <item><see cref="NewSlotEphemeralPublicKey"/>/<see cref="NewSlotWrapped"/> — the output of
/// <see cref="RecoverySlotWrap.Wrap"/>, called with the requester's long-term public key as the
/// "recovery" recipient. This is the same ephemeral-ECDH-then-AEAD construction issue #120 already
/// built and tests, reused wholesale rather than re-implemented (see this issue's PR body for why
/// a second, near-identical construction would not be justified here).</item>
/// <item><see cref="NewSlotHwBlob"/> (version 2, brief T4 decision 6) — the request's
/// <see cref="YubiKeySlotBlob"/>, echoed so <c>slot accept</c> writes it into the new slot after
/// checking it against its own pending copy. <c>slot accept</c> refuses an approve file without
/// it.</item>
/// </list>
/// </summary>
public sealed record SlotApproveFile(
    int FormatVersion,
    byte KeyringFormatVersion,
    string VaultId,
    byte K,
    List<SlotDto> ExistingSlots,
    string NewSlotId,
    string NewSlotPublicKey,
    string NewSlotEphemeralPublicKey,
    string NewSlotWrapped,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? NewSlotHwBlob = null,
    // Brief T5 decision 2: the request's Backend, passed on (null for a YubiKey slot).
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] HardwareBackend? NewSlotBackend = null)
{
    /// <summary>Current format version this build writes and requires on read (2 since brief T4,
    /// which added <see cref="NewSlotHwBlob"/>).</summary>
    public const int CurrentFormatVersion = 2;
}

/// <summary>
/// Serializes/deserializes <see cref="SlotRequestFile"/>/<see cref="SlotApproveFile"/> to/from
/// JSON, with explicit version checks on both this small format's own version and (for the
/// approve file) the embedded <see cref="KeyringFormat.KeyringFormatVersion"/> — see
/// <see cref="SlotRequestFile"/>'s doc comment for why JSON was chosen over fixed-binary here, and
/// <c>MULTI_MACHINE_KEYING.md</c>'s implementation notes on this module's history of
/// version-check gaps (never skip this check for a new persisted format).
/// </summary>
public static class SlotEnrollmentFileCodec
{
    public static string SerializeRequest(SlotRequestFile file) =>
        JsonSerializer.Serialize(file, TswapJsonContext.Default.SlotRequestFile);

    /// <summary>
    /// Parses a <see cref="SlotRequestFile"/> previously produced by
    /// <see cref="SerializeRequest"/>. Throws <see cref="TswapException"/> — never a raw
    /// exception — for invalid JSON, a null/empty result, or an unsupported
    /// <see cref="SlotRequestFile.FormatVersion"/>.
    /// </summary>
    public static SlotRequestFile DeserializeRequest(string json)
    {
        SlotRequestFile? file;
        try
        {
            file = JsonSerializer.Deserialize(json, TswapJsonContext.Default.SlotRequestFile);
        }
        catch (JsonException ex)
        {
            throw new TswapException($"Slot request file is not valid JSON: {ex.Message}");
        }

        if (file is null)
            throw new TswapException("Slot request file is empty or invalid.");
        if (file.FormatVersion == SlotRequestFile.PairFormatVersion)
            throw new TswapException(
                "This slot request was made by an older tswap, which enrolls a YubiKey pair. Keyring slots now take " +
                "one YubiKey each, and pair enrollments are no longer accepted. On the requesting machine, update " +
                "tswap and run 'tswap slot request <file>' again with one YubiKey plugged in.");
        if (file.FormatVersion != SlotRequestFile.CurrentFormatVersion)
            throw new TswapException(
                $"Unsupported slot request file format version {file.FormatVersion} " +
                $"(this build supports {SlotRequestFile.CurrentFormatVersion}). Use a matching tswap version on both machines.");
        if (file.HwBlob is not null)
            ValidateNewSlotBlob(file.Backend, DecodeVariable(file.HwBlob, "slot request file's hardware blob"), "slot request file");

        return file;
    }

    public static string SerializeApprove(SlotApproveFile file) =>
        JsonSerializer.Serialize(file, TswapJsonContext.Default.SlotApproveFile);

    /// <summary>
    /// Parses a <see cref="SlotApproveFile"/> previously produced by
    /// <see cref="SerializeApprove"/>. Throws <see cref="TswapException"/> — never a raw
    /// exception — for invalid JSON, a null/empty result, an unsupported
    /// <see cref="SlotApproveFile.FormatVersion"/>, or an unsupported embedded
    /// <see cref="SlotApproveFile.KeyringFormatVersion"/> (this build's <c>slot accept</c> would
    /// otherwise silently reconstruct the wrong AAD and fail the AEAD unwrap with a confusing
    /// "authentication failed" message instead of a clear version error).
    /// </summary>
    public static SlotApproveFile DeserializeApprove(string json)
    {
        SlotApproveFile? file;
        try
        {
            file = JsonSerializer.Deserialize(json, TswapJsonContext.Default.SlotApproveFile);
        }
        catch (JsonException ex)
        {
            throw new TswapException($"Slot approve file is not valid JSON: {ex.Message}");
        }

        if (file is null)
            throw new TswapException("Slot approve file is empty or invalid.");
        if (file.FormatVersion != SlotApproveFile.CurrentFormatVersion)
            throw new TswapException(
                $"Unsupported slot approve file format version {file.FormatVersion} " +
                $"(this build supports {SlotApproveFile.CurrentFormatVersion}). Use a matching tswap version on both machines.");
        // Version 2 (a YubiKey keyring vault from before issue #154) and 3 are both current:
        // slot accept keeps the approving vault's version, which its slots' AEAD binds.
        if (file.KeyringFormatVersion is not (KeyringFormat.KeyringFormatVersionWithoutHwBlob or KeyringFormat.KeyringFormatVersion))
            throw new TswapException(
                $"Unsupported keyring format version {file.KeyringFormatVersion} in approve file " +
                $"(this build supports {KeyringFormat.KeyringFormatVersionWithoutHwBlob} and {KeyringFormat.KeyringFormatVersion}).");

        // The new slot's YubiKey blob (brief T4): strictly decoded, and only in a keyring that has
        // the hwBlob column. Its absence is refused by 'slot accept', which needs it.
        if (file.NewSlotHwBlob is not null)
        {
            if (file.KeyringFormatVersion < KeyringFormat.KeyringFormatVersion)
                throw new TswapException(
                    $"Malformed slot approve file: a keyring format version {file.KeyringFormatVersion} slot cannot carry a hardware blob.");
            ValidateNewSlotBlob(file.NewSlotBackend, DecodeVariable(file.NewSlotHwBlob, "approve file's new slot hardware blob"), "slot approve file");
        }

        // A slot's hwBlob must be one KeyringCodec.Encode can write (security review of T2):
        // reject it here with a clear error instead of a raw ArgumentException at slot accept.
        foreach (var slot in file.ExistingSlots ?? [])
        {
            if (slot.HwBlob is null)
                continue;
            if (file.KeyringFormatVersion < KeyringFormat.KeyringFormatVersion)
                throw new TswapException(
                    $"Malformed slot approve file: a keyring format version {file.KeyringFormatVersion} slot cannot carry a hardware blob.");
            if (slot.Kind == SlotKind.Recovery)
                throw new TswapException("Malformed slot approve file: a recovery slot cannot carry a hardware blob.");
            var hwBlob = DecodeVariable(slot.HwBlob, "approve file's existing slot hardware blob");
            if (hwBlob.Length > KeyringFormat.MaxHwBlobSize)
                throw new TswapException(
                    $"Malformed slot approve file: a slot's hardware blob is {hwBlob.Length} bytes, more than the {KeyringFormat.MaxHwBlobSize}-byte limit.");
        }

        return file;
    }

    /// <summary>
    /// Decodes a base64 field to exactly <paramref name="expectedLength"/> bytes. Throws
    /// <see cref="TswapException"/> — never a raw <see cref="FormatException"/> or silent
    /// truncation — for invalid base64 or a wrong-length result, naming
    /// <paramref name="what"/> in the error so a corrupted enrollment file points at the actual
    /// offending field rather than a generic decode failure.
    /// </summary>
    /// <summary>
    /// The new slot's blob in a request or approve file, checked against the backend the file
    /// names (brief T5 decision 2): none or YubiKey ⇒ a strictly decoded <see cref="YubiKeySlotBlob"/>
    /// (brief T4); TPM or Secure Enclave ⇒ an opaque blob within <see cref="KeyringFormat.MaxHwBlobSize"/>
    /// that is not a YubiKey blob (a mislabelled request is refused rather than guessed at).
    /// </summary>
    private static void ValidateNewSlotBlob(HardwareBackend? backend, byte[] hwBlob, string what)
    {
        if ((backend ?? HardwareBackend.YubiKey) == HardwareBackend.YubiKey)
        {
            YubiKeySlotBlob.Decode(hwBlob);
            return;
        }
        if (YubiKeySlotBlob.IsYubiKeyBlob(hwBlob))
            throw new TswapException(
                $"Malformed {what}: it names the '{backend!.Value.DisplayName()}' backend but carries a YubiKey slot blob.");
        SlotReceiptCodec.ValidateHwBlob(hwBlob, what);
    }

    public static byte[] DecodeFixed(string base64, int expectedLength, string what)
    {
        var bytes = DecodeVariable(base64, what);
        if (bytes.Length != expectedLength)
            throw new TswapException($"Malformed enrollment file: {what} must be {expectedLength} bytes, got {bytes.Length}.");
        return bytes;
    }

    /// <summary>Decodes a base64 field of any length. Throws <see cref="TswapException"/> for invalid base64.</summary>
    public static byte[] DecodeVariable(string base64, string what)
    {
        try
        {
            return Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            throw new TswapException($"Malformed enrollment file: {what} is not valid base64.");
        }
    }
}
