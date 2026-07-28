using System.Text.Json;

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
/// </summary>
public sealed record SlotRequestFile(int FormatVersion, string SlotId, string PublicKey)
{
    /// <summary>Current format version this build writes and requires on read.</summary>
    public const int CurrentFormatVersion = 1;
}

/// <summary>
/// One existing keyring slot, verbatim, as carried inside a <see cref="SlotApproveFile"/> (design
/// decision: the approve file propagates the *entire* current slot list, not just the new slot's
/// material — see this issue's PR body). Every field here is the base64/raw form of the
/// corresponding <see cref="Slot"/> field; <see cref="SlotEnrollmentFileCodec"/> round-trips
/// these back into real <see cref="Slot"/> instances at <c>slot accept</c> time.
/// </summary>
public sealed record SlotDto(string SlotId, string PublicKey, string Wrapped, SlotKind Kind);

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
    string NewSlotWrapped)
{
    /// <summary>Current format version this build writes and requires on read.</summary>
    public const int CurrentFormatVersion = 1;
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

        if (file == null)
            throw new TswapException("Slot request file is empty or invalid.");
        if (file.FormatVersion != SlotRequestFile.CurrentFormatVersion)
            throw new TswapException(
                $"Unsupported slot request file format version {file.FormatVersion} " +
                $"(this build supports {SlotRequestFile.CurrentFormatVersion}). Use a matching tswap version on both machines.");

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

        if (file == null)
            throw new TswapException("Slot approve file is empty or invalid.");
        if (file.FormatVersion != SlotApproveFile.CurrentFormatVersion)
            throw new TswapException(
                $"Unsupported slot approve file format version {file.FormatVersion} " +
                $"(this build supports {SlotApproveFile.CurrentFormatVersion}). Use a matching tswap version on both machines.");
        if (file.KeyringFormatVersion != KeyringFormat.KeyringFormatVersion)
            throw new TswapException(
                $"Unsupported keyring format version {file.KeyringFormatVersion} in approve file " +
                $"(this build supports {KeyringFormat.KeyringFormatVersion}).");

        return file;
    }

    /// <summary>
    /// Decodes a base64 field to exactly <paramref name="expectedLength"/> bytes. Throws
    /// <see cref="TswapException"/> — never a raw <see cref="FormatException"/> or silent
    /// truncation — for invalid base64 or a wrong-length result, naming
    /// <paramref name="what"/> in the error so a corrupted enrollment file points at the actual
    /// offending field rather than a generic decode failure.
    /// </summary>
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
