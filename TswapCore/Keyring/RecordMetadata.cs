using TswapCore.Fingerprints;

namespace TswapCore.Keyring;

/// <summary>
/// Brief T16-S1: what a v3 record's metadata section holds, decrypted without any value section
/// (<see cref="SecretRecordCodec.DecodeMetadata"/>): everything about a secret except its value
/// bytes. Commands that only need names, burns or fingerprints (Stages 2 and 3) read this and never
/// decrypt a value.
/// </summary>
/// <param name="RecordId">Raw 32-byte <c>HMAC(K_names, name)</c>.</param>
/// <param name="Write">The write stamp (cleartext header, authenticated).</param>
/// <param name="Type">Value, tombstone or burned.</param>
/// <param name="Version">The stamp of the value or delete that decides existence.</param>
/// <param name="Name">The plaintext name.</param>
/// <param name="CreatedMs">Display only.</param>
/// <param name="Burns">Canonical burn list, as in <see cref="SecretRecord.Burns"/>.</param>
/// <param name="Fingerprints">The current value's fingerprints, or null (a tombstone, or none yet).</param>
/// <param name="PreviousVersion">The previous value's version stamp, or null when there is none.</param>
/// <param name="PreviousFingerprints">The previous value's fingerprints, or null.</param>
/// <param name="Extensions">Extension entries, kept byte for byte (ruling 6).</param>
public sealed record RecordMetadata(
    byte[] RecordId,
    Stamp Write,
    RecordType Type,
    Stamp Version,
    string Name,
    long CreatedMs,
    IReadOnlyList<BurnEntry> Burns,
    FingerprintSet? Fingerprints,
    Stamp? PreviousVersion,
    FingerprintSet? PreviousFingerprints,
    IReadOnlyList<RecordExtension> Extensions)
{
    /// <summary>The retained value versions (none for a tombstone; current, then previous).</summary>
    public IEnumerable<(Stamp Version, FingerprintSet? Fingerprints, bool IsPrevious)> RetainedVersions()
    {
        if (Type == RecordType.Tombstone)
            yield break;
        yield return (Version, Fingerprints, false);
        if (PreviousVersion is not null)
            yield return (PreviousVersion, PreviousFingerprints, true);
    }
}
