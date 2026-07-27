using System.Security.Cryptography;
using System.Text;

namespace TswapCore.Keyring;

/// <summary>
/// Deterministic per-secret filenames (issue #114): <c>HMAC(K_names, secretName)</c>, hex
/// encoded. This is what lets two synced copies of the same secret recognise each other as the
/// same record without either side ever writing the plaintext name to disk — the property the
/// per-secret record split (issue #112) depends on for mergeability.
///
/// <para><b>Settled, not open</b> (see <c>REFACTORING_PLAN.md</c> §Phase 6, "per-file security
/// considerations", item 2, and <c>MULTI_MACHINE_KEYING.md</c>): deterministic filenames were
/// chosen over randomizing the filename per write plus an internal record-id and a periodic
/// compaction pass. Randomizing defeats which-secret correlation but not "an edit of about this
/// size happened around now", and the compaction machinery needed to keep it bounded is real,
/// ongoing complexity for a marginal privacy gain against tswap's actual threat model — a
/// personal fleet syncing over a semi-trusted transport (git/Syncthing/Dropbox), not a hostile
/// transport operator. Do not re-litigate this.</para>
///
/// <para><b>Accepted tradeoff — document this wherever the format is described to users:</b>
/// because the filename is stable, a transport observer who cannot read any content can still
/// see "the file with hash <c>abc123…</c> changed again at 14:03" — i.e. per-secret edit-timing
/// patterns leak, even though the name and value do not. The old single-blob format only leaked
/// "something changed" with no per-secret resolution. This is the price of mergeability.</para>
///
/// <para><b>Open, not gating v0:</b> where <c>K_names</c> itself comes from — derived from
/// <c>K_v</c> (so a v1 rotation renames every record) versus a separate, non-rotated fleet
/// constant (avoids mass renames, but must never be reconstructible without fleet membership) —
/// is intentionally left to the caller. This type takes <c>K_names</c> as a plain
/// <c>byte[]</c> and has no opinion on its provenance; see <c>MULTI_MACHINE_KEYING.md</c>
/// §Open questions.</para>
/// </summary>
public static class FilenameHasher
{
    /// <summary>Byte length of <c>K_names</c> (HMAC-SHA256 key).</summary>
    public const int KeyLength = 32;

    /// <summary>
    /// Computes the raw (non-hex) 32-byte record id for <paramref name="secretName"/> — the
    /// same value <see cref="SecretRecord.RecordId"/> carries and <see cref="RecordKeyDerivation"/>
    /// uses as its HKDF salt input, so the filename and the per-record key derivation are tied
    /// to one shared identifier rather than two independently-computed ones.
    /// </summary>
    public static byte[] ComputeRecordId(byte[] kNames, string secretName)
    {
        if (kNames.Length != KeyLength)
            throw new ArgumentException($"kNames must be {KeyLength} bytes", nameof(kNames));

        return HMACSHA256.HashData(kNames, Encoding.UTF8.GetBytes(secretName));
    }

    /// <summary>Lowercase hex encoding of a record id, for use as an on-disk filename.</summary>
    public static string ToFilename(byte[] recordId) => Convert.ToHexStringLower(recordId);

    /// <summary>Convenience: <c>ToFilename(ComputeRecordId(kNames, secretName))</c>.</summary>
    public static string ComputeFilename(byte[] kNames, string secretName)
        => ToFilename(ComputeRecordId(kNames, secretName));
}
