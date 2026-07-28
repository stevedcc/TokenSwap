using System.Security.Cryptography;

namespace TswapCore.Keyring;

/// <summary>
/// A short, human-comparable fingerprint of an X25519 public key (issue #122), displayed on both
/// machines during hand-carried enrollment: <c>slot request</c> shows a fingerprint of its own
/// freshly-generated public key, <c>slot approve</c> shows one of the public key it just read
/// from the request file. A user who wants extra assurance can read both aloud and compare.
///
/// <para><b>Not load-bearing in v0.</b> The hand-carried file exchange itself is the trust
/// boundary (see <c>MULTI_MACHINE_KEYING.md</c> §Hand-carried enrollment) — there is no network
/// path for a MITM to substitute a different public key on, so this fingerprint is defense in
/// depth, not a required verification step. It is, however, the seam v1's transport-borne
/// enrollment builds on, where substitution again becomes possible and this fingerprint becomes
/// the *primary* defense — hence adding it now, cheaply, while this file format is being
/// designed, rather than retrofitting it later (see <c>MULTI_MACHINE_KEYING.md</c> §Deferred to
/// v1).</para>
///
/// <para><b>Construction:</b> SHA-256 the public key, keep the first <see cref="DisplayBytes"/>
/// bytes (64 bits — small enough to read aloud, large enough that an accidental or malicious
/// substitution is essentially certain to change it), render as hyphen-separated 4-hex-digit
/// groups — the same spirit as an SSH host key fingerprint, just shorter since this isn't (yet)
/// a security boundary.</para>
/// </summary>
public static class SlotFingerprint
{
    private const int DisplayBytes = 8;

    /// <summary>Computes the fingerprint, e.g. <c>"A1B2-C3D4-E5F6-0718"</c>.</summary>
    public static string Compute(byte[] publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        var hex = Convert.ToHexString(hash, 0, DisplayBytes);
        return string.Join('-', Enumerable.Range(0, hex.Length / 4).Select(i => hex.Substring(i * 4, 4)));
    }
}
