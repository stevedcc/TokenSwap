namespace TswapCore.Keyring;

/// <summary>
/// The three per-secret record kinds (issue #112). A delete or burn is a <b>record</b>, not an
/// absent file: without an explicit tombstone, machine A deletes a secret, machine B still has
/// the old file, and a sync merge silently resurrects it — worse for <see cref="Burned"/>,
/// where resurrection destroys the incident record the burn exists to create.
///
/// Encoded as a single byte inside the encrypted payload (see <see cref="SecretRecordCodec"/>)
/// — deliberately <b>not</b> a cleartext envelope field, so a transport observer cannot tell a
/// tombstone/burn from an ordinary edit without the vault key. That, combined with size-bucket
/// padding (issue #113a), is what makes tombstones indistinguishable from live records by
/// looking at the file alone.
/// </summary>
public enum RecordType : byte
{
    /// <summary>A live secret value.</summary>
    Value = 0,

    /// <summary>
    /// The secret was deleted. Retained (not an absent file) so sync can't resurrect it.
    /// </summary>
    Tombstone = 1,

    /// <summary>
    /// The secret was burned (marked compromised/seen). Carries the burn reason as its value.
    /// </summary>
    Burned = 2,
}
