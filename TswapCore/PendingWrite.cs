namespace TswapCore;

/// <summary>
/// Brief T16-S2b: one write a command asks of <see cref="RecordVaultStore.CommitWrites"/>, on the
/// entry <see cref="RecordVaultStore.OpenForWrite"/> gave for <see cref="Name"/> (null: no record).
/// The store applies <see cref="RecordVaultStore.SaveSecrets"/>' rules to it: on the entry's
/// metadata and held sections when it is format 3, on its plaintext when it was decoded whole.
/// </summary>
internal abstract record PendingWrite(string Name, SecretEntry? Entry);

/// <summary>
/// A value: a new version when there is no live record, when <paramref name="Always"/> (rotate,
/// restore), or when <paramref name="Value"/> differs from the current one (add). The caller owns
/// <paramref name="Value"/> and zeroes it after the commit.
/// </summary>
/// <param name="Restored"><c>restore</c>: the previous value's burns become outstanding again.</param>
/// <param name="Created">The creation time of a secret that has no live record.</param>
/// <param name="ImportedBurnAt">An imported burn, kept on the new version with its own time.</param>
internal sealed record ValueWrite(string Name, SecretEntry? Entry, byte[] Value, bool Always, bool Restored, DateTime Created,
    DateTime? ImportedBurnAt = null, string? ImportedBurnReason = null) : PendingWrite(Name, Entry);

/// <summary>A burn of the current version (nothing is written when it is burned already).</summary>
internal sealed record BurnWrite(string Name, SecretEntry Entry, string? Reason) : PendingWrite(Name, Entry);

/// <summary>A delete: a tombstone over the live record.</summary>
internal sealed record DeleteWrite(string Name, SecretEntry Entry) : PendingWrite(Name, Entry);
