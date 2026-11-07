namespace TswapCore;

/// <summary>
/// Brief T16-S2: what <c>apply</c>, <c>check</c> and <c>run</c> ask of the vault about the secrets a
/// file or a command names. <see cref="SecretsDb"/> answers it from a full load; <see cref="VaultView"/>
/// from metadata, decrypting only the value versions <see cref="ResolveToken"/> returns. Both give
/// the same answers and the same exception texts.
/// </summary>
public interface ISecretLookup
{
    /// <summary>True when <paramref name="name"/> is a secret (not deleted, not unreadable).</summary>
    bool Contains(string name);

    /// <summary>True when <paramref name="name"/> keeps the value its last rotation replaced.</summary>
    bool HasPreviousValue(string name);

    /// <summary>True when <paramref name="token"/> (<c>name</c> or <c>name:previous</c>) refers to a burned value version.</summary>
    bool IsBurnedToken(string token);

    /// <summary>
    /// The value <paramref name="token"/> names (<c>name</c>, or <c>name:previous</c>); throws for a
    /// missing or unreadable secret and for <c>:previous</c> without a previous value.
    /// <paramref name="where"/> is appended to the "not found" text (e.g. <c>" (line 3)"</c>).
    /// </summary>
    string ResolveToken(string token, string? where = null);

    /// <summary>Throws, naming the hashed file, when <paramref name="name"/>'s record can't be read.</summary>
    void ThrowIfUnreadable(string name);
}
