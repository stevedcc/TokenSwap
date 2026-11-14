namespace TswapCore.Vault.Fido2;

/// <summary>An AAGUID as a key sends it, shared by the SDK and libfido2 backends (brief T19, item 2).</summary>
public static class Fido2Aaguid
{
    /// <summary>The size of an AAGUID on the wire.</summary>
    public const int Size = 16;

    /// <summary>16 bytes as the key sends them, read <b>big-endian</b>, as tswap stores them; anything else is empty.</summary>
    public static Guid ToGuid(ReadOnlySpan<byte> aaguid) => aaguid.Length == Size ? new Guid(aaguid, bigEndian: true) : Guid.Empty;
}
