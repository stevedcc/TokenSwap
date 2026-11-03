namespace TswapCore.Keyring;

/// <summary>
/// The hardware blob of a password Secure Enclave slot (brief T17 ruling 3): <c>"TSSE" | version 1 |
/// flags 1 (bit 0 = password)</c>, followed by the Secure Enclave package exactly as a password-free slot
/// stores it, whose key was created with <c>.applicationPassword</c> (ruling 19). Mirrors
/// <see cref="TpmSlotBlob"/>: a legacy package (4-byte little-endian length first) never starts with the
/// magic, and stripping the header doesn't remove the password the Enclave enforces.
/// </summary>
public static class SecureEnclaveSlotBlob
{
    /// <summary>"TSSE": TokenSwap Secure Enclave password slot.</summary>
    public static ReadOnlySpan<byte> Magic => "TSSE"u8;

    /// <summary>True when <paramref name="hwBlob"/> starts with the <c>TSSE</c> magic.</summary>
    public static bool HasHeader(byte[]? hwBlob) => PasswordBlobHeader.HasMagic(hwBlob, Magic);

    /// <summary>A password slot's blob around <paramref name="package"/>; the password bit is always set.</summary>
    public static byte[] Wrap(byte[] package) => PasswordBlobHeader.Wrap(Magic, package);

    /// <inheritdoc cref="TpmSlotBlob.Split"/>
    public static (bool Password, byte[] Package) Split(byte[] hwBlob) =>
        PasswordBlobHeader.Split(hwBlob, Magic, "Secure Enclave");
}
