namespace TswapCore.Vault.Fido2.Libfido2;

/// <summary>
/// libfido2's calls tswap makes (brief T19, Appendix A), C#-shaped: <see cref="Libfido2Native"/> is the real one, a fake
/// drives the tests of the device layer built on it. Handles (<c>fido_dev_t *</c>, <c>fido_cred_t *</c>, ...) are
/// opaque <see cref="nint"/>s; a <c>*_free</c> takes the handle itself (the binding passes its address). Returned
/// byte arrays are fresh copies of libfido2's memory (empty when it holds none); strings are read as UTF-8. A PIN is
/// the address of a NUL-terminated buffer (<see cref="Libfido2Pin.Send{T}"/>), or 0 for none.
/// </summary>
public interface ILibfido2
{
    /// <summary><c>fido_strerr</c>: for <c>-v</c> only, never in a user text.</summary>
    string? StrErr(int error);

    nint DevInfoNew(nuint count);
    void DevInfoFree(nint list, nuint count);
    int DevInfoManifest(nint list, nuint capacity, out nuint found);
    nint DevInfoPtr(nint list, nuint index);
    string? DevInfoPath(nint info);
    short DevInfoVendor(nint info);
    short DevInfoProduct(nint info);
    string? DevInfoManufacturerString(nint info);
    string? DevInfoProductString(nint info);

    nint DevNew();
    void DevFree(nint dev);
    int DevOpen(nint dev, string path);
    int DevClose(nint dev);
    int DevGetCborInfo(nint dev, nint info);
    int DevGetRetryCount(nint dev, out int retries);

    /// <summary><c>fido_dev_set_pin(dev, pin, NULL)</c>: a first PIN only (no old PIN).</summary>
    int DevSetPin(nint dev, nint pin);

    int DevMakeCred(nint dev, nint cred, nint pin);
    int DevGetAssert(nint dev, nint assert, nint pin);

    nint CborInfoNew();
    void CborInfoFree(nint info);

    /// <summary><c>fido_cbor_info_aaguid_ptr</c>/<c>_len</c>.</summary>
    byte[] CborInfoAaguid(nint info);

    /// <summary><c>fido_cbor_info_extensions_ptr</c>/<c>_len</c>.</summary>
    IReadOnlyList<string> CborInfoExtensions(nint info);

    /// <summary><c>fido_cbor_info_options_name_ptr</c>/<c>_value_ptr</c>/<c>_len</c>.</summary>
    IReadOnlyList<(string Name, bool Value)> CborInfoOptions(nint info);

    nint CredNew();
    void CredFree(nint cred);
    int CredSetType(nint cred, int coseAlgorithm);
    int CredSetClientDataHash(nint cred, ReadOnlySpan<byte> hash);
    int CredSetRp(nint cred, string id, string? name);
    int CredSetUser(nint cred, ReadOnlySpan<byte> userId, string? name, string? displayName, string? icon);
    int CredSetExtensions(nint cred, int extensions);
    int CredSetRk(nint cred, FidoOpt rk);
    int CredExclude(nint cred, ReadOnlySpan<byte> credentialId);

    /// <summary><c>fido_cred_id_ptr</c>/<c>_len</c>.</summary>
    byte[] CredId(nint cred);

    byte CredFlags(nint cred);

    /// <summary><c>fido_cred_aaguid_ptr</c>/<c>_len</c>.</summary>
    byte[] CredAaguid(nint cred);

    nint AssertNew();
    void AssertFree(nint assert);
    int AssertSetRp(nint assert, string id);
    int AssertSetClientDataHash(nint assert, ReadOnlySpan<byte> hash);
    int AssertAllowCred(nint assert, ReadOnlySpan<byte> credentialId);
    int AssertSetExtensions(nint assert, int extensions);
    int AssertSetHmacSalt(nint assert, ReadOnlySpan<byte> salt);
    int AssertSetUp(nint assert, FidoOpt up);
    nuint AssertCount(nint assert);

    /// <summary><c>fido_assert_hmac_secret_ptr</c>/<c>_len</c> of statement <paramref name="index"/>; the caller zeroes it.</summary>
    byte[] AssertHmacSecret(nint assert, nuint index);

    byte AssertFlags(nint assert, nuint index);

    /// <summary><c>fido_assert_id_ptr</c>/<c>_len</c> of statement <paramref name="index"/> (empty when the key left it out).</summary>
    byte[] AssertId(nint assert, nuint index);
}
