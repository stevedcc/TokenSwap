using System.Runtime.InteropServices;

namespace TswapCore.Vault.Fido2.Libfido2;

/// <summary>
/// The libfido2 binding (brief T19, item 1): <b>function pointers only</b>, every one of the 57 functions of Appendix A
/// (<see cref="Symbols"/>) resolved from the one handle <see cref="Libfido2Loader"/> loaded, before any is called. No
/// <c>[LibraryImport]</c>/<c>[DllImport]</c> (a static import would find the library by bare name, against decision 5,
/// and fail per call instead of at load) and no <c>DisableRuntimeMarshalling</c> (assembly-wide; the
/// <c>webauthn.dll</c> and Secure Enclave interop rely on runtime marshalling). Only blittable types cross: <see cref="nint"/>
/// for every pointer, <see cref="nuint"/> for <c>size_t</c>, <see cref="int"/>, <see cref="short"/> for <c>int16_t</c>,
/// <see cref="byte"/> for <c>uint8_t</c> and <c>bool</c>, <see cref="int"/> for <c>fido_opt_t</c> (<see cref="FidoOpt"/>).
/// </summary>
public sealed unsafe class Libfido2Native : ILibfido2
{
    /// <summary>Appendix A's functions, by their exported names.</summary>
    public static IReadOnlyList<string> Symbols { get; } =
    [
        "fido_init", "fido_strerr",
        "fido_dev_info_new", "fido_dev_info_free", "fido_dev_info_manifest", "fido_dev_info_ptr", "fido_dev_info_path",
        "fido_dev_info_vendor", "fido_dev_info_product", "fido_dev_info_manufacturer_string", "fido_dev_info_product_string",
        "fido_dev_new", "fido_dev_free", "fido_dev_open", "fido_dev_close", "fido_dev_get_cbor_info", "fido_dev_get_retry_count",
        "fido_dev_set_pin", "fido_dev_make_cred", "fido_dev_get_assert",
        "fido_cbor_info_new", "fido_cbor_info_free", "fido_cbor_info_aaguid_ptr", "fido_cbor_info_aaguid_len",
        "fido_cbor_info_extensions_ptr", "fido_cbor_info_extensions_len", "fido_cbor_info_options_name_ptr",
        "fido_cbor_info_options_value_ptr", "fido_cbor_info_options_len",
        "fido_cred_new", "fido_cred_free", "fido_cred_set_type", "fido_cred_set_clientdata_hash", "fido_cred_set_rp",
        "fido_cred_set_user", "fido_cred_set_extensions", "fido_cred_set_rk", "fido_cred_exclude", "fido_cred_id_ptr",
        "fido_cred_id_len", "fido_cred_flags", "fido_cred_aaguid_ptr", "fido_cred_aaguid_len",
        "fido_assert_new", "fido_assert_free", "fido_assert_set_rp", "fido_assert_set_clientdata_hash", "fido_assert_allow_cred",
        "fido_assert_set_extensions", "fido_assert_set_hmac_salt", "fido_assert_set_up", "fido_assert_count",
        "fido_assert_hmac_secret_ptr", "fido_assert_hmac_secret_len", "fido_assert_flags", "fido_assert_id_ptr", "fido_assert_id_len",
    ];

    private readonly delegate* unmanaged[Cdecl]<int, void> _init;
    private readonly delegate* unmanaged[Cdecl]<int, nint> _strerr;

    private readonly delegate* unmanaged[Cdecl]<nuint, nint> _devInfoNew;
    private readonly delegate* unmanaged[Cdecl]<nint*, nuint, void> _devInfoFree;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint, nuint*, int> _devInfoManifest;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint, nint> _devInfoPtr;
    private readonly delegate* unmanaged[Cdecl]<nint, nint> _devInfoPath;
    private readonly delegate* unmanaged[Cdecl]<nint, short> _devInfoVendor;
    private readonly delegate* unmanaged[Cdecl]<nint, short> _devInfoProduct;
    private readonly delegate* unmanaged[Cdecl]<nint, nint> _devInfoManufacturerString;
    private readonly delegate* unmanaged[Cdecl]<nint, nint> _devInfoProductString;

    private readonly delegate* unmanaged[Cdecl]<nint> _devNew;
    private readonly delegate* unmanaged[Cdecl]<nint*, void> _devFree;
    private readonly delegate* unmanaged[Cdecl]<nint, nint, int> _devOpen;
    private readonly delegate* unmanaged[Cdecl]<nint, int> _devClose;
    private readonly delegate* unmanaged[Cdecl]<nint, nint, int> _devGetCborInfo;
    private readonly delegate* unmanaged[Cdecl]<nint, int*, int> _devGetRetryCount;
    private readonly delegate* unmanaged[Cdecl]<nint, nint, nint, int> _devSetPin;
    private readonly delegate* unmanaged[Cdecl]<nint, nint, nint, int> _devMakeCred;
    private readonly delegate* unmanaged[Cdecl]<nint, nint, nint, int> _devGetAssert;

    private readonly delegate* unmanaged[Cdecl]<nint> _cborInfoNew;
    private readonly delegate* unmanaged[Cdecl]<nint*, void> _cborInfoFree;
    private readonly delegate* unmanaged[Cdecl]<nint, nint> _cborInfoAaguidPtr;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint> _cborInfoAaguidLen;
    private readonly delegate* unmanaged[Cdecl]<nint, nint> _cborInfoExtensionsPtr;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint> _cborInfoExtensionsLen;
    private readonly delegate* unmanaged[Cdecl]<nint, nint> _cborInfoOptionsNamePtr;
    private readonly delegate* unmanaged[Cdecl]<nint, nint> _cborInfoOptionsValuePtr;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint> _cborInfoOptionsLen;

    private readonly delegate* unmanaged[Cdecl]<nint> _credNew;
    private readonly delegate* unmanaged[Cdecl]<nint*, void> _credFree;
    private readonly delegate* unmanaged[Cdecl]<nint, int, int> _credSetType;
    private readonly delegate* unmanaged[Cdecl]<nint, byte*, nuint, int> _credSetClientDataHash;
    private readonly delegate* unmanaged[Cdecl]<nint, nint, nint, int> _credSetRp;
    private readonly delegate* unmanaged[Cdecl]<nint, byte*, nuint, nint, nint, nint, int> _credSetUser;
    private readonly delegate* unmanaged[Cdecl]<nint, int, int> _credSetExtensions;
    private readonly delegate* unmanaged[Cdecl]<nint, int, int> _credSetRk;
    private readonly delegate* unmanaged[Cdecl]<nint, byte*, nuint, int> _credExclude;
    private readonly delegate* unmanaged[Cdecl]<nint, nint> _credIdPtr;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint> _credIdLen;
    private readonly delegate* unmanaged[Cdecl]<nint, byte> _credFlags;
    private readonly delegate* unmanaged[Cdecl]<nint, nint> _credAaguidPtr;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint> _credAaguidLen;

    private readonly delegate* unmanaged[Cdecl]<nint> _assertNew;
    private readonly delegate* unmanaged[Cdecl]<nint*, void> _assertFree;
    private readonly delegate* unmanaged[Cdecl]<nint, nint, int> _assertSetRp;
    private readonly delegate* unmanaged[Cdecl]<nint, byte*, nuint, int> _assertSetClientDataHash;
    private readonly delegate* unmanaged[Cdecl]<nint, byte*, nuint, int> _assertAllowCred;
    private readonly delegate* unmanaged[Cdecl]<nint, int, int> _assertSetExtensions;
    private readonly delegate* unmanaged[Cdecl]<nint, byte*, nuint, int> _assertSetHmacSalt;
    private readonly delegate* unmanaged[Cdecl]<nint, int, int> _assertSetUp;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint> _assertCount;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint, nint> _assertHmacSecretPtr;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint, nuint> _assertHmacSecretLen;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint, byte> _assertFlags;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint, nint> _assertIdPtr;
    private readonly delegate* unmanaged[Cdecl]<nint, nuint, nuint> _assertIdLen;

    /// <summary>
    /// The binding over <paramref name="exports"/>, the address of every name in <see cref="Symbols"/> (the loader
    /// checked each is there). Resolving calls nothing; <see cref="Init"/> is the first call.
    /// </summary>
    internal Libfido2Native(Func<string, nint> exports)
    {
        _init = (delegate* unmanaged[Cdecl]<int, void>)exports("fido_init");
        _strerr = (delegate* unmanaged[Cdecl]<int, nint>)exports("fido_strerr");

        _devInfoNew = (delegate* unmanaged[Cdecl]<nuint, nint>)exports("fido_dev_info_new");
        _devInfoFree = (delegate* unmanaged[Cdecl]<nint*, nuint, void>)exports("fido_dev_info_free");
        _devInfoManifest = (delegate* unmanaged[Cdecl]<nint, nuint, nuint*, int>)exports("fido_dev_info_manifest");
        _devInfoPtr = (delegate* unmanaged[Cdecl]<nint, nuint, nint>)exports("fido_dev_info_ptr");
        _devInfoPath = (delegate* unmanaged[Cdecl]<nint, nint>)exports("fido_dev_info_path");
        _devInfoVendor = (delegate* unmanaged[Cdecl]<nint, short>)exports("fido_dev_info_vendor");
        _devInfoProduct = (delegate* unmanaged[Cdecl]<nint, short>)exports("fido_dev_info_product");
        _devInfoManufacturerString = (delegate* unmanaged[Cdecl]<nint, nint>)exports("fido_dev_info_manufacturer_string");
        _devInfoProductString = (delegate* unmanaged[Cdecl]<nint, nint>)exports("fido_dev_info_product_string");

        _devNew = (delegate* unmanaged[Cdecl]<nint>)exports("fido_dev_new");
        _devFree = (delegate* unmanaged[Cdecl]<nint*, void>)exports("fido_dev_free");
        _devOpen = (delegate* unmanaged[Cdecl]<nint, nint, int>)exports("fido_dev_open");
        _devClose = (delegate* unmanaged[Cdecl]<nint, int>)exports("fido_dev_close");
        _devGetCborInfo = (delegate* unmanaged[Cdecl]<nint, nint, int>)exports("fido_dev_get_cbor_info");
        _devGetRetryCount = (delegate* unmanaged[Cdecl]<nint, int*, int>)exports("fido_dev_get_retry_count");
        _devSetPin = (delegate* unmanaged[Cdecl]<nint, nint, nint, int>)exports("fido_dev_set_pin");
        _devMakeCred = (delegate* unmanaged[Cdecl]<nint, nint, nint, int>)exports("fido_dev_make_cred");
        _devGetAssert = (delegate* unmanaged[Cdecl]<nint, nint, nint, int>)exports("fido_dev_get_assert");

        _cborInfoNew = (delegate* unmanaged[Cdecl]<nint>)exports("fido_cbor_info_new");
        _cborInfoFree = (delegate* unmanaged[Cdecl]<nint*, void>)exports("fido_cbor_info_free");
        _cborInfoAaguidPtr = (delegate* unmanaged[Cdecl]<nint, nint>)exports("fido_cbor_info_aaguid_ptr");
        _cborInfoAaguidLen = (delegate* unmanaged[Cdecl]<nint, nuint>)exports("fido_cbor_info_aaguid_len");
        _cborInfoExtensionsPtr = (delegate* unmanaged[Cdecl]<nint, nint>)exports("fido_cbor_info_extensions_ptr");
        _cborInfoExtensionsLen = (delegate* unmanaged[Cdecl]<nint, nuint>)exports("fido_cbor_info_extensions_len");
        _cborInfoOptionsNamePtr = (delegate* unmanaged[Cdecl]<nint, nint>)exports("fido_cbor_info_options_name_ptr");
        _cborInfoOptionsValuePtr = (delegate* unmanaged[Cdecl]<nint, nint>)exports("fido_cbor_info_options_value_ptr");
        _cborInfoOptionsLen = (delegate* unmanaged[Cdecl]<nint, nuint>)exports("fido_cbor_info_options_len");

        _credNew = (delegate* unmanaged[Cdecl]<nint>)exports("fido_cred_new");
        _credFree = (delegate* unmanaged[Cdecl]<nint*, void>)exports("fido_cred_free");
        _credSetType = (delegate* unmanaged[Cdecl]<nint, int, int>)exports("fido_cred_set_type");
        _credSetClientDataHash = (delegate* unmanaged[Cdecl]<nint, byte*, nuint, int>)exports("fido_cred_set_clientdata_hash");
        _credSetRp = (delegate* unmanaged[Cdecl]<nint, nint, nint, int>)exports("fido_cred_set_rp");
        _credSetUser = (delegate* unmanaged[Cdecl]<nint, byte*, nuint, nint, nint, nint, int>)exports("fido_cred_set_user");
        _credSetExtensions = (delegate* unmanaged[Cdecl]<nint, int, int>)exports("fido_cred_set_extensions");
        _credSetRk = (delegate* unmanaged[Cdecl]<nint, int, int>)exports("fido_cred_set_rk");
        _credExclude = (delegate* unmanaged[Cdecl]<nint, byte*, nuint, int>)exports("fido_cred_exclude");
        _credIdPtr = (delegate* unmanaged[Cdecl]<nint, nint>)exports("fido_cred_id_ptr");
        _credIdLen = (delegate* unmanaged[Cdecl]<nint, nuint>)exports("fido_cred_id_len");
        _credFlags = (delegate* unmanaged[Cdecl]<nint, byte>)exports("fido_cred_flags");
        _credAaguidPtr = (delegate* unmanaged[Cdecl]<nint, nint>)exports("fido_cred_aaguid_ptr");
        _credAaguidLen = (delegate* unmanaged[Cdecl]<nint, nuint>)exports("fido_cred_aaguid_len");

        _assertNew = (delegate* unmanaged[Cdecl]<nint>)exports("fido_assert_new");
        _assertFree = (delegate* unmanaged[Cdecl]<nint*, void>)exports("fido_assert_free");
        _assertSetRp = (delegate* unmanaged[Cdecl]<nint, nint, int>)exports("fido_assert_set_rp");
        _assertSetClientDataHash = (delegate* unmanaged[Cdecl]<nint, byte*, nuint, int>)exports("fido_assert_set_clientdata_hash");
        _assertAllowCred = (delegate* unmanaged[Cdecl]<nint, byte*, nuint, int>)exports("fido_assert_allow_cred");
        _assertSetExtensions = (delegate* unmanaged[Cdecl]<nint, int, int>)exports("fido_assert_set_extensions");
        _assertSetHmacSalt = (delegate* unmanaged[Cdecl]<nint, byte*, nuint, int>)exports("fido_assert_set_hmac_salt");
        _assertSetUp = (delegate* unmanaged[Cdecl]<nint, int, int>)exports("fido_assert_set_up");
        _assertCount = (delegate* unmanaged[Cdecl]<nint, nuint>)exports("fido_assert_count");
        _assertHmacSecretPtr = (delegate* unmanaged[Cdecl]<nint, nuint, nint>)exports("fido_assert_hmac_secret_ptr");
        _assertHmacSecretLen = (delegate* unmanaged[Cdecl]<nint, nuint, nuint>)exports("fido_assert_hmac_secret_len");
        _assertFlags = (delegate* unmanaged[Cdecl]<nint, nuint, byte>)exports("fido_assert_flags");
        _assertIdPtr = (delegate* unmanaged[Cdecl]<nint, nuint, nint>)exports("fido_assert_id_ptr");
        _assertIdLen = (delegate* unmanaged[Cdecl]<nint, nuint, nuint>)exports("fido_assert_id_len");
    }

    /// <summary><c>fido_init(0)</c>: once, right after loading (<see cref="Libfido2Loader"/>).</summary>
    internal void Init() => _init(0);

    public string? StrErr(int error) => Marshal.PtrToStringUTF8(_strerr(error));

    public nint DevInfoNew(nuint count) => _devInfoNew(count);

    public void DevInfoFree(nint list, nuint count)
    {
        var handle = list;
        _devInfoFree(&handle, count);
    }

    public int DevInfoManifest(nint list, nuint capacity, out nuint found)
    {
        nuint olen = 0;
        var result = _devInfoManifest(list, capacity, &olen);
        found = olen;
        return result;
    }

    public nint DevInfoPtr(nint list, nuint index) => _devInfoPtr(list, index);
    public string? DevInfoPath(nint info) => Marshal.PtrToStringUTF8(_devInfoPath(info));
    public short DevInfoVendor(nint info) => _devInfoVendor(info);
    public short DevInfoProduct(nint info) => _devInfoProduct(info);
    public string? DevInfoManufacturerString(nint info) => Marshal.PtrToStringUTF8(_devInfoManufacturerString(info));
    public string? DevInfoProductString(nint info) => Marshal.PtrToStringUTF8(_devInfoProductString(info));

    public nint DevNew() => _devNew();

    public void DevFree(nint dev)
    {
        var handle = dev;
        _devFree(&handle);
    }

    public int DevOpen(nint dev, string path) => WithUtf8(path, p => _devOpen(dev, p));
    public int DevClose(nint dev) => _devClose(dev);
    public int DevGetCborInfo(nint dev, nint info) => _devGetCborInfo(dev, info);

    public int DevGetRetryCount(nint dev, out int retries)
    {
        var count = 0;
        var result = _devGetRetryCount(dev, &count);
        retries = count;
        return result;
    }

    public int DevSetPin(nint dev, nint pin) => _devSetPin(dev, pin, 0);
    public int DevMakeCred(nint dev, nint cred, nint pin) => _devMakeCred(dev, cred, pin);
    public int DevGetAssert(nint dev, nint assert, nint pin) => _devGetAssert(dev, assert, pin);

    public nint CborInfoNew() => _cborInfoNew();

    public void CborInfoFree(nint info)
    {
        var handle = info;
        _cborInfoFree(&handle);
    }

    public byte[] CborInfoAaguid(nint info) => Copy(_cborInfoAaguidPtr(info), _cborInfoAaguidLen(info));

    public IReadOnlyList<string> CborInfoExtensions(nint info)
    {
        var names = (nint*)_cborInfoExtensionsPtr(info);
        var count = _cborInfoExtensionsLen(info);
        List<string> result = [];
        for (nuint i = 0; names is not null && i < count; i++)
            if (Marshal.PtrToStringUTF8(names[i]) is { } name)
                result.Add(name);
        return result;
    }

    public IReadOnlyList<(string Name, bool Value)> CborInfoOptions(nint info)
    {
        var names = (nint*)_cborInfoOptionsNamePtr(info);
        var values = (byte*)_cborInfoOptionsValuePtr(info);
        var count = _cborInfoOptionsLen(info);
        List<(string, bool)> result = [];
        for (nuint i = 0; names is not null && values is not null && i < count; i++)
            if (Marshal.PtrToStringUTF8(names[i]) is { } name)
                result.Add((name, values[i] != 0));
        return result;
    }

    public nint CredNew() => _credNew();

    public void CredFree(nint cred)
    {
        var handle = cred;
        _credFree(&handle);
    }

    public int CredSetType(nint cred, int coseAlgorithm) => _credSetType(cred, coseAlgorithm);

    public int CredSetClientDataHash(nint cred, ReadOnlySpan<byte> hash)
    {
        fixed (byte* p = hash)
            return _credSetClientDataHash(cred, p, (nuint)hash.Length);
    }

    public int CredSetRp(nint cred, string id, string? name) =>
        WithUtf8(id, i => WithUtf8(name, n => _credSetRp(cred, i, n)));

    public int CredSetUser(nint cred, ReadOnlySpan<byte> userId, string? name, string? displayName, string? icon)
    {
        var n = Utf8(name);
        var d = Utf8(displayName);
        var c = Utf8(icon);
        try
        {
            fixed (byte* p = userId)
                return _credSetUser(cred, p, (nuint)userId.Length, n, d, c);
        }
        finally
        {
            Marshal.FreeCoTaskMem(n);
            Marshal.FreeCoTaskMem(d);
            Marshal.FreeCoTaskMem(c);
        }
    }

    public int CredSetExtensions(nint cred, int extensions) => _credSetExtensions(cred, extensions);
    public int CredSetRk(nint cred, FidoOpt rk) => _credSetRk(cred, (int)rk);

    public int CredExclude(nint cred, ReadOnlySpan<byte> credentialId)
    {
        fixed (byte* p = credentialId)
            return _credExclude(cred, p, (nuint)credentialId.Length);
    }

    public byte[] CredId(nint cred) => Copy(_credIdPtr(cred), _credIdLen(cred));
    public byte CredFlags(nint cred) => _credFlags(cred);
    public byte[] CredAaguid(nint cred) => Copy(_credAaguidPtr(cred), _credAaguidLen(cred));

    public nint AssertNew() => _assertNew();

    public void AssertFree(nint assert)
    {
        var handle = assert;
        _assertFree(&handle);
    }

    public int AssertSetRp(nint assert, string id) => WithUtf8(id, i => _assertSetRp(assert, i));

    public int AssertSetClientDataHash(nint assert, ReadOnlySpan<byte> hash)
    {
        fixed (byte* p = hash)
            return _assertSetClientDataHash(assert, p, (nuint)hash.Length);
    }

    public int AssertAllowCred(nint assert, ReadOnlySpan<byte> credentialId)
    {
        fixed (byte* p = credentialId)
            return _assertAllowCred(assert, p, (nuint)credentialId.Length);
    }

    public int AssertSetExtensions(nint assert, int extensions) => _assertSetExtensions(assert, extensions);

    public int AssertSetHmacSalt(nint assert, ReadOnlySpan<byte> salt)
    {
        fixed (byte* p = salt)
            return _assertSetHmacSalt(assert, p, (nuint)salt.Length);
    }

    public int AssertSetUp(nint assert, FidoOpt up) => _assertSetUp(assert, (int)up);
    public nuint AssertCount(nint assert) => _assertCount(assert);
    public byte[] AssertHmacSecret(nint assert, nuint index) => Copy(_assertHmacSecretPtr(assert, index), _assertHmacSecretLen(assert, index));
    public byte AssertFlags(nint assert, nuint index) => _assertFlags(assert, index);
    public byte[] AssertId(nint assert, nuint index) => Copy(_assertIdPtr(assert, index), _assertIdLen(assert, index));

    /// <summary>libfido2's buffer copied straight into the returned array (no intermediate copy); empty for none.</summary>
    private static byte[] Copy(nint pointer, nuint length) =>
        pointer == 0 || length == 0 ? [] : new ReadOnlySpan<byte>((void*)pointer, checked((int)length)).ToArray();

    private static nint Utf8(string? value) => value is null ? 0 : Marshal.StringToCoTaskMemUTF8(value);

    private static int WithUtf8(string? value, Func<nint, int> call)
    {
        var p = Utf8(value);
        try
        {
            return call(p);
        }
        finally
        {
            Marshal.FreeCoTaskMem(p);
        }
    }
}
