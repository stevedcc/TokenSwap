using System.Runtime.InteropServices;
using System.Security.Cryptography;
using TswapCore.Vault.Fido2.Libfido2;

namespace TswapTests;

/// <summary>
/// Brief T19, item 2: <see cref="ILibfido2"/> without a library. Devices with a path, USB ids, strings, CBOR info and
/// the answers each call gives; every <c>fido_cred_t</c> and <c>fido_assert_t</c> sent is recorded as it was set
/// (<see cref="Creds"/>, <see cref="Asserts"/>), the PIN as the C string the call saw, and every object allocated is
/// counted until freed (<see cref="Live"/>). The hmac-secret output is <c>HMAC-SHA256(device secret, salt)</c>, so the
/// salt sent decides the output, as on a real key.
/// </summary>
internal sealed class FakeLibfido2 : ILibfido2
{
    public sealed class Device
    {
        public required string Path { get; init; }
        public short Vendor { get; init; } = 0x349e; // not Yubico's 0x1050
        public short Product { get; init; } = 0x0022;
        public string? Manufacturer { get; init; } = "Token2";
        public string? ProductString { get; init; } = "Token2 PIN+ Dual";
        public byte[] Aaguid { get; init; } = Convert.FromHexString("eabb46cce24180bfae9e96fa6d2975cf");
        public List<string> Extensions { get; init; } = ["credProtect", "hmac-secret"];
        public bool? ClientPin { get; set; } = true;

        public int OpenResult { get; set; } = Libfido2Errors.Ok;
        public int CborInfoResult { get; set; } = Libfido2Errors.Ok;
        public int RetryCountResult { get; set; } = Libfido2Errors.Ok;
        public int Retries { get; set; } = 8;

        /// <summary>What make-credential answers; on <c>FIDO_OK</c> the cred gets <see cref="MadeId"/>, <see cref="Aaguid"/>, <see cref="MadeFlags"/>.</summary>
        public int MakeCredResult { get; set; } = Libfido2Errors.Ok;
        public byte[] MadeId { get; set; } = RandomNumberGenerator.GetBytes(48);
        public byte MadeFlags { get; set; } = Libfido2Params.FlagUserPresent | Libfido2Params.FlagUserVerified;

        /// <summary>What the user-verified assertion answers.</summary>
        public int AssertResult { get; set; } = Libfido2Errors.Ok;
        public byte AssertFlags { get; set; } = Libfido2Params.FlagUserPresent | Libfido2Params.FlagUserVerified;

        /// <summary>The key leaves the credential id out of its answer (CTAP allows it with one allowed credential).</summary>
        public bool OmitsAssertId { get; set; }

        public byte[] Secret { get; } = RandomNumberGenerator.GetBytes(32);

        /// <summary>The hmac-secret output's length the key gives (32 for a key that follows the spec).</summary>
        public int HmacSecretLength { get; set; } = 32;

        /// <summary>The probe's answer: <c>FIDO_OK</c> for these credentials (hex), else <see cref="ProbeMissResult"/>.</summary>
        public HashSet<string> Holds { get; } = [];
        public int ProbeMissResult { get; set; } = Libfido2Errors.NoCredentials;

        /// <summary>Overrides the probe's answer for every credential (a failing device).</summary>
        public int? ProbeResult { get; set; }

        public int SetPinResult { get; set; } = Libfido2Errors.Ok;

        /// <summary>Unplugged after listing: no longer in the manifest, and opening it fails.</summary>
        public bool Gone { get; set; }
    }

    /// <summary>A <c>fido_cred_t</c> as tswap set it, and the PIN its make-credential got.</summary>
    public sealed class Cred
    {
        public int? Type;
        public byte[]? ClientDataHash;
        public string? RpId, RpName, UserName, UserDisplayName, UserIcon;
        public byte[]? UserId;
        public int? Extensions;
        public int? Rk;
        public List<byte[]> Excluded = [];
        public string? Pin;
        public string? DevicePath;
        public bool Sent;
        public byte[] Id = [];
        public byte[] Aaguid = [];
        public byte Flags;
    }

    /// <summary>A <c>fido_assert_t</c> as tswap set it, and the PIN its get-assertion got (null: none).</summary>
    public sealed class Assert
    {
        public string? RpId;
        public byte[]? ClientDataHash;
        public List<byte[]> Allowed = [];
        public int? Extensions;
        public byte[]? Salt;
        public int? Up;
        public string? Pin;
        public bool PinPointerNull;
        public string? DevicePath;
        public bool Sent;
        public int Count;
        public byte[] HmacSecret = [];
        public byte Flags;
        public byte[] Id = [];
    }

    private sealed class Dev
    {
        public Device? Opened;
    }

    private sealed class CborInfo
    {
        public Device? Of;
    }

    private sealed class InfoList
    {
        public List<Device> Listed = [];
    }

    private readonly Dictionary<nint, object> _objects = [];
    private nint _next = 0x1000;

    public List<Device> Devices { get; } = [];
    public int ManifestResult { get; set; } = Libfido2Errors.Ok;

    /// <summary>Review N5: the setter that fails (its exported name, e.g. <c>fido_cred_set_rp</c>) and what it returns.</summary>
    public (string Setter, int Result)? FailingSetter { get; set; }

    /// <summary>Review S1: how many times <c>fido_dev_get_retry_count</c> was called.</summary>
    public int RetryCountCalls { get; private set; }
    public List<Cred> Creds { get; } = [];
    public List<Assert> Asserts { get; } = [];

    /// <summary>Every <c>fido_dev_set_pin</c>: the device and the new PIN as sent.</summary>
    public List<(string Path, string? Pin)> PinsSet { get; } = [];

    /// <summary>Every <c>fido_dev_open</c> path, in order.</summary>
    public List<string> Opened { get; } = [];

    /// <summary>Objects allocated and not yet freed (0 after every operation).</summary>
    public int Live => _objects.Count;

    public Device AddDevice(string path, short vendor = 0x349e)
    {
        var device = new Device { Path = path, Vendor = vendor };
        Devices.Add(device);
        return device;
    }

    private nint Add(object o)
    {
        var handle = _next++;
        _objects[handle] = o;
        return handle;
    }

    private T Get<T>(nint handle) => (T)_objects[handle];

    private void Free(nint handle)
    {
        if (!_objects.Remove(handle))
            throw new InvalidOperationException($"freed twice or never allocated: {handle}");
    }

    public string? StrErr(int error) => $"prose for {error}";

    public nint DevInfoNew(nuint count) => Add(new InfoList());
    public void DevInfoFree(nint list, nuint count) => Free(list);

    public int DevInfoManifest(nint list, nuint capacity, out nuint found)
    {
        found = 0;
        if (ManifestResult != Libfido2Errors.Ok)
            return ManifestResult;
        var listed = Get<InfoList>(list).Listed;
        listed.Clear();
        listed.AddRange(Devices.Where(d => !d.Gone).Take((int)capacity));
        found = (nuint)listed.Count;
        return Libfido2Errors.Ok;
    }

    // An info entry is (list handle, index); encoded as the list handle * 256 + index + 1 (never freed on its own).
    public nint DevInfoPtr(nint list, nuint index) => list * 256 + (nint)index + 1;

    private Device InfoDevice(nint info)
    {
        var list = (info - 1) / 256;
        var index = (int)((info - 1) % 256);
        return Get<InfoList>(list).Listed[index];
    }

    public string? DevInfoPath(nint info) => InfoDevice(info).Path;
    public short DevInfoVendor(nint info) => InfoDevice(info).Vendor;
    public short DevInfoProduct(nint info) => InfoDevice(info).Product;
    public string? DevInfoManufacturerString(nint info) => InfoDevice(info).Manufacturer;
    public string? DevInfoProductString(nint info) => InfoDevice(info).ProductString;

    public nint DevNew() => Add(new Dev());
    public void DevFree(nint dev) => Free(dev);

    public int DevOpen(nint dev, string path)
    {
        Opened.Add(path);
        var device = Devices.FirstOrDefault(d => d.Path == path && !d.Gone);
        if (device is null)
            return Libfido2Errors.Rx;
        if (device.OpenResult != Libfido2Errors.Ok)
            return device.OpenResult;
        Get<Dev>(dev).Opened = device;
        return Libfido2Errors.Ok;
    }

    public int DevClose(nint dev)
    {
        Get<Dev>(dev).Opened = null;
        return Libfido2Errors.Ok;
    }

    private Device OpenDevice(nint dev) => Get<Dev>(dev).Opened ?? throw new InvalidOperationException("device not open");

    public int DevGetCborInfo(nint dev, nint info)
    {
        var device = OpenDevice(dev);
        if (device.CborInfoResult != Libfido2Errors.Ok)
            return device.CborInfoResult;
        Get<CborInfo>(info).Of = device;
        return Libfido2Errors.Ok;
    }

    public int DevGetRetryCount(nint dev, out int retries)
    {
        RetryCountCalls++;
        var device = OpenDevice(dev);
        retries = device.RetryCountResult == Libfido2Errors.Ok ? device.Retries : 0;
        return device.RetryCountResult;
    }

    public int DevSetPin(nint dev, nint pin)
    {
        var device = OpenDevice(dev);
        PinsSet.Add((device.Path, pin == 0 ? null : Marshal.PtrToStringUTF8(pin)));
        return device.SetPinResult;
    }

    public int DevMakeCred(nint dev, nint cred, nint pin)
    {
        var device = OpenDevice(dev);
        var c = Get<Cred>(cred);
        c.Sent = true;
        c.DevicePath = device.Path;
        c.Pin = pin == 0 ? null : Marshal.PtrToStringUTF8(pin);
        if (device.MakeCredResult != Libfido2Errors.Ok)
            return device.MakeCredResult;
        c.Id = device.MadeId;
        c.Aaguid = device.Aaguid;
        c.Flags = device.MadeFlags;
        return Libfido2Errors.Ok;
    }

    public int DevGetAssert(nint dev, nint assert, nint pin)
    {
        var device = OpenDevice(dev);
        var a = Get<Assert>(assert);
        a.Sent = true;
        a.DevicePath = device.Path;
        a.PinPointerNull = pin == 0;
        a.Pin = pin == 0 ? null : Marshal.PtrToStringUTF8(pin);
        if (a.Up == (int)FidoOpt.False)
        {
            if (device.ProbeResult is { } forced)
                return forced;
            return a.Allowed.Any(id => device.Holds.Contains(Convert.ToHexString(id))) ? Libfido2Errors.Ok : device.ProbeMissResult;
        }
        if (device.AssertResult != Libfido2Errors.Ok)
            return device.AssertResult;
        a.Count = 1;
        var full = a.Salt is null ? [] : HMACSHA256.HashData(device.Secret, a.Salt);
        a.HmacSecret = device.HmacSecretLength <= full.Length ? full[..device.HmacSecretLength] : [.. full, .. new byte[device.HmacSecretLength - full.Length]];
        a.Flags = device.AssertFlags;
        a.Id = device.OmitsAssertId ? [] : a.Allowed[0].ToArray();
        return Libfido2Errors.Ok;
    }

    public nint CborInfoNew() => Add(new CborInfo());
    public void CborInfoFree(nint info) => Free(info);
    public byte[] CborInfoAaguid(nint info) => [.. Get<CborInfo>(info).Of!.Aaguid];
    public IReadOnlyList<string> CborInfoExtensions(nint info) => Get<CborInfo>(info).Of!.Extensions;

    public IReadOnlyList<(string Name, bool Value)> CborInfoOptions(nint info)
    {
        var device = Get<CborInfo>(info).Of!;
        List<(string, bool)> options = [("rk", true), ("up", true)];
        if (device.ClientPin is { } set)
            options.Add(("clientPin", set));
        return options;
    }

    public nint CredNew()
    {
        var cred = new Cred();
        Creds.Add(cred);
        return Add(cred);
    }

    public void CredFree(nint cred) => Free(cred);
    public int CredSetType(nint cred, int coseAlgorithm) => Failing("fido_cred_set_type") ?? Set(() => Get<Cred>(cred).Type = coseAlgorithm);
    public int CredSetClientDataHash(nint cred, ReadOnlySpan<byte> hash) =>
        Failing("fido_cred_set_clientdata_hash") ?? Set(Get<Cred>(cred), hash.ToArray(), (c, h) => c.ClientDataHash = h);

    public int CredSetRp(nint cred, string id, string? name) => Failing("fido_cred_set_rp") ?? Set(() =>
    {
        Get<Cred>(cred).RpId = id;
        Get<Cred>(cred).RpName = name;
    });

    public int CredSetUser(nint cred, ReadOnlySpan<byte> userId, string? name, string? displayName, string? icon)
    {
        var c = Get<Cred>(cred);
        c.UserId = userId.ToArray();
        c.UserName = name;
        c.UserDisplayName = displayName;
        c.UserIcon = icon;
        return Libfido2Errors.Ok;
    }

    public int CredSetExtensions(nint cred, int extensions) => Set(() => Get<Cred>(cred).Extensions = extensions);
    public int CredSetRk(nint cred, FidoOpt rk) => Set(() => Get<Cred>(cred).Rk = (int)rk);
    public int CredExclude(nint cred, ReadOnlySpan<byte> credentialId) => Set(Get<Cred>(cred), credentialId.ToArray(), (c, id) => c.Excluded.Add(id));
    public byte[] CredId(nint cred) => [.. Get<Cred>(cred).Id];
    public byte CredFlags(nint cred) => Get<Cred>(cred).Flags;
    public byte[] CredAaguid(nint cred) => [.. Get<Cred>(cred).Aaguid];

    public nint AssertNew()
    {
        var assert = new Assert();
        Asserts.Add(assert);
        return Add(assert);
    }

    public void AssertFree(nint assert) => Free(assert);
    public int AssertSetRp(nint assert, string id) => Set(() => Get<Assert>(assert).RpId = id);
    public int AssertSetClientDataHash(nint assert, ReadOnlySpan<byte> hash) => Set(Get<Assert>(assert), hash.ToArray(), (a, h) => a.ClientDataHash = h);
    public int AssertAllowCred(nint assert, ReadOnlySpan<byte> credentialId) => Set(Get<Assert>(assert), credentialId.ToArray(), (a, id) => a.Allowed.Add(id));
    public int AssertSetExtensions(nint assert, int extensions) => Set(() => Get<Assert>(assert).Extensions = extensions);
    public int AssertSetHmacSalt(nint assert, ReadOnlySpan<byte> salt) =>
        Failing("fido_assert_set_hmac_salt") ?? Set(Get<Assert>(assert), salt.ToArray(), (a, s) => a.Salt = s);
    public int AssertSetUp(nint assert, FidoOpt up) => Set(() => Get<Assert>(assert).Up = (int)up);
    public nuint AssertCount(nint assert) => (nuint)Get<Assert>(assert).Count;
    public byte[] AssertHmacSecret(nint assert, nuint index)
    {
        byte[] copy = [.. Get<Assert>(assert).HmacSecret];
        HmacSecretsReturned.Add(copy);
        return copy;
    }

    /// <summary>Every hmac-secret array handed out (so a test can see that a refused one was zeroed).</summary>
    public List<byte[]> HmacSecretsReturned { get; } = [];
    public byte AssertFlags(nint assert, nuint index) => Get<Assert>(assert).Flags;
    public byte[] AssertId(nint assert, nuint index) => [.. Get<Assert>(assert).Id];

    private int? Failing(string setter) => FailingSetter is { } f && f.Setter == setter ? f.Result : null;

    private static int Set(Action set)
    {
        set();
        return Libfido2Errors.Ok;
    }

    private static int Set<TObject>(TObject target, byte[] value, Action<TObject, byte[]> set)
    {
        set(target, value);
        return Libfido2Errors.Ok;
    }
}
