namespace TswapCore.Vault.Fido2.Libfido2;

/// <summary>What loading libfido2 gave: the status, and the backend exactly when it is <see cref="Libfido2Status.Loaded"/>.</summary>
public sealed record Libfido2LoadResult(Libfido2Status Status, Libfido2Fido2Keys? Keys);

/// <summary>
/// Both FIDO2 backends at once on Linux and macOS (brief T19, item 3): Yubico's SDK for YubiKeys, libfido2 for every
/// other brand (it skips Yubico devices, so no key is listed twice). <paramref name="other"/> loads libfido2 on its
/// first call and the result is kept: building this loads nothing.
///
/// <para><b>Key refs carry their backend</b>: <c>sdk:</c> and <c>libfido2:</c> prefixes, stripped before the backend
/// sees them; a call goes to the backend that listed the key. <see cref="Find"/> lists both; a backend that throws is
/// reported on <paramref name="notices"/> and its keys are missing, unless neither listed a key: then the failure is
/// thrown (the SDK's when both threw). <see cref="FindHolder"/> asks the SDK, then libfido2: the holder wins over a
/// failure, and with no holder the first failure is thrown.</para>
/// </summary>
public sealed class CompositeFido2Keys(SdkFido2Keys sdk, Func<Libfido2LoadResult> other, TextWriter? notices = null) : IFido2Keys
{
    public const string SdkPrefix = "sdk:";
    public const string Libfido2Prefix = "libfido2:";

    private readonly Lock _gate = new();
    private Libfido2LoadResult? _other;

    public bool CanList => true;

    /// <summary>libfido2's status, loading it if that hasn't happened yet.</summary>
    public Libfido2Status? OtherBrands => Other().Status;

    public IReadOnlyList<Fido2KeyInfo> Find()
    {
        List<Fido2KeyInfo> keys = [];
        List<Fido2DeviceException> failures = [];
        foreach (var (prefix, backend) in Backends())
        {
            try
            {
                keys.AddRange(backend.Find().Select(k => Prefixed(prefix, k)));
            }
            catch (Fido2DeviceException e)
            {
                failures.Add(e);
            }
        }
        if (keys.Count == 0 && failures.Count > 0)
            throw failures[0];
        foreach (var failure in failures)
            notices?.WriteLine(Fido2Texts.LeftOut(failure, OperatingSystem.IsLinux()));
        return keys;
    }

    public Fido2KeyInfo? FindHolder(byte[] credentialId)
    {
        Fido2DeviceException? held = null;
        foreach (var (prefix, backend) in Backends())
        {
            try
            {
                if (backend.FindHolder(credentialId) is { } holder)
                    return Prefixed(prefix, holder);
            }
            catch (Fido2DeviceException e)
            {
                held ??= e;
            }
        }
        return held is null ? null : throw held;
    }

    public Fido2Made MakeCredential(Fido2KeyRef? key, byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds, Fido2DevicePin pin)
    {
        var (backend, inner) = Route(key);
        return backend.MakeCredential(inner, userId, excludeCredentialIds, pin);
    }

    public Fido2Output GetHmacSecret(Fido2KeyRef? key, IReadOnlyList<(byte[] CredentialId, byte[] PrfInput)> allowed, Fido2DevicePin pin)
    {
        var (backend, inner) = Route(key);
        return backend.GetHmacSecret(inner, allowed, pin);
    }

    public void SetPin(Fido2KeyRef key, Fido2DevicePin newPin)
    {
        var (backend, inner) = Route(key);
        backend.SetPin(inner, newPin);
    }

    /// <summary>The SDK backend first, then libfido2 when it loaded.</summary>
    private IEnumerable<(string Prefix, IFido2Keys Backend)> Backends()
    {
        yield return (SdkPrefix, sdk);
        if (Other().Keys is { } libfido2)
            yield return (Libfido2Prefix, libfido2);
    }

    private Libfido2LoadResult Other()
    {
        lock (_gate)
            return _other ??= other();
    }

    private (IFido2Keys Backend, Fido2KeyRef Inner) Route(Fido2KeyRef? key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Id.StartsWith(SdkPrefix, StringComparison.Ordinal))
            return (sdk, new Fido2KeyRef(key.Id[SdkPrefix.Length..]));
        if (key.Id.StartsWith(Libfido2Prefix, StringComparison.Ordinal))
            return (Other().Keys ?? throw new Fido2DeviceException(Fido2Failure.NotPluggedIn, null, "Libfido2NotLoaded"),
                new Fido2KeyRef(key.Id[Libfido2Prefix.Length..]));
        throw new ArgumentException("A key ref names its backend (sdk: or libfido2:)", nameof(key));
    }

    private static Fido2KeyInfo Prefixed(string prefix, Fido2KeyInfo key) => key with { Key = new Fido2KeyRef(prefix + key.Key.Id) };
}
