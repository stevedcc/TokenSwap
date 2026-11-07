using System.Security.Cryptography;
using System.Text;
using TswapCore.Keyring;
using TswapCore.Vault.Fido2;

namespace TswapTests;

/// <summary>The operations of <see cref="IFido2Keys"/>, as <see cref="FakeFido2Keys"/> logs them.</summary>
internal enum FakeFido2Op
{
    Find,
    MakeCredential,
    GetHmacSecret,
    FindHolder,
    SetPin,
}

/// <summary>
/// One call to the fake: the operation, the key handle passed (null on the Windows path), the credential ids it
/// carried (the exclude list, the allow list, the probed id) and the user id of a make-credential.
/// </summary>
internal sealed record FakeFido2Call(FakeFido2Op Op, Fido2KeyRef? Key, IReadOnlyList<byte[]> CredentialIds, byte[]? UserId = null);

/// <summary>
/// FIDO2 plan, task 3: the device seam's fake. Keys with or without a serial, an AAGUID, a PIN (or none) and its
/// retry counters; the credentials it made or was given, each with distinct outputs with and without user
/// verification (as CTAP2's <c>CredRandomWithUV</c> / <c>CredRandomWithoutUV</c>); the exclude list
/// (<see cref="Fido2Failure.CredentialExcluded"/>); <see cref="CanList"/> false plays Windows (the dialog picks
/// <see cref="Picked"/>, asks for the PIN itself, so the PIN delegate is never called; <c>Find</c>, <c>FindHolder</c>
/// and <c>SetPin</c> throw <see cref="NotSupportedException"/>, as <c>WebAuthnFido2Keys</c> does); per-call failure
/// injection for every <see cref="Fido2Failure"/> (<see cref="FailNext"/>); and a log of every call.
///
/// <para>The output for a credential is <c>HMAC-SHA256(secret, Fido2Prf.Salt(prfInput))</c> on both paths, so the
/// same credential gives the same output whether "Linux" or "Windows" asked, as on real keys.</para>
/// </summary>
internal sealed class FakeFido2Keys : IFido2Keys
{
    public const string DefaultPin = "123456";

    /// <summary>A plugged-in (or unplugged) key and its FIDO2 state; tests change it freely.</summary>
    public sealed class Key
    {
        public required Fido2KeyRef Ref { get; init; }
        public int? Serial { get; set; }
        public Guid Aaguid { get; set; }

        /// <summary>The FIDO2 PIN; null when none is set.</summary>
        public string? Pin { get; set; }

        /// <summary>PIN tries left before the key's FIDO2 is blocked (CTAP2: 8 to start with).</summary>
        public int Retries { get; set; } = 8;

        /// <summary>Wrong PINs since the last right one; at 3 the key needs re-inserting.</summary>
        public int WrongInARow { get; set; }

        public bool PluggedIn { get; set; } = true;

        /// <summary>Make-credential reports the credential as made without user verification.</summary>
        public bool MakesWithoutUv { get; set; }

        /// <summary>The assertion answers with the non-UV output and says it did not verify the user.</summary>
        public bool AnswersWithoutUv { get; set; }

        /// <summary>Make-credential returns a credential id of this many bytes (default 64, like a YubiKey's).</summary>
        public int MadeCredentialIdLength { get; set; } = 64;

        /// <summary>The assertion's output is cut to this many bytes (0: no output).</summary>
        public int? OutputLength { get; set; }
    }

    private sealed record Credential(Key Owner, byte[] UvSecret, byte[] NoUvSecret);

    private readonly Dictionary<string, Credential> _credentials = [];
    private readonly List<(FakeFido2Op Op, Fido2DeviceException Failure, bool AfterPin)> _failures = [];
    private int _nextRef;

    public bool CanList { get; set; } = true;

    /// <summary>Every key the fake knows, plugged in or not, in plug order.</summary>
    public List<Key> Keys { get; } = [];

    /// <summary>Windows (<see cref="CanList"/> false): the key the person picks in the dialog.</summary>
    public Key? Picked { get; set; }

    /// <summary>Every call, in order.</summary>
    public List<FakeFido2Call> Calls { get; } = [];

    /// <summary>Runs as each call is logged, before the fake answers it (task 6: what was on disk at that moment).</summary>
    public Action<FakeFido2Call>? OnCall { get; set; }

    /// <summary>Every call the fake made to a <see cref="Fido2DevicePin"/>, with the retries it passed.</summary>
    public List<int?> DevicePinCalls { get; } = [];

    /// <summary>Every PIN buffer the fake was handed (it zeroes each after use, as a device must).</summary>
    public List<byte[]> PinBuffers { get; } = [];

    /// <summary>The <see cref="Fido2Output.Output"/> array last returned (for checks that the caller zeroed it).</summary>
    public byte[]? LastOutput { get; private set; }

    public Key AddKey(int? serial, Guid aaguid, string? pin = DefaultPin, int retries = 8)
    {
        var key = new Key
        {
            Ref = new Fido2KeyRef($"/dev/hidraw-fake{_nextRef++}"),
            Serial = serial,
            Aaguid = aaguid,
            Pin = pin,
            Retries = retries,
        };
        Keys.Add(key);
        return key;
    }

    /// <summary>What <see cref="Find"/> would say about <paramref name="key"/> now.</summary>
    public static Fido2KeyInfo Info(Key key) => new(key.Ref, key.Serial, key.Aaguid, key.Pin is not null, key.Retries);

    /// <summary>A credential made on <paramref name="key"/> earlier (64 random bytes, like a YubiKey's id).</summary>
    public byte[] AddCredential(Key key) => AddCredential(key, 64);

    private byte[] AddCredential(Key key, int length)
    {
        var id = RandomNumberGenerator.GetBytes(length);
        _credentials[Convert.ToHexString(id)] = new Credential(key, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
        return id;
    }

    /// <summary>Forgets every credential of <paramref name="key"/>, as a FIDO2 reset does.</summary>
    public void Reset(Key key)
    {
        foreach (var id in _credentials.Where(c => c.Value.Owner == key).Select(c => c.Key).ToList())
            _credentials.Remove(id);
        key.Pin = null;
        key.Retries = 8;
        key.WrongInARow = 0;
    }

    public bool Holds(Key key, byte[] credentialId) =>
        _credentials.TryGetValue(Convert.ToHexString(credentialId), out var credential) && credential.Owner == key;

    /// <summary>The output the key gives for this credential with user verification.</summary>
    public byte[] UvOutput(byte[] credentialId, byte[] prfInput) =>
        HMACSHA256.HashData(_credentials[Convert.ToHexString(credentialId)].UvSecret, Fido2Prf.Salt(prfInput));

    /// <summary>The output the key gives for this credential without user verification.</summary>
    public byte[] NonUvOutput(byte[] credentialId, byte[] prfInput) =>
        HMACSHA256.HashData(_credentials[Convert.ToHexString(credentialId)].NoUvSecret, Fido2Prf.Salt(prfInput));

    /// <summary>
    /// The next call of <paramref name="op"/> fails with <paramref name="kind"/>: before the PIN is asked for, or after
    /// it was taken (<paramref name="afterPin"/>). Each injected failure fires once.
    /// </summary>
    public FakeFido2Keys FailNext(FakeFido2Op op, Fido2Failure kind, int? retriesLeft = null, string? detail = null, bool afterPin = false)
    {
        _failures.Add((op, new Fido2DeviceException(kind, retriesLeft, detail ?? kind.ToString()), afterPin));
        return this;
    }

    public IReadOnlyList<Fido2KeyInfo> Find()
    {
        RequireCanList();
        Log(new FakeFido2Call(FakeFido2Op.Find, null, []));
        ThrowInjected(FakeFido2Op.Find, afterPin: false);
        return [.. Keys.Where(k => k.PluggedIn).Select(Info)];
    }

    public Fido2KeyInfo? FindHolder(byte[] credentialId)
    {
        RequireCanList();
        Log(new FakeFido2Call(FakeFido2Op.FindHolder, null, [Copy(credentialId)]));
        ThrowInjected(FakeFido2Op.FindHolder, afterPin: false);
        var holder = Keys.FirstOrDefault(k => k.PluggedIn && Holds(k, credentialId));
        return holder is null ? null : Info(holder);
    }

    public Fido2Made MakeCredential(Fido2KeyRef? key, byte[] userId, IReadOnlyList<byte[]> excludeCredentialIds, Fido2DevicePin pin)
    {
        Log(new FakeFido2Call(FakeFido2Op.MakeCredential, key, [.. excludeCredentialIds.Select(Copy)], Copy(userId)));
        var target = Target(key);
        ThrowInjected(FakeFido2Op.MakeCredential, afterPin: false);
        Verify(target, pin);
        ThrowInjected(FakeFido2Op.MakeCredential, afterPin: true);
        if (excludeCredentialIds.Any(id => Holds(target, id)))
            throw new Fido2DeviceException(Fido2Failure.CredentialExcluded, null, "CredentialExcluded");

        var id = AddCredential(target, target.MadeCredentialIdLength);
        return new Fido2Made(id, target.Aaguid, CanList ? target.Serial : null, UserVerified: !target.MakesWithoutUv);
    }

    public Fido2Output GetHmacSecret(Fido2KeyRef? key, IReadOnlyList<(byte[] CredentialId, byte[] PrfInput)> allowed, Fido2DevicePin pin)
    {
        Log(new FakeFido2Call(FakeFido2Op.GetHmacSecret, key, [.. allowed.Select(a => Copy(a.CredentialId))]));
        var target = Target(key);
        ThrowInjected(FakeFido2Op.GetHmacSecret, afterPin: false);
        Verify(target, pin);
        ThrowInjected(FakeFido2Op.GetHmacSecret, afterPin: true);

        var match = allowed.FirstOrDefault(a => Holds(target, a.CredentialId));
        if (match.CredentialId is null)
            throw new Fido2DeviceException(Fido2Failure.NoCredential, null, "NoCredentials");
        var output = target.AnswersWithoutUv
            ? NonUvOutput(match.CredentialId, match.PrfInput)
            : UvOutput(match.CredentialId, match.PrfInput);
        if (target.OutputLength is { } length)
            output = output[..length];
        LastOutput = output;
        return new Fido2Output(Copy(match.CredentialId), output, UserVerified: !target.AnswersWithoutUv);
    }

    public void SetPin(Fido2KeyRef key, Fido2DevicePin newPin)
    {
        RequireCanList();
        Log(new FakeFido2Call(FakeFido2Op.SetPin, key, []));
        var target = Target(key);
        ThrowInjected(FakeFido2Op.SetPin, afterPin: false);
        if (target.Pin is not null)
            throw new Fido2DeviceException(Fido2Failure.Other, null, "NotAllowed");
        DevicePinCalls.Add(null);
        var bytes = newPin(null);
        PinBuffers.Add(bytes);
        target.Pin = Encoding.UTF8.GetString(bytes);
        CryptographicOperations.ZeroMemory(bytes);
    }

    private void Log(FakeFido2Call call)
    {
        Calls.Add(call);
        OnCall?.Invoke(call);
    }

    private Key Target(Fido2KeyRef? key)
    {
        if (!CanList)
        {
            if (key is not null)
                throw new InvalidOperationException("The Windows path never names a key");
            return Picked is { PluggedIn: true } picked
                ? picked
                : throw new Fido2DeviceException(Fido2Failure.NotPluggedIn, null, "NoKeyPicked");
        }

        if (key is null)
            throw new InvalidOperationException("The SDK path always names a key");
        return Keys.FirstOrDefault(k => k.Ref == key && k.PluggedIn)
            ?? throw new Fido2DeviceException(Fido2Failure.NotPluggedIn, null, "DeviceGone");
    }

    /// <summary>CTAP2's PIN rules: 8 tries in all, re-insert after 3 wrong in a row. Windows' dialog owns the PIN.</summary>
    private void Verify(Key key, Fido2DevicePin pin)
    {
        if (!CanList)
            return;
        if (key.Pin is null)
            throw new Fido2DeviceException(Fido2Failure.NoPin, null, "PinNotSet");
        if (key.Retries == 0)
            throw new Fido2DeviceException(Fido2Failure.PinBlocked, 0, "PinBlocked");
        if (key.WrongInARow >= 3)
            throw new Fido2DeviceException(Fido2Failure.PinNeedsReinsert, key.Retries, "PinAuthBlocked");

        DevicePinCalls.Add(key.Retries);
        var typed = pin(key.Retries);
        PinBuffers.Add(typed);
        bool right;
        try
        {
            right = typed.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(key.Pin));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(typed);
        }

        if (right)
        {
            key.WrongInARow = 0;
            return;
        }

        key.Retries--;
        key.WrongInARow++;
        if (key.Retries == 0)
            throw new Fido2DeviceException(Fido2Failure.PinBlocked, 0, "PinBlocked");
        if (key.WrongInARow == 3)
            throw new Fido2DeviceException(Fido2Failure.PinNeedsReinsert, key.Retries, "PinAuthBlocked");
        throw new Fido2DeviceException(Fido2Failure.PinWrong, key.Retries, "PinInvalid");
    }

    private void ThrowInjected(FakeFido2Op op, bool afterPin)
    {
        var index = _failures.FindIndex(f => f.Op == op && f.AfterPin == afterPin);
        if (index < 0)
            return;
        var failure = _failures[index].Failure;
        _failures.RemoveAt(index);
        throw failure;
    }

    private void RequireCanList()
    {
        if (!CanList)
            throw new NotSupportedException("Windows' dialog picks the key: no listing, probing or PIN setting");
    }

    private static byte[] Copy(byte[] bytes) => (byte[])bytes.Clone();
}
