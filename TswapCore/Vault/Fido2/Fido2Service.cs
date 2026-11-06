using System.Security.Cryptography;
using TswapCore.Keyring;

namespace TswapCore.Vault.Fido2;

/// <summary>
/// The FIDO2 service (FIDO2 plan, task 3) over the device seam <see cref="IFido2Keys"/>: the YubiKey check (#193), the
/// PIN policy (no terminal → refused before any key call; one PIN request per operation; never a retry), the silent
/// duplicate probe, the exclude list, the Windows one-ceremony assertion, and every text (<see cref="Fido2Texts"/>).
/// Device failures (<see cref="Fido2DeviceException"/>) become <see cref="Fido2Exception"/>s here. Outputs the service
/// refuses are zeroed before it throws.
/// </summary>
public sealed class Fido2Service(IFido2Keys keys) : IFido2Service
{
    /// <summary>The size of an <c>hmac-secret</c> output for one salt.</summary>
    public const int OutputSize = 32;

    /// <summary>The make-credential user id: random, small (keys outside Yubico's reject large user maps).</summary>
    public const int UserIdSize = 16;

    public bool CanList => keys.CanList;

    public IReadOnlyList<Fido2KeyInfo> ListYubiKeys()
    {
        if (!CanList)
            return [];
        return [.. Call(keys.Find, Fido2Texts.AnyKey, null).Where(k => YubicoAaguids.IsYubico(k.Aaguid))];
    }

    public Fido2SlotBlob Enrol(Fido2KeyInfo? key, bool requiresPassword, IReadOnlyList<Fido2SlotBlob> vaultFido2Slots, Fido2Pin? pin)
    {
        RequireKeyExactlyWhenListing(key);
        var name = key is null ? Fido2Texts.PickedKey : KeyName(key);
        if (pin is null)
            throw new Fido2Exception(Fido2Failure.NoTerminal, key?.Serial, null, Fido2Texts.NoTerminal);

        if (key is not null)
        {
            if (!YubicoAaguids.IsYubico(key.Aaguid))
                throw new Fido2Exception(Fido2Failure.NotAYubiKey, key.Serial, null, Fido2Texts.NotAYubiKey(key.Aaguid));
            if (!key.PinSet)
                throw new Fido2Exception(Fido2Failure.NoPin, key.Serial, null, Fido2Texts.NoPin(name));
            foreach (var slot in vaultFido2Slots)
            {
                var holder = Call(() => keys.FindHolder(slot.CredentialId), name, key.Serial);
                if (holder?.Key == key.Key)
                    throw new Fido2Exception(Fido2Failure.CredentialExcluded, key.Serial, null, Fido2Texts.AlreadyHasSlot(name));
            }
        }

        var userId = RandomNumberGenerator.GetBytes(UserIdSize);
        List<byte[]> exclude = [.. vaultFido2Slots.Select(b => b.CredentialId)];
        var made = Call(() => keys.MakeCredential(key?.Key, userId, exclude, DevicePin(pin, name, key?.PinRetries, newPin: false)),
            name, key?.Serial);

        var serial = made.Serial ?? key?.Serial;
        if (!made.UserVerified)
            throw new Fido2Exception(Fido2Failure.Other, serial, null, Fido2Texts.MadeWithoutUv(name));
        if (!CanList && made.Aaguid == Guid.Empty)
            throw new Fido2Exception(Fido2Failure.NotAYubiKey, serial, null, Fido2Texts.WindowsNoAaguid);
        if (!YubicoAaguids.IsYubico(made.Aaguid))
            throw new Fido2Exception(Fido2Failure.NotAYubiKey, serial, null, Fido2Texts.NotAYubiKey(made.Aaguid));
        if (made.CredentialId.Length is < Fido2SlotBlob.MinCredentialIdSize or > Fido2SlotBlob.MaxCredentialIdSize)
            throw new Fido2Exception(Fido2Failure.Other, serial, null, Fido2Texts.BadCredentialId(name, made.CredentialId.Length));

        return Fido2SlotBlob.Create(serial is > 0 ? serial : null, made.Aaguid, made.CredentialId, requiresPassword);
    }

    public Fido2Opened Open(IReadOnlyList<Fido2SlotBlob> blobs, Fido2KeyInfo? key, Fido2Pin? pin)
    {
        RequireKeyExactlyWhenListing(key);
        if (blobs.Count == 0)
            throw new ArgumentException("Open needs at least one FIDO2 slot", nameof(blobs));
        if (CanList && blobs.Count != 1)
            throw new ArgumentException("On Linux and macOS, Open takes the one located slot", nameof(blobs));

        var name = key is not null ? KeyName(key) : blobs.Count == 1 ? KeyName(blobs[0]) : Fido2Texts.PickedKey;
        var serial = key?.Serial ?? (blobs.Count == 1 ? blobs[0].Serial : null);
        if (pin is null)
            throw new Fido2Exception(Fido2Failure.NoTerminal, serial, null, Fido2Texts.NoTerminal);

        List<(byte[] CredentialId, byte[] PrfInput)> allowed = [.. blobs.Select(b => (b.CredentialId, b.PrfInput))];
        var answer = Call(() => keys.GetHmacSecret(key?.Key, allowed, DevicePin(pin, name, key?.PinRetries, newPin: false)),
            name, serial);

        var blob = blobs.FirstOrDefault(b => b.CredentialId.AsSpan().SequenceEqual(answer.CredentialId));
        if (blob is null)
            throw Refuse(answer, Fido2Texts.ForeignCredential(name), serial);
        if (key is null)
        {
            name = KeyName(blob);
            serial = blob.Serial;
        }

        if (!answer.UserVerified)
            throw Refuse(answer, Fido2Texts.AnsweredWithoutUv(name), serial);
        if (answer.Output is not { Length: OutputSize })
            throw Refuse(answer, Fido2Texts.BadOutput(name, answer.Output?.Length ?? 0), serial);
        return new Fido2Opened(blob, answer.Output);
    }

    public Fido2Locate Locate(Fido2SlotBlob blob)
    {
        if (!CanList)
            return new Fido2Locate.Unknown();

        var name = KeyName(blob);
        var holder = Call(() => keys.FindHolder(blob.CredentialId), name, blob.Serial);
        if (holder is not null)
            return new Fido2Locate.Found(holder);

        var plugged = Call(keys.Find, name, blob.Serial);
        var lookalike = blob.Serial is { } serial
            ? plugged.FirstOrDefault(k => k.Serial == serial)
            : plugged.FirstOrDefault(k => k.Aaguid == blob.Aaguid);
        return lookalike is not null
            ? new Fido2Locate.ResetOrOtherKey(lookalike, SerialMatched: blob.Serial is not null)
            : new Fido2Locate.NotPluggedIn(name);
    }

    public void SetPin(Fido2KeyInfo key, Fido2Pin? pin)
    {
        if (!CanList)
            throw new InvalidOperationException("Windows' dialog sets a FIDO2 PIN itself; tswap can't on this OS");

        var name = KeyName(key);
        if (pin is null)
            throw new Fido2Exception(Fido2Failure.NoTerminal, key.Serial, null, Fido2Texts.NoTerminal);
        if (key.PinSet)
            throw new Fido2Exception(Fido2Failure.Other, key.Serial, null, Fido2Texts.PinAlreadySet(name));
        Call(() => keys.SetPin(key.Key, DevicePin(pin, name, null, newPin: true)), name, key.Serial);
    }

    public string KeyName(Fido2SlotBlob blob) => Fido2SlotBlob.DisplayName(blob.Serial, blob.Aaguid);

    public string KeyName(Fido2KeyInfo key) => Fido2SlotBlob.DisplayName(key.Serial, key.Aaguid);

    private void RequireKeyExactlyWhenListing(Fido2KeyInfo? key)
    {
        if (CanList && key is null)
            throw new ArgumentNullException(nameof(key), "A key is needed where keys can be listed");
        if (!CanList && key is not null)
            throw new ArgumentException("Windows' dialog picks the key; pass no key", nameof(key));
    }

    /// <summary>
    /// The device-layer PIN source for one operation: asks <paramref name="pin"/> once, with the key's name; an empty
    /// answer is a cancellation (no PIN reaches the key). A second request in the same operation is refused, never
    /// passed on: a device that asks again after a wrong PIN gets <see cref="Fido2Failure.PinWrong"/> with the tries it
    /// reported (a new PIN: <see cref="Fido2Failure.Other"/>), so tswap never retries a PIN by itself.
    /// </summary>
    private static Fido2DevicePin DevicePin(Fido2Pin pin, string name, int? knownRetries, bool newPin)
    {
        var asked = false;
        return retriesLeft =>
        {
            if (asked)
                throw newPin
                    ? new Fido2DeviceException(Fido2Failure.Other, retriesLeft, "PinRequestedTwice")
                    : new Fido2DeviceException(Fido2Failure.PinWrong, retriesLeft, "PinRetryRefused");
            asked = true;
            var bytes = pin(new Fido2PinRequest(name, retriesLeft ?? knownRetries, newPin));
            if (bytes is not { Length: > 0 })
                throw new Fido2DeviceException(Fido2Failure.Cancelled, retriesLeft, "PinEntryCancelled");
            return bytes;
        };
    }

    private T Call<T>(Func<T> operation, string name, int? serial)
    {
        try
        {
            return operation();
        }
        catch (Fido2DeviceException e)
        {
            throw Map(e, name, serial);
        }
    }

    private void Call(Action operation, string name, int? serial) =>
        Call(() =>
        {
            operation();
            return true;
        }, name, serial);

    private Fido2Exception Map(Fido2DeviceException e, string name, int? serial)
    {
        var text = e.Kind switch
        {
            Fido2Failure.NotPluggedIn => Fido2Texts.NotPluggedIn(name),
            Fido2Failure.NotAYubiKey => Fido2Texts.NotAYubiKey(null),
            Fido2Failure.NoPin => Fido2Texts.NoPin(name),
            Fido2Failure.PinWrong => Fido2Texts.PinWrong(name, e.RetriesLeft),
            Fido2Failure.PinBlocked => Fido2Texts.PinBlocked(name),
            Fido2Failure.PinNeedsReinsert => Fido2Texts.PinNeedsReinsert(name, e.RetriesLeft),
            Fido2Failure.NoCredential => CanList ? Fido2Texts.CredentialGone(name) : Fido2Texts.PickedHoldsNone,
            Fido2Failure.Cancelled => Fido2Texts.Cancelled(name),
            Fido2Failure.TimedOut => Fido2Texts.TimedOut(name),
            Fido2Failure.Busy => Fido2Texts.Busy(name),
            Fido2Failure.NoTerminal => Fido2Texts.NoTerminal,
            Fido2Failure.Unsupported => Fido2Texts.Unsupported(e.Detail),
            Fido2Failure.CredentialExcluded => Fido2Texts.AlreadyHasSlot(name),
            _ => Fido2Texts.Other(name, e.Detail),
        };
        return new Fido2Exception(e.Kind, serial, e.RetriesLeft, text);
    }

    private static Fido2Exception Refuse(Fido2Output answer, string text, int? serial)
    {
        if (answer.Output is not null)
            CryptographicOperations.ZeroMemory(answer.Output);
        return new Fido2Exception(Fido2Failure.Other, serial, null, text);
    }
}
