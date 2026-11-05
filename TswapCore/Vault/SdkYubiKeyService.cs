using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace TswapCore.Vault;

/// <summary>
/// Production <see cref="IYubiKeyService"/> (YubiKey SDK stage 1): talks to the keys through Yubico's .NET SDK, over
/// the device seam <see cref="IOtpKeys"/> (<see cref="YubicoOtpKeys"/> for real keys). Every failure is a
/// <see cref="TswapException"/> that names the key and what is missing: a key hidden from the keyboard interface gets
/// the per-OS explanation (<see cref="YubiKeyAccessTexts"/>), an empty slot 2 points to <c>tswap yubikey setup</c>,
/// a busy key says so. An optional <paramref name="verboseOut"/> writer receives the progress line ykman's service
/// printed ("YubiKey (serial: N)... ✓").
/// </summary>
public sealed class SdkYubiKeyService : IYubiKeyService
{
    private readonly IOtpKeys _keys;
    private readonly OSPlatform _os;
    private readonly TextWriter? _verboseOut;

    /// <summary>Real keys, through Yubico's SDK.</summary>
    public SdkYubiKeyService(TextWriter? verboseOut = null)
        : this(new YubicoOtpKeys(), YubiKeyAccessTexts.CurrentOs(), verboseOut)
    {
    }

    /// <summary>Tests: any device seam, any OS's texts.</summary>
    internal SdkYubiKeyService(IOtpKeys keys, OSPlatform os, TextWriter? verboseOut = null)
    {
        _keys = keys;
        _os = os;
        _verboseOut = verboseOut;
    }

    public bool IsSimulated => false;

    /// <summary>
    /// The serials of the keys reachable over the keyboard interface, in the SDK's order (a key without a readable
    /// serial is left out). When none is: the per-OS explanation if a key is seen on another transport only, or
    /// "serial can't be read" if the only reachable keys have none; otherwise empty (callers say "no YubiKey").
    /// </summary>
    public IReadOnlyList<int> ListSerials()
    {
        var keys = Find();
        var serials = keys.Where(k => k.KeyboardReachable && k.Serial is not null).Select(k => k.Serial!.Value).ToList();
        if (serials.Count > 0)
            return serials;

        var hidden = keys.Where(k => !k.KeyboardReachable).ToList();
        if (hidden.Count > 0)
            throw new TswapException(string.Join(Environment.NewLine, hidden.Select(k => YubiKeyAccessTexts.ExplainHidden(k.Serial, _os)))
                + Environment.NewLine + BusyHint);
        if (keys.Count > 0)
            throw new TswapException("A YubiKey is plugged in, but its serial number can't be read, so tswap can't tell which key it is.");
        return [];
    }

    /// <summary>
    /// Added where the keyboard interface seems hidden: Yubico's SDK skips an interface it can't talk to while it
    /// lists the keys, which is also what a key busy with another program's command looks like.
    /// </summary>
    internal const string BusyHint = "If another tswap or app is using the key right now, try again when it is done.";

    public IReadOnlyList<YubiKeyInfo> FindKeys() =>
        Find().Select(k => new YubiKeyInfo(k.Serial, k.KeyboardReachable, k.Transports)).ToList();

    public byte[] Challenge(int serial, string challenge) => ChallengeReportingTouch(serial, challenge).Response;

    /// <summary>
    /// The challenge string as ykman got it (UTF-8, truncated or zero-padded to 64 bytes) to slot 2, and whether the
    /// key asked for a touch (from the SDK's touch notification). The key is looked up first, so a missing or hidden
    /// key is named as such before any challenge is sent.
    /// </summary>
    public YubiKeyResponse ChallengeReportingTouch(int serial, string challenge)
    {
        _verboseOut?.Write($"YubiKey (serial: {serial})... ");
        var frame = new byte[64];
        var input = Encoding.UTF8.GetBytes(challenge);
        try
        {
            RequireReachable(serial);
            input.AsSpan(0, Math.Min(input.Length, 64)).CopyTo(frame);
            var result = Call(serial, () => _keys.Challenge(serial, frame, static () => { }));
            _verboseOut?.WriteLine("✓");
            return new YubiKeyResponse(result.Response, result.TouchRequested);
        }
        catch (Exception ex)
        {
            _verboseOut?.WriteLine($"\nFailed: {ex.Message}");
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(frame);
            CryptographicOperations.ZeroMemory(input);
        }
    }

    /// <summary>The SDK exposes no touch flag for a configured slot (spike finding); touch is learned from a challenge.</summary>
    public bool? DetectTouchRequirement(int serial) => null;

    public Slot2State GetSlot2State(int serial)
    {
        RequireReachable(serial);
        return Call(serial, () => _keys.Slot2(serial));
    }

    public void ProgramSlot2(int serial, bool requireTouch)
    {
        RequireReachable(serial);
        try
        {
            _keys.ProgramSlot2(serial, requireTouch);
        }
        catch (OtpKeysException e) when (e.Kind is OtpFailure.ProgramFailed or OtpFailure.VerifyWrong or OtpFailure.VerifyNoAnswer)
        {
            throw new YubiKeyProgramException(e.Kind, serial, e.Detail);
        }
        catch (OtpKeysException e)
        {
            throw new TswapException(Describe(e, serial));
        }
    }

    private IReadOnlyList<OtpKeyInfo> Find()
    {
        try
        {
            return _keys.Find();
        }
        catch (OtpKeysException e)
        {
            throw new TswapException(Describe(e, e.Serial));
        }
    }

    /// <summary>
    /// Names what's missing before a key is used: not plugged in (with the per-OS explanation when a hidden key's
    /// serial can't be read, since it may be this one), or plugged in but hidden from the keyboard interface.
    /// </summary>
    private void RequireReachable(int serial)
    {
        var keys = Find();
        var key = keys.FirstOrDefault(k => k.Serial == serial);
        if (key is null)
        {
            var message = $"YubiKey {serial} is not plugged in.";
            var unknownHidden = keys.Where(k => !k.KeyboardReachable && k.Serial is null).ToList();
            if (unknownHidden.Count > 0)
                message += Environment.NewLine + YubiKeyAccessTexts.ExplainHidden(null, _os);
            throw new TswapException(message);
        }
        if (!key.KeyboardReachable)
            throw new TswapException(YubiKeyAccessTexts.ExplainHidden(serial, _os) + Environment.NewLine + BusyHint);
    }

    private T Call<T>(int serial, Func<T> call)
    {
        try
        {
            return call();
        }
        catch (OtpKeysException e)
        {
            throw new TswapException(Describe(e, serial));
        }
    }

    private string Describe(OtpKeysException e, int? serial) => e.Kind switch
    {
        OtpFailure.Busy => $"{YubiKeyAccessTexts.Name(serial)} is busy (another tswap or app is using it); try again.",
        OtpFailure.Slot2Empty => $"Slot 2 of {YubiKeyAccessTexts.Name(serial)} isn't set up for challenge-response; run `tswap yubikey setup`.",
        OtpFailure.NotReachable => YubiKeyAccessTexts.ExplainHidden(serial, _os),
        _ => $"{YubiKeyAccessTexts.Name(serial)}: {e.Detail}",
    };
}
