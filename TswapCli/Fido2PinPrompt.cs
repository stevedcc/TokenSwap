using System.Security.Cryptography;
using System.Text;
using TswapCore.Vault.Fido2;

namespace TswapCli;

/// <summary>
/// FIDO2 plan, task 6: the terminal's <see cref="Fido2Pin"/>, for enrolment now and for unlock (task 7). Null when
/// there is no terminal (<see cref="CommandContext.Terminal"/> gives none), which <see cref="IFido2Service"/> refuses
/// before any key call. Each request opens the terminal, asks there (no echo on Linux and macOS, read from
/// <c>/dev/tty</c>, so stdin may carry something else) and closes it again. A new PIN is asked twice and asked again
/// while the two differ, it is too short or longer than 63 bytes; an empty answer or the end of input returns no bytes (a cancellation).
/// Brief T54: every PIN is put in NFC before it is checked or sent (<see cref="NormalisePin"/>); a new PIN that is not
/// UTF-8 is asked again, its minimum counts characters (runes), and any PIN ending in a NUL byte is asked again.
/// Windows' dialog asks for the PIN itself, so there the delegate exists but is not called.
/// </summary>
internal static class Fido2PinPrompt
{
    /// <summary>CTAP2: a PIN has at least 4 characters.</summary>
    public const int MinimumPinLength = 4;

    public static string Prompt(string keyName) => $"FIDO2 PIN for {keyName}: ";

    public static string NewPinPrompt(string keyName) => $"New FIDO2 PIN for {keyName}: ";

    public const string RepeatPrompt = "Repeat the new FIDO2 PIN: ";

    public const string MismatchText = "The two PINs differ; type the new PIN again.";

    public const string TooShortText = "A FIDO2 PIN has at least 4 characters; type a longer one.";

    /// <summary>CTAP2: a PIN is at most 63 bytes of UTF-8.</summary>
    public const int MaximumPinBytes = 63;

    public const string TooLongText = "A FIDO2 PIN has at most 63 bytes (UTF-8); type a shorter one.";

    /// <summary>Brief T54: a new PIN must be text, so it can be put in NFC and counted in characters.</summary>
    public const string NotUtf8Text = "A FIDO2 PIN must be text (UTF-8); type it again.";

    /// <summary>
    /// Brief T54, CTAP 2.1 §6.5.1: "PIN MUST NOT end in a 0x00 byte" (setPIN pads with 0x00, so such a PIN can't be told
    /// from a shorter one). Refused before anything is sent: a try would cost one of the key's PIN retries.
    /// </summary>
    public const string EndsInNulText = "A FIDO2 PIN can't end in a NUL character; type it again.";

    /// <summary>Whether a person can answer at a terminal here.</summary>
    public static bool HasTerminal(CommandContext ctx)
    {
        using var terminal = ctx.Terminal?.Invoke();
        return terminal is not null;
    }

    /// <summary>The PIN source for <paramref name="ctx"/>'s terminal, or null when there is none.</summary>
    public static Fido2Pin? For(CommandContext ctx)
    {
        if (!HasTerminal(ctx))
            return null;
        return request =>
        {
            using var terminal = ctx.Terminal?.Invoke();
            if (terminal is null)
                return [];
            return request.NewPin ? AskNew(terminal, request.KeyName) : Ask(terminal, Prompt(request.KeyName));
        };
    }

    /// <summary>
    /// An existing PIN (brief T54): in NFC (<see cref="NormalisePin"/>); one ending in a NUL byte is zeroed and asked
    /// again with <see cref="EndsInNulText"/>, nothing sent. No second try with the raw bytes after the key refuses a
    /// PIN (owner decision 4).
    /// </summary>
    private static byte[] Ask(ITerminal terminal, string prompt)
    {
        while (true)
        {
            var pin = Read(terminal, prompt);
            if (pin.Length == 0 || pin[^1] != 0)
                return pin;
            CryptographicOperations.ZeroMemory(pin);
            prompt = EndsInNulText + "\n" + prompt;
        }
    }

    /// <summary>One answer at the terminal, in NFC (<see cref="NormalisePin"/>); no bytes for an empty answer or the end of input.</summary>
    private static byte[] Read(ITerminal terminal, string prompt)
    {
        terminal.Write(prompt);
        return NormalisePin(terminal.ReadSecret() ?? []);
    }

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>The PIN's text when its bytes are valid UTF-8 (strict decode), else null.</summary>
    private static string? Decode(byte[] pin)
    {
        try
        {
            return StrictUtf8.GetString(pin);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    /// <summary>
    /// Brief T54, CTAP 2.1 §6.5.1 (a platform sends the PIN in Unicode normal form C): the PIN as the key expects it. Bytes all
    /// below 0x80 come back as they are (no string is made, so a numeric PIN never becomes one); valid UTF-8 with no lone
    /// surrogate comes back as the UTF-8 of its NFC, and <paramref name="pin"/> is zeroed; anything else comes back as
    /// it is. The managed strings made for a non-ASCII PIN (the decoded text and its NFC) can't be zeroed: as for the
    /// vault password (<c>VaultPasswordKdf</c>), that window is best effort.
    /// </summary>
    internal static byte[] NormalisePin(byte[] pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        if (System.Text.Ascii.IsValid(pin))
            return pin;
        // A strict decode never yields a lone surrogate (UTF-8 can't encode one), so the text can always be normalised.
        if (Decode(pin) is not { } text)
            return pin;
        var normalised = Encoding.UTF8.GetBytes(text.Normalize(NormalizationForm.FormC));
        CryptographicOperations.ZeroMemory(pin);
        return normalised;
    }

    private static byte[] AskNew(ITerminal terminal, string keyName)
    {
        var prompt = NewPinPrompt(keyName);
        while (true)
        {
            // Brief T54: every check is on the normalised (NFC) bytes.
            var first = Read(terminal, prompt);
            if (first.Length == 0)
                return first;
            var refusal = Decode(first) is not { } text ? NotUtf8Text
                : text.EnumerateRunes().Count() < MinimumPinLength ? TooShortText
                // Asked again before anything is sent: the key would refuse it.
                : first.Length > MaximumPinBytes ? TooLongText
                : first[^1] == 0 ? EndsInNulText
                : null;
            if (refusal is not null)
            {
                CryptographicOperations.ZeroMemory(first);
                prompt = refusal + "\n" + NewPinPrompt(keyName);
                continue;
            }
            // The repeat in NFC too, so one typed in the other spelling matches.
            var second = Read(terminal, RepeatPrompt);
            if (second.Length == 0)
            {
                CryptographicOperations.ZeroMemory(first);
                return second;
            }
            var same = CryptographicOperations.FixedTimeEquals(first, second);
            CryptographicOperations.ZeroMemory(second);
            if (same)
                return first;
            CryptographicOperations.ZeroMemory(first);
            prompt = MismatchText + "\n" + NewPinPrompt(keyName);
        }
    }
}
