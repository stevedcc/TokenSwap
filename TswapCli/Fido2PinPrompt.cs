using System.Security.Cryptography;
using TswapCore.Vault.Fido2;

namespace TswapCli;

/// <summary>
/// FIDO2 plan, task 6: the terminal's <see cref="Fido2Pin"/>, for enrolment now and for unlock (task 7). Null when
/// there is no terminal (<see cref="CommandContext.Terminal"/> gives none), which <see cref="IFido2Service"/> refuses
/// before any key call. Each request opens the terminal, asks there (no echo on Linux and macOS, read from
/// <c>/dev/tty</c>, so stdin may carry something else) and closes it again. A new PIN is asked twice and asked again
/// while the two differ or it is too short; an empty answer or the end of input returns no bytes (a cancellation).
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

    private static byte[] Ask(ITerminal terminal, string prompt)
    {
        terminal.Write(prompt);
        return terminal.ReadSecret() ?? [];
    }

    private static byte[] AskNew(ITerminal terminal, string keyName)
    {
        var prompt = NewPinPrompt(keyName);
        while (true)
        {
            var first = Ask(terminal, prompt);
            if (first.Length == 0)
                return first;
            if (System.Text.Encoding.UTF8.GetCharCount(first) < MinimumPinLength)
            {
                CryptographicOperations.ZeroMemory(first);
                prompt = TooShortText + "\n" + NewPinPrompt(keyName);
                continue;
            }
            var second = Ask(terminal, RepeatPrompt);
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
