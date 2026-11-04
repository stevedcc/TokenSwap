namespace TswapCli;

/// <summary>Prompt helpers for the guided <c>init</c>.</summary>
public static class GuidedPrompts
{
    private const string Modhex = "cbdefghijklnrtuv";

    /// <summary>A Yubico OTP is 32–48 modhex characters.</summary>
    public static bool LooksLikeYubicoOtp(string line) =>
        line.Length is >= 32 and <= 48 && line.All(ch => Modhex.Contains(ch));

    /// <summary>
    /// Reads an answer, skipping lines that are a YubiKey's one-time code (touching a key's
    /// short-press slot types one into the terminal, ending in Enter). Null on end of input.
    /// </summary>
    public static string? ReadAnswer(IConsole c)
    {
        while (c.ReadLine() is { } line)
        {
            if (!LooksLikeYubicoOtp(line))
                return line;
            // Neutral: it can land at any prompt, also where no key is flashing.
            c.Out.WriteLine("That was a YubiKey's one-time code; it was ignored.");
        }
        return null;
    }
}
