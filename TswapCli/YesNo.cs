namespace TswapCli;

/// <summary>
/// #299: every yes/no question takes the same answers. <c>(Y/n)</c> and <c>(y/N)</c> have a default (the capital
/// letter), which Enter alone gives; <c>(yes/no)</c> has none and is asked where a wrong answer destroys or exposes
/// something. Every form accepts <c>y</c>, <c>yes</c>, <c>n</c> and <c>no</c> in any case; anything else (an empty
/// answer without a default included) is asked again, so stray characters typed ahead (#293) never count as an answer.
/// </summary>
internal static class YesNo
{
    /// <summary>
    /// A question and its default together, so the hint shown and the default applied can't drift apart (review of
    /// PR #214).
    /// </summary>
    internal sealed record Question(string Text, bool? Default)
    {
        public string Prompt => YesNo.Prompt(Text, Default);

        public bool? Parse(string answer) => YesNo.Parse(answer, Default);
    }

    /// <summary>
    /// How many answers that are neither yes nor no <see cref="Ask"/> takes before it gives up with its end-of-input
    /// answer: a person gets several tries, and endless redirected garbage (<c>yes maybe | tswap ...</c>) still ends
    /// (review of PR #214).
    /// </summary>
    public const int MaxUnrecognisedAnswers = 5;

    /// <summary>The hint for a question with <paramref name="defaultAnswer"/>: <c>(Y/n)</c>, <c>(y/N)</c> or <c>(yes/no)</c>.</summary>
    public static string Hint(bool? defaultAnswer) => defaultAnswer switch
    {
        true => "(Y/n)",
        false => "(y/N)",
        null => "(yes/no)",
    };

    /// <summary><paramref name="question"/> with its hint and the colon: "Add a recovery slot? (Y/n): ".</summary>
    public static string Prompt(string question, bool? defaultAnswer) => $"{question} {Hint(defaultAnswer)}: ";

    /// <summary>True for yes, false for no, null when the answer is neither (ask again).</summary>
    public static bool? Parse(string answer, bool? defaultAnswer) => answer.Trim().ToLowerInvariant() switch
    {
        "y" or "yes" => true,
        "n" or "no" => false,
        "" when defaultAnswer is { } given => given,
        _ => null,
    };

    /// <summary>
    /// Asks <paramref name="question"/> until the answer is yes or no. At the end of input (a closed stdin, a script
    /// that ran out of answers), and after <see cref="MaxUnrecognisedAnswers"/> answers that are neither, the answer
    /// is <paramref name="atEndOfInput"/>: for a question without a default that is "no", the cancel.
    /// </summary>
    public static bool Ask(Action<string> write, Func<string?> read, string question, bool? defaultAnswer, bool atEndOfInput = false) =>
        Ask(write, read, new Question(question, defaultAnswer), atEndOfInput);

    /// <inheritdoc cref="Ask(Action{string}, Func{string?}, string, bool?, bool)"/>
    public static bool Ask(Action<string> write, Func<string?> read, Question question, bool atEndOfInput = false)
    {
        for (var unrecognised = 0; unrecognised < MaxUnrecognisedAnswers; unrecognised++)
        {
            write(question.Prompt);
            var line = read();
            if (line is null)
                return atEndOfInput;
            if (question.Parse(line) is { } answer)
                return answer;
        }
        return atEndOfInput;
    }
}
