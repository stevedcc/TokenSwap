using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>#299: one rule for every yes/no question.</summary>
public class YesNoTests
{
    [Theory]
    [InlineData(true, "(Y/n)")]
    [InlineData(false, "(y/N)")]
    [InlineData(null, "(yes/no)")]
    public void Hint_CapitalIsTheDefault_YesNoHasNone(bool? defaultAnswer, string hint) =>
        Assert.Equal(hint, YesNo.Hint(defaultAnswer));

    [Theory]
    [InlineData("y", true)]
    [InlineData("Yes", true)]
    [InlineData(" YES ", true)]
    [InlineData("n", false)]
    [InlineData("No", false)]
    [InlineData(" NO\r", false)]
    public void Parse_AcceptsTheShortAndLongFormsInAnyCase(string answer, bool expected)
    {
        Assert.Equal(expected, YesNo.Parse(answer, defaultAnswer: null));
        Assert.Equal(expected, YesNo.Parse(answer, defaultAnswer: !expected)); // a default never overrides an answer
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Parse_Empty_IsTheDefault(bool defaultAnswer) => Assert.Equal(defaultAnswer, YesNo.Parse("  ", defaultAnswer));

    [Theory]
    [InlineData("", null)]
    [InlineData("maybe", true)]
    [InlineData("cccccdhevufr", false)] // a stray OTP (#293)
    [InlineData("yess", null)]
    public void Parse_AnythingElse_AsksAgain(string answer, bool? defaultAnswer) => Assert.Null(YesNo.Parse(answer, defaultAnswer));

    [Fact]
    public void Ask_RepeatsTheQuestionUntilYesOrNo()
    {
        var answers = new Queue<string?>(["maybe", "", "y"]);
        var prompts = new List<string>();

        var result = YesNo.Ask(prompts.Add, answers.Dequeue, "Overwrite?", defaultAnswer: null);

        Assert.True(result);
        Assert.Equal(["Overwrite? (yes/no): ", "Overwrite? (yes/no): ", "Overwrite? (yes/no): "], prompts);
    }

    [Fact]
    public void Ask_EndOfInput_IsTheGivenAnswer_NoByDefault()
    {
        Assert.False(YesNo.Ask(_ => { }, () => null, "Overwrite?", defaultAnswer: null));
        Assert.True(YesNo.Ask(_ => { }, () => null, "Carry on?", defaultAnswer: false, atEndOfInput: true));
    }
}
