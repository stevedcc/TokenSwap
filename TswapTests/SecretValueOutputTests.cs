using TswapCli;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T52 (#403): on Windows, a command that prints a secret value or a filled file (<c>get</c>, <c>apply</c>)
/// writes a redirected stdout as UTF-8. Which commands those are, decided from the arguments as
/// <see cref="CommandRegistry.Dispatch"/> decides the command.
/// </summary>
public sealed class SecretValueOutputTests
{
    [Theory]
    [InlineData("get x")]
    [InlineData("apply f.yaml")]
    [InlineData("-v get x")]
    [InlineData("--verbose -v apply f")]
    [InlineData("GET x")]
    [InlineData("get --help")]
    public void PrintsSecretValues_GetOrApply_IsTrue(string commandLine) =>
        Assert.True(CommandRegistry.PrintsSecretValues(Args(commandLine)), commandLine);

    [Theory]
    [InlineData("")]
    [InlineData("-v")]
    [InlineData("run get")]
    [InlineData("run tswap get x")]
    [InlineData("names")]
    [InlineData("field show x")]
    [InlineData("nosuch")]
    [InlineData("--version")]
    public void PrintsSecretValues_AnyOtherCommand_IsFalse(string commandLine) =>
        Assert.False(CommandRegistry.PrintsSecretValues(Args(commandLine)), commandLine);

    /// <summary>The arguments of a space-separated command line ("" is none).</summary>
    private static string[] Args(string commandLine) => commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    /// <summary>A new command that prints a value must decide: add it here and set its <c>PrintsSecretValues</c>.</summary>
    [Fact]
    public void OnlyGetAndApplyPrintSecretValues() =>
        Assert.Equal(["apply", "get"], CommandRegistry.All.Where(c => c.PrintsSecretValues).Select(c => c.Name).Order());
}
