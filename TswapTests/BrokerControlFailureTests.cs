using System.Reflection;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>
/// The message <c>broker unlock|lock|status</c> give for each control answer that isn't a success
/// (<c>BrokerCommand.Failure</c>), every case and null. Pinned before <see cref="BrokerControlAnswer"/> became a
/// <c>closed</c> record and the switch named each case (idiomatic .NET 11 plan, row 2). <c>Failure</c> is private,
/// so it is reached by reflection rather than by widening it.
/// </summary>
public class BrokerControlFailureTests
{
    private const string Path = "/run/tswap-broker/control.sock";
    private const string Unreadable = "The broker at /run/tswap-broker/control.sock gave an answer tswap can't read.";

    private static string Message(BrokerControlAnswer? answer)
    {
        var failure = typeof(BrokerCommand).GetMethod("Failure", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("BrokerCommand.Failure not found");
        var exception = Assert.IsType<TswapException>(failure.Invoke(null, [answer, Path]));
        return exception.Message;
    }

    [Fact]
    public void Refused_GivesTheBrokersOwnMessage() =>
        Assert.Equal("wrong password", Message(new BrokerControlAnswer.Refused("wrong password")));

    [Fact]
    public void NotRunning_SaysNoBrokerAnswers() =>
        Assert.Equal("No 'tswap broker serve' answers at /run/tswap-broker/control.sock; is it running?", Message(new BrokerControlAnswer.NotRunning()));

    [Fact]
    public void OtherVault_SaysAnotherVaultsBrokerAnswers() =>
        Assert.Equal("Another vault's broker answers at /run/tswap-broker/control.sock.", Message(new BrokerControlAnswer.OtherVault()));

    [Fact]
    public void Malformed_IsAnAnswerTswapCantRead() =>
        Assert.Equal(Unreadable, Message(new BrokerControlAnswer.Malformed()));

    [Fact]
    public void Done_WhereAFailureIsExpected_IsAnAnswerTswapCantRead() =>
        Assert.Equal(Unreadable, Message(new BrokerControlAnswer.Done()));

    [Fact]
    public void State_WhereAFailureIsExpected_IsAnAnswerTswapCantRead() =>
        Assert.Equal(Unreadable, Message(new BrokerControlAnswer.State(true, null, 0)));

    [Fact]
    public void Null_IsAnAnswerTswapCantRead() =>
        Assert.Equal(Unreadable, Message(null));
}
