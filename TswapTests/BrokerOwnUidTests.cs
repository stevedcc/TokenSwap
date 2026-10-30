using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T9 decision 1 (the load-bearing assumption: no container runs with the vault user's uid):
/// the socket layer refuses a peer whose uid is the broker's own, even when that uid is on the
/// socket's list. The in-process harness connects as its own uid, so every other broker test turns
/// the refusal off (<c>AllowOwnUidForTests</c>, which the binary sets only in a Debug build with a
/// test key).
/// </summary>
public class BrokerOwnUidTests : IAsyncDisposable
{
    private readonly BrokerHarness _h = new();

    public ValueTask DisposeAsync() => _h.DisposeAsync();

    [Fact]
    public async Task APeerWithTheBrokersOwnUid_IsClosedUnanswered_AndLogged_EvenWhenListed()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        await _h.StartAsync(allowOwnUid: false); // lane1 lists this uid

        var response = await _h.SendRawAsync("lane1", "GET /echo/a HTTP/1.1\r\nHost: broker\r\n\r\n");

        Assert.Empty(response);
        Assert.Equal(0, _h.Secrets.Unlocks);
        Assert.Equal(0, _h.FakeForwarder.Calls);
        Assert.Contains($"refused-connection socket=lane1 uid={BrokerHarness.MyUid} pid={Environment.ProcessId} reason=own-uid", _h.LogText.ToString());
    }

    [Fact]
    public async Task WithTheTestSeam_TheSameRequestIsAnswered()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only
        await _h.StartAsync(allowOwnUid: true);

        var response = await _h.GetAsync("lane1", "/echo/a");

        Assert.Equal(200, BrokerHarness.StatusOf(response));
        Assert.DoesNotContain("reason=own-uid", _h.LogText.ToString());
    }
}
