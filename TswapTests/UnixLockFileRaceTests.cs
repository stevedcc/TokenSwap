using TswapCore.Agent;
using Xunit;

namespace TswapTests;

/// <summary>
/// #236: two concurrent takers of one lock file must end with exactly one holder. The lock files were opened with
/// FileShare.ReadWrite, for which .NET itself takes a shared flock at open, and then upgraded to an exclusive flock. A
/// flock conversion is not atomic (the old lock is dropped first), so two takers that both held the shared lock could
/// each see the other's and both give up: two `tswap agent start` (or two `broker serve`, two broker.json edits) at
/// once could leave nothing running. macOS CI hit it in AgentServerTests.TwoConcurrentStarts_... (PR #233).
/// </summary>
public class UnixLockFileRaceTests
{
    private const int Takers = 8;

    [Fact]
    public void ConcurrentTakers_ExactlyOneHoldsTheLock_EveryRound()
    {
        if (OperatingSystem.IsWindows())
            return; // flock is Unix
        var dir = Directory.CreateTempSubdirectory("tswap-lock-").FullName;
        try
        {
            var path = Path.Combine(dir, "agent.lock");
            var noWinner = 0;
            for (var round = 0; round < 2000; round++)
            {
                using var barrier = new Barrier(Takers);
                var results = new FileStream?[Takers];
                var threads = Enumerable.Range(0, Takers).Select(i => new Thread(() =>
                {
                    barrier.SignalAndWait();
                    results[i] = UnixLockFile.TryTake(path, out _);
                })).ToList();
                threads.ForEach(t => t.Start());
                threads.ForEach(t => t.Join());

                var holders = results.Count(r => r is not null);
                Assert.True(holders <= 1, $"round {round}: {holders} holders of one exclusive lock");
                if (holders == 0)
                    noWinner++;
                foreach (var r in results)
                    r?.Dispose();
            }
            Assert.True(noWinner == 0, $"{noWinner} of 2000 rounds ended with nobody holding the lock");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
