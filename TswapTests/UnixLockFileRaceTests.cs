using System.Collections.Concurrent;
using TswapCore.Agent;
using Xunit;

namespace TswapTests;

/// <summary>
/// #236: takers of one lock file must end with exactly one holder. The lock files were opened with FileShare.ReadWrite,
/// for which .NET itself takes a shared flock at open, and then upgraded to an exclusive flock. Upgrade semantics differ
/// by platform: Linux drops the shared lock first, so one taker always wins; where a failed upgrade keeps the shared
/// lock, two takers can each block the other and both give up. macOS CI hit that once in
/// AgentServerTests.TwoConcurrentStarts_... (PR #233). The lock is now taken exclusively at open, so nothing is upgraded.
/// The race test below never reproduced the old failure (Linux, and macOS CI run 41712707408): it guards the
/// invariant; the deterministic test pins the busy-lock path the fix now relies on.
/// </summary>
public class UnixLockFileRaceTests
{
    private const int Takers = 8;

    [Fact]
    public void ASecondTaker_WhileTheLockIsHeld_GetsNullAndHeldElsewhere_WithoutThrowing()
    {
        if (OperatingSystem.IsWindows())
            return; // flock is Unix
        var dir = Directory.CreateTempSubdirectory("tswap-lock-").FullName;
        try
        {
            var path = Path.Combine(dir, "agent.lock");
            using var first = UnixLockFile.TryTake(path, out var firstHeldElsewhere);
            Assert.NotNull(first);
            Assert.False(firstHeldElsewhere);

            // The open itself is refused now (EWOULDBLOCK as the IOException's HResult: 11 on Linux, 35 on macOS);
            // a wrong mapping would surface as "Can't open the lock file" (a TswapException) instead of null.
            var second = UnixLockFile.TryTake(path, out var secondHeldElsewhere);

            Assert.Null(second);
            Assert.True(secondHeldElsewhere);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

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
            var errors = new ConcurrentQueue<string>();
            for (var round = 0; round < 2000; round++)
            {
                using var barrier = new Barrier(Takers);
                var results = new FileStream?[Takers];
                var threads = Enumerable.Range(0, Takers).Select(i => new Thread(() =>
                {
                    try
                    {
                        if (!barrier.SignalAndWait(TimeSpan.FromSeconds(10)))
                            throw new TimeoutException("the barrier never filled");
                        results[i] = UnixLockFile.TryTake(path, out _);
                    }
                    catch (Exception ex)
                    {
                        errors.Enqueue($"round {round}, taker {i}: {ex.GetType().Name}: {ex.Message}");
                    }
                })).ToList();
                threads.ForEach(t => t.Start());
                threads.ForEach(t => t.Join());

                var holders = results.Count(r => r is not null);
                foreach (var r in results)
                    r?.Dispose();
                Assert.True(errors.IsEmpty, "a taker threw: " + string.Join("; ", errors.Take(3)));
                Assert.True(holders <= 1, $"round {round}: {holders} holders of one exclusive lock");
                if (holders == 0)
                    noWinner++;
            }
            Assert.True(noWinner == 0, $"{noWinner} of 2000 rounds ended with nobody holding the lock");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
