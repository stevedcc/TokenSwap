using System.Collections.Concurrent;
using Xunit;

namespace TswapTests;

/// <summary>
/// The broker tests' log writer (#383): the broker writes it from its own threads while a test reads or waits on it,
/// so every write and read holds one lock.
/// </summary>
public class ObservedLogTests
{
    [Fact]
    public void WaitForAsync_TextAlreadyWritten_CompletesAtOnce()
    {
        var log = new ObservedLog();
        log.WriteLine("alpha beta");

        var waited = log.WaitForAsync("beta");

        Assert.True(waited.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task WaitForAsync_TextWrittenLater_CompletesOnThatLine()
    {
        var log = new ObservedLog();
        var waited = log.WaitForAsync("gamma");

        log.WriteLine("other");
        Assert.False(waited.IsCompleted);

        log.WriteLine("x gamma y");
        await waited;
    }

    [Fact]
    public void EveryWriteOverload_ReachesTheText()
    {
        var log = new ObservedLog();

        log.Write('a');
        log.Write("b");
        log.Write(['c', 'd'], 1, 1);
        log.Write("e".AsSpan());
        log.WriteLine("f");
        log.WriteLine(42);

        Assert.Equal("abde" + "f" + log.NewLine + "42" + log.NewLine, log.ToString());
    }

    [Fact]
    public void Clear_EmptiesTheText()
    {
        var log = new ObservedLog();
        log.WriteLine("x");

        log.Clear();

        Assert.Equal("", log.ToString());
        Assert.False(log.WaitForAsync("x").IsCompleted);
    }

    [Fact]
    public async Task ConcurrentWritersAndAReader_KeepEveryLineWhole()
    {
        const int writers = 4;
        const int linesEach = 5000;
        var log = new ObservedLog();
        var errors = new ConcurrentQueue<Exception>();
        var expected = Enumerable.Range(0, writers)
            .SelectMany(i => Enumerable.Range(0, linesEach).Select(j => $"w{i}-{j}"))
            .ToHashSet();
        var torn = new ConcurrentQueue<string>();
        var waited = Task.Run(() => log.WaitForAsync("w3-4999"));
        using var start = new Barrier(writers + 1);
        var writersDone = 0;
        var written = 0;

        var writerThreads = Enumerable.Range(0, writers).Select(i => new Thread(() =>
        {
            try
            {
                start.SignalAndWait();
                for (var j = 0; j < linesEach; j++)
                {
                    log.WriteLine($"w{i}-{j}");
                    Interlocked.Increment(ref written);
                }
            }
            catch (Exception e)
            {
                errors.Enqueue(e);
            }
            finally
            {
                Interlocked.Increment(ref writersDone);
            }
        })).ToList();
        var reader = new Thread(() =>
        {
            try
            {
                start.SignalAndWait();
                // Each read copies the whole text inside the lock, so reading back to back holds the writers to about
                // one line per copy (seconds here, past the waiter's 30 s guard on a loaded machine). Between reads the
                // reader waits for 100 more lines instead: it still reads all through the writes.
                var spin = new SpinWait();
                while (Volatile.Read(ref writersDone) < writers)
                {
                    var before = Volatile.Read(ref written);
                    // Each snapshot holds whole lines only: every WriteLine lands as one unit, so the text ends with
                    // a line break and every line is one a writer wrote.
                    var snapshot = log.ToString();
                    if (snapshot.Length > 0 && !snapshot.EndsWith(log.NewLine, StringComparison.Ordinal))
                        torn.Enqueue($"snapshot ends mid-line: ...{snapshot[^Math.Min(20, snapshot.Length)..]}");
                    foreach (var line in snapshot.Split(log.NewLine, StringSplitOptions.RemoveEmptyEntries))
                        if (!expected.Contains(line))
                            torn.Enqueue(line);
                    while (Volatile.Read(ref written) - before < 100 && Volatile.Read(ref writersDone) < writers)
                        spin.SpinOnce();
                }
            }
            catch (Exception e)
            {
                errors.Enqueue(e);
            }
        });

        writerThreads.ForEach(t => t.Start());
        reader.Start();
        writerThreads.ForEach(t => t.Join());
        reader.Join();

        Assert.Empty(errors);
        Assert.Empty(torn);
        var lines = log.ToString().Split(log.NewLine, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(expected.Count, lines.Length);
        Assert.Equal(expected, lines.ToHashSet());
        await waited;
    }
}
