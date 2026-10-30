namespace TswapCore.Broker;

/// <summary>The broker's fixed limits (decision 7). Tests read them; nothing configures them.</summary>
public sealed record BrokerLimits
{
    public int PerSocketInFlight { get; init; } = 4;
    public int TotalInFlight { get; init; } = 8;
    public int MaxQueued { get; init; } = 16;
    public TimeSpan MaxQueueWait { get; init; } = TimeSpan.FromSeconds(30);
    public int FailuresBeforeLockout { get; init; } = 3;
    public TimeSpan Lockout { get; init; } = TimeSpan.FromMinutes(5);
    public int MaxUnlocksPerMinute { get; init; } = 30;
}

/// <summary>
/// Request slots (decision 7): at most <see cref="BrokerLimits.PerSocketInFlight"/> requests in
/// flight per socket and <see cref="BrokerLimits.TotalInFlight"/> in total; a request waiting for a
/// slot joins a bounded queue (<see cref="BrokerLimits.MaxQueued"/>) and waits at most
/// <see cref="BrokerLimits.MaxQueueWait"/> on the injected clock. No slot means <c>503</c>.
/// </summary>
public sealed class BrokerLimiter(BrokerLimits limits, TimeProvider time)
{
    private readonly SemaphoreSlim _total = new(limits.TotalInFlight, limits.TotalInFlight);
    private readonly Dictionary<string, SemaphoreSlim> _perSocket = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();
    private int _queued;

    /// <summary>Requests waiting for a slot now.</summary>
    public int Queued => Volatile.Read(ref _queued);

    /// <summary>Raised with the new queue length whenever it changes (tests wait on it instead of sleeping).</summary>
    public event Action<int>? QueueChanged;

    /// <summary>A slot for <paramref name="socket"/>, or null (queue full or waited too long): answer 503.</summary>
    public async Task<IDisposable?> TryAcquireAsync(string socket, CancellationToken aborted)
    {
        SemaphoreSlim perSocket;
        lock (_gate)
        {
            if (!_perSocket.TryGetValue(socket, out perSocket!))
                _perSocket[socket] = perSocket = new SemaphoreSlim(limits.PerSocketInFlight, limits.PerSocketInFlight);
        }

        // The fast path: free slots now, no queueing.
        if (perSocket.Wait(0))
        {
            if (_total.Wait(0))
                return new Slot(perSocket, _total);
            perSocket.Release();
        }

        var queued = Interlocked.Increment(ref _queued);
        if (queued > limits.MaxQueued)
        {
            Interlocked.Decrement(ref _queued);
            return null;
        }
        QueueChanged?.Invoke(queued);
        using var deadline = new CancellationTokenSource(limits.MaxQueueWait, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token, aborted);
        var holdsSocket = false;
        try
        {
            await perSocket.WaitAsync(linked.Token).ConfigureAwait(false);
            holdsSocket = true;
            await _total.WaitAsync(linked.Token).ConfigureAwait(false);
            return new Slot(perSocket, _total);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !aborted.IsCancellationRequested)
        {
            if (holdsSocket) perSocket.Release();
            return null;
        }
        catch
        {
            if (holdsSocket) perSocket.Release();
            throw;
        }
        finally
        {
            var left = Interlocked.Decrement(ref _queued); // not inside ?.Invoke(): that would skip it with no subscriber
            QueueChanged?.Invoke(left);
        }
    }

    private sealed class Slot(SemaphoreSlim perSocket, SemaphoreSlim total) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            total.Release();
            perSocket.Release();
        }
    }
}

/// <summary>
/// Unlock failure limits (decision 7): after <see cref="BrokerLimits.FailuresBeforeLockout"/> failed
/// unlocks in a row on one socket, that socket is refused for <see cref="BrokerLimits.Lockout"/>;
/// and no more than <see cref="BrokerLimits.MaxFailedUnlocksPerMinute"/> failed unlocks a minute in
/// total. Only failed unlocks count, never refusals. Times come from the injected clock.
/// </summary>
public sealed class BrokerUnlockGuard(BrokerLimits limits, TimeProvider time)
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, (int Failures, DateTimeOffset LockedUntil)> _sockets = new(StringComparer.Ordinal);
    private readonly Queue<DateTimeOffset> _recentAttempts = new();

    /// <summary>Why an unlock may not be tried now (<c>locked-out</c>, <c>unlock-rate</c>), or null when it may.</summary>
    public string? Refusal(string socket)
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            if (_sockets.TryGetValue(socket, out var state) && state.LockedUntil > now)
                return "locked-out";
            Prune(now);
            if (_recentAttempts.Count >= limits.MaxUnlocksPerMinute)
                return "unlock-rate";
            return null;
        }
    }

    /// <summary>Records an unlock attempt (counted by the global per-minute limit, whatever its outcome).</summary>
    public void RecordAttempt()
    {
        var now = time.GetUtcNow();
        lock (_gate)
            _recentAttempts.Enqueue(now);
    }

    /// <summary>Records a failed unlock; returns true when it locked <paramref name="socket"/> out.</summary>
    public bool RecordFailure(string socket)
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            var failures = (_sockets.TryGetValue(socket, out var state) ? state.Failures : 0) + 1;
            if (failures >= limits.FailuresBeforeLockout)
            {
                _sockets[socket] = (0, now + limits.Lockout);
                return true;
            }
            _sockets[socket] = (failures, state.LockedUntil);
            return false;
        }
    }

    /// <summary>Records a successful unlock: the socket's run of failures ends.</summary>
    public void RecordSuccess(string socket)
    {
        lock (_gate)
            _sockets.Remove(socket);
    }

    private void Prune(DateTimeOffset now)
    {
        while (_recentAttempts.Count > 0 && _recentAttempts.Peek() <= now - TimeSpan.FromMinutes(1))
            _recentAttempts.Dequeue();
    }
}
