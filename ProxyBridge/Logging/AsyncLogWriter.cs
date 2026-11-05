using System.Diagnostics;
using System.Threading.Channels;

namespace ProxyBridge;

internal sealed record AsyncLogStats(long Accepted, long Written, long Dropped, long Failures,
    long QueueDepth, long QueueHighWater, long LastWriteMs, long WriteInFlightMs, string? LastError);

internal sealed class AsyncLogWriter : IDisposable
{
    sealed record Pending(LogFileEntry Entry, TaskCompletionSource<bool>? Receipt);
    readonly Channel<Pending> queue;
    readonly Func<IReadOnlyList<LogFileEntry>, bool> write;
    readonly Func<string?> error;
    readonly Task worker;
    long accepted, written, dropped, failures, depth, highWater, lastWriteMs, writeStarted;
    string? lastError;
    int disposed;
    public AsyncLogWriter(Func<IReadOnlyList<LogFileEntry>, bool> write, Func<string?>? error = null, int capacity = 2048)
    {
        this.write = write;
        this.error = error ?? (() => "log-write-failed");
        queue = Channel.CreateBounded<Pending>(new BoundedChannelOptions(capacity) { SingleReader = true });
        worker = Task.Run(Loop);
    }
    public AsyncLogStats Stats
    {
        get
        {
            long started = Interlocked.Read(ref writeStarted);
            return new(Interlocked.Read(ref accepted), Interlocked.Read(ref written), Interlocked.Read(ref dropped),
                Interlocked.Read(ref failures), Interlocked.Read(ref depth), Interlocked.Read(ref highWater),
                Interlocked.Read(ref lastWriteMs), started == 0 ? 0 : (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds,
                Volatile.Read(ref lastError));
        }
    }
    bool Enqueue(LogFileEntry entry, TaskCompletionSource<bool>? receipt)
    {
        long current = Interlocked.Increment(ref depth);
        if (Volatile.Read(ref disposed) != 0 || !queue.Writer.TryWrite(new(entry, receipt)))
        {
            Interlocked.Decrement(ref depth);
            Interlocked.Increment(ref dropped);
            receipt?.TrySetResult(false);
            return false;
        }
        Interlocked.Increment(ref accepted);
        long old;
        do
        {
            old = Interlocked.Read(ref highWater);
            if (old >= current)
            {
                break;
            }
        }
        while (Interlocked.CompareExchange(ref highWater, current, old) != old);
        return true;
    }
    public bool TryWrite(LogFileEntry entry) => Enqueue(entry, null);
    public async Task<bool> WriteConfirmedAsync(LogFileEntry entry, CancellationToken token = default)
    {
        var receipt = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!Enqueue(entry, receipt))
        {
            return false;
        }

        try
        {
            return await receipt.Task.WaitAsync(TimeSpan.FromSeconds(2), token).ConfigureAwait(false);
        }
        catch (TimeoutException) { return false; }
        // Cancellation/timeout does not imply that an already queued record
        // cannot be written later. The caller retains its note until confirmed.
    }
    async Task Loop()
    {
        var pending = new List<Pending>(128);
        while (await queue.Reader.WaitToReadAsync().ConfigureAwait(false))
        {
            // Coalesce bursts into a single disk flush; confirmed user notes
            // share the same ordered writer and receive an actual disk result.
            await Task.Delay(100).ConfigureAwait(false);
            while (pending.Count < 128 && queue.Reader.TryRead(out var entry))
            {
                Interlocked.Decrement(ref depth);
                pending.Add(entry);
            }
            long began = Stopwatch.GetTimestamp();
            Interlocked.Exchange(ref writeStarted, began);
            bool success = false;
            try
            {
                success = write(pending.Select(p => p.Entry).ToArray());
                if (success)
                {
                    Interlocked.Add(ref written, pending.Count);
                    Volatile.Write(ref lastError, null);
                }
                else
                {
                    Interlocked.Increment(ref failures);
                    Volatile.Write(ref lastError, error());
                }
            }
            catch (Exception ex) { Interlocked.Increment(ref failures); Volatile.Write(ref lastError, ex.GetType().Name); }
            finally { Interlocked.Exchange(ref lastWriteMs, (long)Stopwatch.GetElapsedTime(began).TotalMilliseconds); Interlocked.Exchange(ref writeStarted, 0); }
            foreach (var item in pending)
            {
                item.Receipt?.TrySetResult(success);
            }

            pending.Clear();
        }
    }
    public async Task StopAsync(TimeSpan budget)
    {
        Interlocked.Exchange(ref disposed, 1);
        queue.Writer.TryComplete();
        try
        {
            await worker.WaitAsync(budget).ConfigureAwait(false);
        }
        catch (TimeoutException) { Volatile.Write(ref lastError, "shutdown-timeout"); }
    }
    public void Dispose() => StopAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
}
