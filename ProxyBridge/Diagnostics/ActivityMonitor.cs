using System.Diagnostics;
using System.Threading.Channels;

namespace ProxyBridge;

internal sealed class ActivityMonitor : IDisposable
{
    readonly SemaphoreSlim lifecycle = new(1, 1);
    readonly Func<IActivityEventSource> sourceFactory;
    readonly Func<int, DateTimeOffset, ActivityProcessIdentity?> resolver;
    readonly IActivitySink? suppliedSink;
    readonly int capacity, batchSize;
    readonly TimeSpan interval;
    readonly bool captureBaseline;
    readonly object enqueueGate = new();
    sealed record QueuedEvent(ActivityEvent Value, long Epoch);
    IActivityEventSource? source;
    Action<Exception>? sourceFault;
    IActivitySink? sink;
    Channel<QueuedEvent>? queue;
    Task? writer;
    volatile bool accepting, running, disposed;
    string? lastError;
    long accepted, written, dropped, aggregationDropped;
    long queueEpoch, generation;
    public bool Running => running;
    public string FilePath
    {
        get;
    }
    public string? LastError => Volatile.Read(ref lastError);
    public event Action? StateChanged;
    public ActivityMonitorCounters Counters => new(Interlocked.Read(ref accepted), Interlocked.Read(ref written),
        Interlocked.Read(ref dropped), Interlocked.Read(ref aggregationDropped));

    public ActivityMonitor() : this(() => new ActivityEventSource()) { }
    internal ActivityMonitor(Func<IActivityEventSource> sourceFactory, IActivitySink? sink = null,
        Func<int, DateTimeOffset, ActivityProcessIdentity?>? resolver = null,
        int queueCapacity = 8192, int batchSize = 128, TimeSpan? flushInterval = null,
        bool captureBaseline = true)
    {
        if (queueCapacity < 1 || batchSize < 1 || batchSize > 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(queueCapacity));
        }

        this.sourceFactory = sourceFactory;
        suppliedSink = sink;
        this.resolver = resolver ?? ActivityJournal.ResolveProcess;
        capacity = queueCapacity;
        this.batchSize = batchSize;
        interval = flushInterval ?? TimeSpan.FromSeconds(1);
        if (interval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(flushInterval));
        }

        this.captureBaseline = captureBaseline;
        FilePath = sink?.FilePath ?? Path.Combine(Settings.DataDir, "ProxyBridge-activity.log");
    }
    void Notify()
    {
        try
        {
            StateChanged?.Invoke();
        }
        catch { }
    }
    void SetError(Exception error)
    {
        Volatile.Write(ref lastError, AppLog.ExceptionCodes(error));
        Notify();
    }
    void OnFault(Exception error, long ownerGeneration)
    {
        _ = Task.Run(async () =>
        {
            await lifecycle.WaitAsync().ConfigureAwait(false);
            try
            {
                if (Interlocked.Read(ref generation) != ownerGeneration)
                {
                    return;
                }

                SetError(error);
                await StopCore().ConfigureAwait(false);
            }
            finally { lifecycle.Release(); Notify(); }
        });
    }
    async Task StopGenerationAsync(long ownerGeneration)
    {
        await lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            if (Interlocked.Read(ref generation) == ownerGeneration)
            {
                await StopCore().ConfigureAwait(false);
            }
        }
        finally { lifecycle.Release(); Notify(); }
    }
    void Enqueue(ActivityEvent value)
    {
        lock (enqueueGate)
        {
            if (!accepting)
            {
                return;
            }

            if (queue?.Writer.TryWrite(new(value, queueEpoch)) == true)
            {
                Interlocked.Increment(ref accepted);
            }
            else
            {
                Interlocked.Increment(ref dropped);
                queueEpoch++;
            }
        }
    }
    public async Task StartAsync()
    {
        await lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            if (disposed || running)
            {
                return;
            }

            if (source != null)
            {
                await StopCore().ConfigureAwait(false);
            }

            Volatile.Write(ref lastError, null);
            try
            {
                if (suppliedSink == null)
                {
                    Settings.PrepareDirectory();
                }

                sink = suppliedSink ?? new ActivityFileSink(FilePath);
                queue = Channel.CreateBounded<QueuedEvent>(new BoundedChannelOptions(capacity)
                {
                    SingleReader = true,
                    SingleWriter = false,
                    FullMode = BoundedChannelFullMode.Wait
                });
                long ownerGeneration = Interlocked.Increment(ref generation);
                lock (enqueueGate)
                {
                    queueEpoch = 0;
                }

                source = sourceFactory();
                sourceFault = error => OnFault(error, ownerGeneration);
                source.Event += Enqueue;
                source.Fault += sourceFault;
                // Queue is bounded even before the reader is scheduled.
                accepting = true;
                await Task.Run(source.Start).ConfigureAwait(false);
                if (captureBaseline)
                {
                    CaptureProcesses();
                }

                running = true;
                writer = Task.Run(() => WriteLoop(ownerGeneration));
            }
            catch (Exception ex)
            {
                SetError(ex);
                await StopCore().ConfigureAwait(false);
            }
        }
        finally { lifecycle.Release(); Notify(); }
    }
    void CaptureProcesses()
    {
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    try
                    {
                        Enqueue(new(DateTimeOffset.Now, "process.present", process.Id, process.ProcessName));
                    }
                    catch { }
                }
            }
        }
        catch (Exception ex) { SetError(ex); }
    }
    async Task WriteLoop(long ownerGeneration)
    {
        var channel = queue!;
        var journal = new ActivityJournal(resolver);
        var pending = new List<string>(batchSize);
        var watch = Stopwatch.StartNew();
        TimeSpan lastFlows = TimeSpan.Zero, lastStats = TimeSpan.Zero, lastWrite = TimeSpan.Zero;
        long lastDrops = -1, attributedEpoch = 0, attributedTraceLost = 0;
        void Flush()
        {
            if (pending.Count == 0)
            {
                return;
            }

            sink!.WriteBatch(pending);
            Interlocked.Add(ref written, pending.Count);
            pending.Clear();
            lastWrite = watch.Elapsed;
        }
        void Add(string record)
        {
            DiagnosticJournal.RecordActivityLine(record);
            pending.Add(record);
            if (pending.Count >= batchSize)
            {
                Flush();
            }
        }
        void Stats()
        {
            ActivityTraceStats? trace = null;
            try
            {
                trace = source?.ReadStats();
            }
            catch (Exception ex) { SetError(ex); }
            long traceLost = (trace?.EventsLost ?? 0) + (trace?.RealTimeBuffersLost ?? 0) + (trace?.CallbackErrors ?? 0);
            if (traceLost > attributedTraceLost)
            {
                // Mark a FIFO boundary. Already queued lifecycle records must
                // not rebuild a cache that survives into post-gap events.
                lock (enqueueGate)
                {
                    queueEpoch++;
                }

                attributedTraceLost = traceLost;
                Add(ActivityJournal.Diagnostic("monitor.attribution-gap", new
                {
                    reason = "etw-loss",
                    traceLost
                }));
            }
            Add(ActivityJournal.Diagnostic("monitor.counters", new
            {
                accepted = Interlocked.Read(ref accepted),
                dropped = Interlocked.Read(ref dropped),
                aggregationDropped = journal.AggregationDropped,
                trace
            }));
            Interlocked.Exchange(ref aggregationDropped, journal.AggregationDropped);
        }
        try
        {
            Add(ActivityJournal.Diagnostic("monitor.start", new
            {
                processId = Environment.ProcessId,
                metadataOnly = true,
                flowWindowSeconds = 5,
                queueCapacity = capacity,
                note = "TCP events are not HTTP results; UDP is aggregated; gaps are reported"
            }));
            Task<bool>? ready = null;
            while (true)
            {
                ready ??= channel.Reader.WaitToReadAsync().AsTask();
                await Task.WhenAny(ready, Task.Delay(interval)).ConfigureAwait(false);
                int count = 0;
                while (count++ < 2048 && channel.Reader.TryRead(out var queuedEvent))
                {
                    if (queuedEvent.Epoch != attributedEpoch)
                    {
                        foreach (string record in journal.FlushFlows())
                        {
                            Add(record);
                        }

                        journal.InvalidateAttribution();
                        attributedEpoch = queuedEvent.Epoch;
                        Add(ActivityJournal.Diagnostic("monitor.attribution-gap", new
                        {
                            reason = "queue-epoch",
                            epoch = attributedEpoch,
                            queueDrops = Interlocked.Read(ref dropped)
                        }));
                    }
                    foreach (string record in journal.Accept(queuedEvent.Value))
                    {
                        Add(record);
                    }
                }
                if (watch.Elapsed - lastFlows >= TimeSpan.FromSeconds(5))
                {
                    foreach (string record in journal.FlushFlows())
                    {
                        Add(record);
                    }

                    lastFlows = watch.Elapsed;
                }
                if (watch.Elapsed - lastStats >= TimeSpan.FromSeconds(10) || lastDrops != Interlocked.Read(ref dropped))
                {
                    Stats();
                    lastStats = watch.Elapsed;
                    lastDrops = Interlocked.Read(ref dropped);
                }
                if (watch.Elapsed - lastWrite >= interval)
                {
                    Flush();
                }

                if (ready.IsCompleted)
                {
                    bool more = await ready.ConfigureAwait(false);
                    ready = null;
                    if (!more && channel.Reader.Completion.IsCompleted)
                    {
                        break;
                    }
                }
            }
            foreach (string record in journal.FlushFlows())
            {
                Add(record);
            }

            Stats();
            Add(ActivityJournal.Diagnostic("monitor.stop"));
            Flush();
        }
        catch (Exception ex)
        {
            accepting = false;
            running = false;
            SetError(ex);
            channel.Writer.TryComplete();
            _ = Task.Run(() => StopGenerationAsync(ownerGeneration));
        }
    }
    public async Task StopAsync()
    {
        await lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            await StopCore().ConfigureAwait(false);
        }
        finally { lifecycle.Release(); Notify(); }
    }
    async Task StopCore()
    {
        if (source != null)
        {
            // Native Stop flushes final ETW buffers. Keep the queue open until
            // the consumer has drained them, including short process exits.
            try
            {
                await Task.Run(source.Stop).ConfigureAwait(false);
            }
            catch (Exception ex) { SetError(ex); }
            source.Event -= Enqueue;
            if (sourceFault != null)
            {
                source.Fault -= sourceFault;
            }
        }
        accepting = false;
        queue?.Writer.TryComplete();
        if (writer != null)
        {
            try
            {
                await writer.ConfigureAwait(false);
            }
            catch (Exception ex) { SetError(ex); }
        }
        if (source != null)
        {
            try
            {
                source.Dispose();
            }
            catch (Exception ex) { SetError(ex); }
        }
        try
        {
            sink?.Dispose();
        }
        catch (Exception ex) { SetError(ex); }
        source = null;
        sourceFault = null;
        sink = null;
        writer = null;
        queue = null;
        running = false;
    }
    public void Dispose()
    {
        disposed = true;
        var stop = StopAsync();
        // A stalled diagnostic disk must not indefinitely delay MainForm's
        // Guard/Engine cleanup. The same serialized cleanup continues in the
        // background; disposed forbids a new writer from racing the old one.
        if (!stop.Wait(TimeSpan.FromSeconds(2)))
        {
            SetError(new TimeoutException("Activity journal shutdown exceeded its UI budget."));
        }
        else
        {
            stop.GetAwaiter().GetResult();
        }
    }
}
