using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Threading.Channels;

namespace ProxyBridge;

// First-failure trigger touches only bounded in-memory data. All disk/native
// observations run elsewhere and must never delay a protection transition.
internal static class DiagnosticJournal
{
    static readonly DiagnosticRing Ring = new();
    static readonly DiagnosticIncidentGate Episodes = new();
    static readonly Channel<DiagnosticRingEntry> Output = Channel.CreateBounded<DiagnosticRingEntry>(1024);
    static readonly Channel<DiagnosticIncident> Incidents = Channel.CreateBounded<DiagnosticIncident>(2);
    static readonly string Session = Guid.NewGuid().ToString("N");
    static readonly JsonSerializerOptions Json = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };
    static DiagnosticContext? context;
    static CancellationTokenSource? cancellation;
    static Task? worker, sampler;
    static WfpBlockDiagnostics? wfp;
    static long queued, written, dropped, incidentDropped, errors, depth, highWater, lastWriteMs, writeStarted;
    static string? lastError;
    static int enabled, started, writerAvailable;
    public static bool Enabled => Volatile.Read(ref enabled) != 0;
    public static string FilePath => Path.Combine(Settings.DataDir, "ProxyBridge-diagnostics.log");
    public static string IncidentDirectory => Path.Combine(Settings.DataDir, "incidents");
    public static string? LastError => Volatile.Read(ref lastError);
    public static void UpdateContext(DiagnosticContext value)
    {
        Volatile.Write(ref context, value);
        Record("context", value, value.CapturedAt);
    }
    public static void Record(string kind, object? data = null, DateTimeOffset? eventTime = null, long? monoTicks = null)
        => RecordCore(kind, data, eventTime, monoTicks, null, useCurrentContext: true);
    static void RecordCore(string kind, object? data, DateTimeOffset? eventTime, long? monoTicks,
        DiagnosticContext? capturedContext, bool useCurrentContext)
    {
        if (!Enabled)
        {
            return;
        }

        try
        {
            var current = useCurrentContext ? Volatile.Read(ref context) : capturedContext;
            DateTimeOffset now = DateTimeOffset.UtcNow;
            long mono = Stopwatch.GetTimestamp();
            string json = AppLog.Redact(JsonSerializer.Serialize(new
            {
                schema = 1,
                session = Session,
                incident = Episodes.Current,
                kind,
                eventTime = eventTime ?? now,
                observedAt = now,
                monotonicTicks = monoTicks ?? mono,
                observedMonotonicTicks = mono,
                generation = current?.EngineGeneration,
                enginePid = current?.EnginePid,
                contextCapturedAt = current?.CapturedAt,
                contextChangedDuringSample = !useCurrentContext && !Equals(current, Volatile.Read(ref context)),
                operation = AppLog.CurrentOperation,
                data
            }, Json));
            var entry = Ring.Add(json, eventTime ?? now);
            if (entry == null)
            {
                return;
            }

            long currentDepth = Interlocked.Increment(ref depth);
            if (Output.Writer.TryWrite(entry))
            {
                Interlocked.Increment(ref queued);
                long old;
                do
                {
                    old = Interlocked.Read(ref highWater);
                    if (old >= currentDepth)
                    {
                        break;
                    }
                }
                while (Interlocked.CompareExchange(ref highWater, currentDepth, old) != old);
            }
            else
            {
                Interlocked.Decrement(ref depth);
                Interlocked.Increment(ref dropped);
            }
        }
        catch { Interlocked.Increment(ref errors); }
    }
    public static void RecordActivityLine(string line)
    {
        if (!Enabled)
        {
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(line);
            var value = document.RootElement;
            DateTimeOffset? time = value.TryGetProperty("time", out var timestamp) && timestamp.TryGetDateTimeOffset(out var parsed) ? parsed : null;
            Record("activity", value, time);
        }
        catch { Interlocked.Increment(ref errors); }
    }
    public static void Trigger(string reason, object? state = null)
    {
        if (!Enabled)
        {
            return;
        }

        try
        {
            string? id = Episodes.TryBegin();
            if (id == null)
            {
                return;
            }

            Record("incident.trigger", new
            {
                reason,
                state,
                note = "memory-only trigger; protection transition is not delayed"
            });
            var captured = new DiagnosticIncident(id, AppLog.Redact(reason), DateTimeOffset.UtcNow,
                Stopwatch.GetTimestamp(), Ring.Snapshot(), Volatile.Read(ref context));
            if (!Incidents.Writer.TryWrite(captured))
            {
                Interlocked.Increment(ref incidentDropped);
            }
        }
        catch { Interlocked.Increment(ref errors); }
    }
    public static void Start()
    {
        // One collector lifetime per process: completed channels are never reused.
        if (Interlocked.CompareExchange(ref started, 1, 0) != 0)
        {
            return;
        }

        Interlocked.Exchange(ref enabled, 1);
        cancellation = new();
        worker = Task.Run(WriteLoop);
        sampler = Task.Run(() => SampleLoop(cancellation.Token));
        Record("diagnostics.start", new
        {
            version = AppVersion.Display,
            timestampFrequency = Stopwatch.Frequency,
            preWindowSeconds = 60,
            postWindowSeconds = 30,
            ringBytes = 4_000_000,
            ringRecords = 4096,
            outputQueue = 1024,
            incidentQueue = 2,
            incidentMaxFiles = 5,
            incidentMaxBytes = 12_000_000,
            activeProbe = "test-only controlled transport; production collector does not bypass Guard"
        });
    }
    static void Error(Exception error)
    {
        Volatile.Write(ref lastError, AppLog.ExceptionCodes(error));
        Interlocked.Increment(ref errors);
    }
    static async Task WriteLoop()
    {
        try
        {
            BundledAssets.RejectReparsePoints(Settings.DataDir);
            Settings.PrepareDirectory();
            using var sink = new ActivityFileSink(FilePath);
            Interlocked.Exchange(ref writerAvailable, 1);
            var incidents = new DiagnosticIncidentStore(IncidentDirectory);
            string? activePath = null;
            long postUntil = 0, firstSequence = 0;
            var batch = new List<DiagnosticRingEntry>(128);
            while (!Output.Reader.Completion.IsCompleted || !Incidents.Reader.Completion.IsCompleted)
            {
                while (Incidents.Reader.TryRead(out var incident))
                {
                    try
                    {
                        activePath = incidents.Write(incident);
                        firstSequence = incident.Before.LastOrDefault()?.Sequence ?? 0;
                        postUntil = incident.TriggerTicks + 30 * Stopwatch.Frequency;
                    }
                    catch (Exception ex)
                    {
                        Error(ex);
                        Interlocked.Increment(ref incidentDropped);
                        Record("incident.write-failed", new
                        {
                            incident.Id,
                            error = AppLog.ExceptionCodes(ex)
                        });
                    }
                }
                while (batch.Count < 128 && Output.Reader.TryRead(out var entry))
                {
                    Interlocked.Decrement(ref depth);
                    batch.Add(entry);
                }
                if (batch.Count != 0)
                {
                    long began = Stopwatch.GetTimestamp();
                    Interlocked.Exchange(ref writeStarted, began);
                    try
                    {
                        sink.WriteBatch(batch.Select(e => DiagnosticDiskStamp.Add(e.Json)).ToArray());
                        Interlocked.Add(ref written, batch.Count);
                        if (activePath != null)
                        {
                            var after = batch.Where(e => e.Sequence > firstSequence && e.MonotonicTicks <= postUntil).ToArray();
                            if (after.Length != 0)
                            {
                                incidents.Append(activePath, after);
                            }
                        }
                        Volatile.Write(ref lastError, null);
                    }
                    catch (Exception ex) { Error(ex); Interlocked.Add(ref dropped, batch.Count); }
                    finally { Interlocked.Exchange(ref lastWriteMs, (long)Stopwatch.GetElapsedTime(began).TotalMilliseconds); Interlocked.Exchange(ref writeStarted, 0); }
                    batch.Clear();
                }
                else
                {
                    await Task.Delay(200).ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex)
        {
            Error(ex);
            // The ring remains usable, but a failed disk consumer must not look healthy.
            Output.Writer.TryComplete();
            Incidents.Writer.TryComplete();
            AppLog.Write("DIAGNOSTICS writer unavailable: " + AppLog.ExceptionCodes(ex));
        }
        finally { Interlocked.Exchange(ref writerAvailable, 0); }
    }
    static async Task SampleLoop(CancellationToken token)
    {
        long? previousCpu = null;
        long previousStamp = 0;
        try
        {
            try
            {
                wfp = new WfpBlockDiagnostics(value => { Record("wfp.block", value, value.EventUtc, value.ObservedMonotonicTicks); return Enabled; });
                Record("wfp.status", wfp.Start());
            }
            catch (Exception ex) { Error(ex); Record("wfp.unavailable", new { error = AppLog.ExceptionCodes(ex) }); }
            int tick = 0;
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var current = Volatile.Read(ref context);
                    IPAddress? endpoint = IPAddress.TryParse(current?.ProxyHost, out var parsed) ? parsed : null;
                    using var engineProcess = OpenEngine(current);
                    DateTimeOffset? engineStarted = null;
                    try
                    {
                        if (engineProcess != null)
                        {
                            engineStarted = new DateTimeOffset(engineProcess.StartTime.ToUniversalTime());
                        }
                    }
                    catch { }
                    bool identityKnown = DiagnosticIdentity.Matches(current, Volatile.Read(ref context), engineStarted);
                    var tcp = TcpConnectionDiagnostics.Capture(endpoint, current?.ProxyPort, identityKnown ? current?.EnginePid : null, maxRows: 256);
                    if (!DiagnosticIdentity.Matches(current, Volatile.Read(ref context), engineStarted))
                    {
                        tcp = tcp with
                        {
                            EngineProcessId = null,
                            Summary = tcp.Summary with
                            {
                                Engine = Array.Empty<TcpStateCount>()
                            }
                        };
                    }

                    RecordCore("tcp.snapshot", tcp, tcp.StartedUtc, tcp.StartedMonotonicTicks, current, false);
                    if (tick++ % 5 == 0)
                    {
                        DateTimeOffset networkTime = DateTimeOffset.UtcNow;
                        long networkTicks = Stopwatch.GetTimestamp();
                        using (var network = JsonDocument.Parse(NetworkDiagnostics.CaptureHost(current?.ProxyHost)))
                        {
                            RecordCore("network.snapshot", new
                            {
                                snapshot = network.RootElement,
                                policy = current,
                                policyEvidence = "last verified controller observation; see CapturedAt and EngineGeneration",
                                sampleEndedUtc = DateTimeOffset.UtcNow
                            }, networkTime, networkTicks, current, false);
                        }

                        using var own = Process.GetCurrentProcess();
                        long stamp = Stopwatch.GetTimestamp(), cpu = own.TotalProcessorTime.Ticks;
                        double? percent = DiagnosticCpu.Percent(previousCpu, cpu,
                            previousStamp == 0 ? TimeSpan.Zero : Stopwatch.GetElapsedTime(previousStamp, stamp), Environment.ProcessorCount);
                        previousCpu = cpu;
                        previousStamp = stamp;
                        object? engine = null;
                        if (current?.EnginePid is int pid)
                        {
                            try
                            {
                                if (engineProcess == null || !DiagnosticIdentity.Matches(current, Volatile.Read(ref context), engineStarted))
                                {
                                    engine = new
                                    {
                                        pid,
                                        attribution = "unverified-or-stale",
                                        expectedStartedUtc = current.EngineStartedUtc
                                    };
                                }
                                else
                                {
                                    engine = new
                                    {
                                        pid,
                                        attribution = "start-time-qualified",
                                        processStartedUtc = engineStarted,
                                        cpuTotalMs = engineProcess.TotalProcessorTime.TotalMilliseconds,
                                        workingSetBytes = engineProcess.WorkingSet64,
                                        privateBytes = engineProcess.PrivateMemorySize64,
                                        handleCount = engineProcess.HandleCount
                                    };
                                }
                            }
                            catch (Exception ex) { engine = new { pid, error = AppLog.ExceptionCodes(ex) }; }
                        }
                        long writing = Interlocked.Read(ref writeStarted);
                        RecordCore("collector.stats", new
                        {
                            queued = Interlocked.Read(ref queued),
                            written = Interlocked.Read(ref written),
                            dropped = Interlocked.Read(ref dropped),
                            queueDepth = Interlocked.Read(ref depth),
                            queueHighWater = Interlocked.Read(ref highWater),
                            incidentDropped = Interlocked.Read(ref incidentDropped),
                            incidentCoalesced = Episodes.Coalesced,
                            errors = Interlocked.Read(ref errors),
                            lastError = LastError,
                            lastWriteMs = Interlocked.Read(ref lastWriteMs),
                            writerAvailable = Volatile.Read(ref writerAvailable) != 0,
                            writeInFlightMs = writing == 0 ? 0 : (long)Stopwatch.GetElapsedTime(writing).TotalMilliseconds,
                            ring = Ring.Stats,
                            appLog = AppLog.Stats,
                            cpuPercentNormalized = percent,
                            ownWorkingSetBytes = own.WorkingSet64,
                            ownPrivateBytes = own.PrivateMemorySize64,
                            own.HandleCount,
                            engine,
                            wfp = wfp?.ReadStatus()
                        }, null, null, current, false);
                    }
                }
                catch (Exception ex) { Error(ex); Record("collector.sample-failed", new { error = AppLog.ExceptionCodes(ex) }); }
                await Task.Delay(1000, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception ex) { Error(ex); Record("collector.unavailable", new { error = AppLog.ExceptionCodes(ex) }); }
        finally { try { wfp?.Stop(); } catch (Exception ex) { Error(ex); } }
    }
    static Process? OpenEngine(DiagnosticContext? value)
    {
        if (value?.EnginePid is not int pid || value.EngineStartedUtc == null)
        {
            return null;
        }

        Process? process = null;
        try
        {
            process = Process.GetProcessById(pid);
            // Retain a real handle across the sample; PID reuse cannot silently
            // redirect subsequent properties to a different process instance.
            _ = process.SafeHandle;
            if (new DateTimeOffset(process.StartTime.ToUniversalTime()) == value.EngineStartedUtc)
            {
                return process;
            }
        }
        catch { }
        process?.Dispose();
        return null;
    }
    public static async Task StopAsync()
    {
        if (!Enabled)
        {
            return;
        }

        Record("diagnostics.stop-requested");
        cancellation?.Cancel();
        if (sampler != null)
        {
            try
            {
                await sampler.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch (Exception ex) { Error(ex); }
        }
        Interlocked.Exchange(ref enabled, 0);
        Output.Writer.TryComplete();
        Incidents.Writer.TryComplete();
        if (worker != null)
        {
            try
            {
                await worker.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch (Exception ex) { Error(ex); }
        }
    }
}
