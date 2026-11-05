using System.Text;
using System.Text.Json;

namespace ProxyBridge;

// Offline tests only: injected sources, injected sinks and synthetic process
// identities. No ETW session, process launch, DNS or socket is used here.
internal static class ActivityMonitorTests
{
    static readonly DateTimeOffset Epoch = new(2026, 11, 4, 8, 0, 0, TimeSpan.Zero);
    static readonly TimeSpan Deadline = TimeSpan.FromSeconds(4);
    static void Require(bool value, string message)
    {
        if (!value) throw new InvalidOperationException(message);
    }
    static JsonElement Parse(string value)
    {
        using var document = JsonDocument.Parse(value);
        return document.RootElement.Clone();
    }
    static JsonElement Accept(ActivityJournal journal, ActivityEvent value) => Parse(journal.Accept(value).Single());
    static ActivityEvent Event(string kind, int pid = 42, int second = 0) => new(Epoch.AddSeconds(second), kind, pid);
    static bool Unknown(JsonElement value) => value.GetProperty("instance").ValueKind == JsonValueKind.Null &&
        value.GetProperty("attribution").GetString() == "unknown";
    static string Record(string marker, int padding = 0) => JsonSerializer.Serialize(new { kind = "test", marker, text = new string('x', padding) });
    static string[] ReadRecords(string path) => new UTF8Encoding(false, true).GetString(File.ReadAllBytes(path))
        .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
    static Task Done(Action action) { action(); return Task.CompletedTask; }

    public static async Task RunAsync(Func<string, Func<string, Task>, Task> test)
    {
        await test("Metadata remains one JSON record and masks complete and boundary-crossing secrets", _ => Done(() => {
            const string secret = "qa-activity-boundary-secret-7428";
            AppLog.RegisterSecret(secret);
            var journal = new ActivityJournal((_, _) => null);
            string image = new string('a', 2040) + secret + "\r\nforged-record";
            string line = journal.Accept(Event("process.start") with { ImageName = image }).Single();
            var value = Parse(line);
            string saved = value.GetProperty("image").GetString()!;
            Require(!saved.Contains("qa-activ", StringComparison.Ordinal), "A truncated secret prefix leaked.");
            Require(!line.Contains('\r') && !line.Contains('\n'), "Metadata forged a physical log line.");
            var ordinary = Accept(journal, Event("process.start", 43) with { ImageName = "ёж🦔\r\n" + secret });
            Require(ordinary.GetProperty("image").GetString()!.Contains("ёж🦔"), "Unicode metadata was lost.");
            Require(!ordinary.GetRawText().Contains(secret), "A registered secret leaked.");
            string[] forbidden = ["commandLine", "argv", "payload", "packet", "headers", "url"];
            Require(!value.EnumerateObject().Any(p => forbidden.Contains(p.Name, StringComparer.OrdinalIgnoreCase)),
                "Sensitive nonmetadata field entered the activity record.");
        }));

        await test("Delivered PID reuse separates instances and ignores an old delayed stop", _ => Done(() => {
            var journal = new ActivityJournal((_, _) => null);
            var a = Accept(journal, Event("process.start", second: 1) with { ImageName = "first.exe" });
            Accept(journal, Event("process.stop", second: 2));
            var b = Accept(journal, Event("process.start", second: 3) with { ImageName = "second.exe" });
            Require(a.GetProperty("instance").GetString() != b.GetProperty("instance").GetString(), "PID reuse retained the old instance.");
            Require(Unknown(Accept(journal, Event("process.stop", second: 2))), "Old stop was attributed to the newer instance.");
            var next = Accept(journal, Event("tcp.connect", second: 4));
            Require(next.GetProperty("image").GetString() == "second.exe", "Old stop removed the newer process.");
            Require(Unknown(Accept(journal, Event("tcp.connect", second: 2))), "Old event received the new PID owner's name.");
        }));

        await test("Reported event gap invalidates attribution before a reused PID is resolved", _ => Done(() => {
            ActivityProcessIdentity? live = new(42, Epoch, "first.exe");
            var journal = new ActivityJournal((_, _) => live);
            Require(Accept(journal, Event("tcp.connect", second: 1)).GetProperty("image").GetString() == "first.exe",
                "Positive identity control failed.");
            // A reported queue/native gap invalidates lifecycle assumptions;
            // this does not claim detection of silent or not-yet-polled ETW loss.
            live = new(42, Epoch.AddSeconds(3), "second.exe");
            journal.InvalidateAttribution();
            var next = Accept(journal, Event("tcp.connect", second: 4));
            Require(Unknown(next) || next.GetProperty("image").GetString() == "second.exe", "Stale name survived PID reuse.");
            var late = Accept(journal, Event("tcp.connect", second: 2));
            Require(late.GetProperty("image").GetString() != "second.exe", "Late event was attributed to a later process.");
        }));

        await test("Delayed start cannot resurrect an instance already known to have stopped", _ => Done(() => {
            var journal = new ActivityJournal((_, _) => null);
            Accept(journal, Event("process.start", second: 1) with { ImageName = "stopped.exe" });
            Accept(journal, Event("process.stop", second: 2));
            // Arrival order differs from timestamp order. The stop tombstone
            // must survive an old start even though no newer instance is cached.
            Accept(journal, Event("process.start", second: 1) with { ImageName = "stopped.exe" });
            Require(Unknown(Accept(journal, Event("tcp.connect", second: 3))),
                "Delayed start resurrected stale attribution after a known stop.");
            Accept(journal, Event("process.start", second: 4) with { ImageName = "replacement.exe" });
            var later = Accept(journal, Event("tcp.connect", second: 5));
            Require(later.GetProperty("image").GetString() == "replacement.exe",
                "Old tombstone prevented a legitimate later process start.");
        }));

        await test("Future, wrong-PID and unavailable identities stay unknown", _ => Done(() => {
            var future = new ActivityJournal((pid, _) => new(pid, Epoch.AddSeconds(5), "future.exe"));
            Require(Unknown(Accept(future, Event("tcp.connect"))), "A future process was attributed backwards.");
            var wrong = new ActivityJournal((_, _) => new(99, Epoch, "wrong.exe"));
            Require(Unknown(Accept(wrong, Event("tcp.connect"))), "Resolver returned another PID.");
            var unavailable = new ActivityJournal((_, _) => throw new UnauthorizedAccessException());
            Require(Unknown(Accept(unavailable, Event("tcp.connect"))), "Resolver failure was not isolated.");
            Require(Unknown(Accept(unavailable, Event("tcp.connect", pid: 0))), "Unspecified PID received an identity.");
        }));

        await test("Traffic aggregates directional bytes and bounds distinct flows", _ => Done(() => {
            var journal = new ActivityJournal((_, _) => null, maxFlows: 2);
            ActivityEvent Flow(string kind, string remote, long bytes, int second) => Event(kind, second: second) with {
                Protocol = "UDP", LocalAddress = "::1", LocalPort = 1200, RemoteAddress = remote, RemotePort = 1300, Bytes = bytes
            };
            Require(!journal.Accept(Flow("udp.send", "::1", 10, 1)).Any(), "Traffic event bypassed aggregation.");
            journal.Accept(Flow("udp.receive", "::1", 20, 2)).ToArray();
            journal.Accept(Flow("udp.send", "::1", -8, 3)).ToArray();
            journal.Accept(Flow("udp.send", "::2", 5, 4)).ToArray();
            journal.Accept(Flow("udp.send", "::3", 5, 5)).ToArray();
            Require(journal.AggregationDropped == 1, "Flow-cap loss was not counted.");
            var records = journal.FlushFlows().Select(Parse).ToArray();
            Require(records.Length == 2, "Flow cap was not enforced.");
            var traffic = records.Single(r => r.GetProperty("remoteAddress").GetString() == "::1").GetProperty("traffic");
            Require(traffic.GetProperty("sentBytes").GetInt64() == 10 && traffic.GetProperty("receivedBytes").GetInt64() == 20,
                "Directional or invalid-byte accounting failed.");
            Require(traffic.GetProperty("observedEvents").GetInt64() == 3, "Aggregated event count changed.");
            Require(!journal.FlushFlows().Any(), "Flushed flows were written twice.");
        }));

        await test("Unflushed flows retain their original process instance across PID reuse", _ => Done(() => {
            var journal = new ActivityJournal((_, _) => null);
            Accept(journal, Event("process.start", second: 1) with { ImageName = "first.exe" });
            var send = Event("tcp.send", second: 2) with { Protocol = "TCP", RemoteAddress = "127.0.0.1", RemotePort = 443, Bytes = 12 };
            journal.Accept(send).ToArray();
            Accept(journal, Event("process.stop", second: 3));
            Accept(journal, Event("process.start", second: 4) with { ImageName = "second.exe" });
            journal.Accept(send with { Timestamp = Epoch.AddSeconds(5), Bytes = 24 }).ToArray();
            var records = journal.FlushFlows().Select(Parse).ToArray();
            Require(records.Length == 2, "Different process instances merged into one flow.");
            Require(records.Select(r => r.GetProperty("instance").GetString()).Distinct().Count() == 2, "Instance correlation was lost.");
            Require(records.Single(r => r.GetProperty("image").GetString() == "first.exe").GetProperty("traffic").GetProperty("sentBytes").GetInt64() == 12,
                "Old flow was reassigned to the current PID owner.");
        }));

        await test("Bounded producer remains nonblocking while the writer is blocked and reports drops", async _ => {
            var source = new FakeSource();
            using var sink = new RecordingSink(blockFirst: true);
            using var monitor = Monitor(source, sink, capacity: 3, batch: 1);
            try {
                await monitor.StartAsync().WaitAsync(Deadline);
                await sink.Entered.Task.WaitAsync(Deadline);
                // Complete producer independently: if callbacks block on file I/O,
                // this bounded wait fails and finally still releases the writer.
                await Task.Run(() => { for (int i = 0; i < 12; i++) source.Emit(Event("tcp.connect", pid: i + 1)); }).WaitAsync(Deadline);
                Require(monitor.Counters.Accepted == 3 && monitor.Counters.Dropped == 9, "Bounded queue accounting differs from burst size.");
            } finally { sink.Release.Set(); }
            await monitor.StopAsync().WaitAsync(Deadline);
            var records = sink.Records.Select(Parse).ToArray();
            Require(records.Count(r => r.GetProperty("kind").GetString() == "tcp.connect") == 3, "Accepted events were lost or duplicated on drain.");
            var stats = records.Last(r => r.GetProperty("kind").GetString() == "monitor.counters").GetProperty("data");
            Require(stats.GetProperty("dropped").GetInt64() == 9, "Drop report omitted queue gaps.");
            Require(monitor.Counters.Written == records.Length, "Written counter differs from successful sink records.");
        });

        await test("Stop drains events emitted by source Stop and flushes pending UDP traffic", async _ => {
            var source = new FakeSource();
            using var sink = new RecordingSink();
            using var monitor = Monitor(source, sink, batch: 64);
            source.Stopping = () => {
                source.Emit(Event("udp.send") with { Protocol = "UDP", RemoteAddress = "127.0.0.1", RemotePort = 80, Bytes = 17 });
                source.Emit(Event("process.stop", second: 1));
            };
            await monitor.StartAsync().WaitAsync(Deadline);
            source.Emit(Event("process.start") with { ImageName = "short-lived.exe" });
            await monitor.StopAsync().WaitAsync(Deadline);
            var records = sink.Records.Select(Parse).ToArray();
            Require(records.Count(r => r.GetProperty("kind").GetString() == "process.stop") == 1, "Final ETW stop event was not drained.");
            Require(records.Single(r => r.GetProperty("kind").GetString() == "network.activity").GetProperty("traffic").GetProperty("sentBytes").GetInt64() == 17,
                "Pending flow disappeared at Stop.");
            Require(records[^1].GetProperty("kind").GetString() == "monitor.stop", "Stop marker preceded unfinished output.");
            long accepted = monitor.Counters.Accepted;
            source.Emit(Event("tcp.connect", pid: 999));
            await monitor.StopAsync().WaitAsync(Deadline);
            Require(monitor.Counters.Accepted == accepted && source.Stops == 1, "Stopped source remained subscribed or Stop was duplicated.");
        });

        await test("Monitor sends multi-record bounded batches rather than one durable write per event", async _ => {
            var source = new FakeSource();
            source.Starting = () => { for (int i = 0; i < 11; i++) source.Emit(Event("tcp.connect", i + 1)); };
            using var sink = new RecordingSink();
            using var monitor = Monitor(source, sink, batch: 4);
            await monitor.StartAsync().WaitAsync(Deadline);
            await monitor.StopAsync().WaitAsync(Deadline);
            Require(sink.BatchSizes.Any(n => n > 1) && sink.BatchSizes.All(n => n <= 4), "Batch size contract was not preserved.");
            Require(sink.Records.Select(Parse).Count(r => r.GetProperty("kind").GetString() == "tcp.connect") == 11,
                "Batching dropped a process event.");
        });

        await test("Dispose returns within its UI budget while blocked writer cleanup continues safely", async _ => {
            var source = new FakeSource();
            using var sink = new RecordingSink(blockFirst: true);
            using var monitor = Monitor(source, sink, batch: 1);
            try {
                await monitor.StartAsync().WaitAsync(Deadline);
                await sink.Entered.Task.WaitAsync(Deadline);
                var elapsed = System.Diagnostics.Stopwatch.StartNew();
                await Task.Run(monitor.Dispose).WaitAsync(Deadline);
                Require(elapsed.Elapsed < TimeSpan.FromSeconds(3.5), "Diagnostic disposal exceeded the UI shutdown budget.");
                Require(monitor.LastError?.Contains(nameof(TimeoutException), StringComparison.Ordinal) == true,
                    "Bounded shutdown did not report incomplete background drain.");
                Require(!sink.Release.IsSet, "Dispose unblocked or disposed the test-owned writer while it was still active.");
            } finally { sink.Release.Set(); }
            await monitor.StopAsync().WaitAsync(Deadline);
            Require(!monitor.Running && source.Stops == 1 && source.Disposals == 1,
                "Background cleanup duplicated or lost source ownership.");
            Require(sink.Records.Select(Parse).Last().GetProperty("kind").GetString() == "monitor.stop",
                "Background drain lost its final stop record.");
            await monitor.StartAsync().WaitAsync(Deadline);
            Require(source.Starts == 1 && !monitor.Running, "Disposed monitor restarted a competing writer.");
        });

        await test("File rotation preserves complete bounded UTF-8 JSON and new records", directory => Done(() => {
            string path = Path.Combine(directory, "activity.log");
            using var sink = new ActivityFileSink(path, 1024);
            sink.WriteBatch([Record("old", 400)]);
            sink.WriteBatch([Record("recent", 600), Record("last", 100)]);
            string[] records = ReadRecords(path);
            Require(new FileInfo(path).Length <= 1024, "Rotated file exceeds its cap.");
            foreach (string record in records) Parse(record);
            Require(records.Any(r => Parse(r).GetProperty("kind").GetString() == "monitor.log-reset"), "Rollover was silent.");
            Require(!string.Join("", records).Contains("\"marker\":\"old\""), "Old file contents survived rollover.");
            Require(records.Any(r => r.Contains("\"marker\":\"last\"")), "Newest record disappeared during rotation.");
            using var reopened = new ActivityFileSink(path, 1024);
            reopened.WriteBatch([Record("reopened")]);
            Require(ReadRecords(path).Any(r => r.Contains("reopened")), "New sink did not append.");
        }));

        await test("Oversized Unicode record is explicitly omitted without invalid JSON or a larger file", directory => Done(() => {
            string path = Path.Combine(directory, "activity.log");
            using var sink = new ActivityFileSink(path, 512);
            string huge = JsonSerializer.Serialize(new { kind = "test", text = string.Concat(Enumerable.Repeat("ёж🦔", 5000)) });
            sink.WriteBatch([huge, Record("after")]);
            var records = ReadRecords(path).Select(Parse).ToArray();
            Require(new FileInfo(path).Length <= 512, "Oversized record escaped file cap.");
            Require(records.Any(r => r.GetProperty("kind").GetString() == "monitor.record-omitted"), "Oversized record disappeared silently.");
            Require(records.Any(r => r.TryGetProperty("marker", out var m) && m.GetString() == "after"), "Subsequent valid record was lost.");
        }));

        await test("File sink exposes an I/O failure for monitor isolation instead of swallowing it", directory => Done(() => {
            string path = Path.Combine(directory, "occupied");
            Directory.CreateDirectory(path);
            using var sink = new ActivityFileSink(path);
            bool failed = false;
            try { sink.WriteBatch([Record("cannot-write")]); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { failed = true; }
            Require(failed, "File sink claimed success when no file could be written.");
        }));

        await test("Source start failure is contained and never reports Running", async _ => {
            var source = new FakeSource { Starting = () => throw new IOException("qa-private-failure-detail") };
            using var sink = new RecordingSink();
            using var monitor = Monitor(source, sink);
            monitor.StateChanged += () => throw new InvalidOperationException("Observer failure");
            await monitor.StartAsync().WaitAsync(Deadline);
            Require(!monitor.Running && monitor.LastError != null, "Failed source was reported running.");
            Require(!monitor.LastError!.Contains("qa-private"), "Exception message leaked through status.");
            Require(source.Disposals == 1, "Failed source was not disposed.");
            await monitor.StopAsync().WaitAsync(Deadline);
        });

        await test("Writer failure is isolated, counted only after successful writes, and stops the source", async _ => {
            var source = new FakeSource();
            using var sink = new RecordingSink { Failure = new IOException("qa-private-writer-detail") };
            using var monitor = Monitor(source, sink, batch: 1);
            var fault = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            monitor.StateChanged += () => { if (monitor.LastError != null) fault.TrySetResult(); };
            await monitor.StartAsync().WaitAsync(Deadline);
            await fault.Task.WaitAsync(Deadline);
            await monitor.StopAsync().WaitAsync(Deadline);
            Require(!monitor.Running && source.Stops == 1, "Writer failure left source running.");
            Require(monitor.Counters.Written == 0, "Failed write was counted as durable output.");
            Require(monitor.LastError != null && !monitor.LastError.Contains("qa-private"), "Writer error detail leaked.");
        });

        await test("Source fault and stop failure are contained and do not escape lifecycle calls", async _ => {
            var source = new FakeSource { Stopping = () => throw new IOException("qa-stop-private") };
            using var sink = new RecordingSink();
            using var monitor = Monitor(source, sink);
            await monitor.StartAsync().WaitAsync(Deadline);
            source.Fail(new InvalidOperationException("qa-fault-private"));
            await monitor.StopAsync().WaitAsync(Deadline);
            Require(!monitor.Running && monitor.LastError != null, "Source failure did not reach diagnostic status.");
            Require(!monitor.LastError!.Contains("qa-"), "Source error text was exposed.");
            Require(source.Disposals == 1, "Stop failure prevented source disposal.");
        });

        await test("Trace loss counters are included without claiming complete coverage", async _ => {
            var source = new FakeSource { Stats = new(7, 3, 2, true, "test:loss") };
            using var sink = new RecordingSink();
            using var monitor = Monitor(source, sink);
            await monitor.StartAsync().WaitAsync(Deadline);
            await monitor.StopAsync().WaitAsync(Deadline);
            var counters = sink.Records.Select(Parse).Last(r => r.GetProperty("kind").GetString() == "monitor.counters");
            var trace = counters.GetProperty("data").GetProperty("trace");
            Require(trace.GetProperty("EventsLost").GetInt64() == 7 && trace.GetProperty("RealTimeBuffersLost").GetInt64() == 3 &&
                trace.GetProperty("CallbackErrors").GetInt64() == 2, "ETW gaps were omitted from the journal.");
        });

        await test("Old settings default metadata logging on and explicit off survives serialization", _ => Done(() => {
            const string old = "{\"Host\":\"127.0.0.1\",\"Port\":1080,\"Username\":\"\",\"Password\":\"\",\"Protocol\":\"socks\"}";
            var settings = JsonSerializer.Deserialize<Settings>(old)!;
            Require(settings.ActivityLoggingEnabled, "Old settings did not adopt the approved default.");
            var off = settings with { ActivityLoggingEnabled = false };
            var reloaded = JsonSerializer.Deserialize<Settings>(JsonSerializer.Serialize(off))!;
            Require(!reloaded.ActivityLoggingEnabled && reloaded.Host == settings.Host && reloaded.Port == settings.Port &&
                reloaded.Protocol == settings.Protocol, "Metadata preference changed network settings or was lost.");
        }));
    }

    static ActivityMonitor Monitor(FakeSource source, RecordingSink sink, int capacity = 64, int batch = 8) =>
        new(() => source, sink, (_, _) => null, queueCapacity: capacity, batchSize: batch,
            flushInterval: TimeSpan.FromMilliseconds(20), captureBaseline: false);

    sealed class FakeSource : IActivityEventSource
    {
        public event Action<ActivityEvent>? Event;
        public event Action<Exception>? Fault;
        public Action? Starting, Stopping;
        public int Starts, Stops, Disposals;
        public ActivityTraceStats Stats = new(0, 0, 0, true, null);
        public void Emit(ActivityEvent value) => Event?.Invoke(value);
        public void Fail(Exception error) => Fault?.Invoke(error);
        public void Start() { Interlocked.Increment(ref Starts); Starting?.Invoke(); }
        public void Stop() { Interlocked.Increment(ref Stops); Stopping?.Invoke(); }
        public ActivityTraceStats ReadStats() => Stats;
        public void Dispose() => Interlocked.Increment(ref Disposals);
    }

    sealed class RecordingSink(bool blockFirst = false) : IActivitySink
    {
        readonly object gate = new();
        readonly List<string> records = [];
        readonly List<int> batchSizes = [];
        int calls;
        public readonly ManualResetEventSlim Release = new(!blockFirst);
        public readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Exception? Failure;
        public string FilePath => "synthetic-activity.log";
        public string[] Records { get { lock (gate) return records.ToArray(); } }
        public int[] BatchSizes { get { lock (gate) return batchSizes.ToArray(); } }
        public void WriteBatch(IReadOnlyList<string> values)
        {
            if (Interlocked.Increment(ref calls) == 1) {
                Entered.TrySetResult();
                if (!Release.Wait(TimeSpan.FromSeconds(6))) throw new TimeoutException("Test gate was not released.");
            }
            if (Failure != null) throw Failure;
            lock (gate) { batchSizes.Add(values.Count); records.AddRange(values); }
        }
        // Test-owned wait handles remain alive until all monitor callbacks have
        // drained. Idempotent disposal also permits supplied-sink lifecycle tests.
        public void Dispose() { Release.Set(); }
    }
}
