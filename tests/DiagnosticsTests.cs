using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;

namespace ProxyBridge;

internal static class DiagnosticsTests
{
    static void Check(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Diagnostic invariant failed.");
        }
    }
    static void Throws<T>(Action action) where T : Exception
    {
        try
        { action(); }
        catch (T) { return; }
        throw new InvalidOperationException("Expected failure was not raised.");
    }
    static readonly DateTimeOffset Epoch = new(2026, 11, 4, 8, 0, 0, TimeSpan.Zero);
    sealed class Clock : TimeProvider
    {
        public long Ticks = 1;
        public DateTimeOffset Utc = Epoch;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Ticks;
        public override DateTimeOffset GetUtcNow() => Utc;
        public void Advance(double seconds) { Ticks += TimeSpan.FromSeconds(seconds).Ticks; Utc += TimeSpan.FromSeconds(seconds); }
    }
    static DiagnosticRingEntry Entry(string json, long sequence = 1) => new(sequence, sequence, Epoch, json, Encoding.UTF8.GetByteCount(json) + 2);
    static DiagnosticIncident Incident(string id, params DiagnosticRingEntry[] entries) => new(id, "synthetic-test", Epoch, 1, entries, null);
    static LogFileEntry Log(string message) => new(Epoch, message);
    static Task Done(Action action) { action(); return Task.CompletedTask; }

    public static async Task RunAsync(Func<string, Func<string, Task>, Task> test)
    {
        await test("CPU first/reset/invalid samples stay unknown and valid deltas normalize by processor count", _ => Done(() =>
        {
            long second = TimeSpan.TicksPerSecond;
            Check(DiagnosticCpu.Percent(null, second, TimeSpan.FromSeconds(1), 4) == null);
            Check(DiagnosticCpu.Percent(second, second - 1, TimeSpan.FromSeconds(1), 4) == null);
            Check(DiagnosticCpu.Percent(0, second, TimeSpan.Zero, 4) == null);
            Check(DiagnosticCpu.Percent(0, second, TimeSpan.FromSeconds(-1), 4) == null);
            Check(DiagnosticCpu.Percent(0, second, TimeSpan.FromSeconds(1), 0) == null);
            Check(DiagnosticCpu.Percent(second, second, TimeSpan.FromSeconds(1), 4) == 0);
            Check(DiagnosticCpu.Percent(second, second * 3, TimeSpan.FromSeconds(2), 4) == 25);
        }));
        await test("engine identity requires matching PID, generation and process start across capture", _ => Done(() =>
        {
            var expected = new DiagnosticContext("198.51.100.9", 8000, "socks", 42, 10, 123, true, true, true, Epoch, "before", Epoch.AddMinutes(-1));
            Check(DiagnosticIdentity.Matches(expected, expected with { Stage = "after" }, Epoch.AddMinutes(-1)));
            Check(!DiagnosticIdentity.Matches(null, expected, Epoch.AddMinutes(-1)));
            Check(!DiagnosticIdentity.Matches(expected, null, Epoch.AddMinutes(-1)));
            Check(!DiagnosticIdentity.Matches(expected, expected, null));
            Check(!DiagnosticIdentity.Matches(expected with { EngineStartedUtc = null }, expected, Epoch.AddMinutes(-1)));
            Check(!DiagnosticIdentity.Matches(expected, expected with { EngineGeneration = 11 }, Epoch.AddMinutes(-1)));
            Check(!DiagnosticIdentity.Matches(expected, expected with { EnginePid = 43 }, Epoch.AddMinutes(-1)));
            Check(!DiagnosticIdentity.Matches(expected, expected with { EngineStartedUtc = Epoch }, Epoch));
            Check(!DiagnosticIdentity.Matches(expected, expected, Epoch));
        }));
        await test("ring ages by monotonic time despite wall-clock rollback", _ => Done(() =>
        {
            var clock = new Clock();
            var ring = new DiagnosticRing(clock);
            ring.Add("{}", Epoch);
            clock.Advance(60);
            clock.Utc = Epoch.AddDays(-1);
            Check(ring.Snapshot().Length == 1);
            clock.Advance(.001);
            Check(ring.Snapshot().Length == 0 && ring.Stats.Evicted == 1);
        }));
        await test("ring enforces UTF8 byte, count and oversized-record bounds", _ => Done(() =>
        {
            var ring = new DiagnosticRing(new Clock(), maxCount: 2, maxBytes: 12, maxRecordBytes: 8);
            Check(ring.Add("яя", Epoch)!.Utf8Bytes == 6);
            ring.Add("яя", Epoch);
            ring.Add("x", Epoch);
            Check(ring.Stats.Count == 2 && ring.Stats.Bytes == 9 && ring.Stats.Evicted == 1);
            Check(ring.Add("яяяя", Epoch) == null && ring.Stats.Oversized == 1);
            ring.Add("яяя", Epoch);
            Check(ring.Stats.Count == 2 && ring.Stats.Bytes == 11);
        }));
        await test("frozen ring snapshot survives mutation and eviction", _ => Done(() =>
        {
            var ring = new DiagnosticRing(new Clock(), maxCount: 1);
            ring.Add("first", Epoch);
            var frozen = ring.Snapshot();
            ring.Add("second", Epoch);
            Check(frozen.Single().Json == "first" && ring.Snapshot().Single().Json == "second");
            frozen[0] = Entry("foreign");
            Check(ring.Snapshot().Single().Json == "second");
        }));
        await test("incident retries retain first ID and extend monotonic quiet period", _ => Done(() =>
        {
            var clock = new Clock();
            var gate = new DiagnosticIncidentGate(clock);
            string first = gate.TryBegin()!;
            clock.Advance(59);
            Check(gate.TryBegin() == null);
            clock.Advance(59);
            clock.Utc = Epoch.AddDays(-2);
            Check(gate.TryBegin() == null);
            Check(gate.Current == first && gate.Coalesced == 2);
            clock.Advance(60);
            Check(gate.TryBegin() is string next && next != first);
        }));
        await test("incident create refuses overwrite and preserves pre/post evidence order", dir => Done(() =>
        {
            var store = new DiagnosticIncidentStore(dir);
            string path = store.Write(Incident("a", Entry("{\"kind\":\"before\"}")));
            byte[] first = File.ReadAllBytes(path);
            Throws<IOException>(() => store.Write(Incident("a", Entry("{}"))));
            Check(first.SequenceEqual(File.ReadAllBytes(path)));
            store.Append(path, [Entry("{\"kind\":\"after\"}", 2)]);
            string text = File.ReadAllText(path);
            Check(text.IndexOf("before", StringComparison.Ordinal) < text.IndexOf("incident.pre-window-end", StringComparison.Ordinal));
            Check(text.IndexOf("incident.pre-window-end", StringComparison.Ordinal) < text.LastIndexOf("after", StringComparison.Ordinal));
        }));
        await test("incident retention bounds owned files and preserves foreign files", dir => Done(() =>
        {
            string foreign = Path.Combine(dir, "user.jsonl");
            File.WriteAllText(foreign, "keep");
            var store = new DiagnosticIncidentStore(dir, maxFiles: 2, maxTotalBytes: 2048, maxFileBytes: 1024);
            for (int i = 0; i < 4; i++)
            {
                store.Write(Incident("20261104-" + i, Entry("{\"x\":\"" + new string('x', 100) + "\"}")));
            }

            var files = new DirectoryInfo(dir).GetFiles("ProxyBridge-incident-*.jsonl");
            Check(files.Length == 2 && files.Sum(f => f.Length) <= 2048 && files.All(f => f.Length <= 1024));
            Check(File.ReadAllText(foreign) == "keep");
            Throws<ArgumentException>(() => store.Write(Incident("../outside")));
            Throws<IOException>(() => store.Append(foreign, [Entry("{}")]));
        }));
        await test("append also preserves aggregate incident byte limit", dir => Done(() =>
        {
            var store = new DiagnosticIncidentStore(dir, maxFiles: 3, maxTotalBytes: 1600, maxFileBytes: 1024);
            string first = store.Write(Incident("a"));
            var extra = Entry("{\"x\":\"" + new string('x', 95) + "\"}");
            store.Append(first, Enumerable.Repeat(extra, 10).ToArray());
            string second = store.Write(Incident("b"));
            store.Append(second, Enumerable.Repeat(extra, 10).ToArray());
            Check(new DirectoryInfo(dir).GetFiles("ProxyBridge-incident-*.jsonl").Sum(f => f.Length) <= 1600);
        }));
        await test("incident file cap keeps complete valid JSON lines", dir => Done(() =>
        {
            var store = new DiagnosticIncidentStore(dir, maxFileBytes: 1024, maxTotalBytes: 1024);
            var entries = Enumerable.Range(0, 30).Select(i => Entry("{\"i\":" + i + ",\"text\":\"" + new string('я', 60) + "\"}", i)).ToArray();
            string path = store.Write(Incident("bounded", entries));
            store.Append(path, entries);
            Check(new FileInfo(path).Length <= 1024);
            foreach (string line in File.ReadAllLines(path))
            {
                using (JsonDocument.Parse(line))
                { }
            }
        }));
        await test("incident footer reports actual retained evidence and disk time remains distinct from event time", dir => Done(() =>
        {
            foreach (bool limited in new[] { false, true })
            {
                string folder = Path.Combine(dir, limited ? "limited" : "complete");
                var store = new DiagnosticIncidentStore(folder, maxFileBytes: limited ? 1024 : 16000, maxTotalBytes: 16000);
                var entries = Enumerable.Range(0, 12).Select(i => Entry(JsonSerializer.Serialize(new
                {
                    kind = "fixture.evidence",
                    eventTime = Epoch,
                    number = i,
                    text = new string('я', 70)
                }), i)).ToArray();
                DateTimeOffset before = DateTimeOffset.UtcNow;
                string path = store.Write(Incident("footer", entries));
                DateTimeOffset after = DateTimeOffset.UtcNow;
                var lines = File.ReadAllLines(path).Select(line => { using var d = JsonDocument.Parse(line); return d.RootElement.Clone(); }).ToArray();
                var header = lines.Single(r => r.GetProperty("kind").GetString() == "incident.begin");
                var footer = lines.Single(r => r.GetProperty("kind").GetString() == "incident.pre-window-end");
                var evidence = lines.Where(r => r.GetProperty("kind").GetString() == "fixture.evidence").ToArray();
                Check(header.GetProperty("availableRecords").GetInt32() == entries.Length);
                Check(footer.GetProperty("retainedRecords").GetInt32() == evidence.Length);
                Check(footer.GetProperty("truncated").GetBoolean() == limited);
                Check(limited ? evidence.Length < entries.Length : evidence.Length == entries.Length);
                Check(footer.GetProperty("followingEvidence").GetString() == "observed-after-trigger");
                foreach (var line in lines)
                {
                    DateTimeOffset written = line.GetProperty("writeStartedAtUtc").GetDateTimeOffset();
                    Check(written >= before && written <= after);
                    Check(!line.TryGetProperty("writeCompletedAtUtc", out _));
                }
                Check(evidence.All(e => e.GetProperty("eventTime").GetDateTimeOffset() == Epoch));
            }
        }));
        await test("blocked async sink cannot block producers and reports saturation", async unused =>
        {
            using var entered = new ManualResetEventSlim();
            using var release = new ManualResetEventSlim();
            using var writer = new AsyncLogWriter(records => { entered.Set(); Check(release.Wait(TimeSpan.FromSeconds(5))); return true; }, capacity: 2);
            try
            {
                Check(writer.TryWrite(Log("first")));
                Check(entered.Wait(TimeSpan.FromSeconds(2)));
                var watch = Stopwatch.StartNew();
                Check(writer.TryWrite(Log("second")));
                Check(writer.TryWrite(Log("third")));
                Check(!writer.TryWrite(Log("overflow")) && watch.Elapsed < TimeSpan.FromSeconds(1));
                Check(writer.Stats.QueueDepth == 2 && writer.Stats.Dropped == 1 && writer.Stats.Written == 0);
                await writer.StopAsync(TimeSpan.FromMilliseconds(30));
                Check(writer.Stats.LastError == "shutdown-timeout" && !writer.TryWrite(Log("closed")));
            }
            finally { release.Set(); await writer.StopAsync(TimeSpan.FromSeconds(2)); }
            Check(writer.Stats.Written == 3 && writer.Stats.QueueDepth == 0);
        });
        await test("confirmed receipt waits for actual sink success and preserves order", async unused =>
        {
            using var entered = new ManualResetEventSlim();
            using var release = new ManualResetEventSlim();
            var seen = new List<string>();
            using var writer = new AsyncLogWriter(records => { entered.Set(); Check(release.Wait(TimeSpan.FromSeconds(5))); seen.AddRange(records.Select(r => r.Message)); return true; });
            try
            {
                Check(writer.TryWrite(Log("first")));
                var receipt = writer.WriteConfirmedAsync(Log("note"));
                Check(entered.Wait(TimeSpan.FromSeconds(2)) && !receipt.IsCompleted);
                release.Set();
                Check(await receipt.WaitAsync(TimeSpan.FromSeconds(2)));
                await writer.StopAsync(TimeSpan.FromSeconds(2));
                Check(seen.SequenceEqual(new[] { "first", "note" }) && writer.Stats.Written == 2);
            }
            finally { release.Set(); await writer.StopAsync(TimeSpan.FromSeconds(2)); }
        });
        await test("failed and throwing sinks return negative receipts and remain isolated", async unused =>
        {
            int calls = 0;
            using var writer = new AsyncLogWriter(_ => (++calls) switch { 1 => false, 2 => throw new IOException("synthetic-sensitive-message"), _ => true }, () => "disk-unavailable");
            Check(!await writer.WriteConfirmedAsync(Log("one")));
            Check(!await writer.WriteConfirmedAsync(Log("two")));
            Check(writer.Stats.LastError == nameof(IOException));
            Check(await writer.WriteConfirmedAsync(Log("three")));
            await writer.StopAsync(TimeSpan.FromSeconds(2));
            Check(writer.Stats.Failures == 2 && writer.Stats.Written == 1 && writer.Stats.LastError == null);
        });
        await test("log batches preserve event time and redact before clipping", dir => Done(() =>
        {
            string secret = "UNIQUE_PASSWORD_" + Guid.NewGuid().ToString("N");
            var file = new BoundedLogFile(Path.Combine(dir, "log.txt"), 2048);
            file.RegisterSecret(secret);
            Check(file.WriteBatch([new(Epoch, "marker\r\nforged " + secret)]));
            string text = File.ReadAllText(Path.Combine(dir, "log.txt"));
            Check(text.StartsWith("2026-11-04 08:00:00.000 +00:00", StringComparison.Ordinal));
            Check(!text.Contains(secret) && text.Contains("\\r\\nforged"));
            Check(file.WriteBatch([new(Epoch, new string('x', 1950) + secret)]));
            text = File.ReadAllText(Path.Combine(dir, "log.txt"));
            Check(!text.Contains(secret) && !text.Contains("UNIQUE_PASSWORD_") && new FileInfo(Path.Combine(dir, "log.txt")).Length <= 2048);
        }));
        await test("TCP table decoder preserves IPv4 port endian and unknown states", _ => Done(() =>
        {
            byte[] data = new byte[28];
            U32(data, 0, 1);
            U32(data, 4, 777);
            IPAddress.Parse("192.0.2.17").GetAddressBytes().CopyTo(data, 8);
            Port(data, 12, 50001);
            IPAddress.Parse("198.51.100.9").GetAddressBytes().CopyTo(data, 16);
            Port(data, 20, 8000);
            U32(data, 24, 42);
            var parsed = TcpConnectionDiagnostics.ParseTable(data, 2);
            var row = parsed.Rows.Single();
            Check(row.ProcessId == 42 && row.State == 777 && row.StateName == "UNKNOWN" && row.LocalAddress == "192.0.2.17" && row.RemoteAddress == "198.51.100.9");
            Check(row.LocalPort == 50001 && row.RemotePort == 8000 && !parsed.Truncated);
            U32(data, 0, 2);
            Throws<ArgumentException>(() => TcpConnectionDiagnostics.ParseTable(data, 2));
            Throws<ArgumentException>(() => TcpConnectionDiagnostics.ParseTable([], 23));
        }));
        await test("TCP IPv6 decoder retains scopes and separate state/PID fields", _ => Done(() =>
        {
            byte[] data = new byte[60];
            U32(data, 0, 1);
            IPAddress.Parse("fe80::1").GetAddressBytes().CopyTo(data, 4);
            U32(data, 20, 22);
            Port(data, 24, 40000);
            IPAddress.Parse("fe80::2").GetAddressBytes().CopyTo(data, 28);
            U32(data, 44, 23);
            Port(data, 48, 443);
            U32(data, 52, 3);
            U32(data, 56, 9001);
            var row = TcpConnectionDiagnostics.ParseTable(data, 23).Rows.Single();
            Check(row.LocalAddress == "fe80::1%22" && row.RemoteAddress == "fe80::2%23" && row.LocalPort == 40000 && row.RemotePort == 443);
            Check(row.StateName == "SYN_SENT" && row.ProcessId == 9001);
        }));
        await test("TCP summary counts all rows while bounding selected rows and processes", _ => Done(() =>
        {
            var rows = Enumerable.Range(1, 40).Select(i => new TcpConnectionRow((uint)i, 2, i % 2 == 0 ? 3u : 5u,
                i % 2 == 0 ? "SYN_SENT" : "ESTABLISHED", "192.0.2.1", 40000 + i, "198.51.100.9", i <= 10 ? 8000 : 443)).ToArray();
            var s = TcpConnectionDiagnostics.Summarize(rows, IPAddress.Parse("198.51.100.9"), 8000, 40, 2);
            Check(s.ScannedRows == 40 && s.All.Sum(v => v.Count) == 40 && s.Endpoint.Sum(v => v.Count) == 10);
            Check(s.Engine.Sum(v => v.Count) == 1 && s.MatchedRows == 11 && s.Rows.Count == 2 && s.RowsTruncated);
            Check(s.Processes.Count == 32 && s.OmittedProcesses == 8);
        }));
        await test("WFP availability distinguishes disabled, denied, unavailable and subscribed", _ => Done(() =>
        {
            Check(WfpBlockDiagnostics.Availability(false, null, false) == "collection_disabled");
            Check(WfpBlockDiagnostics.Availability(null, 5, false) == "access_denied");
            Check(WfpBlockDiagnostics.Availability(true, 50, false) == "unavailable");
            Check(WfpBlockDiagnostics.Availability(null, null, false) == "unavailable");
            Check(WfpBlockDiagnostics.Availability(true, null, true) == "subscribed");
        }));
        await test("WFP decode honors availability flags and never invents process ID", _ => Done(() =>
        {
            byte[] header = new byte[120], drop = new byte[32];
            BinaryPrimitives.WriteInt64LittleEndian(header, Epoch.ToFileTime());
            U32(header, 104, 3);
            U32(header, 8, 0x13f);
            U32(header, 12, 0);
            header[16] = 6;
            U32(header, 20, 0xC0000201);
            U32(header, 36, 0xC6336409);
            BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(52), 50000);
            BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(54), 8000);
            BinaryPrimitives.WriteUInt64LittleEndian(drop, 987654);
            BinaryPrimitives.WriteUInt16LittleEndian(drop.AsSpan(8), 44);
            U32(drop, 24, 0x3901);
            var value = WfpBlockDiagnostics.DecodeEvent(header, drop, "C:\\synthetic.exe", Epoch.AddSeconds(1), 123)!;
            Check(value.ProcessId == null && value.ProcessIdentitySource == "app_id" && value.FilterId == 987654 && value.LayerId == 44);
            Check(value.LocalAddress == "192.0.2.1" && value.RemoteAddress == "198.51.100.9" && value.LocalPort == 50000 && value.RemotePort == 8000 && value.Direction == "outbound");
            Check(value.EventUtc == Epoch && value.ObservedUtc == Epoch.AddSeconds(1) && value.OriginStatus == "pending");
            U32(header, 8, 0);
            value = WfpBlockDiagnostics.DecodeEvent(header, drop, "untrusted.exe", Epoch, 1)!;
            Check(value.ApplicationPath == null && value.LocalAddress == null && value.Protocol == null && value.LocalPort == null);
            U32(header, 104, 1);
            Check(WfpBlockDiagnostics.DecodeEvent(header, [], null, Epoch, 1) == null);
            Throws<ArgumentException>(() => WfpBlockDiagnostics.DecodeEvent([], drop, null, Epoch, 1));
            Check(WfpBlockDiagnostics.SafeText("a\r\nb\0hidden", 10) == "a??b");
        }));
        await test("WFP ScopeId is IPv6-only and requires both version and scope flags", _ => Done(() =>
        {
            byte[] header = new byte[120], drop = new byte[32];
            BinaryPrimitives.WriteInt64LittleEndian(header, Epoch.ToFileTime());
            U32(header, 104, 3);
            U32(header, 8, 0x186);
            U32(header, 12, 0);
            U32(header, 20, 0xC0000201);
            U32(header, 36, 0xC6336409);
            U32(header, 56, 0xDEADBEEF);
            var v4 = WfpBlockDiagnostics.DecodeEvent(header, drop, null, Epoch, 1)!;
            Check(v4.ScopeId == null && v4.LocalAddress == "192.0.2.1" && v4.RemoteAddress == "198.51.100.9");
            U32(header, 12, 1);
            U32(header, 56, 22);
            IPAddress.Parse("fe80::1").GetAddressBytes().CopyTo(header, 20);
            IPAddress.Parse("fe80::2").GetAddressBytes().CopyTo(header, 36);
            var v6 = WfpBlockDiagnostics.DecodeEvent(header, drop, null, Epoch, 1)!;
            Check(v6.ScopeId == 22 && v6.LocalAddress == "fe80::1%22" && v6.RemoteAddress == "fe80::2%22");
            U32(header, 8, 0x86);
            var noVersion = WfpBlockDiagnostics.DecodeEvent(header, drop, null, Epoch, 1)!;
            Check(noVersion.ScopeId == null && noVersion.LocalAddress == null && noVersion.RemoteAddress == null);
            U32(header, 8, 0x106);
            Check(WfpBlockDiagnostics.DecodeEvent(header, drop, null, Epoch, 1)!.ScopeId == null);
        }));
        await ProbeTests(test);
        await ActivityBoundaryTests(test);
    }

    static void U32(byte[] data, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
    static void Port(byte[] data, int offset, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(offset), value);
    static Settings SyntheticSettings(string protocol = "socks", string username = "", string password = "") => new("198.51.100.9", 8000, username, password, protocol);

    sealed class ScriptStream(byte[] input) : Stream
    {
        int position;
        public bool Closed;
        public readonly List<byte[]> Writes = [];
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => input.Length;
        public override long Position { get => position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int length = Math.Min(1, Math.Min(count, input.Length - position));
            input.AsSpan(position, length).CopyTo(buffer.AsSpan(offset));
            position += length;
            return length;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int length = Math.Min(1, Math.Min(buffer.Length, input.Length - position));
            input.AsMemory(position, length).CopyTo(buffer);
            position += length;
            return ValueTask.FromResult(length);
        }
        public override void Write(byte[] buffer, int offset, int count) => Writes.Add(buffer.AsSpan(offset, count).ToArray());
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Writes.Add(buffer.ToArray());
            return ValueTask.CompletedTask;
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { Closed = true; base.Dispose(disposing); }
    }
    sealed class Transport(ScriptStream stream) : IProxyPhaseTransport
    {
        public int Connects, TlsCalls;
        public Exception? TlsError;
        public Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken token)
        {
            Check(address.Equals(IPAddress.Parse("198.51.100.9")) && port == 8000);
            Connects++;
            return Task.FromResult<Stream>(stream);
        }
        public Task<Stream> AuthenticateTlsAsync(Stream input, string name, CancellationToken token)
        {
            TlsCalls++;
            Check(ReferenceEquals(input, stream) && name == "one.one.one.one");
            return TlsError == null ? Task.FromResult<Stream>(stream) : Task.FromException<Stream>(TlsError);
        }
    }
    sealed class PendingTransport : IProxyPhaseTransport
    {
        public readonly TaskCompletionSource<Stream> Pending = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken token) { Entered.TrySetResult(); return Pending.Task; }
        public Task<Stream> AuthenticateTlsAsync(Stream stream, string name, CancellationToken token) => throw new InvalidOperationException();
    }
    static byte[] Reply(string http = "HTTP/1.1 200 OK\r\nX-Synthetic: PRIVATE_HEADER\r\n\r\nPRIVATE_BODY", bool auth = false, byte rep = 0) =>
        (auth ? new byte[] { 5, 2, 1, 0 } : new byte[] { 5, 0 }).Concat(new byte[] { 5, rep, 0, 1, 192, 0, 2, 99, 0, 80 }).Concat(Encoding.ASCII.GetBytes(http)).ToArray();

    static async Task ProbeTests(Func<string, Func<string, Task>, Task> test)
    {
        await test("fragmented SOCKS auth/TLS/HTTP phases succeed without sensitive output", async unused =>
        {
            var stream = new ScriptStream(Reply(auth: true));
            var transport = new Transport(stream);
            var events = new List<ProbeObservation>();
            var result = await ProxyPhaseProbe.RunAsync(SyntheticSettings(username: "SYNTHETIC_USER", password: "SYNTHETIC_PASSWORD"), new(77), events.Add, transport: transport);
            Check(result.Succeeded && result.HttpStatus == 200 && transport.Connects == 1 && transport.TlsCalls == 1 && stream.Closed);
            Check(events.Any(e => e.Phase == ProbePhase.SocksAuth && e.Outcome == ProbeOutcome.Succeeded));
            Check(events.Any(e => e.SocksMethod == 2) && events.Any(e => e.SocksAuthStatus == 0));
            Check(events.All(e => e.EngineGeneration == 77 && e.DurationTicks >= 0) && events.Select(e => e.ProbeId).Distinct().Count() == 1);
            string json = JsonSerializer.Serialize(new { result, events });
            foreach (string forbidden in new[] { "SYNTHETIC_USER", "SYNTHETIC_PASSWORD", "PRIVATE_HEADER", "PRIVATE_BODY" })
            {
                Check(!json.Contains(forbidden));
            }

            Check(stream.Writes[2].SequenceEqual(new byte[] { 5, 1, 0, 1, 1, 1, 1, 1, 1, 187 }));
        });
        await test("SOCKS greeting downgrade, auth rejection and truncated replies fail in their phases", async unused =>
        {
            foreach (var item in new[] {
                (Bytes: new byte[] { 5, 0 }, Phase: ProbePhase.SocksGreeting),
                (Bytes: new byte[] { 5, 2, 1, 1 }, Phase: ProbePhase.SocksAuth),
                (Bytes: new byte[] { 5, 2, 1, 0, 5, 0 }, Phase: ProbePhase.SocksConnect) })
            {
                var transport = new Transport(new ScriptStream(item.Bytes));
                var r = await ProxyPhaseProbe.RunAsync(SyntheticSettings(username: "u", password: "p"), new(1), _ => { }, transport: transport);
                Check(!r.Succeeded && r.Outcome == ProbeOutcome.Failed && r.Phase == item.Phase && transport.TlsCalls == 0);
            }
        });
        await test("SOCKS rejection retains numeric REP and never attempts TLS", async unused =>
        {
            var transport = new Transport(new ScriptStream(Reply(rep: 2)));
            var r = await ProxyPhaseProbe.RunAsync(SyntheticSettings(), new(1), _ => { }, transport: transport);
            Check(!r.Succeeded && r.SocksReply == 2 && r.Phase == ProbePhase.SocksConnect && transport.TlsCalls == 0);
        });
        await test("TLS exception remains a TLS failure without exposing its message", async unused =>
        {
            var transport = new Transport(new ScriptStream(Reply())) { TlsError = new AuthenticationException("PRIVATE_TLS_MESSAGE") };
            var events = new List<ProbeObservation>();
            var r = await ProxyPhaseProbe.RunAsync(SyntheticSettings(), new(1), events.Add, transport: transport);
            Check(!r.Succeeded && r.Phase == ProbePhase.TlsHandshake && !JsonSerializer.Serialize(new { r, events }).Contains("PRIVATE_TLS_MESSAGE"));
        });
        await test("HTTP non-success, malformed and oversized headers never pass", async unused =>
        {
            foreach (string response in new[] { "HTTP/1.1 302 Redirect\r\n\r\n", "NOTHTTP 200 OK\r\n\r\n", "HTTP/1.1 200 OK\r\nX: " + new string('x', 9000) })
            {
                var r = await ProxyPhaseProbe.RunAsync(SyntheticSettings(), new(1), _ => { }, transport: new Transport(new ScriptStream(Reply(response))));
                Check(!r.Succeeded && r.Phase == ProbePhase.HttpHeaders);
            }
        });
        await test("observer failures cannot change successful probe outcome", async unused =>
        {
            var r = await ProxyPhaseProbe.RunAsync(SyntheticSettings(), new(1), _ => throw new IOException("observer"), transport: new Transport(new ScriptStream(Reply())));
            Check(r.Succeeded);
        });
        await test("unsupported proxy protocol skips without creating a transport connection", async unused =>
        {
            var transport = new Transport(new ScriptStream([]));
            var r = await ProxyPhaseProbe.RunAsync(SyntheticSettings("http"), new(1), _ => { }, transport: transport);
            Check(r.Outcome == ProbeOutcome.Skipped && transport.Connects == 0);
        });
        await test("caller cancellation bounds uncooperative transport and disposes its late stream", async unused =>
        {
            var transport = new PendingTransport();
            using var cancel = new CancellationTokenSource();
            var pending = ProxyPhaseProbe.RunAsync(SyntheticSettings(), new(1), _ => { }, cancel.Token, transport);
            await transport.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
            cancel.Cancel();
            var r = await pending.WaitAsync(TimeSpan.FromSeconds(1));
            Check(r.Outcome == ProbeOutcome.Canceled && r.Phase == ProbePhase.TcpConnect);
            var late = new ScriptStream([]);
            transport.Pending.SetResult(late);
            Check(SpinWait.SpinUntil(() => late.Closed, TimeSpan.FromSeconds(1)));
        });
        await test("observed health probe reports caller pre-cancel without sending a request", async unused =>
        {
            using var cancel = new CancellationTokenSource();
            cancel.Cancel();
            var events = new List<ProbeObservation>();
            var handler = new HttpFixture(_ => throw new InvalidOperationException());
            try
            { await ConnectionProbe.CheckObservedAsync(new(81), events.Add, cancel.Token, testHandler: handler); Check(false); }
            catch (OperationCanceledException error) { Check(error.CancellationToken == cancel.Token); }
            Check(handler.Calls == 0 && events.Count == 1 && events[0].Phase == ProbePhase.Setup && events[0].Outcome == ProbeOutcome.Canceled);
        });
        await test("health fallback retains one probe ID and correct attempt/generation without body leakage", async unused =>
        {
            var events = new List<ProbeObservation>();
            var handler = new HttpFixture(call => new(HttpStatusCode.OK) { Content = new StringContent(call == 1 ? "PRIVATE_INVALID_BODY" : "198.51.100.7") });
            await ConnectionProbe.CheckObservedAsync(new(82), events.Add, log: _ => throw new IOException("observer"), testHandler: handler);
            Check(handler.Calls == 2 && events.All(e => e.EngineGeneration == 82) && events.Select(e => e.ProbeId).Distinct().Count() == 1);
            Check(events.Any(e => e.Attempt == 1 && e.Outcome == ProbeOutcome.Failed) && events.Any(e => e.Attempt == 2 && e.Phase == ProbePhase.Validate && e.Outcome == ProbeOutcome.Succeeded));
            Check(!JsonSerializer.Serialize(events).Contains("PRIVATE_INVALID_BODY"));
        });
        await test("handler self-cancel without caller or deadline cancellation is failure rather than timeout", async unused =>
        {
            var events = new List<ProbeObservation>();
            var messages = new List<string>();
            var handler = new HttpFixture(call => call == 1
                ? throw new OperationCanceledException("PRIVATE_HANDLER_DETAIL")
                : new(HttpStatusCode.OK) { Content = new StringContent("198.51.100.7") });
            await ConnectionProbe.CheckObservedAsync(new(83), events.Add, log: messages.Add, testHandler: handler);
            Check(handler.Calls == 2);
            Check(events.Any(e => e.Attempt == 1 && e.Phase == ProbePhase.Request && e.Outcome == ProbeOutcome.Failed));
            Check(!events.Any(e => e.Outcome is ProbeOutcome.TimedOut or ProbeOutcome.Canceled));
            Check(messages.Any(m => m.Contains("timeout=none", StringComparison.Ordinal)));
            Check(!JsonSerializer.Serialize(new { events, messages }).Contains("PRIVATE_HANDLER_DETAIL"));
        });
    }

    sealed class HttpFixture(Func<int, HttpResponseMessage> reply) : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => Task.FromResult(reply(++Calls));
    }
    sealed class ActivitySource : IActivityEventSource
    {
        public event Action<ActivityEvent>? Event;
        public event Action<Exception>? Fault;
        public Action<Exception>? CapturedFault;
        public int Stops;
        public void Start() => CapturedFault = Fault;
        public void Stop() => Stops++;
        public void Dispose() { }
        public ActivityTraceStats ReadStats() => new(0, 0, 0, true, null);
        public void Emit(ActivityEvent value) => Event?.Invoke(value);
    }
    sealed class ActivitySink(bool blocked = false) : IActivitySink
    {
        readonly object gate = new();
        readonly List<string> records = [];
        int batches;
        public string FilePath => "synthetic-diagnostics-activity.log";
        public readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly ManualResetEventSlim Release = new(!blocked);
        public Action<string>? Written;
        public string[] Records { get { lock (gate) { return records.ToArray(); } } }
        public void WriteBatch(IReadOnlyList<string> values)
        {
            if (Interlocked.Increment(ref batches) == 1)
            {
                Entered.TrySetResult();
                Check(Release.Wait(TimeSpan.FromSeconds(5)));
            }
            lock (gate)
            {
                records.AddRange(values);
            }

            foreach (string record in values)
            {
                Written?.Invoke(record);
            }
        }
        public void Dispose() => Release.Set();
    }
    static async Task ActivityBoundaryTests(Func<string, Func<string, Task>, Task> test)
    {
        await test("queued pre-gap lifecycle cannot attribute post-gap PID reuse to stale process", async unused =>
        {
            var source = new ActivitySource();
            var sink = new ActivitySink(blocked: true);
            using var monitor = new ActivityMonitor(() => source, sink, (_, _) => null,
                queueCapacity: 2, batchSize: 1, flushInterval: TimeSpan.FromMilliseconds(10), captureBaseline: false);
            var beforeWritten = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            sink.Written = line =>
            {
                using var json = JsonDocument.Parse(line);
                if (json.RootElement.TryGetProperty("localPort", out var port) && port.ValueKind == JsonValueKind.Number && port.GetInt32() == 50001)
                {
                    beforeWritten.TrySetResult();
                }
            };
            try
            {
                await monitor.StartAsync().WaitAsync(TimeSpan.FromSeconds(2));
                await sink.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
                source.Emit(new(Epoch, "process.start", 42, "old-process"));
                source.Emit(new(Epoch.AddSeconds(1), "tcp.connect", 42, Protocol: "TCP", LocalPort: 50001));
                source.Emit(new(Epoch.AddSeconds(2), "process.start", 42, "new-process"));
                Check(monitor.Counters.Dropped == 1);
                sink.Release.Set();
                await beforeWritten.Task.WaitAsync(TimeSpan.FromSeconds(2));
                source.Emit(new(Epoch.AddSeconds(3), "tcp.connect", 42, Protocol: "TCP", LocalPort: 50002));
                await monitor.StopAsync().WaitAsync(TimeSpan.FromSeconds(2));
                var records = sink.Records.Select(line => { using var d = JsonDocument.Parse(line); return d.RootElement.Clone(); }).ToArray();
                var after = records.Single(r => r.TryGetProperty("localPort", out var p) && p.ValueKind == JsonValueKind.Number && p.GetInt32() == 50002);
                Check(after.GetProperty("attribution").GetString() == "unknown" && after.GetProperty("instance").ValueKind == JsonValueKind.Null);
                Check(records.Any(r => r.GetProperty("kind").GetString() == "monitor.attribution-gap"));
            }
            finally { sink.Release.Set(); await monitor.StopAsync().WaitAsync(TimeSpan.FromSeconds(2)); }
        });
        await test("late old-source fault cannot stop or contaminate a restarted monitor", async unused =>
        {
            var first = new ActivitySource();
            var second = new ActivitySource();
            int created = 0;
            var sink = new ActivitySink();
            using var monitor = new ActivityMonitor(() => ++created == 1 ? first : second, sink, (_, _) => null,
                flushInterval: TimeSpan.FromMilliseconds(10), captureBaseline: false);
            await monitor.StartAsync().WaitAsync(TimeSpan.FromSeconds(2));
            var late = first.CapturedFault!;
            await monitor.StopAsync().WaitAsync(TimeSpan.FromSeconds(2));
            await monitor.StartAsync().WaitAsync(TimeSpan.FromSeconds(2));
            late(new IOException("stale-source"));
            Check(monitor.Running && monitor.LastError == null && second.Stops == 0);
            await monitor.StopAsync().WaitAsync(TimeSpan.FromSeconds(2));
            Check(second.Stops == 1);
        });
    }
}
