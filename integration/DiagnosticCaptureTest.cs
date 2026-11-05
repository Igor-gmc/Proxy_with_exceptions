using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using ProxyBridge;

// Fresh integration process only. Creates loopback TCP sockets and isolated log
// files; never installs filters, changes global audit/options, or connects outside
// loopback. Root owns the CLI entry, singleton mutex, build and execution.
internal static class DiagnosticCaptureTest
{
    static readonly UTF8Encoding Utf8 = new(false);
    const long Generation = 61004;
    const long EvidenceLimit = 16 * 1024 * 1024;

    sealed class LoopbackPair(TcpListener listener, TcpClient client, TcpClient accepted,
        IPAddress address, int clientPort, int serverPort) : IDisposable
    {
        public IPAddress Address { get; } = address;
        public int ClientPort { get; } = clientPort;
        public int ServerPort { get; } = serverPort;
        public void Dispose() { accepted.Dispose(); client.Dispose(); listener.Stop(); }
    }

    public static async Task RunAsync(string output, Action<string> record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!OperatingSystem.IsWindows())
        { record("SKIP: diagnostic collector smoke requires Windows."); return; }
        if (DiagnosticJournal.Enabled || Settings.TestDirectory != null)
        {
            throw new IOException("Diagnostic smoke requires a fresh, isolated integration process.");
        }

        string root = Path.GetFullPath(output);
        BundledAssets.RejectReparsePoints(root);
        Directory.CreateDirectory(root);
        string data = Path.Combine(root, "diagnostic-data");
        if (Directory.Exists(data) || File.Exists(data))
        {
            throw new IOException("Diagnostic data directory must be new.");
        }

        Directory.CreateDirectory(data);
        Settings.TestDirectory = data;
        // Intentionally retain the override until this fresh process exits. A
        // bounded Stop timeout must never redirect a pending worker to production.
        bool journalStarted = false;
        var pairs = new List<LoopbackPair>();
        try
        {
            foreach (bool ipv6 in new[] { false, true })
            {
                string family = ipv6 ? "IPv6" : "IPv4";
                LoopbackPair pair;
                try
                { pair = await OpenPair(ipv6); }
                catch (SocketException ex) when (ipv6 && ex.SocketErrorCode is SocketError.AddressFamilyNotSupported or SocketError.ProtocolNotSupported)
                {
                    record("SKIP: IPv6 loopback unavailable: " + AppLog.ExceptionCodes(ex));
                    continue;
                }
                pairs.Add(pair);
                var snapshot = TcpConnectionDiagnostics.Capture(pair.Address, pair.ServerPort, Environment.ProcessId);
                WriteJson(Path.Combine(root, "tcp-" + family.ToLowerInvariant() + ".json"), snapshot);
                AssertTcp(snapshot, pair, ipv6 ? 23 : 2);
                record("PASS: " + family + " TCP snapshot has both ESTABLISHED loopback tuples, known PID and endpoint/engine counts.");
            }

            AssertWfpDecoder(root);
            record("PASS: synthetic WFP decoder fixture preserves tuple, filter/layer, timestamp and unknown PID; unset fields remain null.");
            await ObserveWfp(root, record);

            var primary = pairs.First(p => p.Address.AddressFamily == AddressFamily.InterNetwork);
            DiagnosticJournal.Start();
            journalStarted = true;
            var capturedAt = DateTimeOffset.UtcNow;
            var context = new DiagnosticContext(primary.Address.ToString(), primary.ServerPort, "diagnostic-loopback",
                Environment.ProcessId, Generation, 0, false, false, null, capturedAt, "diagnostic-smoke.before",
                new DateTimeOffset(Process.GetCurrentProcess().StartTime.ToUniversalTime()));
            DiagnosticJournal.UpdateContext(context);
            DiagnosticJournal.Record("smoke.before", new { marker = "before-first-trigger" });
            // Allow sampler to produce its first TCP/status evidence while sockets
            // remain established; this test does not perform a protection transition.
            await Task.Delay(2000);
            long began = Stopwatch.GetTimestamp();
            DiagnosticJournal.Trigger("diagnostic-smoke", new { fixture = true });
            double triggerMilliseconds = Stopwatch.GetElapsedTime(began).TotalMilliseconds;
            DiagnosticJournal.Record("smoke.after", new { marker = "after-first-trigger" });
            DiagnosticJournal.Trigger("diagnostic-smoke-coalesced", new { fixture = true });
            await Task.Delay(6000);
            await DiagnosticJournal.StopAsync();
            journalStarted = false;
            if (DiagnosticJournal.Enabled || DiagnosticJournal.LastError != null)
            {
                throw new IOException("Diagnostic collector did not stop cleanly: " + DiagnosticJournal.LastError);
            }

            if (!string.Equals(Settings.DataDir, data, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("Diagnostic output escaped the isolated data directory.");
            }

            AssertJournal(data, capturedAt, record);
            WriteJson(Path.Combine(root, "diagnostic-smoke.json"), new
            {
                pid = Environment.ProcessId,
                generation = Generation,
                triggerMilliseconds,
                dataDirectory = data,
                journal = DiagnosticJournal.FilePath,
                source = "read-only collectors and loopback positive control",
                blockPositiveControl = "not performed: no WFP policy changes",
                fullPostWindow = "not exercised: smoke stops before the 30-second window completes"
            });
            record("OBSERVE: Trigger elapsedMs=" + triggerMilliseconds.ToString("F3", System.Globalization.CultureInfo.InvariantCulture) +
                "; not a load/latency guarantee. TestDirectory remains isolated until process exit.");
            record("SKIP: known native WFP block tuple/provider positive control; this smoke deliberately creates no blocking policy.");
            record("SKIP: full 60-second retention/30-second post-window timing; covered separately from this short runtime smoke.");
        }
        finally
        {
            if (journalStarted)
            {
                await DiagnosticJournal.StopAsync();
            }

            foreach (var pair in pairs)
            {
                pair.Dispose();
            }
        }
    }

    static async Task<LoopbackPair> OpenPair(bool ipv6)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        IPAddress address = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        var listener = new TcpListener(address, 0);
        var client = new TcpClient(address.AddressFamily);
        TcpClient? accepted = null;
        try
        {
            if (ipv6)
            { listener.Server.DualMode = false; client.Client.DualMode = false; }
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            await client.ConnectAsync(address, port, timeout.Token);
            accepted = await listener.AcceptTcpClientAsync(timeout.Token);
            return new(listener, client, accepted, address, ((IPEndPoint)client.Client.LocalEndPoint!).Port, port);
        }
        catch { accepted?.Dispose(); client.Dispose(); listener.Stop(); throw; }
    }

    static void AssertTcp(TcpConnectionSnapshot snapshot, LoopbackPair pair, int family)
    {
        var result = snapshot.Families.Single(f => f.Family == family);
        if (result.Status != "captured" || result.Truncated)
        {
            throw new IOException("TCP positive control family unavailable/truncated: " + result.Status + "/" + result.ErrorCode);
        }

        bool Has(int localPort, int remotePort) => snapshot.Summary.Rows.Any(r =>
            r.ProcessId == (uint)Environment.ProcessId && r.Family == family && r.State == 5 &&
            r.LocalAddress == pair.Address.ToString() && r.RemoteAddress == pair.Address.ToString() &&
            r.LocalPort == localPort && r.RemotePort == remotePort);
        if (!Has(pair.ClientPort, pair.ServerPort) || !Has(pair.ServerPort, pair.ClientPort))
        {
            throw new IOException("TCP snapshot did not identify both sides of the known loopback connection.");
        }

        if (snapshot.Summary.Endpoint.Where(s => s.State == 5).Sum(s => s.Count) < 1 ||
            snapshot.Summary.Engine.Where(s => s.State == 5).Sum(s => s.Count) < 2 ||
            snapshot.EndedUtc < snapshot.StartedUtc || snapshot.EndedMonotonicTicks < snapshot.StartedMonotonicTicks ||
            snapshot.MonotonicFrequency != Stopwatch.Frequency)
        {
            throw new IOException("TCP counts/timestamps disagree with positive control.");
        }
    }

    static async Task ObserveWfp(string root, Action<string> record)
    {
        var observed = new ConcurrentQueue<WfpBlockEvent>();
        int admitted = 0;
        using var observer = new WfpBlockDiagnostics(value =>
        {
            if (Interlocked.Increment(ref admitted) > 64)
            {
                return false;
            }

            observed.Enqueue(value);
            return true;
        });
        WfpDiagnosticStatus started = observer.Start();
        long deadline = Stopwatch.GetTimestamp() + 5 * Stopwatch.Frequency;
        while (started.ReasonCode == "starting" && Stopwatch.GetTimestamp() < deadline)
        {
            await Task.Delay(100);
            started = observer.ReadStatus();
        }
        if (started.State == "subscribed")
        {
            if (!started.Subscribed || started.CollectionEnabled != true)
            {
                throw new IOException("WFP subscribed status contradicts prerequisites.");
            }

            record("PASS: passive native WFP subscription started while collection was enabled.");
            await Task.Delay(500);
        }
        else if (started.State is "collection_disabled" or "access_denied" or "unavailable")
        {
            record("SKIP: passive WFP source state=" + started.State + "; reason=" + started.ReasonCode +
                "; nativeError=" + (started.NativeError is uint code ? "0x" + code.ToString("X8") : "none") + ". No global setting changed.");
        }
        else
        {
            throw new IOException("Unexpected WFP startup state: " + started.State);
        }

        observer.Stop();
        var stopped = observer.ReadStatus();
        WriteJson(Path.Combine(root, "wfp-status.json"), new { started, stopped });
        WriteJson(Path.Combine(root, "wfp-observed.json"), new { knownPositiveControl = false, events = observed.ToArray() });
        if (stopped.CallbackErrors != 0 || stopped.ReasonCode is "stop_timeout" or "cleanup_error" || stopped.Subscribed)
        {
            throw new IOException("WFP decoder/lifecycle fault: " + stopped.ReasonCode);
        }

        if (started.State == "subscribed" && stopped.State != "stopped")
        {
            throw new IOException("Own WFP subscription did not stop.");
        }

        if (started.State == "subscribed")
        {
            record("PASS: own WFP subscription stopped without a callback/lifecycle fault.");
        }

        if (observed.IsEmpty)
        {
            record("SKIP: no incidental native classify-drop event arrived; this is not evidence of no blocking.");
        }
        else
        {
            if (observed.Any(e => e.ProcessId != null || e.Source != "wfp.net_event" || e.OriginStatus == "pending"))
            {
                throw new IOException("Native WFP event violated metadata contract.");
            }

            record("PASS: incidental native WFP events decoded as metadata with unknown PID; filter attribution lacks a controlled positive case.");
        }
    }

    static void AssertWfpDecoder(string root)
    {
        byte[] header = new byte[WfpBlockDiagnostics.HeaderBytes], drop = new byte[WfpBlockDiagnostics.DropPrefixBytes];
        var time = DateTimeOffset.UtcNow;
        BinaryPrimitives.WriteInt64LittleEndian(header, time.UtcDateTime.ToFileTimeUtc());
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), 0x33F);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12), 0);
        header[16] = 6;
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(20), 0x7F000001);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(36), 0xCB007109);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(52), 43123);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(54), 8000);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(104), 3);
        BinaryPrimitives.WriteUInt64LittleEndian(drop, 1234);
        BinaryPrimitives.WriteUInt16LittleEndian(drop.AsSpan(8), 48);
        BinaryPrimitives.WriteUInt32LittleEndian(drop.AsSpan(12), 7);
        BinaryPrimitives.WriteUInt32LittleEndian(drop.AsSpan(24), 0x3901);
        var decoded = WfpBlockDiagnostics.DecodeEvent(header, drop, @"C:\diagnostic-fixture.exe", time, Stopwatch.GetTimestamp())!;
        if (decoded.ProcessId != null || decoded.LocalAddress != "127.0.0.1" || decoded.RemoteAddress != "203.0.113.9" ||
            decoded.LocalPort != 43123 || decoded.RemotePort != 8000 || decoded.Protocol != 6 ||
            decoded.FilterId != 1234 || decoded.LayerId != 48 || decoded.Direction != "outbound" ||
            decoded.ReauthorizationReason != 7 || decoded.EventUtc != time)
        {
            throw new IOException("Synthetic WFP metadata fixture failed.");
        }

        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), 0);
        var unset = WfpBlockDiagnostics.DecodeEvent(header, drop, "ignored", time, Stopwatch.GetTimestamp())!;
        if (unset.LocalAddress != null || unset.RemoteAddress != null || unset.LocalPort != null || unset.RemotePort != null ||
            unset.ApplicationPath != null || unset.Protocol != null || unset.ProcessId != null || unset.ReauthorizationReason != null)
        {
            throw new IOException("WFP decoder exposed a field without its presence flag.");
        }

        WriteJson(Path.Combine(root, "wfp-decoder-fixture.json"), new { evidence = "synthetic bytes, not native delivery", decoded, unset });
    }

    static void AssertJournal(string data, DateTimeOffset capturedAt, Action<string> record)
    {
        var entries = ReadEntries(Path.Combine(data, "ProxyBridge-diagnostics.log"));
        bool Has(string kind) => entries.Any(e => Kind(e) == kind);
        foreach (string required in new[] { "diagnostics.start", "context", "smoke.before", "incident.trigger", "smoke.after",
            "tcp.snapshot", "wfp.status", "collector.stats", "diagnostics.stop-requested" })
        {
            if (!Has(required))
            {
                throw new IOException("Diagnostic journal missing required kind: " + required);
            }
        }

        var before = entries.Single(e => Kind(e) == "smoke.before");
        if (before.GetProperty("generation").GetInt64() != Generation || before.GetProperty("enginePid").GetInt32() != Environment.ProcessId ||
            !before.GetProperty("eventTime").TryGetDateTimeOffset(out _) || !before.GetProperty("observedAt").TryGetDateTimeOffset(out _) ||
            before.GetProperty("monotonicTicks").GetInt64() <= 0 || before.GetProperty("observedMonotonicTicks").GetInt64() <= 0)
        {
            throw new IOException("Journal metadata lacks the captured generation/PID/timestamps.");
        }

        if (!entries.Where(e => Kind(e) == "tcp.snapshot").Any(e =>
            e.GetProperty("data").GetProperty("EngineProcessId").ValueKind == JsonValueKind.Number &&
            e.GetProperty("data").GetProperty("EngineProcessId").GetInt32() == Environment.ProcessId))
        {
            throw new IOException("Sampler did not use the known PID context.");
        }

        var stats = entries.Last(e => Kind(e) == "collector.stats").GetProperty("data");
        foreach (string counter in new[] { "dropped", "incidentDropped", "errors" })
        {
            if (stats.GetProperty(counter).GetInt64() != 0)
            {
                throw new IOException("Collector reported nonzero " + counter + ".");
            }
        }

        if (stats.GetProperty("incidentCoalesced").GetInt64() < 1)
        {
            throw new IOException("Repeated incident was not coalesced.");
        }

        record("PASS: runtime journal has collector TCP/WFP status, generation/PID/timestamps, zero reported collector errors/drops and coalesced retry.");

        string[] files = Directory.GetFiles(Path.Combine(data, "incidents"), "ProxyBridge-incident-*.jsonl");
        if (files.Length != 1)
        {
            throw new IOException("Expected exactly one coalesced incident file.");
        }

        var incident = ReadEntries(files[0]);
        int boundary = Array.FindIndex(incident, e => Kind(e) == "incident.pre-window-end");
        int pre = Array.FindIndex(incident, e => Kind(e) == "smoke.before");
        int post = Array.FindIndex(incident, e => Kind(e) == "smoke.after");
        var metadata = incident[0];
        var frozen = metadata.GetProperty("context");
        if (Kind(metadata) != "incident.begin" || pre < 0 || boundary <= pre || post <= boundary ||
            frozen.GetProperty("EngineGeneration").GetInt64() != Generation || frozen.GetProperty("EnginePid").GetInt32() != Environment.ProcessId ||
            frozen.GetProperty("CapturedAt").GetDateTimeOffset() != capturedAt || frozen.GetProperty("PolicyVerified").ValueKind != JsonValueKind.Null)
        {
            throw new IOException("Incident pre/post boundary or frozen context assertion failed.");
        }

        record("PASS: isolated incident preserves pre-trigger evidence/context and appends post-trigger evidence after its boundary; no fresh policy audit is claimed.");
    }

    static string? Kind(JsonElement entry) => entry.TryGetProperty("kind", out var kind) ? kind.GetString() : null;
    static JsonElement[] ReadEntries(string path)
    {
        if (!File.Exists(path) || new FileInfo(path).Length > EvidenceLimit)
        {
            throw new IOException("Missing/oversized smoke evidence.");
        }

        var rows = new List<JsonElement>();
        foreach (string line in File.ReadLines(path, Utf8))
        {
            if (rows.Count >= 20000)
            {
                throw new IOException("Smoke evidence exceeded record limit.");
            }

            using var document = JsonDocument.Parse(line);
            rows.Add(document.RootElement.Clone());
        }
        return rows.ToArray();
    }
    static void WriteJson(string path, object value)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(stream, value);
    }
}
