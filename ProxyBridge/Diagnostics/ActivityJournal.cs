using System.Diagnostics;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ProxyBridge;

internal sealed class ActivityFileSink(string filePath, long maxBytes = 25_000_000) : IActivitySink
{
    static readonly UTF8Encoding Utf8 = new(false);
    public string FilePath => filePath;
    public void WriteBatch(IReadOnlyList<string> records)
    {
        if (maxBytes < 512)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }

        if (records.Count == 0)
        {
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(filePath))!);
        using var file = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
        file.Position = file.Length;
        foreach (string record in records)
        {
            // Serialize complete JSON records; never split UTF-8 or leave invalid JSON.
            byte[] bytes = Utf8.GetBytes(record + "\r\n");
            if (bytes.Length > Math.Min(64_000, maxBytes - 256))
            {
                bytes = Utf8.GetBytes("{\"kind\":\"monitor.record-omitted\",\"reason\":\"size-limit\"}\r\n");
            }

            if (file.Length > maxBytes - bytes.Length)
            {
                file.SetLength(0);
                file.Position = 0;
                file.Write(Utf8.GetBytes("{\"kind\":\"monitor.log-reset\",\"reason\":\"size-limit\"}\r\n"));
            }
            file.Write(bytes);
        }
        // One durability flush for the whole batch, never on the ETW thread.
        file.Flush(flushToDisk: true);
    }
    public void Dispose()
    {
    }
}

// Single-consumer reducer; all attribution is time-qualified to avoid PID reuse.
internal sealed class ActivityJournal(Func<int, DateTimeOffset, ActivityProcessIdentity?> resolver,
    int maxProcesses = 8192, int maxFlows = 4096)
{
    static readonly JsonSerializerOptions Json = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    readonly Dictionary<int, ActivityProcessIdentity> processes = [];
    readonly Dictionary<int, DateTimeOffset> ended = [];
    readonly Dictionary<FlowKey, Flow> flows = [];
    public long AggregationDropped
    { get; private set; }
    sealed record FlowKey(int Pid, string? Instance, string Protocol, string? Local, int? LocalPort, string? Remote, int? RemotePort);
    sealed class Flow(ActivityEvent first, ActivityProcessIdentity? identity)
    {
        public ActivityEvent First = first;
        public ActivityProcessIdentity? Identity = identity;
        public DateTimeOffset Last = first.Timestamp;
        public long Sent, Received, Events;
    }
    static string? Safe(string? text)
    {
        if (text == null)
        {
            return null;
        }

        string clean = AppLog.Redact(text);
        return clean.Length <= 2048 ? clean : clean[..2048];
    }
    static string? Instance(ActivityProcessIdentity? identity) => identity == null ? null : $"{identity.ProcessId}:{identity.Started.UtcTicks}";
    public static string Diagnostic(string kind, object? data = null) => JsonSerializer.Serialize(new
    {
        schema = 1,
        time = DateTimeOffset.Now,
        kind,
        source = "monitor",
        data
    }, Json);
    static string Line(ActivityEvent value, ActivityProcessIdentity? identity, object? traffic = null) =>
        JsonSerializer.Serialize(new
        {
            schema = 1,
            time = value.Timestamp,
            observed = DateTimeOffset.Now,
            kind = Safe(value.Kind),
            source = value.Kind == "process.present" ? "snapshot" : "etw",
            pid = value.ProcessId > 0 ? (int?)value.ProcessId : null,
            instance = Instance(identity),
            attribution = identity == null ? "unknown" : "time-qualified",
            image = Safe(identity?.ImageName ?? value.ImageName),
            path = Safe(identity?.ImagePath),
            parentPid = value.ParentProcessId,
            exitCode = value.ExitCode,
            protocol = Safe(value.Protocol),
            localAddress = Safe(value.LocalAddress),
            localPort = value.LocalPort,
            remoteAddress = Safe(value.RemoteAddress),
            remotePort = value.RemotePort,
            errorCode = Safe(value.ErrorCode),
            traffic,
            observational = true
        }, Json);

    ActivityProcessIdentity? Resolve(ActivityEvent value)
    {
        if (value.ProcessId <= 0)
        {
            return null;
        }

        processes.TryGetValue(value.ProcessId, out var cached);
        bool hasStop = ended.TryGetValue(value.ProcessId, out var stopped);
        if (hasStop && value.Timestamp <= stopped)
        {
            return null;
        }

        if (hasStop && cached?.Started <= stopped)
        {
            cached = null;
        }

        ActivityProcessIdentity? found;
        try
        {
            found = resolver(value.ProcessId, value.Timestamp);
        }
        catch { return null; }
        if (found == null)
        {
            return cached?.Started <= value.Timestamp ? cached : null;
        }

        if (found.ProcessId != value.ProcessId)
        {
            return null;
        }

        if (hasStop && found.Started <= stopped)
        {
            return null;
        }

        if (found.Started > value.Timestamp)
        {
            return cached?.Started <= value.Timestamp ? cached : null;
        }

        if (processes.Count < maxProcesses)
        {
            processes[value.ProcessId] = found;
        }

        return found;
    }
    public void InvalidateAttribution()
    {
        processes.Clear();
        ended.Clear();
    }
    public IEnumerable<string> Accept(ActivityEvent value)
    {
        if (value.Kind is "process.start" or "process.present")
        {
            // Per-CPU ETW buffers can arrive out of order. An older start must
            // never erase a known stop and revive attribution for a dead PID.
            if (ended.TryGetValue(value.ProcessId, out var stopped) && value.Timestamp <= stopped)
            {
                yield return Line(value, null);
                yield break;
            }
            if (processes.TryGetValue(value.ProcessId, out var newer) && newer.Started > value.Timestamp)
            {
                yield return Line(value, null);
                yield break;
            }
            ActivityProcessIdentity? resolved = null;
            try
            {
                resolved = resolver(value.ProcessId, value.Timestamp);
            }
            catch { }
            if (resolved != null && (resolved.ProcessId != value.ProcessId || resolved.Started > value.Timestamp))
            {
                resolved = null;
            }

            var identity = resolved ?? (value.Kind == "process.start" && value.ProcessId > 0
                ? new ActivityProcessIdentity(value.ProcessId, value.Timestamp, value.ImageName ?? "unknown") : null);
            if (identity != null && ended.TryGetValue(value.ProcessId, out stopped) && identity.Started <= stopped)
            {
                identity = null;
            }

            if (identity != null)
            {
                if (processes.Count >= maxProcesses && !processes.ContainsKey(value.ProcessId))
                {
                    processes.Remove(processes.Keys.First());
                }

                processes[value.ProcessId] = identity;
                ended.Remove(value.ProcessId);
            }
            yield return Line(value, identity);
            yield break;
        }
        var current = Resolve(value);
        if (value.Kind == "process.stop")
        {
            yield return Line(value, current);
            if (current != null && processes.TryGetValue(value.ProcessId, out var cached) && cached == current)
            {
                processes.Remove(value.ProcessId);
            }

            if (ended.Count >= maxProcesses && !ended.ContainsKey(value.ProcessId))
            {
                ended.Remove(ended.Keys.First());
            }

            if (!ended.TryGetValue(value.ProcessId, out var oldEnd) || oldEnd < value.Timestamp)
            {
                ended[value.ProcessId] = value.Timestamp;
            }

            yield break;
        }
        if (value.Kind is "tcp.send" or "tcp.receive" or "udp.send" or "udp.receive")
        {
            var key = new FlowKey(value.ProcessId, Instance(current), value.Protocol ?? "unknown",
                value.LocalAddress, value.LocalPort, value.RemoteAddress, value.RemotePort);
            if (!flows.TryGetValue(key, out var flow))
            {
                if (flows.Count >= maxFlows)
                {
                    AggregationDropped++;
                    yield break;
                }
                flow = new(value, current);
                flows.Add(key, flow);
            }
            flow.Last = value.Timestamp > flow.Last ? value.Timestamp : flow.Last;
            flow.Events++;
            if (value.Kind.EndsWith(".send", StringComparison.Ordinal))
            {
                flow.Sent += Math.Max(0, value.Bytes ?? 0);
            }
            else
            {
                flow.Received += Math.Max(0, value.Bytes ?? 0);
            }

            yield break;
        }
        yield return Line(value, current);
    }
    public IEnumerable<string> FlushFlows()
    {
        foreach (var flow in flows.Values)
        {
            yield return Line(flow.First with
            {
                Kind = "network.activity"
            }, flow.Identity,
            new
            {
                first = flow.First.Timestamp,
                last = flow.Last,
                observedEvents = flow.Events,
                sentBytes = flow.Sent,
                receivedBytes = flow.Received
            });
        }

        flows.Clear();
    }
    public static ActivityProcessIdentity? ResolveProcess(int pid, DateTimeOffset eventTime)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            var start = new DateTimeOffset(process.StartTime.ToUniversalTime());
            if (start > eventTime)
            {
                return null;
            }

            string? path = null;
            try
            {
                path = process.MainModule?.FileName;
            }
            catch { }
            return new(pid, start, process.ProcessName, path);
        }
        catch { return null; }
    }
}
