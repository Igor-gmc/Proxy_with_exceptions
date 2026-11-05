namespace ProxyBridge;

// Only these metadata fields may cross the ETW callback boundary. Never add
// command lines, arbitrary payloads, packet contents, URLs or headers here.
internal sealed record ActivityEvent(DateTimeOffset Timestamp, string Kind, int ProcessId,
    string? ImageName = null, int? ParentProcessId = null, int? ExitCode = null,
    string? Protocol = null, string? LocalAddress = null, int? LocalPort = null,
    string? RemoteAddress = null, int? RemotePort = null, long? Bytes = null, string? ErrorCode = null);

internal sealed record ActivityTraceStats(long EventsLost, long RealTimeBuffersLost,
    long CallbackErrors, bool Running, string? ErrorCode);

internal interface IActivityEventSource : IDisposable
{
    event Action<ActivityEvent>? Event;
    event Action<Exception>? Fault;
    void Start();
    void Stop();
    ActivityTraceStats ReadStats();
}

internal interface IActivitySink : IDisposable
{
    string FilePath
    {
        get;
    }
    void WriteBatch(IReadOnlyList<string> records);
}

internal sealed record ActivityProcessIdentity(int ProcessId, DateTimeOffset Started,
    string ImageName, string? ImagePath = null);

internal sealed record ActivityMonitorCounters(long Accepted, long Written, long Dropped, long AggregationDropped);
