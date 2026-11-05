namespace ProxyBridge;

// Never add Settings, credentials, request bodies or arbitrary command lines.
internal sealed record DiagnosticContext(string ProxyHost, int ProxyPort, string Protocol,
    int? EnginePid, long EngineGeneration, ulong ActiveLuid, bool ProtectionRequired,
    bool ConnectWanted, bool? PolicyVerified, DateTimeOffset CapturedAt, string Stage,
    DateTimeOffset? EngineStartedUtc = null);

internal sealed record DiagnosticRingEntry(long Sequence, long MonotonicTicks, DateTimeOffset EventTime,
    string Json, int Utf8Bytes);
internal sealed record DiagnosticRingStats(int Count, long Bytes, long Evicted, long Oversized);
internal sealed record DiagnosticIncident(string Id, string Reason, DateTimeOffset TriggerTime,
    long TriggerTicks, DiagnosticRingEntry[] Before, DiagnosticContext? Context);
