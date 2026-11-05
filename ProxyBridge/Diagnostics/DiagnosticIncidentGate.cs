namespace ProxyBridge;

// An ongoing failure episode retains its first evidence. Repeated retries
// extend the quiet-period deadline instead of replacing the original snapshot.
internal sealed class DiagnosticIncidentGate(TimeProvider? clock = null, TimeSpan? quietPeriod = null)
{
    readonly object gate = new();
    readonly TimeProvider time = clock ?? TimeProvider.System;
    readonly TimeSpan quiet = quietPeriod ?? TimeSpan.FromSeconds(60);
    long lastFailure;
    string? current;
    long coalesced;
    public string? Current
    {
        get
        {
            lock (gate)
            {
                return current;
            }
        }
    }
    public long Coalesced
    {
        get
        {
            lock (gate)
            {
                return coalesced;
            }
        }
    }
    public string? TryBegin()
    {
        lock (gate)
        {
            long now = time.GetTimestamp();
            bool existing = current != null && time.GetElapsedTime(lastFailure, now) < quiet;
            lastFailure = now;
            if (existing)
            {
                coalesced++;
                return null;
            }
            current = time.GetUtcNow().ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..12];
            return current;
        }
    }
}
