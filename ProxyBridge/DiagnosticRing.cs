using System.Text;

namespace ProxyBridge;

// No filesystem/native/network calls under this lock. Snapshot copies only the
// bounded array of immutable references; event strings themselves are immutable.
internal sealed class DiagnosticRing
{
    readonly object gate = new();
    readonly Queue<DiagnosticRingEntry> entries = new();
    readonly TimeProvider clock;
    readonly int maxCount, maxRecordBytes;
    readonly long maxBytes;
    readonly TimeSpan age;
    long bytes, sequence, evicted, oversized;
    public DiagnosticRing(TimeProvider? clock = null, int maxCount = 4096,
        long maxBytes = 4_000_000, int maxRecordBytes = 64_000, TimeSpan? age = null)
    {
        if (maxCount < 1 || maxBytes < 1 || maxRecordBytes < 1) throw new ArgumentOutOfRangeException(nameof(maxCount));
        this.clock = clock ?? TimeProvider.System; this.maxCount = maxCount;
        this.maxBytes = maxBytes; this.maxRecordBytes = maxRecordBytes;
        this.age = age ?? TimeSpan.FromSeconds(60);
        if (this.age <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(age));
    }
    void Prune(long now)
    {
        while (entries.TryPeek(out var first) && clock.GetElapsedTime(first.MonotonicTicks, now) > age) Remove();
    }
    void Remove() { bytes -= entries.Dequeue().Utf8Bytes; evicted++; }
    public DiagnosticRingEntry? Add(string json, DateTimeOffset eventTime)
    {
        int size = Encoding.UTF8.GetByteCount(json) + 2;
        lock (gate) {
            long now = clock.GetTimestamp(); Prune(now);
            if (size > maxRecordBytes || size > maxBytes) { oversized++; return null; }
            while (entries.Count >= maxCount || bytes + size > maxBytes) Remove();
            var entry = new DiagnosticRingEntry(++sequence, now, eventTime, json, size);
            entries.Enqueue(entry); bytes += size; return entry;
        }
    }
    public DiagnosticRingEntry[] Snapshot()
    {
        lock (gate) { Prune(clock.GetTimestamp()); return entries.ToArray(); }
    }
    public DiagnosticRingStats Stats
    {
        get { lock (gate) { Prune(clock.GetTimestamp()); return new(entries.Count, bytes, evicted, oversized); } }
    }
}
