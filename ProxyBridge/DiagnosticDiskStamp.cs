namespace ProxyBridge;

internal static class DiagnosticDiskStamp
{
    // Captured immediately before issuing writes, not a claim that Flush has
    // completed. Completion latency and failures are separate collector stats.
    internal static string Add(string json) => json.StartsWith('{')
        ? "{\"writeStartedAtUtc\":\"" + DateTimeOffset.UtcNow.ToString("O") + "\"," + json[1..]
        : json;
}
