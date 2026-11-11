namespace ProxyBridge;

// Pure classification of one sing-box output line, kept separate from the
// stdout drain so that the incident rules can be tested without a process.
internal static class EngineOutputClassifier
{
    public static string Classify(string message)
    {
        bool error = message.Contains("ERROR", StringComparison.Ordinal) || message.Contains("FATAL", StringComparison.Ordinal);
        bool canceled = message.Contains("context canceled", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("operation was canceled", StringComparison.OrdinalIgnoreCase);
        // Excluded applications use outbound/direct; their failures concern the
        // destination, not the proxy, and must not open a proxy incident.
        bool direct = message.Contains("outbound/direct", StringComparison.OrdinalIgnoreCase);
        return !error ? "output" : canceled ? "canceled" : direct ? "direct-error" :
            message.Contains("dial tcp", StringComparison.OrdinalIgnoreCase) ? "proxy-dial-error" :
            message.Contains("read tcp", StringComparison.OrdinalIgnoreCase) ? "proxy-read-error" :
            message.Contains("socks5: request rejected", StringComparison.OrdinalIgnoreCase) ? "proxy-rejected" : "engine-error";
    }

    // Only proxy/engine errors outside an expected stop open or extend an incident.
    public static bool ShouldTrigger(string category, bool expectedStop) =>
        !expectedStop && category is "proxy-dial-error" or "proxy-read-error" or "proxy-rejected" or "engine-error";
}
