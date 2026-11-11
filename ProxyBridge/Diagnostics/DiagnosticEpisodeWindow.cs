namespace ProxyBridge;

// Post-trigger evidence window: 30 s after the latest trigger of an episode,
// capped at 5 minutes after its first trigger. Ticks are Stopwatch-style
// timestamps; frequency is ticks per second.
internal static class DiagnosticEpisodeWindow
{
    public const int PostWindowSeconds = 30;
    public const int MaxEpisodeSeconds = 300;

    // Deadline requested by a coalesced trigger observed at nowTicks.
    public static long ExtendRequest(long nowTicks, long frequency) =>
        nowTicks + PostWindowSeconds * frequency;

    // Window of a freshly written incident.
    public static long Initial(long triggerTicks, long frequency) =>
        triggerTicks + PostWindowSeconds * frequency;

    // The window never shrinks and never passes first trigger + MaxEpisodeSeconds.
    public static long Apply(long postUntil, long extendRequest, long firstTriggerTicks, long frequency) =>
        Math.Max(postUntil, Math.Min(extendRequest, firstTriggerTicks + MaxEpisodeSeconds * frequency));
}
