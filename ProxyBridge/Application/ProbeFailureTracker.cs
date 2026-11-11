namespace ProxyBridge;

// Counts consecutive health-probe failures while the tunnel and WFP policy are
// still verified. A single slow or failed probe only reports degradation; the
// tunnel is restarted after Threshold failures in a row. Loss of the engine or
// policy is not counted here: the caller recovers from it immediately.
// Tolerating probe failures never permits direct traffic: the active WFP policy
// stays installed while the counter accumulates.
internal sealed class ProbeFailureTracker(int threshold = ProbeFailureTracker.DefaultThreshold)
{
    public const int DefaultThreshold = 3;

    public int Threshold { get; } = threshold >= 1
        ? threshold
        : throw new ArgumentOutOfRangeException(nameof(threshold));

    public int ConsecutiveFailures { get; private set; }

    // Returns true when the failure reaches the threshold and recovery is due.
    // The counter is reset at that point, so the next connection starts clean.
    public bool RecordFailure()
    {
        ConsecutiveFailures++;
        if (ConsecutiveFailures < Threshold)
        {
            return false;
        }

        ConsecutiveFailures = 0;
        return true;
    }

    public void Reset() => ConsecutiveFailures = 0;
}
