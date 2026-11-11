namespace ProxyBridge;

internal static class ProbeFailureTrackerTests
{
    static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> test)
    {
        await test("probe tracker: tunnel restart only after three consecutive failures", () =>
        {
            var tracker = new ProbeFailureTracker();
            Require(tracker.Threshold == 3, "Default threshold must be 3");
            Require(!tracker.RecordFailure() && tracker.ConsecutiveFailures == 1, "First failure must not restart");
            Require(!tracker.RecordFailure() && tracker.ConsecutiveFailures == 2, "Second failure must not restart");
            Require(tracker.RecordFailure(), "Third consecutive failure must restart");
            Require(tracker.ConsecutiveFailures == 0, "Counter must reset after restart is requested");
            return Task.CompletedTask;
        });
        await test("probe tracker: a success between failures resets the streak", () =>
        {
            var tracker = new ProbeFailureTracker();
            tracker.RecordFailure();
            tracker.RecordFailure();
            tracker.Reset();
            Require(!tracker.RecordFailure() && !tracker.RecordFailure(), "Streak must restart after success");
            Require(tracker.RecordFailure(), "Three new consecutive failures must restart");
            return Task.CompletedTask;
        });
        await test("probe tracker: threshold 1 restarts immediately; invalid threshold rejected", () =>
        {
            Require(new ProbeFailureTracker(1).RecordFailure(), "Threshold 1 must restart on first failure");
            bool rejected = false;
            try
            {
                _ = new ProbeFailureTracker(0);
            }
            catch (ArgumentOutOfRangeException) { rejected = true; }
            Require(rejected, "Threshold 0 must be rejected");
            return Task.CompletedTask;
        });
    }
}
