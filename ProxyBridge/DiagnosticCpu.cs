namespace ProxyBridge;

internal static class DiagnosticCpu
{
    internal static double? Percent(long? previousCpuTicks, long currentCpuTicks,
        TimeSpan elapsed, int processorCount)
    {
        if (previousCpuTicks == null || currentCpuTicks < previousCpuTicks.Value ||
            elapsed <= TimeSpan.Zero || processorCount <= 0) return null;
        return 100.0 * (currentCpuTicks - previousCpuTicks.Value) / TimeSpan.TicksPerSecond /
            elapsed.TotalSeconds / processorCount;
    }
}
