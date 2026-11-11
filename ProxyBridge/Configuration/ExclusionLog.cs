namespace ProxyBridge;

// Startup-only journal lines listing the exclusions in effect, so that any
// direct traffic seen later can be attributed. Contains only EXE paths and
// address rules; endpoint and credentials are never included.
internal static class ExclusionLog
{
    public static string[] StartupLines(Settings settings)
    {
        var lines = new List<string>(1 + settings.ExcludedApplications.Length + settings.ExcludedAddresses.Length)
        {
            $"STARTUP exclusions applications={settings.ExcludedApplications.Length} addresses={settings.ExcludedAddresses.Length}"
        };
        for (int i = 0; i < settings.ExcludedApplications.Length; i++)
        {
            lines.Add($"STARTUP exclusion application[{i + 1}]={settings.ExcludedApplications[i]}");
        }
        for (int i = 0; i < settings.ExcludedAddresses.Length; i++)
        {
            lines.Add($"STARTUP exclusion address[{i + 1}]={settings.ExcludedAddresses[i]}");
        }
        return [.. lines];
    }
}
