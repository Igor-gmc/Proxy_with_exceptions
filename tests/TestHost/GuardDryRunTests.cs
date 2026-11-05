
namespace ProxyBridge;

internal static class GuardDryRunTests
{
    static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Test invariant failed.");
        }
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> Test, Action<string> Record, Settings s, Settings excluded, string app)
    {
        await Test("WFP dry runs preserve filter count and exact policy matches, no commit", () =>
        {
            string stage = "read initial filter count";
            try
            {
                uint before = Guard.Status;
                stage = "match initial base policy";
                bool baseMatch = Guard.IsConfigured(s);
                stage = "match initial exclusion policy";
                bool? excludedMatch = File.Exists(app) ? Guard.IsConfigured(excluded) : null;
                bool? stoppedDnsMatch = File.Exists(app) ? Guard.IsConfigured(excluded, allowStoppedDns: true) : null;
                void CheckUnchanged()
                {
                    stage += ": verify unchanged count and policy";
                    Require(Guard.Status == before);
                    Require(Guard.IsConfigured(s) == baseMatch);
                    if (excludedMatch.HasValue)
                    {
                        Require(Guard.IsConfigured(excluded) == excludedMatch.Value);
                    }

                    if (stoppedDnsMatch.HasValue)
                    {
                        Require(Guard.IsConfigured(excluded, allowStoppedDns: true) == stoppedDnsMatch.Value);
                    }
                }
                stage = "reject invalid port";
                Reject(() => Guard.Configure(s with { Port = 65536 }, dryRun: true));
                CheckUnchanged();
                stage = "reject IPv6 proxy endpoint";
                Reject(() => Guard.Configure(s with { Host = "::1" }, dryRun: true));
                CheckUnchanged();
                stage = "configure base policy dry run";
                Guard.Configure(s, dryRun: true);
                CheckUnchanged();
                if (File.Exists(app))
                {
                    stage = "configure exclusion policy dry run";
                    Guard.Configure(excluded, dryRun: true);
                    CheckUnchanged();
                    stage = "configure stopped DNS exclusion policy dry run";
                    Guard.Configure(excluded, dryRun: true, allowStoppedDns: true);
                    CheckUnchanged();
                }
                else
                {
                    Record("SKIP: WFP exclusion dry run: System32/notepad.exe missing");
                }

                stage = "enumerate interface GUIDs";
                var nic = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback && Guid.TryParse(n.Id, out _));
                if (nic == null)
                {
                    Record("SKIP: WFP TUN-condition dry run: no interface GUID available");
                }
                else
                {
                    var guid = Guid.Parse(nic.Id);
                    stage = "convert interface GUID to LUID";
                    Require(ConvertInterfaceGuidToLuid(ref guid, out ulong luid) == 0);
                    stage = "match initial TUN policy";
                    bool tunMatch = Guard.IsConfigured(s, luid);
                    stage = "configure TUN policy dry run";
                    Guard.Configure(s, luid, dryRun: true);
                    CheckUnchanged();
                    stage = "verify unchanged TUN policy match";
                    Require(Guard.IsConfigured(s, luid) == tunMatch);
                    if (File.Exists(app))
                    { stage = "configure TUN exclusion policy dry run"; Guard.Configure(excluded, luid, dryRun: true); CheckUnchanged(); }
                }
                return Task.CompletedTask;
            }
            catch (Exception ex) { throw new InvalidOperationException("WFP stage: " + stage + "; " + ex.Message, ex); }
        });
    }
    static void Reject(Action action)
    {
        try
        { action(); }
        catch (ArgumentException) { return; }
        throw new InvalidOperationException("Invalid input accepted.");
    }

    [System.Runtime.InteropServices.DllImport("iphlpapi.dll")]
    static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);
}
