using System.Net;
using System.Net.NetworkInformation;

namespace ProxyBridge;

internal static class TunReadinessTests
{
    static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("TUN readiness invariant failed.");
        }
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> test)
    {
        await test("TUN readiness rejects stale Down and mismatched adapter/address state", () =>
        {
            var v4 = new TunAddress(IPAddress.Parse("172.29.231.1"), 30, DuplicateAddressDetectionState.Preferred);
            var v6 = new TunAddress(IPAddress.Parse("fdfe:dcba:7231::1"), 126, DuplicateAddressDetectionState.Preferred);
            bool Ready(params TunAddress[] addresses) => Guard.IsTunReady(OperationalStatus.Up, "sing-tun Tunnel", (NetworkInterfaceType)53, addresses);
            Require(Ready(v4, v6));
            Require(!Guard.IsTunReady(OperationalStatus.Down, "sing-tun Tunnel", (NetworkInterfaceType)53, []));
            Require(!Guard.IsTunReady(OperationalStatus.Down, "sing-tun Tunnel", (NetworkInterfaceType)53, [v4, v6]));
            Require(!Guard.IsTunReady(OperationalStatus.Up, "Other VPN", (NetworkInterfaceType)53, [v4, v6]));
            Require(!Guard.IsTunReady(OperationalStatus.Up, "sing-tun Tunnel", NetworkInterfaceType.Ethernet, [v4, v6]));
            Require(!Ready(v4));
            Require(!Ready(v4 with { PrefixLength = 24 }, v6));
            Require(!Ready(v4, v6 with { DadState = DuplicateAddressDetectionState.Tentative }));
            Require(!Ready(v4, v6, new TunAddress(IPAddress.Parse("192.168.1.20"), 24, DuplicateAddressDetectionState.Preferred)));
            Require(!Ready(v4, v6, new TunAddress(IPAddress.Parse("169.254.1.20"), 16, DuplicateAddressDetectionState.Preferred)));
            Require(!Ready(v4, v4, v6));
            Require(Ready(v4, v6, new TunAddress(IPAddress.Parse("fe80::1"), 64, DuplicateAddressDetectionState.Preferred)));
            return Task.CompletedTask;
        });
    }
}
