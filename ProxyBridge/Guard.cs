using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace ProxyBridge;
internal readonly record struct TunAddress(IPAddress Address, int PrefixLength, DuplicateAddressDetectionState DadState);
internal static class Guard
{
    [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    static extern uint GuardConfigureV4(uint ip, ushort port, ulong luid, string engine,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr, SizeParamIndex = 5)] string[] excluded,
        uint count, [MarshalAs(UnmanagedType.Bool)] bool allowStoppedDns, [MarshalAs(UnmanagedType.Bool)] bool dryRun);
    [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    static extern uint GuardMatchesV4(uint ip, ushort port, ulong luid, string engine,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr, SizeParamIndex = 5)] string[] excluded,
        uint count, [MarshalAs(UnmanagedType.Bool)] bool allowStoppedDns, [MarshalAs(UnmanagedType.Bool)] out bool matches);
    [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl)] static extern uint GuardRemove();
    [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl)] static extern uint GuardDeactivateV3();
    [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl)] static extern uint GuardStatus(out uint count);
    [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl)] static extern IntPtr GuardLastDiagnostic();
    [DllImport("iphlpapi.dll")] static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);
    // Count is informational. IsConfigured verifies the complete expected policy.
    public static uint Status { get { Check(GuardStatus(out var count)); return count; } }
    static uint Address(Settings s)
    {
        s.Validate();
        var bytes = IPAddress.Parse(s.Host).GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }
    public static void Configure(Settings s, ulong luid = 0, bool dryRun = false, bool allowStoppedDns = false)
    {
        uint ip = Address(s);
        Check(GuardConfigureV4(ip, checked((ushort)s.Port), luid, Engine.Executable,
            s.ExcludedApplications, checked((uint)s.ExcludedApplications.Length), allowStoppedDns, dryRun));
    }
    public static bool IsConfigured(Settings s, ulong luid = 0, bool allowStoppedDns = false)
    {
        uint ip = Address(s);
        Check(GuardMatchesV4(ip, checked((ushort)s.Port), luid, Engine.Executable,
            s.ExcludedApplications, checked((uint)s.ExcludedApplications.Length), allowStoppedDns, out bool matches));
        return matches;
    }
    public static void Remove() => Check(GuardRemove());
    // Revoke this process's active permissions without reading settings or
    // removing the persistent baseline. Call before stopping the engine.
    public static void Deactivate() => Check(GuardDeactivateV3());
    internal static bool IsTunReady(OperationalStatus status, string description, NetworkInterfaceType interfaceType, IEnumerable<TunAddress> addresses)
    {
        // Sanity checks for the pinned sing-box/sing-tun configuration. These
        // identify a ready-looking interface, not driver or session ownership.
        if (status != OperationalStatus.Up || description != "sing-tun Tunnel" || (int)interfaceType != 53) return false;
        var expectedV4 = IPAddress.Parse("172.29.231.1");
        var expectedV6 = IPAddress.Parse("fdfe:dcba:7231::1");
        bool hasV4 = false, hasV6 = false;
        foreach (var address in addresses) {
            if (address.Address.Equals(expectedV4)) {
                if (hasV4 || address.PrefixLength != 30 || address.DadState != DuplicateAddressDetectionState.Preferred) return false;
                hasV4 = true;
            } else if (address.Address.Equals(expectedV6)) {
                if (hasV6 || address.PrefixLength != 126 || address.DadState != DuplicateAddressDetectionState.Preferred) return false;
                hasV6 = true;
            } else {
                // IPv6 link-local is normal interface metadata. APIPA is not
                // part of the pinned IPv4 configuration and remains rejected.
                if (!address.Address.IsIPv6LinkLocal) return false;
            }
        }
        return hasV4 && hasV6;
    }
    public static ulong TunLuid()
    {
        try {
            var candidates = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => string.Equals(n.Name, "ProxyBridge-TUN", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (candidates.Length != 1) return 0;
            var nic = candidates[0];
            var addresses = nic.GetIPProperties().UnicastAddresses
                .Select(a => new TunAddress(a.Address, a.PrefixLength, a.DuplicateAddressDetectionState)).ToArray();
            if (!IsTunReady(nic.OperationalStatus, nic.Description, nic.NetworkInterfaceType, addresses) || !Guid.TryParse(nic.Id, out var guid)) return 0;
            // An adapter may disappear between enumeration and conversion.
            return ConvertInterfaceGuidToLuid(ref guid, out var luid) == 0 ? luid : 0;
        } catch (NetworkInformationException) {
            return 0; // Network changes must never turn partial discovery into a permit.
        }
    }
    static void Check(uint error)
    {
        if (error == 0) return;
        string detail = Marshal.PtrToStringUni(GuardLastDiagnostic()) ?? "";
        throw new InvalidOperationException($"Windows WFP: 0x{error:X8}. {detail}. Проверьте права администратора и службу BFE.");
    }
}
