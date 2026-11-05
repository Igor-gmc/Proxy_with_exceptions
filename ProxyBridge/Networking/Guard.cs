using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace ProxyBridge;

internal readonly record struct TunAddress(
    IPAddress Address,
    int PrefixLength,
    DuplicateAddressDetectionState DadState);

internal static class Guard
{
    // Count is informational. IsConfigured verifies the complete expected policy.
    public static uint Status
    {
        get
        {
            Check(NativeMethods.GuardStatus(out uint count));
            return count;
        }
    }

    public static void Configure(Settings s, ulong luid = 0, bool dryRun = false, bool allowStoppedDns = false)
    {
        uint proxyAddress = ToNativeProxyAddress(s);
        Check(NativeMethods.GuardConfigureV4(
            proxyAddress,
            checked((ushort)s.Port),
            luid,
            Engine.Executable,
            s.ExcludedApplications,
            checked((uint)s.ExcludedApplications.Length),
            allowStoppedDns,
            dryRun));
    }

    public static bool IsConfigured(Settings s, ulong luid = 0, bool allowStoppedDns = false)
    {
        uint proxyAddress = ToNativeProxyAddress(s);
        Check(NativeMethods.GuardMatchesV4(
            proxyAddress,
            checked((ushort)s.Port),
            luid,
            Engine.Executable,
            s.ExcludedApplications,
            checked((uint)s.ExcludedApplications.Length),
            allowStoppedDns,
            out bool matches));
        return matches;
    }

    public static void Remove() => Check(NativeMethods.GuardRemove());

    // Revoke this process's active permissions without reading settings or
    // removing the persistent baseline. Call before stopping the engine.
    public static void Deactivate() => Check(NativeMethods.GuardDeactivateV3());

    public static ulong TunLuid()
    {
        try
        {
            if (!TryFindReadyTun(out Guid interfaceId))
            {
                return 0;
            }

            // An adapter may disappear between enumeration and conversion.
            return NativeMethods.ConvertInterfaceGuidToLuid(ref interfaceId, out ulong luid) == 0
                ? luid
                : 0;
        }
        catch (NetworkInformationException)
        {
            // Network changes must never turn partial discovery into a permit.
            return 0;
        }
    }

    private static bool TryFindReadyTun(out Guid interfaceId)
    {
        interfaceId = default;
        NetworkInterface[] candidates = NetworkInterface.GetAllNetworkInterfaces()
            .Where(adapter => string.Equals(adapter.Name, "ProxyBridge-TUN", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (candidates.Length != 1)
        {
            return false;
        }

        NetworkInterface candidate = candidates[0];
        TunAddress[] addresses = candidate.GetIPProperties().UnicastAddresses
            .Select(address => new TunAddress(address.Address, address.PrefixLength, address.DuplicateAddressDetectionState))
            .ToArray();

        return IsTunReady(candidate.OperationalStatus, candidate.Description, candidate.NetworkInterfaceType, addresses)
            && Guid.TryParse(candidate.Id, out interfaceId);
    }

    internal static bool IsTunReady(
        OperationalStatus status,
        string description,
        NetworkInterfaceType interfaceType,
        IEnumerable<TunAddress> addresses)
    {
        // Sanity checks for the pinned sing-box/sing-tun configuration. These
        // identify a ready-looking interface, not driver or session ownership.
        if (status != OperationalStatus.Up || description != "sing-tun Tunnel" || (int)interfaceType != 53)
        {
            return false;
        }

        IPAddress expectedV4 = IPAddress.Parse("172.29.231.1");
        IPAddress expectedV6 = IPAddress.Parse("fdfe:dcba:7231::1");
        bool hasV4 = false;
        bool hasV6 = false;

        foreach (TunAddress address in addresses)
        {
            if (address.Address.Equals(expectedV4))
            {
                if (hasV4 || address.PrefixLength != 30 || address.DadState != DuplicateAddressDetectionState.Preferred)
                {
                    return false;
                }

                hasV4 = true;
            }
            else if (address.Address.Equals(expectedV6))
            {
                if (hasV6 || address.PrefixLength != 126 || address.DadState != DuplicateAddressDetectionState.Preferred)
                {
                    return false;
                }

                hasV6 = true;
            }
            else
            {
                // IPv6 link-local is normal interface metadata. APIPA is not
                // part of the pinned IPv4 configuration and remains rejected.
                if (!address.Address.IsIPv6LinkLocal)
                {
                    return false;
                }
            }
        }

        return hasV4 && hasV6;
    }

    private static uint ToNativeProxyAddress(Settings settings)
    {
        settings.Validate();
        byte[] addressBytes = IPAddress.Parse(settings.Host).GetAddressBytes();
        return ((uint)addressBytes[0] << 24)
            | ((uint)addressBytes[1] << 16)
            | ((uint)addressBytes[2] << 8)
            | addressBytes[3];
    }

    private static void Check(uint error)
    {
        if (error == 0)
        {
            return;
        }

        string detail = Marshal.PtrToStringUni(NativeMethods.GuardLastDiagnostic()) ?? "";
        throw new InvalidOperationException($"Windows WFP: 0x{error:X8}. {detail}. Проверьте права администратора и службу BFE.");
    }

    private static class NativeMethods
    {
        [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        internal static extern uint GuardConfigureV4(
            uint ip,
            ushort port,
            ulong luid,
            string engine,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr, SizeParamIndex = 5)] string[] excluded,
            uint count,
            [MarshalAs(UnmanagedType.Bool)] bool allowStoppedDns,
            [MarshalAs(UnmanagedType.Bool)] bool dryRun);

        [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        internal static extern uint GuardMatchesV4(
            uint ip,
            ushort port,
            ulong luid,
            string engine,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr, SizeParamIndex = 5)] string[] excluded,
            uint count,
            [MarshalAs(UnmanagedType.Bool)] bool allowStoppedDns,
            [MarshalAs(UnmanagedType.Bool)] out bool matches);

        [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint GuardRemove();

        [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint GuardDeactivateV3();

        [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint GuardStatus(out uint count);

        [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr GuardLastDiagnostic();

        [DllImport("iphlpapi.dll")]
        internal static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);
    }
}
