using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ProxyBridge;

// Local, read-only transition snapshot. No name resolution, sockets, shell,
// credentials, MAC addresses, configuration serialization or network mutation.
internal static class NetworkDiagnostics
{
    const int MaxInterfaces = 24, MaxAddresses = 8, MaxRoutes = 64, MaxScanRoutes = 16384;
    const int MaxJsonBytes = 48000;
    static readonly JsonSerializerOptions Json = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    // Windows SDK 10.0.26100.0 netioapi.h/ws2ipdef.h, x64 natural alignment:
    // SOCKADDR_INET=28; IP_ADDRESS_PREFIX=32; MIB_IPFORWARD_ROW2=104;
    // MIB_IPFORWARD_TABLE2.Table offset=8 (ULONG followed by 8-aligned row).
    // MIB_IPINTERFACE_ROW=168; ZoneIndices[16] occupies offsets 80..143.
    // https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
    // https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row
    [StructLayout(LayoutKind.Explicit, Size = 28)]
    struct SockaddrInet
    {
        [FieldOffset(0)] public ushort Family;
        [FieldOffset(4)] public uint V4;
        [FieldOffset(8)] public ulong V6Low;
        [FieldOffset(16)] public ulong V6High;
        [FieldOffset(24)] public uint Scope;
        public IPAddress? Address()
        {
            if (Family == 2)
            {
                return new IPAddress(BitConverter.GetBytes(V4));
            }

            if (Family != 23)
            {
                return null;
            }

            Span<byte> bytes = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64LittleEndian(bytes, V6Low);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes[8..], V6High);
            return new IPAddress(bytes, Scope);
        }
    }
    [StructLayout(LayoutKind.Explicit, Size = 104)]
    struct ForwardRow
    {
        [FieldOffset(0)] public ulong Luid;
        [FieldOffset(8)] public uint Index;
        [FieldOffset(12)] public SockaddrInet Destination;
        [FieldOffset(40)] public byte PrefixLength;
        [FieldOffset(44)] public SockaddrInet NextHop;
        [FieldOffset(76)] public uint ValidLifetime;
        [FieldOffset(84)] public uint Metric;
        [FieldOffset(88)] public uint Protocol;
        [FieldOffset(100)] public uint Origin;
    }
    [StructLayout(LayoutKind.Explicit, Size = 168)]
    struct InterfaceRow
    {
        [FieldOffset(0)] public ushort Family;
        [FieldOffset(8)] public ulong Luid;
        [FieldOffset(16)] public uint Index;
        [FieldOffset(41)] public byte Forwarding;
        [FieldOffset(42)] public byte WeakHostSend;
        [FieldOffset(43)] public byte WeakHostReceive;
        [FieldOffset(44)] public byte AutomaticMetric;
        [FieldOffset(148)] public uint Metric;
        [FieldOffset(152)] public uint Mtu;
        [FieldOffset(156)] public byte Connected;
        [FieldOffset(166)] public byte DisableDefaultRoutes;
    }
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    static extern uint GetIpForwardTable2(ushort family, out IntPtr table);
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    static extern void FreeMibTable(IntPtr table);
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    static extern uint GetIpInterfaceEntry(ref InterfaceRow row);

    static string Clip(string value, int limit = 160) => value.Length <= limit ? value : value[..limit] + "…";
    static object Error(Exception error) => new
    {
        error = error.GetType().Name,
        code = $"0x{(error is Win32Exception w ? unchecked((uint)w.NativeErrorCode) : error is NetworkInformationException n ? unchecked((uint)n.ErrorCode) : unchecked((uint)error.HResult)):X8}"
    };
    static object NativeError(uint code) => new { error = "Win32", code = $"0x{code:X8}" };
    static object? Read(Func<object?> read)
    {
        try
        {
            return read();
        }
        catch (Exception error) { return Error(error); }
    }

    sealed record NativeInterface(object Data, uint? Metric);
    static NativeInterface InterfaceInfo(ushort family, uint index,
        Dictionary<(ushort, uint), NativeInterface> cache)
    {
        if (cache.TryGetValue((family, index), out var existing))
        {
            return existing;
        }

        NativeInterface result;
        try
        {
            if (IntPtr.Size != 8)
            {
                result = new(new
                {
                    error = "UnsupportedArchitecture"
                }, null);
            }
            else
            {
                var row = new InterfaceRow { Family = family, Index = index };
                uint code = GetIpInterfaceEntry(ref row);
                result = code != 0 ? new(NativeError(code), null) : new(new
                {
                    ifIndex = row.Index,
                    luid = $"0x{row.Luid:X16}",
                    metric = row.Metric,
                    mtu = row.Mtu,
                    automaticMetric = row.AutomaticMetric != 0,
                    weakHostSend = row.WeakHostSend != 0,
                    weakHostReceive = row.WeakHostReceive != 0,
                    forwarding = row.Forwarding != 0,
                    connected = row.Connected != 0,
                    disableDefaultRoutes = row.DisableDefaultRoutes != 0
                }, row.Metric);
            }
        }
        catch (Exception error) { result = new(Error(error), null); }
        cache[(family, index)] = result;
        return result;
    }

    static Dictionary<string, object?> Adapter(NetworkInterface nic,
        Dictionary<uint, string> names, HashSet<uint> tunIndices,
        Dictionary<(ushort, uint), NativeInterface> native)
    {
        var record = new Dictionary<string, object?>
        {
            ["name"] = Read(() => Clip(nic.Name)),
            ["description"] = Read(() => Clip(nic.Description)),
            ["status"] = Read(() => nic.OperationalStatus.ToString()),
            ["type"] = Read(() => nic.NetworkInterfaceType.ToString())
        };
        string name = record["name"] as string ?? "";
        bool tun = name.Equals("ProxyBridge-TUN", StringComparison.OrdinalIgnoreCase)
            || (record["description"] as string)?.Equals("sing-tun Tunnel", StringComparison.OrdinalIgnoreCase) == true;
        record["tun"] = tun;
        try
        {
            var properties = nic.GetIPProperties();
            record["ipv4"] = Read(() =>
            {
                if (!nic.Supports(NetworkInterfaceComponent.IPv4))
                {
                    return new
                    {
                        unavailable = true
                    };
                }

                var ipv4 = properties.GetIPv4Properties();
                if (ipv4 == null)
                {
                    return new
                    {
                        unavailable = true
                    };
                }

                uint index = checked((uint)ipv4.Index);
                names[index] = name;
                if (tun)
                {
                    tunIndices.Add(index);
                }

                return new
                {
                    ifIndex = index,
                    mtu = Read(() => ipv4.Mtu),
                    native = InterfaceInfo(2, index, native).Data
                };
            });
            record["ipv6"] = Read(() =>
            {
                if (!nic.Supports(NetworkInterfaceComponent.IPv6))
                {
                    return new
                    {
                        unavailable = true
                    };
                }

                var ipv6 = properties.GetIPv6Properties();
                if (ipv6 == null)
                {
                    return new
                    {
                        unavailable = true
                    };
                }

                uint index = checked((uint)ipv6.Index);
                names[index] = name;
                if (tun)
                {
                    tunIndices.Add(index);
                }

                return new
                {
                    ifIndex = index,
                    mtu = Read(() => ipv6.Mtu),
                    native = InterfaceInfo(23, index, native).Data
                };
            });
            record["unicast"] = Read(() =>
            {
                var addresses = properties.UnicastAddresses;
                return new
                {
                    total = addresses.Count,
                    rows = addresses.Take(MaxAddresses).Select(a => new
                    {
                        address = Read(() => a.Address.ToString()),
                        prefix = Read(() => a.PrefixLength),
                        dad = Read(() => a.DuplicateAddressDetectionState.ToString())
                    }).ToArray()
                };
            });
            record["dns"] = Read(() => new
            {
                total = properties.DnsAddresses.Count,
                rows = properties.DnsAddresses.Take(4).Select(a => a.ToString()).ToArray()
            });
            record["gateways"] = Read(() => new
            {
                total = properties.GatewayAddresses.Count,
                rows = properties.GatewayAddresses.Take(4).Select(a => a.Address.ToString()).ToArray()
            });
        }
        catch (Exception error) { record["ipProperties"] = Error(error); }
        return record;
    }

    // Pure prefix match, deliberately never resolves a hostname.
    static bool Contains(IPAddress prefix, byte bits, IPAddress? address)
    {
        if (address == null || address.AddressFamily != prefix.AddressFamily)
        {
            return false;
        }

        byte[] network = prefix.GetAddressBytes(), candidate = address.GetAddressBytes();
        if (bits > network.Length * 8)
        {
            return false;
        }

        int whole = bits / 8, remainder = bits % 8;
        for (int i = 0; i < whole; i++)
        {
            if (network[i] != candidate[i])
            {
                return false;
            }
        }

        return remainder == 0 || (network[whole] & (0xff << (8 - remainder))) == (candidate[whole] & (0xff << (8 - remainder)));
    }

    static object Routes(IPAddress? proxy, Dictionary<uint, string> names, HashSet<uint> tunIndices,
        Dictionary<(ushort, uint), NativeInterface> native, List<object> rows)
    {
        IntPtr table = IntPtr.Zero;
        try
        {
            if (IntPtr.Size != 8)
            {
                return new
                {
                    error = "UnsupportedArchitecture"
                };
            }

            uint code = GetIpForwardTable2(0, out table);
            if (code != 0)
            {
                return NativeError(code);
            }

            if (table == IntPtr.Zero)
            {
                return new
                {
                    error = "NullRouteTable"
                };
            }

            uint count = unchecked((uint)Marshal.ReadInt32(table));
            uint inspected = Math.Min(count, MaxScanRoutes), selected = 0;
            var errors = new List<object>();
            for (uint i = 0; i < inspected; i++)
            {
                try
                {
                    var row = Marshal.PtrToStructure<ForwardRow>(IntPtr.Add(table, checked(8 + (int)i * 104)));
                    IPAddress? prefix = row.Destination.Address();
                    if (prefix == null || row.PrefixLength > (prefix.AddressFamily == AddressFamily.InterNetwork ? 32 : 128))
                    {
                        if (errors.Count < 4)
                        {
                            errors.Add(new
                            {
                                error = "InvalidRouteFamilyOrPrefix",
                                row = i
                            });
                        }

                        continue;
                    }
                    bool broad = row.PrefixLength <= 1, tun = tunIndices.Contains(row.Index);
                    bool proxyRoute = Contains(prefix, row.PrefixLength, proxy);
                    if (!broad && !tun && !proxyRoute)
                    {
                        continue;
                    }

                    selected++;
                    if (rows.Count == MaxRoutes)
                    {
                        continue;
                    }

                    var nic = InterfaceInfo(row.Destination.Family, row.Index, native);
                    rows.Add(new
                    {
                        destination = prefix + "/" + row.PrefixLength,
                        nextHop = row.NextHop.Address()?.ToString(),
                        ifIndex = row.Index,
                        name = names.GetValueOrDefault(row.Index),
                        luid = $"0x{row.Luid:X16}",
                        routeMetric = row.Metric,
                        interfaceMetric = nic.Metric,
                        totalMetric = nic.Metric.HasValue && row.Metric != uint.MaxValue ? (ulong?)row.Metric + nic.Metric.Value : null,
                        kind = broad ? "default-or-split" : tun ? "tun" : "proxy-prefix",
                        matchesProxy = proxyRoute,
                        protocol = row.Protocol,
                        origin = row.Origin,
                        validLifetime = row.ValidLifetime,
                        interfaceError = nic.Metric.HasValue ? null : nic.Data
                    });
                }
                catch (Exception error)
                {
                    if (errors.Count < 4)
                    {
                        errors.Add(Error(error));
                    }
                }
            }
            return new
            {
                total = count,
                inspected,
                selected,
                omitted = selected - (uint)rows.Count,
                errors
            };
        }
        catch (Exception error) { return Error(error); }
        finally
        {
            if (table != IntPtr.Zero)
            {
                FreeMibTable(table);
            }
        }
    }

    internal static string Capture(Settings? settings) => CaptureHost(settings?.Host);
    internal static string CaptureHost(string? proxyHost)
    {
        try
        {
            var names = new Dictionary<uint, string>();
            var tunIndices = new HashSet<uint>();
            var native = new Dictionary<(ushort, uint), NativeInterface>();
            var adapters = new List<Dictionary<string, object?>>();
            var routes = new List<object>();
            var snapshot = new Dictionary<string, object?> { ["schema"] = 1 };
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                snapshot["interfacesTotal"] = interfaces.Length;
                // Bound native reads and retain TUN/up interfaces first in output.
                foreach (var nic in interfaces.Take(128))
                {
                    adapters.Add(Adapter(nic, names, tunIndices, native));
                }

                adapters = adapters.OrderByDescending(a => a["tun"] is true)
                    .ThenByDescending(a => Equals(a["status"], "Up")).Take(MaxInterfaces).ToList();
                snapshot["interfacesOmitted"] = interfaces.Length - adapters.Count;
            }
            catch (Exception error) { snapshot["interfacesError"] = Error(error); }
            IPAddress? proxy = null;
            // Host is the only settings field read; no credentials or raw settings.
            if (proxyHost != null)
            {
                IPAddress.TryParse(proxyHost, out proxy);
            }

            snapshot["proxyAddressAvailable"] = proxy != null;
            snapshot["interfaces"] = adapters;
            snapshot["routeSummary"] = Routes(proxy, names, tunIndices, native, routes);
            snapshot["routes"] = routes;
            int trimmedRoutes = 0, trimmedInterfaces = 0;
            while (true)
            {
                snapshot["sizeTrimmedRoutes"] = trimmedRoutes;
                snapshot["sizeTrimmedInterfaces"] = trimmedInterfaces;
                string json = JsonSerializer.Serialize(snapshot, Json);
                if (Encoding.UTF8.GetByteCount(json) <= MaxJsonBytes)
                {
                    return json;
                }

                if (routes.Count != 0)
                {
                    routes.RemoveAt(routes.Count - 1);
                    trimmedRoutes++;
                }
                else if (adapters.Count != 0)
                {
                    adapters.RemoveAt(adapters.Count - 1);
                    trimmedInterfaces++;
                }
                else
                {
                    return "{\"error\":\"SnapshotSizeLimit\"}";
                }
            }
        }
        catch (Exception error)
        {
            try
            {
                return JsonSerializer.Serialize(new
                {
                    error = Error(error)
                }, Json);
            }
            catch { return "{\"error\":\"NetworkSnapshotUnavailable\"}"; }
        }
    }
}
