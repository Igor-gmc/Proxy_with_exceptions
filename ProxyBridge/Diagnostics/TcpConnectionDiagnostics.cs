using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ProxyBridge;

internal sealed record TcpConnectionRow(uint ProcessId, int Family, uint State, string StateName,
    string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort);
internal sealed record TcpStateCount(uint State, string Name, int Count);
internal sealed record TcpProcessSummary(uint ProcessId, int Count, IReadOnlyList<TcpStateCount> States);
internal sealed record TcpParsedTable(uint TableRows, int ScannedRows, bool Truncated,
    IReadOnlyList<TcpConnectionRow> Rows);
internal sealed record TcpFamilyStatus(int Family, string Status, string? ErrorCode, uint? NativeError,
    uint TableRows, int ScannedRows, bool Truncated, DateTimeOffset StartedUtc, DateTimeOffset EndedUtc);
internal sealed record TcpConnectionSummary(int ScannedRows, int MatchedRows, bool RowsTruncated,
    IReadOnlyList<TcpStateCount> All, IReadOnlyList<TcpStateCount> Endpoint,
    IReadOnlyList<TcpStateCount> Engine, IReadOnlyList<TcpProcessSummary> Processes,
    int OmittedProcesses, IReadOnlyList<TcpConnectionRow> Rows);
internal sealed record TcpConnectionSnapshot(DateTimeOffset StartedUtc, DateTimeOffset EndedUtc,
    long StartedMonotonicTicks, long EndedMonotonicTicks, long MonotonicFrequency,
    string Status, string? EndpointAddress, int? EndpointPort, int? EngineProcessId,
    IReadOnlyList<TcpFamilyStatus> Families, TcpConnectionSummary Summary);

// Read-only IP Helper snapshots. The caller schedules collection off the UI and
// freezes its latest completed snapshot before recovery; no sockets or DNS here.
internal static class TcpConnectionDiagnostics
{
    internal const int MaxBufferBytes = 4 * 1024 * 1024;
    internal const int MaxScannedRowsPerFamily = 65536;
    internal const int MaxOutputRows = 2048, MaxProcessSummaries = 32;
    const uint InsufficientBuffer = 122, OwnerPidAll = 5;

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    static extern uint GetExtendedTcpTable(IntPtr table, ref uint size,
        [MarshalAs(UnmanagedType.Bool)] bool order, uint family, uint tableClass, uint reserved);

    public static TcpConnectionSnapshot Capture(IPAddress? endpointAddress = null,
        int? endpointPort = null, int? processId = null, int maxRows = 256)
    {
        Validate(endpointPort, processId, maxRows);
        var started = DateTimeOffset.UtcNow;
        long ticks = Stopwatch.GetTimestamp();
        var v4 = ReadFamily(2);
        var v6 = ReadFamily(23);
        var summary = Summarize(v4.Rows.Concat(v6.Rows), endpointAddress, endpointPort, processId, maxRows);
        string status = v4.Status.Status == "captured" && v6.Status.Status == "captured" ? "captured"
            : v4.Status.Status == "unavailable" && v6.Status.Status == "unavailable" ? "unavailable" : "partial";
        return new(started, DateTimeOffset.UtcNow, ticks, Stopwatch.GetTimestamp(), Stopwatch.Frequency,
            status, endpointAddress?.ToString(), endpointPort, processId,
            Array.AsReadOnly(new[] { v4.Status, v6.Status }), summary);
    }

    static (TcpFamilyStatus Status, IReadOnlyList<TcpConnectionRow> Rows) ReadFamily(int family)
    {
        var started = DateTimeOffset.UtcNow;
        (TcpFamilyStatus, IReadOnlyList<TcpConnectionRow>) Failed(string error, uint? code = null) =>
            (new(family, "unavailable", error, code, 0, 0, false, started, DateTimeOffset.UtcNow),
                Array.Empty<TcpConnectionRow>());
        IntPtr buffer = IntPtr.Zero;
        try
        {
            uint size = 0;
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref size, false, (uint)family, OwnerPidAll, 0);
            if (result != 0 && result != InsufficientBuffer)
            {
                return Failed("native_error", result);
            }

            for (int attempt = 0; attempt < 3; attempt++)
            {
                if (size < 4 || size > MaxBufferBytes)
                {
                    return Failed("buffer_limit");
                }

                int allocated = (int)size;
                buffer = Marshal.AllocHGlobal(allocated);
                result = GetExtendedTcpTable(buffer, ref size, false, (uint)family, OwnerPidAll, 0);
                if (result == InsufficientBuffer)
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                    continue;
                }
                if (result != 0)
                {
                    return Failed("native_error", result);
                }

                if (size < 4 || size > allocated)
                {
                    return Failed("invalid_table_size");
                }

                byte[] bytes = new byte[(int)size];
                Marshal.Copy(buffer, bytes, 0, bytes.Length);
                var parsed = ParseTable(bytes, family);
                return (new(family, parsed.Truncated ? "partial" : "captured",
                    parsed.Truncated ? "scan_limit" : null, null, parsed.TableRows, parsed.ScannedRows,
                    parsed.Truncated, started, DateTimeOffset.UtcNow), parsed.Rows);
            }
            return Failed("table_changing", InsufficientBuffer);
        }
        catch (Exception ex)
        {
            // Never serialize exception messages (which may contain unrelated data).
            return Failed(ex is PlatformNotSupportedException or DllNotFoundException or EntryPointNotFoundException
                ? "unsupported" : "capture_error", unchecked((uint)ex.HResult));
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    // SDK MIB_TCP[6]ROW_OWNER_PID: 24/56 bytes, DWORD-aligned table starts at4.
    // Pure entry point for fixture tests, including IPv6 scopes and port endian.
    internal static TcpParsedTable ParseTable(ReadOnlySpan<byte> data, int family)
    {
        if (family != 2 && family != 23)
        {
            throw new ArgumentOutOfRangeException(nameof(family));
        }

        if (data.Length < 4)
        {
            throw new ArgumentException("Invalid TCP table.", nameof(data));
        }

        uint total = BinaryPrimitives.ReadUInt32LittleEndian(data);
        int stride = family == 2 ? 24 : 56;
        if (total > (uint)((data.Length - 4) / stride))
        {
            throw new ArgumentException("Invalid TCP rows.", nameof(data));
        }

        int count = (int)Math.Min(total, (uint)MaxScannedRowsPerFamily);
        var rows = new TcpConnectionRow[count];
        for (int i = 0; i < count; i++)
        {
            var row = data.Slice(4 + i * stride, stride);
            uint state, pid;
            IPAddress local, remote;
            int localPort, remotePort;
            if (family == 2)
            {
                state = BinaryPrimitives.ReadUInt32LittleEndian(row);
                local = new IPAddress(row.Slice(4, 4));
                localPort = BinaryPrimitives.ReadUInt16BigEndian(row.Slice(8, 2));
                remote = new IPAddress(row.Slice(12, 4));
                remotePort = BinaryPrimitives.ReadUInt16BigEndian(row.Slice(16, 2));
                pid = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(20, 4));
            }
            else
            {
                local = new IPAddress(row[..16], BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(16, 4)));
                localPort = BinaryPrimitives.ReadUInt16BigEndian(row.Slice(20, 2));
                remote = new IPAddress(row.Slice(24, 16), BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(40, 4)));
                remotePort = BinaryPrimitives.ReadUInt16BigEndian(row.Slice(44, 2));
                state = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(48, 4));
                pid = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(52, 4));
            }
            rows[i] = new(pid, family, state, StateName(state), local.ToString(), localPort, remote.ToString(), remotePort);
        }
        return new(total, count, total > count, Array.AsReadOnly(rows));
    }

    internal static TcpConnectionSummary Summarize(IEnumerable<TcpConnectionRow> rows,
        IPAddress? endpointAddress = null, int? endpointPort = null, int? processId = null, int maxRows = 256)
    {
        Validate(endpointPort, processId, maxRows);
        var all = new Dictionary<uint, int>();
        var endpoint = new Dictionary<uint, int>();
        var engine = new Dictionary<uint, int>();
        var processes = new Dictionary<uint, Dictionary<uint, int>>();
        var output = new List<TcpConnectionRow>(maxRows);
        int scanned = 0, matched = 0;
        bool endpointSpecified = endpointAddress != null || endpointPort != null;
        bool anySelector = endpointSpecified || processId != null;
        foreach (var row in rows)
        {
            scanned++;
            Add(all, row.State);
            if (!processes.TryGetValue(row.ProcessId, out var states))
            {
                processes.Add(row.ProcessId, states = new());
            }

            Add(states, row.State);
            bool atEndpoint = endpointSpecified
                && (endpointPort == null || row.RemotePort == endpointPort)
                && (endpointAddress == null || IPAddress.TryParse(row.RemoteAddress, out var address) && address.Equals(endpointAddress));
            bool atEngine = processId != null && row.ProcessId == (uint)processId.Value;
            if (atEndpoint)
            {
                Add(endpoint, row.State);
            }

            if (atEngine)
            {
                Add(engine, row.State);
            }

            if (!anySelector || atEndpoint || atEngine)
            {
                matched++;
                if (output.Count < maxRows)
                {
                    output.Add(row);
                }
            }
        }
        var top = processes.Select(p => new TcpProcessSummary(p.Key, p.Value.Values.Sum(), Counts(p.Value)))
            .OrderByDescending(p => p.Count).ThenBy(p => p.ProcessId).Take(MaxProcessSummaries).ToArray();
        return new(scanned, matched, matched > output.Count, Counts(all), Counts(endpoint), Counts(engine),
            Array.AsReadOnly(top), Math.Max(0, processes.Count - top.Length), output.AsReadOnly());
    }

    static void Validate(int? port, int? pid, int maxRows)
    {
        if (port is < 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        if (pid is < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(pid));
        }

        if (maxRows is < 0 or > MaxOutputRows)
        {
            throw new ArgumentOutOfRangeException(nameof(maxRows));
        }
    }
    static void Add(Dictionary<uint, int> values, uint state) => values[state] = values.GetValueOrDefault(state) + 1;
    static IReadOnlyList<TcpStateCount> Counts(Dictionary<uint, int> values) =>
        Array.AsReadOnly(values.OrderBy(p => p.Key).Select(p => new TcpStateCount(p.Key, StateName(p.Key), p.Value)).ToArray());
    internal static string StateName(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT_1",
        7 => "FIN_WAIT_2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN"
    };
}
