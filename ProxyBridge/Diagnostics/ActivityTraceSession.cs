using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ProxyBridge;

// Controls only the session successfully created by this instance. TraceEvent is
// deliberately NOT used as a controller: its Stop can alter global ETW settings.
internal sealed class ActivityTraceSession : IDisposable
{
    internal const string SessionName = "ProxyBridge.Activity.v1";
    const uint RealTime = 0x00000100, SystemLogger = 0x02000000;
    const uint TracedGuid = 0x00020000, ProcessEvents = 0x1, NetworkEvents = 0x10000;
    const uint Query = 0, StopControl = 1, NotFound = 4201;
    readonly object gate = new();
    readonly Guid sessionGuid = Guid.NewGuid();
    ulong handle;
    bool owned;
    long eventsLost, realTimeBuffersLost;
    string? errorCode;

    [StructLayout(LayoutKind.Sequential)]
    struct WnodeHeader
    {
        public uint BufferSize, ProviderId;
        public ulong HistoricalContext;
        public long TimeStamp;
        public Guid Guid;
        public uint ClientContext, Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TraceProperties
    {
        public WnodeHeader Wnode;
        public uint BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize;
        public uint LogFileMode, FlushTimer, EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten;
        public uint LogBuffersLost, RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset, LoggerNameOffset;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    static extern uint StartTraceW(out ulong sessionHandle, string name, IntPtr properties);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    static extern uint ControlTraceW(ulong sessionHandle, string? name, IntPtr properties, uint control);

    IntPtr AllocateProperties()
    {
        int size = Marshal.SizeOf<TraceProperties>();
        int bytes = checked(size + (SessionName.Length + 1) * sizeof(char));
        var value = new TraceProperties
        {
            Wnode = new WnodeHeader
            {
                BufferSize = (uint)bytes,
                Guid = sessionGuid,
                ClientContext = 1,
                Flags = TracedGuid
            },
            BufferSize = 64,
            MinimumBuffers = 16,
            MaximumBuffers = 128,
            LogFileMode = RealTime | SystemLogger,
            FlushTimer = 1,
            EnableFlags = ProcessEvents | NetworkEvents,
            LoggerNameOffset = (uint)size
        };
        IntPtr buffer = Marshal.AllocHGlobal(bytes);
        try
        {
            Marshal.Copy(new byte[bytes], 0, buffer, bytes);
            Marshal.StructureToPtr(value, buffer, false);
            Marshal.Copy((SessionName + '\0').ToCharArray(), 0, IntPtr.Add(buffer, size), SessionName.Length + 1);
            return buffer;
        }
        catch { Marshal.FreeHGlobal(buffer); throw; }
    }

    public void Start()
    {
        lock (gate)
        {
            if (owned)
            {
                throw new InvalidOperationException("Activity ETW session already started.");
            }

            IntPtr properties = AllocateProperties();
            try
            {
                uint status = StartTraceW(out ulong created, SessionName, properties);
                if (status != 0)
                {
                    errorCode = $"start:0x{status:X8}";
                    // In particular ERROR_ALREADY_EXISTS never authorizes Stop.
                    throw new Win32Exception((int)status, "Activity ETW session could not be created.");
                }
                handle = created;
                owned = true;
                errorCode = null;
            }
            finally { Marshal.FreeHGlobal(properties); }
        }
    }

    void Remember(TraceProperties value)
    {
        eventsLost = value.EventsLost;
        realTimeBuffersLost = value.RealTimeBuffersLost;
    }

    public ActivityTraceStats ReadStats()
    {
        lock (gate)
        {
            if (owned)
            {
                IntPtr properties = AllocateProperties();
                try
                {
                    uint status = ControlTraceW(handle, null, properties, Query);
                    if (status == 0)
                    {
                        var value = Marshal.PtrToStructure<TraceProperties>(properties);
                        if (value.Wnode.Guid == sessionGuid)
                        {
                            Remember(value);
                        }
                        else
                        {
                            errorCode = "query:ownership-mismatch";
                        }
                    }
                    else
                    {
                        errorCode = $"query:0x{status:X8}";
                    }
                }
                finally { Marshal.FreeHGlobal(properties); }
            }
            return new(eventsLost, realTimeBuffersLost, 0, owned, errorCode);
        }
    }

    public void Stop()
    {
        lock (gate)
        {
            if (!owned)
            {
                return;
            }

            IntPtr properties = AllocateProperties();
            try
            {
                uint status = ControlTraceW(handle, null, properties, Query);
                if (status == NotFound)
                {
                    owned = false;
                    handle = 0;
                    return;
                }
                if (status != 0)
                {
                    errorCode = $"stop-query:0x{status:X8}";
                    throw new Win32Exception((int)status, "Activity ETW ownership could not be verified.");
                }
                var value = Marshal.PtrToStructure<TraceProperties>(properties);
                if (value.Wnode.Guid != sessionGuid)
                {
                    errorCode = "stop:ownership-mismatch";
                    // A replaced/reused session handle never authorizes removal.
                    owned = false;
                    handle = 0;
                    throw new InvalidOperationException("Activity ETW session identity changed.");
                }
                Remember(value);
                status = ControlTraceW(handle, null, properties, StopControl);
                if (status != 0 && status != NotFound)
                {
                    errorCode = $"stop:0x{status:X8}";
                    throw new Win32Exception((int)status, "Activity ETW session could not be stopped.");
                }
                if (status == 0)
                {
                    Remember(Marshal.PtrToStructure<TraceProperties>(properties));
                }

                owned = false;
                handle = 0;
            }
            finally { Marshal.FreeHGlobal(properties); }
        }
    }

    public void Dispose() => Stop();
}
