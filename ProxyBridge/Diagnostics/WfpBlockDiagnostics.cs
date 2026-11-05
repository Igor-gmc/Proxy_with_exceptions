using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Channels;

namespace ProxyBridge;

internal sealed record WfpBlockEvent(DateTimeOffset EventUtc, DateTimeOffset ObservedUtc,
    long ObservedMonotonicTicks, long MonotonicFrequency, string Source,
    int? ProcessId, string ProcessIdentitySource, string? ApplicationPath,
    int? Protocol, string? LocalAddress, int? LocalPort, string? RemoteAddress, int? RemotePort,
    uint? ScopeId, ulong FilterId, ushort LayerId, string Direction, uint? ReauthorizationReason,
    Guid? FilterKey = null, Guid? ProviderKey = null, string? ProviderName = null,
    Guid? LayerKey = null, Guid? SubLayerKey = null, uint? ActionType = null,
    Guid? CalloutKey = null, string OriginStatus = "pending", uint? OriginError = null,
    DateTimeOffset? OriginResolvedUtc = null);
internal sealed record WfpDiagnosticStatus(string State, string? ReasonCode, uint? NativeError,
    bool? CollectionEnabled, bool Subscribed, DateTimeOffset CheckedUtc, long CheckedMonotonicTicks,
    long MonotonicFrequency, DateTimeOffset? LastEventUtc, long EventsReceived, long Queued,
    long Dropped, long CallbackErrors, long OriginErrors, long SinkRejected,
    bool SourceLossKnown = false, string Coverage = "classify_drop");

// Passive observer: this file deliberately imports no policy/audit mutation API.
// AppId is an application identity, NOT a process ID. WFP headers contain no PID.
internal sealed class WfpBlockDiagnostics : IDisposable
{
    internal const int QueueCapacity = 1024, FilterCacheCapacity = 512;
    internal const int HeaderBytes = 120, DropPrefixBytes = 32;
    const uint ClassifyDrop = 3, UInt32Type = 3;
    readonly Func<WfpBlockEvent, bool> tryQueue;
    readonly object lifecycle = new();
    readonly AutoResetEvent wake = new(false);
    readonly ManualResetEventSlim ready = new(false);
    readonly Channel<WfpBlockEvent> queue = Channel.CreateBounded<WfpBlockEvent>(new BoundedChannelOptions(QueueCapacity)
    {
        SingleReader = true,
        SingleWriter = false,
        FullMode = BoundedChannelFullMode.Wait,
        AllowSynchronousContinuations = false
    });
    readonly Dictionary<ulong, Origin> filterCache = new();
    readonly Queue<ulong> filterOrder = new();
    readonly NetEventCallback callback;
    Task? worker;
    int stopping;
    long received, queued, dropped, callbackErrors, originErrors, sinkRejected, lastEventTicks;
    WfpDiagnosticStatus status = new("unavailable", "not_started", null, null, false,
        DateTimeOffset.UtcNow, Stopwatch.GetTimestamp(), Stopwatch.Frequency, null, 0, 0, 0, 0, 0, 0);

    sealed record Origin(Guid? FilterKey, Guid? ProviderKey, string? ProviderName, Guid? LayerKey,
        Guid? SubLayerKey, uint? ActionType, Guid? CalloutKey, string Status, uint? Error,
        DateTimeOffset ResolvedUtc, long ExpiresTicks);

    // SDK10.0.26100 x64: session72, subscription32 (GUID at12), FWP_VALUE0 union at8.
    // FWPM_NET_EVENT2: header104, type104, union pointer112. No pointer crosses callback.
    [StructLayout(LayoutKind.Sequential)]
    struct Session
    {
        public Guid Key;
        public IntPtr Name, Description;
        public uint Flags, TransactionTimeout, ProcessId;
        public IntPtr Sid, Username;
        public int KernelMode;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Subscription
    {
        public IntPtr Template;
        public uint Flags;
        public Guid SessionKey;
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate void NetEventCallback(IntPtr context, IntPtr netEvent);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    static extern uint FwpmEngineOpen0(string? serverName, uint authenticationService,
        IntPtr authenticationIdentity, ref Session session, out IntPtr engine);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    static extern uint FwpmEngineGetOption0(IntPtr engine, uint option, out IntPtr value);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    static extern uint FwpmNetEventSubscribe1(IntPtr engine, ref Subscription subscription,
        NetEventCallback callback, IntPtr context, out IntPtr eventsHandle);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    static extern uint FwpmNetEventUnsubscribe0(IntPtr engine, IntPtr eventsHandle);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    static extern uint FwpmFilterGetById0(IntPtr engine, ulong id, out IntPtr filter);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    static extern uint FwpmProviderGetByKey0(IntPtr engine, ref Guid key, out IntPtr provider);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    static extern void FwpmFreeMemory0(ref IntPtr memory);

    public WfpBlockDiagnostics(Func<WfpBlockEvent, bool> tryQueue)
    {
        this.tryQueue = tryQueue ?? throw new ArgumentNullException(nameof(tryQueue));
        callback = OnNativeEvent;
    }

    // Single-use lifetime. Native RPC runs on one dedicated worker. Start's wait,
    // Stop's wait and all callback work are bounded even if a native RPC stalls.
    public WfpDiagnosticStatus Start()
    {
        lock (lifecycle)
        {
            if (worker == null && Volatile.Read(ref stopping) == 0)
            {
                SetStatus("unavailable", "starting", null, null, false);
                worker = Task.Factory.StartNew(Run, CancellationToken.None,
                    TaskCreationOptions.LongRunning, TaskScheduler.Default);
            }
        }
        ready.Wait(TimeSpan.FromMilliseconds(1500));
        return ReadStatus();
    }

    public WfpDiagnosticStatus ReadStatus()
    {
        long last = Interlocked.Read(ref lastEventTicks);
        return Volatile.Read(ref status) with
        {
            LastEventUtc = last == 0 ? null : new DateTimeOffset(last, TimeSpan.Zero),
            EventsReceived = Interlocked.Read(ref received),
            Queued = Interlocked.Read(ref queued),
            Dropped = Interlocked.Read(ref dropped),
            CallbackErrors = Interlocked.Read(ref callbackErrors),
            OriginErrors = Interlocked.Read(ref originErrors),
            SinkRejected = Interlocked.Read(ref sinkRejected)
        };
    }

    void SetStatus(string state, string? reason, uint? error, bool? collection, bool subscribed)
    {
        Volatile.Write(ref status, new(state, reason, error, collection, subscribed, DateTimeOffset.UtcNow,
            Stopwatch.GetTimestamp(), Stopwatch.Frequency, null, 0, 0, 0, 0, 0, 0));
    }

    internal static string Availability(bool? collectionEnabled, uint? error, bool subscribed) =>
        error is 5 or 0x80070005 ? "access_denied" : error is not null and not 0 ? "unavailable"
        : collectionEnabled == false ? "collection_disabled"
        : collectionEnabled == true && subscribed ? "subscribed" : "unavailable";

    void Run()
    {
        IntPtr engine = IntPtr.Zero, subscription = IntPtr.Zero;
        GCHandle callbackRoot = default;
        bool failed = false;
        try
        {
            if (!OperatingSystem.IsWindows() || IntPtr.Size != 8)
            {
                failed = true;
                SetStatus("unavailable", "unsupported_platform", null, null, false);
                return;
            }
            var session = new Session { Key = Guid.NewGuid() };
            uint error = FwpmEngineOpen0(null, 10 /* RPC_C_AUTHN_WINNT */, IntPtr.Zero, ref session, out engine);
            if (error != 0)
            {
                failed = true;
                SetStatus(Availability(null, error, false), "engine_open", error, null, false);
                return;
            }
            long nextCheck = 0;
            while (Volatile.Read(ref stopping) == 0)
            {
                if (Stopwatch.GetTimestamp() >= nextCheck)
                {
                    var option = ReadCollection(engine);
                    if (option.Enabled == true && option.Error == null && subscription == IntPtr.Zero)
                    {
                        if (!callbackRoot.IsAllocated)
                        {
                            callbackRoot = GCHandle.Alloc(this);
                        }
                        // NULL template receives all native events, but callback immediately
                        // ignores everything except CLASSIFY_DROP, without copying payload.
                        var request = new Subscription { SessionKey = session.Key };
                        error = FwpmNetEventSubscribe1(engine, ref request, callback, IntPtr.Zero, out var owned);
                        if (error == 0)
                        {
                            subscription = owned;
                        }
                        else
                        {
                            option = (option.Enabled, error, "subscribe");
                        }
                    }
                    SetStatus(Availability(option.Enabled, option.Error, subscription != IntPtr.Zero),
                        option.Reason, option.Error, option.Enabled, subscription != IntPtr.Zero);
                    ready.Set();
                    nextCheck = Stopwatch.GetTimestamp() + Stopwatch.Frequency * 5;
                }
                // Bound each batch so a busy stream cannot starve status refresh or Stop.
                int batch = 0;
                while (batch++ < 64 && Volatile.Read(ref stopping) == 0 && queue.Reader.TryRead(out var value))
                {
                    WfpBlockEvent enriched;
                    try
                    {
                        enriched = Enrich(engine, value);
                    }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref originErrors);
                        enriched = value with
                        {
                            OriginStatus = "lookup_error",
                            OriginError = unchecked((uint)ex.HResult)
                        };
                    }
                    try
                    {
                        if (!tryQueue(enriched))
                        {
                            Interlocked.Increment(ref sinkRejected);
                            Interlocked.Increment(ref dropped);
                        }
                    }
                    catch
                    {
                        Interlocked.Increment(ref sinkRejected);
                        Interlocked.Increment(ref dropped);
                    }
                }
                if (!queue.Reader.TryPeek(out _))
                {
                    wake.WaitOne(250);
                }
            }
        }
        catch (Exception ex)
        {
            failed = true;
            SetStatus("unavailable", ex is DllNotFoundException or EntryPointNotFoundException
                ? "unsupported_api" : "worker_error", unchecked((uint)ex.HResult), null, subscription != IntPtr.Zero);
        }
        finally
        {
            ready.Set();
            queue.Writer.TryComplete();
            while (queue.Reader.TryRead(out _))
            {
                Interlocked.Increment(ref dropped);
            }
            // Never free a live callback delegate. Closing this own engine also cancels
            // its subscriptions. If both RPCs fail, retain one root until process exit.
            bool callbacksEnded = subscription == IntPtr.Zero;
            uint? cleanupError = null;
            try
            {
                if (subscription != IntPtr.Zero)
                {
                    uint error = FwpmNetEventUnsubscribe0(engine, subscription);
                    callbacksEnded = error == 0;
                    if (error != 0)
                    {
                        cleanupError = error;
                    }
                }
                if (engine != IntPtr.Zero)
                {
                    uint error = FwpmEngineClose0(engine);
                    if (error == 0)
                    {
                        callbacksEnded = true;
                        cleanupError = null;
                    }
                    else
                    {
                        cleanupError = error;
                    }
                }
            }
            catch (Exception ex) { cleanupError = unchecked((uint)ex.HResult); }
            if (callbacksEnded && callbackRoot.IsAllocated)
            {
                callbackRoot.Free();
            }

            if (cleanupError != null)
            {
                SetStatus("unavailable", "cleanup_error", cleanupError, null, !callbacksEnded);
            }
            else if (!failed)
            {
                SetStatus("stopped", null, null, null, false);
            }
        }
    }

    static (bool? Enabled, uint? Error, string? Reason) ReadCollection(IntPtr engine)
    {
        IntPtr value = IntPtr.Zero;
        try
        {
            uint error = FwpmEngineGetOption0(engine, 0 /* COLLECT_NET_EVENTS */, out value);
            if (error != 0)
            {
                return (null, error, "collection_query");
            }

            if (value == IntPtr.Zero || (uint)Marshal.ReadInt32(value) != UInt32Type)
            {
                return (null, null, "invalid_collection_option");
            }

            uint enabled = unchecked((uint)Marshal.ReadInt32(value, 8));
            return enabled <= 1 ? (enabled == 1, null, enabled == 0 ? "collection_disabled" : null)
                : (null, null, "invalid_collection_option");
        }
        finally
        {
            if (value != IntPtr.Zero)
            {
                FwpmFreeMemory0(ref value);
            }
        }
    }

    void OnNativeEvent(IntPtr context, IntPtr netEvent)
    {
        try
        {
            if (netEvent == IntPtr.Zero || unchecked((uint)Marshal.ReadInt32(netEvent, 104)) != ClassifyDrop)
            {
                return;
            }

            Interlocked.Increment(ref received);
            if (Volatile.Read(ref stopping) != 0)
            {
                Interlocked.Increment(ref dropped);
                return;
            }
            byte[] header = new byte[HeaderBytes];
            Marshal.Copy(netEvent, header, 0, header.Length);
            IntPtr drop = Marshal.ReadIntPtr(netEvent, 112);
            if (drop == IntPtr.Zero)
            {
                throw new InvalidOperationException("Missing WFP metadata.");
            }

            byte[] detail = new byte[DropPrefixBytes];
            Marshal.Copy(drop, detail, 0, detail.Length);
            string? app = null;
            if ((BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8, 4)) & 0x20) != 0)
            {
                uint bytes = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(64, 4));
                IntPtr appData = Marshal.ReadIntPtr(netEvent, 72);
                if (appData != IntPtr.Zero && bytes >= 2)
                {
                    app = ReadBlobText(appData, bytes);
                }
            }
            var value = DecodeEvent(header, detail, app, DateTimeOffset.UtcNow, Stopwatch.GetTimestamp());
            if (value == null)
            {
                return;
            }

            Interlocked.Exchange(ref lastEventTicks, value.EventUtc.UtcTicks);
            if (queue.Writer.TryWrite(value))
            {
                Interlocked.Increment(ref queued);
                wake.Set();
            }
            else
            {
                Interlocked.Increment(ref dropped);
            }
        }
        catch
        {
            Interlocked.Increment(ref callbackErrors);
            Interlocked.Increment(ref dropped);
            // Exceptions must never cross the native callback boundary.
        }
    }

    // Pure metadata decoder for x64 SDK fixtures; neither pointer is dereferenced here.
    internal static WfpBlockEvent? DecodeEvent(ReadOnlySpan<byte> header, ReadOnlySpan<byte> drop,
        string? applicationPath, DateTimeOffset observedUtc, long observedMonotonicTicks)
    {
        if (header.Length < HeaderBytes)
        {
            throw new ArgumentException("Invalid WFP header.", nameof(header));
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(104, 4)) != ClassifyDrop)
        {
            return null;
        }

        if (drop.Length < DropPrefixBytes)
        {
            throw new ArgumentException("Invalid WFP drop.", nameof(drop));
        }

        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(8, 4));
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(12, 4));
        bool hasVersion = (flags & 0x100) != 0;
        uint? scope = hasVersion && version == 1 && (flags & 0x80) != 0
            ? BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(56, 4)) : null;
        string? local = (flags & 2) != 0 && hasVersion ? Address(header.Slice(20, 16), version, scope) : null;
        string? remote = (flags & 4) != 0 && hasVersion ? Address(header.Slice(36, 16), version, scope) : null;
        uint direction = BinaryPrimitives.ReadUInt32LittleEndian(drop.Slice(24, 4));
        return new(DateTimeOffset.FromFileTime(BinaryPrimitives.ReadInt64LittleEndian(header)).ToUniversalTime(),
            observedUtc.ToUniversalTime(), observedMonotonicTicks, Stopwatch.Frequency, "wfp.net_event", null,
            (flags & 0x20) != 0 ? "app_id" : "unknown", (flags & 0x20) != 0 ? SafeText(applicationPath, 1024) : null,
            (flags & 1) != 0 ? header[16] : null, local,
            (flags & 8) != 0 ? BinaryPrimitives.ReadUInt16LittleEndian(header.Slice(52, 2)) : null, remote,
            (flags & 16) != 0 ? BinaryPrimitives.ReadUInt16LittleEndian(header.Slice(54, 2)) : null, scope,
            BinaryPrimitives.ReadUInt64LittleEndian(drop), BinaryPrimitives.ReadUInt16LittleEndian(drop.Slice(8, 2)),
            direction switch
            {
                0x3900 => "inbound",
                0x3901 => "outbound",
                0x3902 => "forward",
                _ => "unknown"
            },
            (flags & 0x200) != 0 ? BinaryPrimitives.ReadUInt32LittleEndian(drop.Slice(12, 4)) : null);
    }

    static string? Address(ReadOnlySpan<byte> bytes, uint version, uint? scope)
    {
        if (version == 0)
        {
            // WFP IPv4 scalars are host-order; byte arrays (IPv6) are network-order.
            Span<byte> address = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(address, BinaryPrimitives.ReadUInt32LittleEndian(bytes));
            return new IPAddress(address).ToString();
        }
        return version == 1 ? new IPAddress(bytes, scope ?? 0).ToString() : null;
    }

    WfpBlockEvent Enrich(IntPtr engine, WfpBlockEvent value)
    {
        long now = Stopwatch.GetTimestamp();
        if (!filterCache.TryGetValue(value.FilterId, out var origin) || origin.ExpiresTicks <= now)
        {
            origin = ResolveOrigin(engine, value.FilterId);
            if (!filterCache.ContainsKey(value.FilterId))
            {
                if (filterCache.Count == FilterCacheCapacity)
                {
                    filterCache.Remove(filterOrder.Dequeue());
                }

                filterOrder.Enqueue(value.FilterId);
            }
            filterCache[value.FilterId] = origin;
        }
        return value with
        {
            FilterKey = origin.FilterKey,
            ProviderKey = origin.ProviderKey,
            ProviderName = origin.ProviderName,
            LayerKey = origin.LayerKey,
            SubLayerKey = origin.SubLayerKey,
            ActionType = origin.ActionType,
            CalloutKey = origin.CalloutKey,
            OriginStatus = origin.Status,
            OriginError = origin.Error,
            OriginResolvedUtc = origin.ResolvedUtc
        };
    }

    Origin ResolveOrigin(IntPtr engine, ulong id)
    {
        IntPtr filter = IntPtr.Zero, provider = IntPtr.Zero;
        var utc = DateTimeOffset.UtcNow;
        long expires = Stopwatch.GetTimestamp() + Stopwatch.Frequency * 30;
        try
        {
            uint error = FwpmFilterGetById0(engine, id, out filter);
            if (error != 0 || filter == IntPtr.Zero)
            {
                Interlocked.Increment(ref originErrors);
                return new(null, null, null, null, null, null, null, "filter_unavailable", error == 0 ? null : error,
                    utc, Stopwatch.GetTimestamp() + Stopwatch.Frequency * 5);
            }
            // Read only whitelisted FWPM_FILTER0 fields, never conditions/providerData.
            Guid filterKey = Marshal.PtrToStructure<Guid>(filter);
            IntPtr providerKeyPointer = Marshal.ReadIntPtr(filter, 40);
            Guid? providerKey = providerKeyPointer == IntPtr.Zero ? null : Marshal.PtrToStructure<Guid>(providerKeyPointer);
            Guid layerKey = Marshal.PtrToStructure<Guid>(IntPtr.Add(filter, 64));
            Guid subLayerKey = Marshal.PtrToStructure<Guid>(IntPtr.Add(filter, 80));
            uint action = unchecked((uint)Marshal.ReadInt32(filter, 128));
            Guid? callout = (action & 0x4000) != 0 ? Marshal.PtrToStructure<Guid>(IntPtr.Add(filter, 132)) : null;
            if (providerKey == null)
            {
                return new(filterKey, null, null, layerKey, subLayerKey, action, callout,
                "provider_unspecified", null, utc, expires);
            }

            Guid key = providerKey.Value;
            error = FwpmProviderGetByKey0(engine, ref key, out provider);
            string? name = error == 0 && provider != IntPtr.Zero ? ReadTerminatedText(Marshal.ReadIntPtr(provider, 16), 256) : null;
            if (error != 0 || provider == IntPtr.Zero)
            {
                Interlocked.Increment(ref originErrors);
            }

            return new(filterKey, providerKey, name, layerKey, subLayerKey, action, callout,
                error == 0 && provider != IntPtr.Zero ? "resolved" : "provider_unavailable",
                error == 0 ? null : error, utc, expires);
        }
        finally
        {
            if (provider != IntPtr.Zero)
            {
                FwpmFreeMemory0(ref provider);
            }

            if (filter != IntPtr.Zero)
            {
                FwpmFreeMemory0(ref filter);
            }
        }
    }

    static string? ReadBlobText(IntPtr pointer, uint byteCount)
    {
        int chars = (int)Math.Min(byteCount / 2, 1024);
        return SafeText(Marshal.PtrToStringUni(pointer, chars), 1024);
    }
    static string? ReadTerminatedText(IntPtr pointer, int limit)
    {
        if (pointer == IntPtr.Zero)
        {
            return null;
        }

        var chars = new char[limit];
        int length = 0;
        while (length < limit)
        {
            char c = (char)Marshal.ReadInt16(pointer, length * 2);
            if (c == '\0')
            {
                break;
            }

            chars[length++] = c;
        }
        return SafeText(new string(chars, 0, length), limit);
    }
    internal static string? SafeText(string? value, int limit)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        int zero = value.IndexOf('\0');
        int length = Math.Min(zero >= 0 ? zero : value.Length, limit);
        char[] output = value.AsSpan(0, length).ToArray();
        for (int i = 0; i < output.Length; i++)
        {
            if (char.IsControl(output[i]))
            {
                output[i] = '?';
            }
        }

        return output.Length == 0 ? null : new string(output);
    }

    public void Stop()
    {
        Task? pending;
        lock (lifecycle)
        {
            Interlocked.Exchange(ref stopping, 1);
            wake.Set();
            pending = worker;
        }
        if (pending == null)
        {
            ready.Set();
            SetStatus("stopped", null, null, null, false);
            return;
        }
        if (!pending.Wait(TimeSpan.FromMilliseconds(2000)))
        {
            var previous = Volatile.Read(ref status);
            SetStatus("unavailable", "stop_timeout", null, previous.CollectionEnabled, previous.Subscribed);
            // Worker retains handles/delegate until native calls finish. Never race it
            // by closing a handle on another thread or stopping someone else's session.
        }
    }
    public void Dispose() => Stop();
}
