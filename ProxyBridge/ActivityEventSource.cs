using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;

namespace ProxyBridge;

// Whitelisted ETW observations only. Event subscribers must enqueue without
// blocking. This class never reads settings, payload bytes, command lines or SID.
internal sealed class ActivityEventSource : IActivityEventSource
{
    readonly object lifecycle = new();
    readonly ActivityTraceSession session = new();
    ETWTraceEventSource? consumer;
    Thread? worker;
    long callbackErrors;
    int running, stopRequested;
    string? errorCode;
    bool disposed;

    public event Action<ActivityEvent>? Event;
    public event Action<Exception>? Fault;

    public void Start()
    {
        lock (lifecycle) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (worker != null) throw new InvalidOperationException("Activity consumer has not stopped.");
            Volatile.Write(ref stopRequested, 0);
            Volatile.Write(ref errorCode, null);
            session.Start(); // Failed/conflicting Start does not give ownership.
            try {
                var source = new ETWTraceEventSource(ActivityTraceSession.SessionName, TraceEventSourceType.Session);
                consumer = source;
                Attach(source);
                var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                worker = new Thread(() => Consume(source, ready)) {
                    IsBackground = true, Name = "ProxyBridge activity ETW"
                };
                worker.Start();
                // OpenTrace already succeeded and callbacks are attached. The
                // thread signals before Process enters its blocking event loop.
                ready.Task.GetAwaiter().GetResult();
                if (Volatile.Read(ref running) == 0)
                    throw new InvalidOperationException("Activity consumer could not remain running.");
            } catch {
                Volatile.Write(ref stopRequested, 1);
                try { session.Stop(); }
                finally {
                    if (worker == null || !worker.IsAlive) {
                        consumer?.Dispose(); consumer = null; worker = null;
                    }
                }
                throw;
            }
        }
    }

    void Consume(ETWTraceEventSource source, TaskCompletionSource ready)
    {
        Volatile.Write(ref running, 1);
        ready.SetResult();
        try {
            source.Process();
            if (Volatile.Read(ref stopRequested) == 0)
                throw new InvalidOperationException("Activity ETW stream ended unexpectedly.");
        } catch (Exception ex) {
            if (Volatile.Read(ref stopRequested) == 0) ReportFault(ex);
        } finally {
            Volatile.Write(ref running, 0);
            try { session.Stop(); } catch (Exception ex) { ReportFault(ex); }
            try { source.Dispose(); } catch (Exception ex) { ReportFault(ex); }
        }
    }

    public void Stop()
    {
        lock (lifecycle) {
            Volatile.Write(ref stopRequested, 1);
            Exception? stopError = null;
            try { session.Stop(); } catch (Exception ex) { stopError = ex; }
            var thread = worker;
            if (thread != null && thread != Thread.CurrentThread) {
                // A successful native Stop flushes its final buffer; allow the
                // consumer to drain before closing its read-only OpenTrace handle.
                if (!thread.Join(TimeSpan.FromSeconds(5))) {
                    Volatile.Write(ref errorCode, "consumer:drain-timeout");
                    consumer?.StopProcessing();
                    consumer?.Dispose();
                    if (!thread.Join(TimeSpan.FromSeconds(5)))
                        throw new TimeoutException("Activity consumer did not stop within its deadline.");
                }
                consumer = null;
                worker = null;
            } else if (thread == null) {
                consumer?.Dispose(); consumer = null;
            }
            // Called from Fault on the consumer thread: never join ourselves.
            // The consuming finally releases its handle; a later Stop may join.
            if (stopError != null) throw stopError;
        }
    }

    public ActivityTraceStats ReadStats()
    {
        var native = session.ReadStats();
        return native with {
            CallbackErrors = Interlocked.Read(ref callbackErrors),
            Running = Volatile.Read(ref running) != 0 && native.Running,
            ErrorCode = Volatile.Read(ref errorCode) ?? native.ErrorCode
        };
    }

    void ReportFault(Exception error)
    {
        Volatile.Write(ref errorCode, $"{error.GetType().Name}:0x{error.HResult:X8}");
        try { Fault?.Invoke(error); }
        catch { Interlocked.Increment(ref callbackErrors); }
    }

    void Publish(ActivityEvent value)
    {
        try { Event?.Invoke(value); }
        catch (Exception ex) {
            // A subscriber failure cannot escape into ETW/native dispatch. Avoid
            // an unbounded stream of Fault notifications from a broken sink.
            if (Interlocked.Increment(ref callbackErrors) == 1) ReportFault(ex);
        }
    }

    static DateTimeOffset Timestamp(TraceEvent value) => new DateTimeOffset(value.TimeStamp).ToUniversalTime();
    static ActivityEvent Network(TraceEvent value, string kind, string protocol,
        IPAddress source, int sourcePort, IPAddress destination, int destinationPort,
        long? bytes = null, bool inbound = false) => new(
            Timestamp(value), kind, value.ProcessID,
            Protocol: protocol,
            LocalAddress: (inbound ? destination : source).ToString(),
            LocalPort: inbound ? destinationPort : sourcePort,
            RemoteAddress: (inbound ? source : destination).ToString(),
            RemotePort: inbound ? sourcePort : destinationPort,
            Bytes: bytes);

    void Attach(ETWTraceEventSource source)
    {
        // Parser fixes ProcessID using the event payload. Do not serialize the
        // TraceEvent object: Process payload also contains a command line.
        var kernel = new KernelTraceEventParser(source);
        kernel.ProcessStart += d => Publish(new(Timestamp(d), "process.start", d.ProcessID,
            ImageName: Path.GetFileName(d.KernelImageFileName), ParentProcessId: d.ParentID));
        kernel.ProcessStop += d => Publish(new(Timestamp(d), "process.stop", d.ProcessID,
            ImageName: Path.GetFileName(d.KernelImageFileName), ParentProcessId: d.ParentID, ExitCode: d.ExitStatus));

        kernel.TcpIpConnect += d => Publish(Network(d, "tcp.connect", "TCP", d.saddr, d.sport, d.daddr, d.dport));
        // Verified with IPv4/IPv6 loopback capture: Accept payload describes
        // the socket endpoints: saddr/sport are the local server endpoint.
        kernel.TcpIpAccept += d => Publish(Network(d, "tcp.accept", "TCP", d.saddr, d.sport, d.daddr, d.dport));
        kernel.TcpIpDisconnect += d => Publish(Network(d, "tcp.disconnect", "TCP", d.saddr, d.sport, d.daddr, d.dport));
        kernel.TcpIpRetransmit += d => Publish(Network(d, "tcp.retransmit", "TCP", d.saddr, d.sport, d.daddr, d.dport, (uint)d.size));
        kernel.TcpIpSend += d => Publish(Network(d, "tcp.send", "TCP", d.saddr, d.sport, d.daddr, d.dport, (uint)d.size));
        // Asymmetric IPv4/IPv6 capture verified TCP Receive uses socket tuples:
        // saddr/sport remain local. UDP Receive below uses packet source/destination.
        kernel.TcpIpRecv += d => Publish(Network(d, "tcp.receive", "TCP", d.saddr, d.sport, d.daddr, d.dport, (uint)d.size));

        kernel.TcpIpConnectIPV6 += d => Publish(Network(d, "tcp.connect", "TCP", d.saddr, d.sport, d.daddr, d.dport));
        kernel.TcpIpAcceptIPV6 += d => Publish(Network(d, "tcp.accept", "TCP", d.saddr, d.sport, d.daddr, d.dport));
        kernel.TcpIpDisconnectIPV6 += d => Publish(Network(d, "tcp.disconnect", "TCP", d.saddr, d.sport, d.daddr, d.dport));
        kernel.TcpIpRetransmitIPV6 += d => Publish(Network(d, "tcp.retransmit", "TCP", d.saddr, d.sport, d.daddr, d.dport, (uint)d.size));
        kernel.TcpIpSendIPV6 += d => Publish(Network(d, "tcp.send", "TCP", d.saddr, d.sport, d.daddr, d.dport, (uint)d.size));
        kernel.TcpIpRecvIPV6 += d => Publish(Network(d, "tcp.receive", "TCP", d.saddr, d.sport, d.daddr, d.dport, (uint)d.size));

        kernel.UdpIpSend += d => Publish(Network(d, "udp.send", "UDP", d.saddr, d.sport, d.daddr, d.dport, (uint)d.size));
        kernel.UdpIpRecv += d => Publish(Network(d, "udp.receive", "UDP", d.saddr, d.sport, d.daddr, d.dport, (uint)d.size, true));
        kernel.UdpIpSendIPV6 += d => Publish(Network(d, "udp.send", "UDP", d.saddr, d.sport, d.daddr, d.dport, (uint)d.size));
        kernel.UdpIpRecvIPV6 += d => Publish(Network(d, "udp.receive", "UDP", d.saddr, d.sport, d.daddr, d.dport, (uint)d.size, true));
        // TcpIp_Fail has no owning PID or tuple in its payload. Header PID is
        // not trustworthy attribution; report this as an uncorrelated event.
        kernel.TcpIpFail += d => Publish(new(Timestamp(d), "tcp.fail", 0,
            Protocol: "TCP", ErrorCode: $"tcpip:{d.FailureCode}"));
    }

    public void Dispose()
    {
        lock (lifecycle) {
            if (disposed) return;
            Stop();
            disposed = true;
        }
    }
}
