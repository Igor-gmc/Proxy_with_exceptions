using System.ComponentModel;
using System.Net.Sockets;

namespace ProxyBridge;

internal enum ProbePhase
{
    Setup, Request, Headers, Body, Validate,
    TcpConnect, SocksGreeting, SocksAuth, SocksConnect, TlsHandshake, HttpRequest, HttpHeaders
}

internal enum ProbeOutcome
{
    Started, Succeeded, Failed, TimedOut, Canceled, Skipped
}

internal sealed record ProbeContext(long EngineGeneration);

// EventTime is captured when the event happens, never when a buffered UI line
// is later rendered. MonoTicks and DurationTicks use Stopwatch.Frequency.
// EndpointId is a fixed diagnostic label; data/headers/credentials are absent.
internal sealed record ProbeObservation(DateTimeOffset EventTime, long MonoTicks, long ProbeId,
    int Attempt, long EngineGeneration, string EndpointId, ProbePhase Phase, ProbeOutcome Outcome,
    long DurationTicks, int? HttpStatus = null, int? NativeCode = null, int? SocksReply = null,
    string? ErrorCodes = null, int Bytes = 0, int? SocksMethod = null, int? SocksAuthStatus = null);

internal static class ProbeObservationSink
{
    static long nextId;
    internal static long NextId() => Interlocked.Increment(ref nextId);
    internal static void Publish(Action<ProbeObservation>? observer, ProbeObservation observation)
    {
        try
        {
            observer?.Invoke(observation);
        }
        catch { /* Diagnostic observers must not change network outcomes. */ }
    }
    internal static int? NativeCode(Exception? error)
    {
        for (int depth = 0; error != null && depth < 12; depth++, error = error.InnerException)
        {
            if (error is SocketException socket)
            {
                return socket.NativeErrorCode;
            }

            if (error is Win32Exception native)
            {
                return native.NativeErrorCode;
            }
        }
        return null;
    }
}
