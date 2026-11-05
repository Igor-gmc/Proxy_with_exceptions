using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace ProxyBridge;

internal interface IProxyPhaseTransport
{
    Task<Stream> ConnectAsync(IPAddress proxyAddress, int proxyPort, CancellationToken cancellationToken);
    Task<Stream> AuthenticateTlsAsync(Stream transport, string serverName, CancellationToken cancellationToken);
}

internal sealed class SocketProxyPhaseTransport(int? physicalInterfaceIndex = null) : IProxyPhaseTransport
{
    public async Task<Stream> ConnectAsync(IPAddress proxyAddress, int proxyPort, CancellationToken cancellationToken)
    {
        if (physicalInterfaceIndex is <= 0 or > 0x00FFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(physicalInterfaceIndex));
        }

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            if (physicalInterfaceIndex is int index)
            {
                socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31, IPAddress.HostToNetworkOrder(index));
            }

            await socket.ConnectAsync(new IPEndPoint(proxyAddress, proxyPort), cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch { socket.Dispose(); throw; }
    }

    public async Task<Stream> AuthenticateTlsAsync(Stream transport, string serverName, CancellationToken cancellationToken)
    {
        // The platform validates the certificate and hostname. There is no
        // permissive validation callback or diagnostic trust override.
        var tls = new SslStream(transport, leaveInnerStreamOpen: false);
        try
        {
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = serverName }, cancellationToken);
            return tls;
        }
        catch { tls.Dispose(); throw; }
    }
}

internal sealed record ProxyPhaseResult(bool Succeeded, ProbeOutcome Outcome, ProbePhase Phase,
    int? HttpStatus, int? SocksReply, string? ErrorCodes);

// Explicit diagnostic control for baseline or an already authorized test-owned
// helper. The production GUI never calls this while its active Guard policy is
// installed. No permits, exceptions, routes or settings are added by this class.
internal static class ProxyPhaseProbe
{
    const string EndpointId = "configured-proxy-control";
    const string ServerName = "one.one.one.one";
    static readonly IPAddress TargetAddress = IPAddress.Parse("1.1.1.1");
    const int MaxHttpHeaders = 8192;

    static async Task<Stream> AwaitStream(Task<Stream> pending, CancellationToken token)
    {
        try
        {
            return await pending.WaitAsync(token);
        }
        catch
        {
            // A poorly behaved injected transport may ignore cancellation.
            // Close any stream it eventually returns and observe its exception.
            _ = pending.ContinueWith(task =>
            {
                if (task.IsCompletedSuccessfully)
                {
                    try
                    {
                        task.Result.Dispose();
                    }
                    catch { }
                }
                else
                {
                    _ = task.Exception;
                }
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
    }

    static async Task ReadExactly(Stream stream, Memory<byte> destination, CancellationToken token)
    {
        while (destination.Length != 0)
        {
            int count = await stream.ReadAsync(destination, token).AsTask().WaitAsync(token);
            if (count == 0)
            {
                throw new EndOfStreamException("Diagnostic reply ended early.");
            }

            destination = destination[count..];
        }
    }

    static Task Write(Stream stream, ReadOnlyMemory<byte> bytes, CancellationToken token) =>
        stream.WriteAsync(bytes, token).AsTask().WaitAsync(token);

    public static async Task<ProxyPhaseResult> RunAsync(Settings settings, ProbeContext context,
        Action<ProbeObservation> observer, CancellationToken cancellationToken = default,
        IProxyPhaseTransport? transport = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(observer);
        long probeId = ProbeObservationSink.NextId();
        ProbePhase phase = ProbePhase.Setup;
        long phaseBegan = Stopwatch.GetTimestamp();
        int? httpStatus = null, socksReply = null;
        int? socksMethod = null, socksAuthStatus = null;
        byte[]? username = null, password = null;
        Stream? stream = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        var token = deadline.Token;
        void Observe(ProbeOutcome outcome, Exception? error = null, string? code = null)
        {
            long now = Stopwatch.GetTimestamp();
            ProbeObservationSink.Publish(observer, new(DateTimeOffset.Now, now, probeId, 1, context.EngineGeneration,
                EndpointId, phase, outcome, outcome == ProbeOutcome.Started ? 0 : now - phaseBegan,
                httpStatus, ProbeObservationSink.NativeCode(error), socksReply,
                code ?? (error == null ? null : AppLog.ExceptionCodes(error)),
                SocksMethod: socksMethod, SocksAuthStatus: socksAuthStatus));
        }
        void Begin(ProbePhase next)
        {
            Observe(ProbeOutcome.Succeeded);
            phase = next;
            phaseBegan = Stopwatch.GetTimestamp();
            Observe(ProbeOutcome.Started);
        }
        Observe(ProbeOutcome.Started);
        try
        {
            token.ThrowIfCancellationRequested();
            settings.Validate();
            if (settings.Protocol != "socks")
            {
                Observe(ProbeOutcome.Skipped, code: "UnsupportedProxyProtocol");
                return new(false, ProbeOutcome.Skipped, phase, null, null, "UnsupportedProxyProtocol");
            }
            username = Encoding.UTF8.GetBytes(settings.Username);
            password = Encoding.UTF8.GetBytes(settings.Password);
            if (username.Length > 255 || password.Length > 255 ||
                (username.Length == 0) != (password.Length == 0))
            {
                throw new InvalidDataException("SOCKS credentials must both be absent or contain 1..255 encoded bytes.");
            }

            transport ??= new SocketProxyPhaseTransport();
            Begin(ProbePhase.TcpConnect);
            // The sole socket destination is the configured proxy, never a
            // destination echoed by the server or a direct fallback endpoint.
            stream = await AwaitStream(transport.ConnectAsync(IPAddress.Parse(settings.Host), settings.Port, token), token);
            Begin(ProbePhase.SocksGreeting);
            byte requestedMethod = username.Length == 0 ? (byte)0 : (byte)2;
            await Write(stream, new byte[] { 5, 1, requestedMethod }, token);
            byte[] greeting = new byte[2];
            await ReadExactly(stream, greeting, token);
            socksMethod = greeting[1];
            if (greeting[0] != 5 || greeting[1] != requestedMethod)
            {
                throw new InvalidDataException("SOCKS version or selected authentication method invalid.");
            }

            if (requestedMethod == 2)
            {
                Begin(ProbePhase.SocksAuth);
                byte[] auth = new byte[3 + username.Length + password.Length];
                try
                {
                    auth[0] = 1;
                    auth[1] = (byte)username.Length;
                    username.CopyTo(auth, 2);
                    auth[2 + username.Length] = (byte)password.Length;
                    password.CopyTo(auth, 3 + username.Length);
                    await Write(stream, auth, token);
                }
                finally { Array.Clear(auth); }
                byte[] authReply = new byte[2];
                await ReadExactly(stream, authReply, token);
                socksAuthStatus = authReply[1];
                if (authReply[0] != 1 || authReply[1] != 0)
                {
                    throw new InvalidDataException("SOCKS authentication failed.");
                }
            }
            Begin(ProbePhase.SocksConnect);
            byte[] connect = [5, 1, 0, 1, 0, 0, 0, 0, 1, 187];
            TargetAddress.GetAddressBytes().CopyTo(connect, 4);
            await Write(stream, connect, token);
            byte[] header = new byte[4];
            await ReadExactly(stream, header, token);
            socksReply = header[1];
            if (header[0] != 5 || header[2] != 0 || header[3] is not (1 or 3 or 4))
            {
                throw new InvalidDataException("SOCKS CONNECT reply framing invalid.");
            }

            int addressBytes = header[3] == 1 ? 4 : 16;
            if (header[3] == 3)
            {
                byte[] length = new byte[1];
                await ReadExactly(stream, length, token);
                if (length[0] == 0)
                {
                    throw new InvalidDataException("SOCKS CONNECT reply address is empty.");
                }

                addressBytes = length[0];
            }
            byte[] boundAddress = new byte[addressBytes + 2];
            try
            {
                await ReadExactly(stream, boundAddress, token);
            }
            finally { Array.Clear(boundAddress); }
            if (socksReply != 0)
            {
                Observe(ProbeOutcome.Failed, code: "SocksConnectRejected");
                return new(false, ProbeOutcome.Failed, phase, null, socksReply, "SocksConnectRejected");
            }
            Begin(ProbePhase.TlsHandshake);
            stream = await AwaitStream(transport.AuthenticateTlsAsync(stream, ServerName, token), token);
            Begin(ProbePhase.HttpRequest);
            await Write(stream, Encoding.ASCII.GetBytes("GET /cdn-cgi/trace HTTP/1.1\r\nHost: " + ServerName + "\r\nConnection: close\r\n\r\n"), token);
            Begin(ProbePhase.HttpHeaders);
            byte[] headers = new byte[MaxHttpHeaders];
            int used = 0;
            while (used < headers.Length)
            {
                await ReadExactly(stream, headers.AsMemory(used, 1), token);
                used++;
                if (used >= 4 && headers[used - 4] == 13 && headers[used - 3] == 10 &&
                    headers[used - 2] == 13 && headers[used - 1] == 10)
                {
                    break;
                }
            }
            if (used < 4 || headers[used - 4] != 13 || headers[used - 3] != 10 || headers[used - 2] != 13 || headers[used - 1] != 10)
            {
                throw new InvalidDataException("HTTP response headers exceeded the diagnostic bound.");
            }
            // Parse the fixed status line only. Neither headers nor body enter
            // events, exceptions or the returned result; no redirects follow.
            string firstLine = Encoding.ASCII.GetString(headers, 0, Array.IndexOf(headers, (byte)13, 0, used));
            string[] fields = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 2 || fields[0] is not ("HTTP/1.0" or "HTTP/1.1") ||
                fields[1].Length != 3 || !int.TryParse(fields[1], out int status) || status is < 100 or > 599)
            {
                throw new InvalidDataException("HTTP status line invalid.");
            }

            httpStatus = status;
            token.ThrowIfCancellationRequested();
            bool success = status is >= 200 and <= 299;
            Observe(success ? ProbeOutcome.Succeeded : ProbeOutcome.Failed, code: success ? null : "HttpStatusRejected");
            return new(success, success ? ProbeOutcome.Succeeded : ProbeOutcome.Failed, phase,
                httpStatus, socksReply, success ? null : "HttpStatusRejected");
        }
        catch (Exception ex)
        {
            ProbeOutcome outcome = ex is OperationCanceledException
                ? cancellationToken.IsCancellationRequested ? ProbeOutcome.Canceled : deadline.IsCancellationRequested ? ProbeOutcome.TimedOut : ProbeOutcome.Failed
                : ProbeOutcome.Failed;
            Observe(outcome, ex);
            return new(false, outcome, phase, httpStatus, socksReply, AppLog.ExceptionCodes(ex));
        }
        finally
        {
            if (username != null)
            {
                Array.Clear(username);
            }

            if (password != null)
            {
                Array.Clear(password);
            }

            try
            {
                stream?.Dispose();
            }
            catch { }
        }
    }
}
