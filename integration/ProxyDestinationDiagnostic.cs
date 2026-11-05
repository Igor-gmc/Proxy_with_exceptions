using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProxyBridge;

// Test-only SOCKS CONNECT probes with a separately reported phased baseline.
// No TLS or HTTP success is inferred from a CONNECT-only reply, and no
// WFP/TUN/routes/settings are changed here.
internal static class ProxyDestinationDiagnostic
{
    const SocketOptionName IpUnicastInterface = (SocketOptionName)31;
    static readonly JsonSerializerOptions PhaseJson = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    static readonly (string Label, IPAddress Address)[] Targets = [
        ("baseline-control", IPAddress.Parse("1.1.1.1")),
        ("incident-destination", IPAddress.Parse("104.18.32.47"))
    ];
    sealed record StageTiming(string Stage, long ElapsedMs);
    sealed record Result(DateTimeOffset Started, string Kind, string Target, int Round,
        bool Succeeded, string Stage, long ElapsedMs, byte? Method, byte? AuthStatus, byte? SocksReply,
        StageTiming[] Stages, string? ErrorCodes);

    static Socket NewSocket(int interfaceIndex)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            socket.SetSocketOption(SocketOptionLevel.IP, IpUnicastInterface,
                IPAddress.HostToNetworkOrder(interfaceIndex));
            return socket;
        }
        catch { socket.Dispose(); throw; }
    }

    static async Task<Result> DirectTcp(string label, IPAddress target, int interfaceIndex)
    {
        var began = DateTimeOffset.Now;
        var elapsed = Stopwatch.StartNew();
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var socket = NewSocket(interfaceIndex);
            await socket.ConnectAsync(new IPEndPoint(target, 443), deadline.Token);
            return new(began, "direct TCP only", label, 0, true, "tcp-connected", elapsed.ElapsedMilliseconds,
                null, null, null, [new("tcp-connect", elapsed.ElapsedMilliseconds)], null);
        }
        catch (Exception ex)
        {
            return new(began, "direct TCP only", label, 0, false, "tcp-connect", elapsed.ElapsedMilliseconds,
                null, null, null, [], AppLog.ExceptionCodes(ex));
        }
    }

    static async Task<Result> SocksConnect(Settings settings, string label, IPAddress target,
        int round, int interfaceIndex, byte[] username, byte[] password)
    {
        var began = DateTimeOffset.Now;
        var elapsed = Stopwatch.StartNew();
        var timings = new List<StageTiming>();
        string stage = "tcp-connect-proxy";
        byte? method = null, authStatus = null, reply = null;
        long stageStart = 0;
        void Advance(string next)
        {
            timings.Add(new(stage, elapsed.ElapsedMilliseconds - stageStart));
            stage = next;
            stageStart = elapsed.ElapsedMilliseconds;
        }
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var token = deadline.Token;
            using var socket = NewSocket(interfaceIndex);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(settings.Host), settings.Port), token);
            using var stream = new NetworkStream(socket, ownsSocket: false);
            Advance("socks-greeting");
            bool authenticated = username.Length != 0;
            byte requestedMethod = authenticated ? (byte)2 : (byte)0;
            await stream.WriteAsync(new byte[] { 5, 1, requestedMethod }, token);
            byte[] greeting = new byte[2];
            await stream.ReadExactlyAsync(greeting, token);
            method = greeting[1];
            if (greeting[0] != 5 || greeting[1] != requestedMethod)
            {
                throw new InvalidDataException("SOCKS greeting version or selected method invalid.");
            }

            if (authenticated)
            {
                Advance("socks-auth");
                byte[] auth = new byte[3 + username.Length + password.Length];
                try
                {
                    auth[0] = 1;
                    auth[1] = (byte)username.Length;
                    username.CopyTo(auth, 2);
                    auth[2 + username.Length] = (byte)password.Length;
                    password.CopyTo(auth, 3 + username.Length);
                    await stream.WriteAsync(auth, token);
                }
                finally { Array.Clear(auth); }
                byte[] response = new byte[2];
                await stream.ReadExactlyAsync(response, token);
                authStatus = response[1];
                if (response[0] != 1 || response[1] != 0)
                {
                    throw new InvalidDataException("SOCKS authentication rejected or version invalid.");
                }
            }
            Advance("socks-connect-target");
            byte[] request = new byte[10] { 5, 1, 0, 1, 0, 0, 0, 0, 1, 187 }; // IPv4, TCP port443
            target.GetAddressBytes().CopyTo(request, 4);
            await stream.WriteAsync(request, token);
            byte[] header = new byte[4];
            await stream.ReadExactlyAsync(header, token);
            reply = header[1];
            if (header[0] != 5 || header[2] != 0 || header[3] is not (1 or 3 or 4))
            {
                throw new InvalidDataException("SOCKS reply framing invalid.");
            }

            int addressLength;
            if (header[3] == 3)
            {
                byte[] length = new byte[1];
                await stream.ReadExactlyAsync(length, token);
                if (length[0] == 0)
                {
                    throw new InvalidDataException("SOCKS reply domain address empty.");
                }

                addressLength = length[0];
            }
            else
            {
                addressLength = header[3] == 1 ? 4 : 16;
            }
            // Consume the complete reply but never store the returned bound
            // address/port in a report or use it as another network destination.
            byte[] boundAddress = new byte[addressLength + 2];
            try
            { await stream.ReadExactlyAsync(boundAddress, token); }
            finally { Array.Clear(boundAddress); }
            timings.Add(new(stage, elapsed.ElapsedMilliseconds - stageStart));
            return new(began, "SOCKS CONNECT only", label, round, reply == 0,
                reply == 0 ? "connect-accepted" : "connect-rejected", elapsed.ElapsedMilliseconds,
                method, authStatus, reply, timings.ToArray(), null);
        }
        catch (Exception ex)
        {
            timings.Add(new(stage, elapsed.ElapsedMilliseconds - stageStart));
            return new(began, "SOCKS CONNECT only", label, round, false, stage, elapsed.ElapsedMilliseconds,
                method, authStatus, reply, timings.ToArray(), AppLog.ExceptionCodes(ex));
        }
    }

    public static async Task RunAsync(Settings settings, int physicalInterfaceIndex, string output, Action<string> record)
    {
        settings.Validate();
        if (settings.Protocol != "socks")
        {
            throw new ArgumentException("Destination diagnostic requires saved SOCKS settings.");
        }

        if (physicalInterfaceIndex is <= 0 or > 0x00FFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(physicalInterfaceIndex));
        }

        ArgumentNullException.ThrowIfNull(record);
        byte[] username = Encoding.UTF8.GetBytes(settings.Username);
        byte[] password = Encoding.UTF8.GetBytes(settings.Password);
        try
        {
            if (username.Length > 255 || password.Length > 255 ||
                (username.Length == 0) != (password.Length == 0))
            {
                throw new ArgumentException("SOCKS username/password must both be absent or each contain 1..255 encoded bytes.");
            }

            string reportPath = Path.Combine(output, "proxy-destination-results.jsonl");
            using var file = new FileStream(reportPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(file, new UTF8Encoding(false)) { AutoFlush = true };
            void Save(Result result)
            {
                writer.WriteLine(JsonSerializer.Serialize(result));
                record($"{(result.Succeeded ? "PASS" : "FAIL")}: {result.Kind}; target={result.Target}; round={result.Round}; stage={result.Stage}; elapsedMs={result.ElapsedMs}; method={result.Method}; authStatus={result.AuthStatus}; socksREP={result.SocksReply}; errors={result.ErrorCodes ?? "none"}.");
            }
            record("OBSERVE: fixed-destination physical TCP and SOCKS CONNECT diagnostic; 5s total deadline per request; no TLS/HTTP claim; no network policy changes.");
            var phaseObservations = new List<ProbeObservation>();
            var phaseStarted = DateTimeOffset.Now;
            var phaseResult = await ProxyPhaseProbe.RunAsync(settings, new ProbeContext(0), phaseObservations.Add,
                transport: new SocketProxyPhaseTransport(physicalInterfaceIndex));
            using (var phaseFile = new FileStream(Path.Combine(output, "proxy-phase-baseline.json"),
                FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            {
                JsonSerializer.Serialize(phaseFile, new
                {
                    Started = phaseStarted,
                    PhysicalInterfaceIndex = physicalInterfaceIndex,
                    Stage = "standalone-baseline",
                    EngineGeneration = 0L,
                    StopwatchFrequency = Stopwatch.Frequency,
                    Result = phaseResult,
                    Observations = phaseObservations.ToArray()
                }, PhaseJson);
            }

            record($"{(phaseResult.Succeeded ? "PASS" : phaseResult.Outcome == ProbeOutcome.Skipped ? "SKIP" : "FAIL")}: physical phase baseline; phase={phaseResult.Phase}; outcome={phaseResult.Outcome}; http={phaseResult.HttpStatus}; socksREP={phaseResult.SocksReply}; errors={phaseResult.ErrorCodes ?? "none"}.");
            foreach (var target in Targets)
            {
                Save(await DirectTcp(target.Label, target.Address, physicalInterfaceIndex));
            }

            for (int round = 1; round <= 3; round++)
            {
                foreach (var target in Targets)
                {
                    Save(await SocksConnect(settings, target.Label, target.Address, round, physicalInterfaceIndex, username, password));
                }
            }

            record("OBSERVE: destination diagnostic completed; response bound addresses and credentials were not reported.");
        }
        finally
        {
            Array.Clear(username);
            Array.Clear(password);
        }
    }
}
