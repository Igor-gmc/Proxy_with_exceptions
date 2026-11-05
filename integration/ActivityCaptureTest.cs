using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using ProxyBridge;

internal static class ActivityCaptureTest
{
    const string Marker = "PB_ACTIVITY_PAYLOAD_SECRET_610C12";
    const string Response = Marker + "-response-xyz";
    sealed record Exchange(string Protocol, string Family, int ClientPort, int ServerPort, bool Success, string? Error);
    sealed record ChildResult(int Pid, Exchange[] Exchanges);
    public static bool TryRun(string[] args, out int code)
    {
        code = 0;
        if (args.Length == 0 || args[0] != "--activity-probe-child")
        {
            return false;
        }

        if (args.Length != 3 || !Path.IsPathFullyQualified(args[1]) || File.Exists(args[1]))
        { code = 2; return true; }
        try
        {
            var rows = new List<Exchange>();
            foreach (bool ipv6 in new[] { false, true })
            {
                rows.Add(Tcp(ipv6).GetAwaiter().GetResult());
                rows.Add(Udp(ipv6).GetAwaiter().GetResult());
            }
            File.WriteAllText(args[1], JsonSerializer.Serialize(new ChildResult(Environment.ProcessId, rows.ToArray())));
            code = rows.All(r => r.Success) ? 0 : 1;
        }
        catch { code = 2; }
        return true;
    }
    static async Task<Exchange> Tcp(bool ipv6)
    {
        string family = ipv6 ? "IPv6" : "IPv4";
        int clientPort = 0, serverPort = 0;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            IPAddress address = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
            using var listener = new TcpListener(address, 0);
            listener.Start();
            serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var client = new TcpClient(address.AddressFamily);
            await client.ConnectAsync(address, serverPort, timeout.Token);
            clientPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;
            using var accepted = await listener.AcceptTcpClientAsync(timeout.Token);
            byte[] data = Encoding.UTF8.GetBytes(Marker);
            await client.GetStream().WriteAsync(data, timeout.Token);
            await accepted.GetStream().ReadExactlyAsync(new byte[data.Length], timeout.Token);
            byte[] response = Encoding.UTF8.GetBytes(Response);
            await accepted.GetStream().WriteAsync(response, timeout.Token);
            await client.GetStream().ReadExactlyAsync(new byte[response.Length], timeout.Token);
            return new("TCP", family, clientPort, serverPort, true, null);
        }
        catch (Exception ex) { return new("TCP", family, clientPort, serverPort, false, AppLog.ExceptionCodes(ex)); }
    }
    static async Task<Exchange> Udp(bool ipv6)
    {
        string family = ipv6 ? "IPv6" : "IPv4";
        int clientPort = 0, serverPort = 0;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            IPAddress address = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
            using var receiver = new UdpClient(new IPEndPoint(address, 0));
            serverPort = ((IPEndPoint)receiver.Client.LocalEndPoint!).Port;
            using var sender = new UdpClient(new IPEndPoint(address, 0));
            clientPort = ((IPEndPoint)sender.Client.LocalEndPoint!).Port;
            byte[] data = Encoding.UTF8.GetBytes(Marker);
            await sender.SendAsync(data, new IPEndPoint(address, serverPort), timeout.Token);
            var received = await receiver.ReceiveAsync(timeout.Token);
            await receiver.SendAsync(Encoding.UTF8.GetBytes(Response), received.RemoteEndPoint, timeout.Token);
            await sender.ReceiveAsync(timeout.Token);
            return new("UDP", family, clientPort, serverPort, true, null);
        }
        catch (Exception ex) { return new("UDP", family, clientPort, serverPort, false, AppLog.ExceptionCodes(ex)); }
    }
    public static async Task RunAsync(string output, Action<string> record)
    {
        var originalSessions = Microsoft.Diagnostics.Tracing.Session.TraceEventSession.GetActiveSessionNames().ToHashSet();
        if (originalSessions.Contains(ActivityTraceSession.SessionName))
        {
            throw new IOException("An activity trace already exists; test refused without touching it.");
        }

        var source = new ActivityEventSource();
        string journalPath = Path.Combine(output, "activity.jsonl");
        using var monitor = new ActivityMonitor(() => source, new ActivityFileSink(journalPath),
            flushInterval: TimeSpan.FromMilliseconds(100), captureBaseline: true);
        try
        {
            await monitor.StartAsync();
            if (!monitor.Running || monitor.LastError != null)
            {
                throw new IOException("Activity start failed: " + monitor.LastError);
            }

            record("PASS: actual process/network ETW session and consumer started.");
            using (var conflict = new ActivityEventSource())
            {
                bool refused = false;
                try
                { conflict.Start(); }
                catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 183) { refused = true; }
                if (!refused)
                {
                    throw new IOException("Duplicate session did not reject Start.");
                }
            }
            if (!source.ReadStats().Running)
            {
                throw new IOException("Conflicting source stopped the first session.");
            }

            record("PASS: duplicate Start and Dispose left the original ETW session running.");
            string childPath = Path.Combine(output, "child.json");
            var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            info.ArgumentList.Add("--activity-probe-child");
            info.ArgumentList.Add(childPath);
            info.ArgumentList.Add(Marker); // Not registered with redaction: detects accidental argv capture.
            using var child = Process.Start(info) ?? throw new IOException("Probe child did not start.");
            try
            { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20)); }
            catch { if (!child.HasExited) { child.Kill(true); } throw; }
            if (child.ExitCode != 0)
            {
                throw new IOException("Loopback positive controls failed.");
            }

            var result = JsonSerializer.Deserialize<ChildResult>(File.ReadAllText(childPath))!;
            // Native Stop must drain even a short-lived child's final events.
            await monitor.StopAsync();
            if (monitor.LastError != null)
            {
                throw new IOException("Activity stop failed: " + monitor.LastError);
            }

            string all = File.ReadAllText(journalPath);
            if (all.Contains(Marker, StringComparison.Ordinal))
            {
                throw new IOException("Command line or payload marker leaked.");
            }

            record("PASS: argv and TCP/UDP payload marker absent from activity log.");
            var docs = File.ReadLines(journalPath).Select(line => JsonDocument.Parse(line)).ToArray();
            try
            {
                var entries = docs.Select(d => d.RootElement).ToArray();
                var own = entries.Where(e => e.TryGetProperty("pid", out var p) && p.ValueKind == JsonValueKind.Number && p.GetInt32() == result.Pid).ToArray();
                bool Has(string kind) => own.Any(e => e.GetProperty("kind").GetString() == kind);
                if (!Has("process.start") || !Has("process.stop"))
                {
                    throw new IOException("Short-lived process lifecycle missing.");
                }

                record("PASS: short-lived child process start and stop captured with its PID.");
                foreach (var exchange in result.Exchanges)
                {
                    string address = exchange.Family == "IPv6" ? "::1" : "127.0.0.1";
                    JsonElement[] Match(int localPort, int remotePort) => own.Where(e => e.TryGetProperty("protocol", out var p) && p.GetString() == exchange.Protocol &&
                        e.TryGetProperty("localAddress", out var a) && a.GetString() == address &&
                        e.TryGetProperty("remoteAddress", out var ra) && ra.GetString() == address &&
                        e.TryGetProperty("localPort", out var l) && l.ValueKind == JsonValueKind.Number && l.GetInt32() == localPort &&
                        e.TryGetProperty("remotePort", out var r) && r.ValueKind == JsonValueKind.Number && r.GetInt32() == remotePort).ToArray();
                    var clientEntries = Match(exchange.ClientPort, exchange.ServerPort);
                    var serverEntries = Match(exchange.ServerPort, exchange.ClientPort);
                    if (exchange.Protocol == "TCP" && (!clientEntries.Any(e => e.GetProperty("kind").GetString() == "tcp.connect") ||
                        !serverEntries.Any(e => e.GetProperty("kind").GetString() == "tcp.accept")))
                    {
                        throw new IOException("TCP " + exchange.Family + " connect/accept endpoint direction mismatch.");
                    }

                    static long Sum(JsonElement[] rows, string field) => rows.Where(e => e.GetProperty("kind").GetString() == "network.activity")
                        .Sum(e => e.GetProperty("traffic").GetProperty(field).GetInt64());
                    long requestBytes = Encoding.UTF8.GetByteCount(Marker), responseBytes = Encoding.UTF8.GetByteCount(Response);
                    if (Sum(clientEntries, "sentBytes") != requestBytes || Sum(clientEntries, "receivedBytes") != responseBytes ||
                        Sum(serverEntries, "sentBytes") != responseBytes || Sum(serverEntries, "receivedBytes") != requestBytes)
                    {
                        throw new IOException(exchange.Protocol + " " + exchange.Family + " asymmetric traffic direction/byte counts mismatch.");
                    }

                    record("PASS: " + exchange.Protocol + " " + exchange.Family + " local/remote endpoints and asymmetric 33/46-byte send/receive matched PID.");
                }
            }
            finally
            {
                foreach (var doc in docs)
                {
                    doc.Dispose();
                }
            }
            var finalSessions = Microsoft.Diagnostics.Tracing.Session.TraceEventSession.GetActiveSessionNames().ToHashSet();
            if (finalSessions.Contains(ActivityTraceSession.SessionName))
            {
                throw new IOException("Own ETW session remained after stop.");
            }

            if (originalSessions.Except(finalSessions).Any())
            {
                throw new IOException("An existing ETW session disappeared during the test; investigate attribution.");
            }

            record("PASS: own ETW session stopped; all pre-existing session names remain present.");
            File.WriteAllText(Path.Combine(output, "capture-stats.json"), JsonSerializer.Serialize(new { monitor.Counters, Trace = source.ReadStats() }));
            record("OBSERVE: loopback metadata test only; no WFP, TUN, DNS, routes or TLS interception changes.");
        }
        finally { await monitor.StopAsync(); }
    }
}
