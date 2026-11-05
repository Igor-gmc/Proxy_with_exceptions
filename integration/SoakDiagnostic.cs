using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProxyBridge;

// Test-only observation. Program owns the global application mutex and IncidentTest
// owns the exact temporary policy and the excluded helper throughout this method.
internal static class SoakDiagnostic
{
    const string TraceUrl = "https://1.1.1.1/cdn-cgi/trace";
    const SocketOptionName IpUnicastInterface = (SocketOptionName)31;
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true,
        Converters = { new JsonStringEnumConverter() } };
    sealed record ProbeResult(string Kind, DateTimeOffset Started, int TimeoutSeconds,
        long ElapsedMs, bool Succeeded, string Stage, int? HttpStatus, string? Errors);
    sealed record PhaseControl(DateTimeOffset Started, long EngineGeneration, long StopwatchFrequency,
        ProxyPhaseResult Result, ProbeObservation[] Observations);
    sealed record ChildReport(DateTimeOffset Started, int PhysicalInterfaceIndex,
        ProbeResult[] Probes, PhaseControl? Phase, string? SetupError);

    public static bool TryRun(string[] args, out int code)
    {
        code = 0;
        if (args.Length == 0 || args[0] is not ("--soak-probe-child" or "--soak-phase-child")) return false;
        long generation = 0;
        if (args.Length is not (3 or 4) || !Path.IsPathFullyQualified(args[1]) || File.Exists(args[1]) ||
            !int.TryParse(args[2], out int interfaceIndex) || interfaceIndex is <= 0 or > 0x00FFFFFF ||
            (args.Length == 4 && (!long.TryParse(args[3], out generation) || generation < 0))) {
            code = 2;
            return true;
        }
        var began = DateTimeOffset.Now;
        ChildReport report;
        try {
            var settings = Program.ReadDiagnosticSettings();
            // Only decrypted in this process. Neither credentials nor response
            // bodies/egress addresses are written to argv, stdout or the report.
            report = RunChild(settings, interfaceIndex, generation, args[0] == "--soak-phase-child").GetAwaiter().GetResult();
            code = report.Probes.All(p => p.Succeeded) && report.Phase is { } phase &&
                (phase.Result.Succeeded || phase.Result.Outcome == ProbeOutcome.Skipped) ? 0 : 1;
        } catch (Exception ex) {
            report = new(began, interfaceIndex, [], null, AppLog.ExceptionCodes(ex));
            code = 2;
        }
        try {
            using var file = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            JsonSerializer.Serialize(file, report, Json);
        } catch { code = 2; }
        return true;
    }

    static async Task<PhaseControl> RunPhase(Settings settings, int interfaceIndex, long generation)
    {
        var began = DateTimeOffset.Now;
        var observations = new List<ProbeObservation>();
        var result = await ProxyPhaseProbe.RunAsync(settings, new ProbeContext(generation), observations.Add,
            transport: new SocketProxyPhaseTransport(interfaceIndex));
        return new(began, generation, Stopwatch.Frequency, result, observations.ToArray());
    }

    static async Task<ChildReport> RunChild(Settings settings, int interfaceIndex, long generation, bool phaseOnly)
    {
        var began = DateTimeOffset.Now;
        var results = new List<ProbeResult>();
        var phase = RunPhase(settings, interfaceIndex, generation);
        if (!phaseOnly) {
            // Exactly two controls run together: phased proxy and direct HTTPS.
            // The longer functional retry starts after both sockets drain.
            var direct = Probe(null, interfaceIndex, 5);
            await Task.WhenAll(phase, direct);
            results.Add(await direct);
            results.Add(await Probe(settings, interfaceIndex, 15));
        }
        return new(began, interfaceIndex, results.ToArray(), await phase, null);
    }

    static async Task<ProbeResult> Probe(Settings? proxy, int interfaceIndex, int timeoutSeconds)
    {
        string kind = proxy == null ? "physical direct HTTPS" : "physical explicit proxy HTTPS";
        var began = DateTimeOffset.Now;
        var elapsed = Stopwatch.StartNew();
        string stage = "setup";
        int? status = null;
        try {
            var endpointAddress = IPAddress.Parse(proxy?.Host ?? "1.1.1.1");
            int endpointPort = proxy?.Port ?? 443;
            using var handler = new SocketsHttpHandler {
                UseProxy = proxy != null,
                Proxy = proxy == null ? null : new WebProxy($"{(proxy.Protocol == "http" ? "http" : "socks5")}://{proxy.Host}:{proxy.Port}") {
                    Credentials = new NetworkCredential(proxy.Username, proxy.Password)
                },
                AllowAutoRedirect = false,
                MaxResponseHeadersLength = 16,
                ConnectTimeout = TimeSpan.FromSeconds(timeoutSeconds),
                ConnectCallback = async (context, token) => {
                    // Permit only the predetermined transport endpoint; this
                    // callback cannot silently fall back to a direct connection.
                    if (context.DnsEndPoint.Port != endpointPort ||
                        !IPAddress.TryParse(context.DnsEndPoint.Host, out var requested) ||
                        !requested.Equals(endpointAddress))
                        throw new IOException("Unexpected diagnostic transport endpoint.");
                    stage = "tcp-connect";
                    var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try {
                        socket.SetSocketOption(SocketOptionLevel.IP, IpUnicastInterface,
                            IPAddress.HostToNetworkOrder(interfaceIndex));
                        await socket.ConnectAsync(new IPEndPoint(endpointAddress, endpointPort), token);
                        stage = proxy == null ? "tls-or-headers" : "proxy-handshake-or-tls-or-headers";
                        return new NetworkStream(socket, ownsSocket: true);
                    } catch { socket.Dispose(); throw; }
                }
            };
            using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
            stage = "request";
            using var response = await client.GetAsync(TraceUrl, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            stage = "headers";
            status = (int)response.StatusCode;
            response.EnsureSuccessStatusCode();
            stage = "body";
            await response.Content.LoadIntoBufferAsync(4096, deadline.Token);
            string body = await response.Content.ReadAsStringAsync(deadline.Token);
            stage = "validate";
            if (!body.Split('\n').Any(line => line.StartsWith("ip=", StringComparison.Ordinal) &&
                IPAddress.TryParse(line[3..].Trim(), out _)))
                throw new IOException("Trace returned no valid address.");
            deadline.Token.ThrowIfCancellationRequested();
            return new(kind, began, timeoutSeconds, elapsed.ElapsedMilliseconds, true, "complete", status, null);
        } catch (Exception ex) {
            return new(kind, began, timeoutSeconds, elapsed.ElapsedMilliseconds, false, stage, status, AppLog.ExceptionCodes(ex));
        }
    }

    static object TcpCounts(Settings settings)
    {
        try {
            var address = IPAddress.Parse(settings.Host);
            var rows = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
                .Where(t => t.RemoteEndPoint.Address.Equals(address) && t.RemoteEndPoint.Port == settings.Port).ToArray();
            return new { Scope = "all host processes to configured proxy endpoint", Total = rows.Length,
                States = rows.GroupBy(t => t.State.ToString()).ToDictionary(g => g.Key, g => g.Count()), Error = (string?)null };
        } catch (Exception ex) {
            return new { Scope = "all host processes to configured proxy endpoint", Error = AppLog.ExceptionCodes(ex) };
        }
    }

    static object State(Settings settings, Engine engine, ProtectionController controller)
    {
        bool? expected = null;
        string? policyError = null;
        try { expected = controller.IsConnectedCandidate(); }
        catch (Exception ex) { policyError = AppLog.ExceptionCodes(ex); }
        return new { At = DateTimeOffset.Now, PolicyAndEngineVerified = expected, PolicyError = policyError,
            EngineRunning = engine.Running, Generation = engine.Generation, ActiveLuid = controller.ActiveLuid,
            controller.ProtectionRequired, controller.StoppedDnsAllowed, Tcp = TcpCounts(settings) };
    }

    static void AppendObservation(string output, object value) =>
        File.AppendAllText(Path.Combine(output, "soak-observations.jsonl"), JsonSerializer.Serialize(value) + Environment.NewLine);

    public static Task RunBaselineControlAsync(string helper, string output, int interfaceIndex, Action<string> record) =>
        RunControl(helper, output, interfaceIndex, record, "baseline", 0, phaseOnly: true);

    public static Task RunFailureControlAsync(string helper, string output, int interfaceIndex,
        Action<string> record, long generation) =>
        RunControl(helper, output, interfaceIndex, record, "failure", generation);

    static async Task RunControl(string helper, string output, int interfaceIndex, Action<string> record,
        string stage, long generation, bool phaseOnly = false)
    {
        if (interfaceIndex is <= 0 or > 0x00FFFFFF) throw new ArgumentOutOfRangeException(nameof(interfaceIndex));
        string reportPath = Path.Combine(output, $"soak-{stage}-control.json");
        if (File.Exists(reportPath)) throw new IOException("Soak control report already exists.");
        var info = new ProcessStartInfo(helper) { UseShellExecute = false, CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory };
        info.ArgumentList.Add(phaseOnly ? "--soak-phase-child" : "--soak-probe-child");
        info.ArgumentList.Add(reportPath);
        info.ArgumentList.Add(interfaceIndex.ToString(System.Globalization.CultureInfo.InvariantCulture));
        info.ArgumentList.Add(generation.ToString(System.Globalization.CultureInfo.InvariantCulture));
        using var child = new Process { StartInfo = info };
        if (!child.Start()) throw new IOException("Soak control helper did not start.");
        try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(40)); }
        catch {
            if (!child.HasExited) child.Kill(true);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            throw;
        }
        var report = JsonSerializer.Deserialize<ChildReport>(File.ReadAllText(reportPath), Json)
            ?? throw new IOException("Soak control helper returned invalid report.");
        if (report.SetupError != null || report.Phase == null || child.ExitCode is < 0 or > 1)
            throw new IOException("Soak control helper setup failed: " + (report.SetupError ?? "exit=" + child.ExitCode));
        var phase = report.Phase.Result;
        record($"{(phase.Succeeded ? "PASS" : phase.Outcome == ProbeOutcome.Skipped ? "SKIP" : "FAIL")}: {stage} control physical proxy phases; generation={report.Phase.EngineGeneration}; phase={phase.Phase}; outcome={phase.Outcome}; http={phase.HttpStatus}; socksREP={phase.SocksReply}; errors={phase.ErrorCodes ?? "none"}.");
        foreach (var probe in report.Probes)
            record($"{(probe.Succeeded ? "PASS" : "FAIL")}: {stage} control {probe.Kind}; timeoutSeconds={probe.TimeoutSeconds}; elapsedMs={probe.ElapsedMs}; stage={probe.Stage}; http={probe.HttpStatus}; errors={probe.Errors ?? "none"}.");
    }

    public static async Task RunAsync(Settings settings, Engine engine, ProtectionController controller,
        string helper, string output, Action<string> record, int seconds, int physicalInterfaceIndex, int concurrency = 1)
    {
        if (seconds is < 60 or > 900 || physicalInterfaceIndex is <= 0 or > 0x00FFFFFF)
            throw new ArgumentOutOfRangeException(nameof(seconds));
        if (concurrency is < 1 or > 8) throw new ArgumentOutOfRangeException(nameof(concurrency));
        var timer = Stopwatch.StartNew();
        TimeSpan duration = TimeSpan.FromSeconds(seconds);
        int round = 0;
        void UpdateContext(string stage, bool policyVerified)
        {
            try {
                // Consume only the policy result already checked by the loop.
                DiagnosticJournal.UpdateContext(new(settings.Host, settings.Port, settings.Protocol,
                    engine.ProcessId, engine.Generation, controller.ActiveLuid, controller.ProtectionRequired,
                    controller.ConnectWanted, policyVerified, DateTimeOffset.Now, stage, engine.ProcessStartedUtc));
            } catch { /* Diagnostics cannot alter the existing test lifecycle. */ }
        }
        void ObserveProbe(ProbeObservation observation)
        {
            try {
                DiagnosticJournal.Record("probe.phase", observation, observation.EventTime, observation.MonoTicks);
                if (observation.Outcome is ProbeOutcome.Failed or ProbeOutcome.TimedOut)
                    DiagnosticJournal.Trigger("soak-probe-first-error", observation);
            } catch { }
        }
        record($"OBSERVE: production soak begins; requestedSeconds={seconds}; intervalSeconds=8; probeConcurrency={concurrency}; natural background traffic retained; no automatic recovery before failure controls.");
        File.WriteAllText(Path.Combine(output, "soak-network-before.json"), NetworkDiagnostics.Capture(settings));
        try {
            while (timer.Elapsed < duration) {
                ++round;
                var began = timer.Elapsed;
                AppendObservation(output, new { Round = round, Stage = "before-probe", ElapsedMs = timer.ElapsedMilliseconds,
                    State = State(settings, engine, controller) });
                bool verifiedBefore = controller.IsConnectedCandidate();
                UpdateContext("soak.before-probe", verifiedBefore);
                if (!verifiedBefore) throw new IOException("Soak policy or engine changed before probe.");
                var probeContext = new ProbeContext(engine.Generation);
                async Task<(List<string> Messages, Exception? Error)> OneProbe()
                {
                    var messages = new List<string>();
                    try {
                        await ConnectionProbe.CheckObservedAsync(probeContext, ObserveProbe, log: messages.Add);
                        return (messages, null);
                    } catch (Exception ex) { return (messages, ex); }
                }
                // Each probe owns its buffer. Program.Record is called only
                // serially after all bounded probes finish, including failures.
                var probes = await Task.WhenAll(Enumerable.Range(0, concurrency).Select(_ => OneProbe()));
                for (int i = 0; i < probes.Length; i++)
                    foreach (var message in probes[i].Messages)
                        record($"OBSERVE: soak {round} probe={i + 1}: {message}");
                bool verifiedAfter = controller.IsConnectedCandidate();
                UpdateContext("soak.after-probe", verifiedAfter);
                if (!verifiedAfter) throw new IOException("Soak policy or engine changed after probe.");
                var failures = probes.Where(p => p.Error != null).Select(p => p.Error!).ToArray();
                if (failures.Length != 0) throw new AggregateException("One or more soak probes failed.", failures);
                AppendObservation(output, new { Round = round, Stage = "after-probe", ElapsedMs = timer.ElapsedMilliseconds,
                    State = State(settings, engine, controller) });
                record($"PASS: soak round={round}; probes={concurrency}; elapsedMs={timer.ElapsedMilliseconds}; HTTPS and active policy verified.");
                var pause = TimeSpan.FromSeconds(8) - (timer.Elapsed - began);
                var remaining = duration - timer.Elapsed;
                if (pause > remaining) pause = remaining;
                if (pause > TimeSpan.Zero) await Task.Delay(pause);
            }
            File.WriteAllText(Path.Combine(output, "soak-network-complete.json"), NetworkDiagnostics.Capture(settings));
            record($"PASS: production soak completed; rounds={round}; elapsedMs={timer.ElapsedMilliseconds}.");
        } catch (Exception primary) {
            try {
                DiagnosticJournal.Trigger("soak-failure-before-cleanup", new { Round = round,
                    EngineGeneration = engine.Generation, Errors = AppLog.ExceptionCodes(primary) });
            } catch { }
            record($"FAIL: production soak; round={round}; elapsedMs={timer.ElapsedMilliseconds}; errors={AppLog.ExceptionCodes(primary)}.");
            try {
                AppLog.Snapshot("soak.failure-before-cleanup", settings);
                File.WriteAllText(Path.Combine(output, "soak-network-failure.json"), NetworkDiagnostics.Capture(settings));
                File.WriteAllText(Path.Combine(output, "soak-state-failure.json"), JsonSerializer.Serialize(State(settings, engine, controller), Json));
            } catch (Exception ex) { record("FAIL: soak failure snapshot: " + AppLog.ExceptionCodes(ex)); }
            try { await RunFailureControlAsync(helper, output, physicalInterfaceIndex, record, engine.Generation); }
            catch (Exception ex) { record("FAIL: soak failure control: " + AppLog.ExceptionCodes(ex)); }
            // IncidentTest's existing finally revokes active permits, stops its
            // engine, and removes only the exact owned policy under the mutex.
            throw;
        }
    }
}
