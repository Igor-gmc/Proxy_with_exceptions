using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using ProxyBridge;

internal static class IncidentTest
{
    const string TraceUrl = "https://1.1.1.1/cdn-cgi/trace";
    const string DomainUrl = "https://www.microsoft.com/";
    sealed record ChildResult(bool Dns, bool LiteralHttps, bool DomainHttps, uint DnsStatus, string? Error);

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode, EntryPoint = "DnsQuery_W")]
    static extern uint DnsQuery(string name, ushort type, uint options, IntPtr extra, out IntPtr records, IntPtr reserved);
    [DllImport("dnsapi.dll")]
    static extern void DnsRecordListFree(IntPtr records, int freeType);

    public static bool TryRun(string[] args, out int code)
    {
        if (SoakDiagnostic.TryRun(args, out code))
        {
            return true;
        }

        code = 0;
        if (args.Length == 0 || args[0] != "--incident-probe-child")
        {
            return false;
        }

        if (args.Length != 2 || !Path.IsPathFullyQualified(args[1]) || File.Exists(args[1]))
        { code = 2; return true; }
        try
        {
            var result = RunChild().GetAwaiter().GetResult();
            using var file = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            JsonSerializer.Serialize(file, result);
            code = result.Dns && result.LiteralHttps && result.DomainHttps ? 0 : 1;
        }
        catch { code = 2; }
        return true;
    }

    static async Task<ChildResult> RunChild()
    {
        bool dns = false, literal = false, domain = false;
        uint status = uint.MaxValue;
        var errors = new List<string>();
        try
        {
            // DNS_QUERY_BYPASS_CACHE, A record. Never flush the user's DNS cache.
            status = DnsQuery("www.microsoft.com", 1, 8, IntPtr.Zero, out var records, IntPtr.Zero);
            try
            { dns = status == 0 && records != IntPtr.Zero; }
            finally
            {
                if (records != IntPtr.Zero)
                {
                    DnsRecordListFree(records, 1);
                }
            }
        }
        catch (Exception ex) { errors.Add("DNS:" + SafeError(ex)); }
        try
        { _ = await Egress(); literal = true; }
        catch (Exception ex) { errors.Add("literal HTTPS:" + SafeError(ex)); }
        try
        {
            using var client = Client();
            using var response = await client.GetAsync(DomainUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();
            domain = true;
        }
        catch (Exception ex) { errors.Add("domain HTTPS:" + SafeError(ex)); }
        return new(dns, literal, domain, status, errors.Count == 0 ? null : string.Join("; ", errors));
    }

    static string SafeError(Exception error)
    {
        var parts = new List<string>();
        for (Exception? current = error; current != null; current = current.InnerException)
        {
            parts.Add(current is SocketException socket ? $"SocketException({socket.SocketErrorCode})" : current.GetType().Name);
        }

        return string.Join("->", parts);
    }

    static HttpClient Client(Settings? proxy = null)
    {
        var handler = new HttpClientHandler { UseProxy = proxy != null, AllowAutoRedirect = false, MaxResponseHeadersLength = 16 };
        if (proxy != null)
        {
            handler.Proxy = new WebProxy($"{(proxy.Protocol == "http" ? "http" : "socks5")}://{proxy.Host}:{proxy.Port}")
            {
                Credentials = new NetworkCredential(proxy.Username, proxy.Password)
            };
        }

        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
    }

    static async Task<string> Egress(Settings? proxy = null)
    {
        using var client = Client(proxy);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var response = await client.GetAsync(TraceUrl, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        response.EnsureSuccessStatusCode();
        await response.Content.LoadIntoBufferAsync(4096, deadline.Token);
        string trace = await response.Content.ReadAsStringAsync(deadline.Token);
        string? value = trace.Split('\n').FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal))?[3..].Trim();
        if (!IPAddress.TryParse(value, out var ip))
        {
            throw new IOException("Trace returned no valid address.");
        }

        return ip.ToString(); // Compare only in memory; never put this value in a report.
    }

    static async Task CheckHelper(string helper, string outputFile, Action<string> record, string stage, bool excluded = true)
    {
        if (File.Exists(outputFile))
        {
            throw new IOException("Child report already exists.");
        }

        var info = new ProcessStartInfo(helper)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory
        };
        info.ArgumentList.Add("--incident-probe-child");
        info.ArgumentList.Add(outputFile);
        using var child = new Process { StartInfo = info };
        if (!child.Start())
        {
            throw new IOException("Excluded probe child did not start.");
        }

        try
        { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(45)); }
        catch
        {
            if (!child.HasExited)
            {
                child.Kill(true);
            }

            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            throw;
        }
        if (!File.Exists(outputFile))
        {
            throw new IOException("Excluded probe child returned no fresh report.");
        }

        var result = JsonSerializer.Deserialize<ChildResult>(File.ReadAllText(outputFile)) ?? throw new IOException("Invalid child report.");
        string role = excluded ? "excluded" : "nonexcluded";
        record($"{(result.Dns ? "PASS" : "FAIL")}: {stage}: {role} fresh DNS, status={result.DnsStatus}.");
        if (excluded)
        {
            record($"{(result.LiteralHttps ? "PASS" : "FAIL")}: {stage}: excluded literal IPv4 HTTPS.");
            record($"{(result.DomainHttps ? "PASS" : "FAIL")}: {stage}: excluded domain HTTPS.");
            if (child.ExitCode != 0 || !result.Dns || !result.LiteralHttps || !result.DomainHttps)
            {
                throw new IOException("Excluded child failed: " + (result.Error ?? "DNS lookup failed"));
            }
        }
        else
        {
            // Failed HTTPS alone cannot establish WFP denial; CheckDenied
            // separately requires Windows' explicit SocketAccessDenied result.
            record($"OBSERVE: {stage}: nonexcluded HTTPS literal={result.LiteralHttps}, domain={result.DomainHttps}; TCP denial checked separately.");
            if (child.ExitCode != 1 || !result.Dns || result.LiteralHttps || result.DomainHttps)
            {
                throw new IOException("Nonexcluded child did not have DNS-only access.");
            }
        }
    }

    static async Task CheckDenied(Action<string> record)
    {
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        try
        { await tcp.ConnectAsync(IPAddress.Parse("1.1.1.1"), 443, deadline.Token); }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
        {
            record("PASS: stopped protection explicitly denies nonexcluded TCP with SocketAccessDenied.");
            return;
        }
        catch (SocketException ex)
        {
            record("SKIP: nonexcluded TCP failed ambiguously (" + ex.SocketErrorCode + "); denial is not proven.");
            return;
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            record("SKIP: nonexcluded TCP timed out; denial is not proven.");
            return;
        }
        throw new IOException("FAIL: nonexcluded direct TCP connected while stopped protection was active.");
    }

    static void Require(ProtectionOutcome result, string stage)
    {
        if (!result.Succeeded)
        {
            throw new AggregateException(stage + " failed.", result.Errors);
        }
    }

    // Program holds its application mutex continuously before entering this
    // method. Only root runs it after explicit VPN-off confirmation.
    public static async Task RunAsync(Settings saved, string output, Action<string> record, string? diagnosticStack = null,
        int soakSeconds = 0, int physicalInterfaceIndex = 0, int soakConcurrency = 1)
    {
        if (diagnosticStack != null && diagnosticStack is not ("mixed" or "gvisor" or "system"))
        {
            throw new ArgumentException("Unsupported diagnostic stack.");
        }

        if (soakSeconds != 0 && (soakSeconds is < 60 or > 900 || physicalInterfaceIndex is <= 0 or > 0x00FFFFFF))
        {
            throw new ArgumentException("Soak requires 60..900 seconds and a physical IPv4 interface index.");
        }

        if (soakConcurrency is < 1 or > 8)
        {
            throw new ArgumentOutOfRangeException(nameof(soakConcurrency));
        }

        saved.Validate();
        AppLog.RegisterSecret(saved.Password);
        var adapters = NetworkInterface.GetAllNetworkInterfaces();
        if (Guard.Status != 0 || adapters.Any(n => n.Name.Equals("ProxyBridge-TUN", StringComparison.OrdinalIgnoreCase)))
        {
            throw new IOException("Existing protection or TUN: incident test refused.");
        }

        var engines = Process.GetProcessesByName("sing-box");
        try
        {
            if (engines.Length != 0)
            {
                throw new IOException("Existing sing-box: incident test refused.");
            }
        }
        finally
        {
            foreach (var process in engines)
            {
                process.Dispose();
            }
        }
        if (adapters.Any(n => n.OperationalStatus == OperationalStatus.Up &&
            (n.Description.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase) || n.Name.Contains("hidemy.name", StringComparison.OrdinalIgnoreCase))))
        {
            throw new IOException("Active OpenVPN: incident test refused.");
        }

        string parent = Environment.ProcessPath ?? throw new IOException("Missing integration apphost.");
        if (saved.ExcludedApplications.Contains(parent, StringComparer.OrdinalIgnoreCase))
        {
            throw new IOException("Integration parent is already excluded: incident test refused.");
        }

        string helper = Path.Combine(AppContext.BaseDirectory, "ExcludedProbe.exe");
        if (File.Exists(helper))
        {
            throw new IOException("ExcludedProbe.exe already exists; refusing to overwrite.");
        }

        output = Path.GetFullPath(output);
        Directory.CreateDirectory(output);
        var settings = saved with { ExcludedApplications = saved.ExcludedApplications.Append(helper).ToArray() };
        settings.Validate();
        File.Copy(parent, helper, false);
        bool touched = false;
        var shapes = new HashSet<(ulong Luid, bool Dns)>();
        using var engine = new Engine();
        object logLock = new();
        engine.Log += line =>
        {
            lock (logLock)
            {
                File.AppendAllText(Path.Combine(output, "engine-output.txt"), AppLog.Redact(line, saved.Password) + Environment.NewLine);
            }
        };
        bool MatchesOurs()
        {
            if (!touched)
            {
                return false;
            }

            foreach (var shape in shapes)
            {
                if (Guard.IsConfigured(settings, shape.Luid, shape.Dns))
                {
                    return true;
                }
            }

            return false;
        }
        void RemoveOwned()
        {
            if (Guard.Status == 0)
            {
                return;
            }

            if (!MatchesOurs())
            {
                throw new IOException("Unexpected policy: automatic removal refused; protection retained.");
            }

            Guard.Remove();
        }
        void Configure(Settings next, ulong luid, bool dns)
        {
            if (next != settings)
            {
                throw new IOException("Unexpected test settings.");
            }

            if (Guard.Status != 0 && !MatchesOurs())
            {
                throw new IOException("Unexpected existing policy: test configuration refused.");
            }
            // Active configure may install its strict baseline before failing.
            shapes.Add((0, false));
            shapes.Add((luid, dns));
            touched = true;
            Guard.Configure(settings, luid, allowStoppedDns: dns);
        }
        var controller = new ProtectionController(settings, new ProtectionOperations(
            () => Guard.Status, () => engine.Running, Configure,
            (s, luid, dns) => Guard.IsConfigured(s, luid, dns), engine.Stop, RemoveOwned, Guard.Deactivate));
        // Fresh integration process: all new evidence stays with this run.
        // The child loads saved settings independently; credentials never enter argv.
        Settings.TestDirectory = Path.Combine(output, "diagnostic-data");
        DiagnosticJournal.Start();
        using var activity = new ActivityMonitor();
        void ObserveContext(string stage, bool? verified) => DiagnosticJournal.UpdateContext(new(
            settings.Host, settings.Port, settings.Protocol, engine.ProcessId, engine.Generation,
            controller.ActiveLuid, controller.ProtectionRequired, controller.ConnectWanted, verified,
            DateTimeOffset.UtcNow, stage, engine.ProcessStartedUtc));
        engine.ObservedLog += observation => AppLog.WriteAt(observation.EventTime, observation.MonoTicks,
            "sing-box: " + observation.Message);
        string? direct = null;
        Exception? primaryError = null;
        bool released = false;
        try
        {
            await activity.StartAsync();
            ObserveContext("integration.baseline", null);
            direct = await Egress();
            string proxy = await Egress(saved);
            if (direct == proxy)
            {
                throw new IOException("Direct and proxy baselines are indistinguishable.");
            }

            record("PASS: direct and explicit proxy HTTPS baselines succeed and have different egress addresses (values withheld).");
            await CheckHelper(helper, Path.Combine(output, "child-baseline.json"), record, "baseline");
            if (soakSeconds > 0)
            {
                await SoakDiagnostic.RunBaselineControlAsync(helper, output, physicalInterfaceIndex, record);
            }

            async Task Connect(string stage)
            {
                controller.RequestConnect();
                Require(await controller.RearmAsync(), stage + " preparation");
                ObserveContext("integration.strict-preparation", true);
                if (controller.StoppedDnsAllowed || !Guard.IsConfigured(settings, 0, false))
                {
                    throw new IOException("Strict preconnect policy was not verified.");
                }

                record("PASS: " + stage + ": strict preparation policy has no stopped DNS allowance.");
                await engine.Check(settings);
                if (diagnosticStack != null)
                {
                    // Test-only controlled variable. Credentials remain in the
                    // existing protected runtime file and never enter argv/logs.
                    var config = JsonNode.Parse(File.ReadAllText(Engine.ConfigPath))!;
                    config["inbounds"]![0]!["stack"] = diagnosticStack;
                    config["log"]!["level"] = "info";
                    File.WriteAllText(Engine.ConfigPath, config.ToJsonString());
                    record("OBSERVE: diagnostic TUN stack=" + diagnosticStack + "; production Guard/settings unchanged.");
                }
                engine.Start();
                ulong luid = 0;
                for (int i = 0; i < 60 && engine.Running; i++)
                {
                    await Task.Delay(250);
                    luid = Guard.TunLuid();
                    if (luid != 0)
                    {
                        break;
                    }
                }
                if (luid == 0 || !engine.Running)
                {
                    throw new IOException("TUN readiness failed.");
                }

                controller.ConfigureActive(luid);
                ObserveContext("integration.active", controller.IsConnectedCandidate());
                await ConnectionProbe.CheckObservedAsync(new(engine.Generation), observation =>
                {
                    DiagnosticJournal.Record("probe.phase", observation, observation.EventTime, observation.MonoTicks);
                    if (observation.Outcome is ProbeOutcome.Failed or ProbeOutcome.TimedOut)
                    {
                        DiagnosticJournal.Trigger("integration.probe-error", observation);
                    }
                }, log: message => record("OBSERVE: " + message));
                if (!controller.IsConnectedCandidate() || controller.StoppedDnsAllowed)
                {
                    throw new IOException("Connected policy was not verified.");
                }

                if (await Egress() != proxy)
                {
                    throw new IOException("Protected TUN egress differs from explicit proxy baseline.");
                }

                record("PASS: " + stage + ": production TUN health and proxy egress verified.");
                ObserveContext("integration.connected", true);
            }
            await Connect("connect");
            if (soakSeconds > 0)
            {
                await SoakDiagnostic.RunAsync(settings, engine, controller, helper, output, record, soakSeconds, physicalInterfaceIndex, soakConcurrency);
            }

            if (diagnosticStack != null || soakSeconds > 0)
            {
                Require(await controller.ReleaseAsync(), "diagnostic release");
                if (Guard.Status != 0 || engine.Running || await Egress() != direct)
                {
                    throw new IOException("Diagnostic release did not restore direct baseline.");
                }

                released = true;
                record("PASS: diagnostic release restored the original direct baseline and zero owned filters.");
                return;
            }
            controller.RequestBlock();
            Require(await controller.RearmAsync(), "stop and block");
            if (!controller.StoppedDnsAllowed || !Guard.IsConfigured(settings, 0, true) || engine.Running)
            {
                throw new IOException("Stopped DNS policy was not verified.");
            }

            record("PASS: stop and block stops engine and verifies stopped DNS policy.");
            await CheckHelper(helper, Path.Combine(output, "child-blocked.json"), record, "blocked");
            await CheckHelper(parent, Path.Combine(output, "child-nonexcluded-blocked.json"), record, "blocked", excluded: false);
            await CheckDenied(record);
            await Connect("reconnect");
            Require(await controller.ReleaseAsync(), "release");
            if (Guard.Status != 0 || engine.Running || await Egress() != direct)
            {
                throw new IOException("Release did not restore the direct baseline.");
            }

            released = true;
            record("PASS: release stops engine, removes owned filters and restores direct egress.");
            record("SKIP: real saved applications, IPv6/UDP leaks and process crashes are outside this incident regression.");
        }
        catch (Exception ex)
        {
            primaryError = ex;
            DiagnosticJournal.Trigger("integration.failure-before-cleanup", new { error = AppLog.ExceptionCodes(ex) });
            try
            {
                if (soakSeconds > 0 && engine.Running && controller.IsConnectedCandidate() &&
                    !File.Exists(Path.Combine(output, "soak-failure-control.json")))
                {
                    await SoakDiagnostic.RunFailureControlAsync(helper, output, physicalInterfaceIndex, record, engine.Generation);
                }
            }
            catch (Exception controlError) { record("FAIL: early failure phase control: " + AppLog.ExceptionCodes(controlError)); }
            throw;
        }
        finally
        {
            var cleanupErrors = new List<Exception>();
            if (touched)
            {
                try
                { Guard.Deactivate(); }
                catch (Exception ex) { cleanupErrors.Add(ex); }
            }
            try
            { await engine.Stop(); }
            catch (Exception ex) { cleanupErrors.Add(ex); }
            if (touched && cleanupErrors.Count == 0)
            {
                try
                {
                    RemoveOwned();
                    if (Guard.Status != 0)
                    {
                        throw new IOException("Owned filters remain after cleanup.");
                    }

                    record("PASS: incident cleanup verified zero filters under the uninterrupted application mutex.");
                    if (!released && direct != null)
                    {
                        if (await Egress() != direct)
                        {
                            throw new IOException("Cleanup did not restore the direct egress baseline.");
                        }

                        record("PASS: incident cleanup restored the original direct egress baseline.");
                    }
                }
                catch (Exception ex) { cleanupErrors.Add(ex); }
            }
            try
            { File.Delete(helper); }
            catch (Exception ex) { cleanupErrors.Add(ex); }
            await activity.StopAsync();
            await DiagnosticJournal.StopAsync();
            await AppLog.StopAsync();
            foreach (var error in cleanupErrors)
            {
                record("FAIL: incident cleanup: " + AppLog.Redact(error.Message, saved.Password));
            }

            if (cleanupErrors.Count != 0)
            {
                if (primaryError != null)
                {
                    cleanupErrors.Insert(0, primaryError);
                }

                throw new AggregateException("Incident cleanup incomplete; no unknown policy was removed.", cleanupErrors);
            }
        }
    }
}
