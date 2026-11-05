using System.Runtime.InteropServices;
using System.Text.Json;
using System.Xml.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace ProxyBridge;
internal static class SelfTest
{
    static void Require(bool condition) { if (!condition) throw new InvalidOperationException("Assertion failed"); }
    static void Reject(Action action)
    {
        try { action(); } catch (ArgumentException) { return; }
        throw new InvalidOperationException("Invalid input accepted");
    }
    // A deliberately narrow entry point for a separate settings-only test host.
    // It performs local settings I/O only: no Program.Main, engine or WFP calls.
    internal static async Task RunInitialSettingsTestsAsync(Func<string, Func<Task>, Task> test)
    {
        async Task Isolated(string name, Action check)
        {
            await test(name, () => {
                string original = Settings.TestDirectory ?? throw new InvalidOperationException("Settings tests require an isolated test directory");
                Settings.TestDirectory = Path.Combine(original, Guid.NewGuid().ToString("N"));
                try { check(); }
                finally { Settings.TestDirectory = original; }
                return Task.CompletedTask;
            });
        }
        await Isolated("first-run defaults contain no endpoint, credentials or exclusions", () => {
            var defaults = Settings.Default;
            Require(defaults.Host == "" && defaults.Username == "" && defaults.Password == "");
            Require(defaults.ExcludedApplications.Length == 0);
            Require(defaults.Port is >= 1 and <= 65535 && (defaults.Protocol is "http" or "socks"));
            Require(!Directory.Exists(Settings.DataDir));
        });
        await Isolated("loading missing settings returns setup state without persisting a configuration", () => {
            Require(!Directory.Exists(Settings.DataDir));
            var loaded = Settings.Load();
            Require(loaded.Host == "" && loaded.Username == "" && loaded.Password == "");
            Require(loaded.ExcludedApplications.Length == 0);
            Require(loaded.Port == Settings.Default.Port && loaded.Protocol == Settings.Default.Protocol);
            Require(!File.Exists(Path.Combine(Settings.DataDir, "settings.dat")));
            Require(!File.Exists(Path.Combine(Settings.DataDir, "settings.dat.tmp")));
            Reject(loaded.Validate);
        });
        await Isolated("unconfigured defaults reject validation and save without creating settings files", () => {
            var defaults = Settings.Default;
            Reject(defaults.Validate);
            Reject(defaults.Save);
            Require(!File.Exists(Path.Combine(Settings.DataDir, "settings.dat")));
            Require(!File.Exists(Path.Combine(Settings.DataDir, "settings.dat.tmp")));
        });
    }
    public static async Task Run()
    {
        const string testPassword = "QA-only-secret-42";
        var results = new List<string>();
        string output = Path.Combine(AppContext.BaseDirectory, "self-test.txt");
        void Record(string text) { results.Add(text); File.WriteAllLines(output, results); }
        async Task Test(string name, Func<Task> test)
        {
            try { await test(); Record("PASS: " + name); }
            catch (Exception ex) {
                string message = ex.Message;
                if (!string.IsNullOrEmpty(Settings.Default.Password)) message = message.Replace(Settings.Default.Password, "***", StringComparison.Ordinal);
                message = message.Replace(testPassword, "***", StringComparison.Ordinal);
                Record("FAIL: " + name + " (" + ex.GetType().Name + "): " + message);
                Environment.ExitCode = 1;
            }
        }
        var s = new Settings("192.0.2.10", 1080, "qa-user", testPassword, "http");
        string app = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        var excluded = s with { ExcludedApplications = [app] };
        var multiple = s with { ExcludedApplications = [@"C:\Program Files\Mozilla Firefox\firefox.exe", @"C:\Users\Тест\AppData\Local\Yandex Music\Яндекс Музыка.exe"] };
        async Task SettingsTest(string name, Action test)
        {
            await Test(name, () => {
                string original = Settings.TestDirectory ?? throw new InvalidOperationException("Settings tests require an isolated test directory");
                Settings.TestDirectory = Path.Combine(original, Guid.NewGuid().ToString("N"));
                try { test(); }
                finally { Settings.TestDirectory = original; }
                return Task.CompletedTask;
            });
        }
        await RunInitialSettingsTestsAsync(Test);
        await SettingsTest("DPAPI storage roundtrip preserves Unicode exclusions and encrypts credentials", () => {
            multiple.Save();
            var loaded = Settings.Load();
            Require(loaded.Host == multiple.Host && loaded.Port == multiple.Port && loaded.Protocol == multiple.Protocol);
            Require(loaded.Username == multiple.Username && loaded.Password == multiple.Password);
            Require(loaded.ExcludedApplications.SequenceEqual(multiple.ExcludedApplications));
            byte[] bytes = File.ReadAllBytes(Path.Combine(Settings.DataDir, "settings.dat"));
            Require(!System.Text.Encoding.UTF8.GetString(bytes).Contains(s.Password, StringComparison.Ordinal));
            Require(!File.Exists(Path.Combine(Settings.DataDir, "settings.dat.tmp")));
        });
        await SettingsTest("corrupt DPAPI settings fail visibly and remain intact until explicit save", () => {
            Settings.PrepareDirectory();
            string path = Path.Combine(Settings.DataDir, "settings.dat");
            byte[] corrupt = [0, 1, 2, 3, 4, 5];
            File.WriteAllBytes(path, corrupt);
            bool rejected = false;
            try { _ = Settings.Load(); } catch (System.ComponentModel.Win32Exception) { rejected = true; }
            Require(rejected && File.ReadAllBytes(path).SequenceEqual(corrupt));
            multiple.Save();
            Require(Settings.Load().ExcludedApplications.SequenceEqual(multiple.ExcludedApplications));
        });
        await SettingsTest("failed settings replacement preserves last saved data; retry succeeds", () => {
            s.Save();
            string path = Path.Combine(Settings.DataDir, "settings.dat");
            byte[] before = File.ReadAllBytes(path);
            bool rejected = false;
            using (var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                try { multiple.Save(); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { rejected = true; }
            }
            Require(rejected && File.ReadAllBytes(path).SequenceEqual(before));
            Require(Settings.Load().ExcludedApplications.Length == 0);
            multiple.Save();
            Require(Settings.Load().ExcludedApplications.SequenceEqual(multiple.ExcludedApplications));
            Require(!File.Exists(path + ".tmp"));
        });
        await SettingsTest("settings test directories isolate persisted state", () => {
            s.Save();
            string first = Settings.TestDirectory!;
            Settings.TestDirectory = Path.Combine(first, "second");
            Require(Settings.Load().ExcludedApplications.Length == 0);
            multiple.Save();
            Settings.TestDirectory = first;
            Require(Settings.Load().ExcludedApplications.Length == 0);
        });
        await Test("legacy settings default to empty exclusions; JSON roundtrip preserves paths", () => {
            string legacy = JsonSerializer.Serialize(new { s.Host, s.Port, s.Username, s.Password, s.Protocol });
            var loaded = JsonSerializer.Deserialize<Settings>(legacy)!;
            loaded.Validate(); Require(loaded.ExcludedApplications.Length == 0);
            var roundtrip = JsonSerializer.Deserialize<Settings>(JsonSerializer.Serialize(excluded))!;
            roundtrip.Validate(); Require(roundtrip.ExcludedApplications.SequenceEqual(excluded.ExcludedApplications));
            return Task.CompletedTask;
        });
        await Test("invalid endpoints/exclusions rejected; paths normalized and deduplicated", () => {
            foreach (var invalid in new[] { s with { Host = "localhost" }, s with { Host = "::1" }, s with { Port = 0 }, s with { Port = 65536 }, s with { Protocol = "direct" } }) Reject(invalid.Validate);
            foreach (string bad in new[] { "", "firefox.exe", @"C:firefox.exe", @"C:\Apps\firefox.dll", Engine.Executable, Environment.ProcessPath!, @"C:\Other\ProxyBridge.exe" })
                Reject(() => (s with { ExcludedApplications = [bad] }).Validate());
            Reject(() => (s with { ExcludedApplications = null! }).Validate());
            Reject(() => (s with { ExcludedApplications = Enumerable.Range(0, 65).Select(i => $@"C:\Apps\App{i}.exe").ToArray() }).Validate());
            var normalized = s with { ExcludedApplications = [app, app.ToUpperInvariant(), Path.Combine(Path.GetDirectoryName(app)!, ".", "notepad.exe")] };
            Require(normalized.ExcludedApplications.Length == 1);
            return Task.CompletedTask;
        });
        await Test("TUN readiness rejects stale Down and mismatched adapter/address state", () => {
            var v4 = new TunAddress(IPAddress.Parse("172.29.231.1"), 30, DuplicateAddressDetectionState.Preferred);
            var v6 = new TunAddress(IPAddress.Parse("fdfe:dcba:7231::1"), 126, DuplicateAddressDetectionState.Preferred);
            bool Ready(params TunAddress[] addresses) => Guard.IsTunReady(OperationalStatus.Up, "sing-tun Tunnel", (NetworkInterfaceType)53, addresses);
            Require(Ready(v4, v6));
            Require(!Guard.IsTunReady(OperationalStatus.Down, "sing-tun Tunnel", (NetworkInterfaceType)53, []));
            Require(!Guard.IsTunReady(OperationalStatus.Down, "sing-tun Tunnel", (NetworkInterfaceType)53, [v4, v6]));
            Require(!Guard.IsTunReady(OperationalStatus.Up, "Other VPN", (NetworkInterfaceType)53, [v4, v6]));
            Require(!Guard.IsTunReady(OperationalStatus.Up, "sing-tun Tunnel", NetworkInterfaceType.Ethernet, [v4, v6]));
            Require(!Ready(v4));
            Require(!Ready(v4 with { PrefixLength = 24 }, v6));
            Require(!Ready(v4, v6 with { DadState = DuplicateAddressDetectionState.Tentative }));
            Require(!Ready(v4, v6, new TunAddress(IPAddress.Parse("192.168.1.20"), 24, DuplicateAddressDetectionState.Preferred)));
            Require(!Ready(v4, v6, new TunAddress(IPAddress.Parse("169.254.1.20"), 16, DuplicateAddressDetectionState.Preferred)));
            Require(!Ready(v4, v4, v6));
            Require(Ready(v4, v6, new TunAddress(IPAddress.Parse("fe80::1"), 64, DuplicateAddressDetectionState.Preferred)));
            return Task.CompletedTask;
        });
        await ProtectionControllerTests.RunAsync(Test, s);
        await ConnectionProbeTests.RunAsync(Test);
        await Test("logging operation scope survives await and restores parent after exception and disposal", async () => {
            string? original = AppLog.CurrentOperation;
            using (AppLog.BeginOperation("qa-outer")) {
                string? outer = AppLog.CurrentOperation;
                Require(!string.IsNullOrEmpty(outer) && outer != original);
                try {
                    using var inner = AppLog.BeginOperation("qa-inner");
                    string? innerId = AppLog.CurrentOperation;
                    Require(innerId != outer && innerId != null);
                    await Task.Yield();
                    Require(AppLog.CurrentOperation == innerId);
                    throw new IOException("synthetic scope unwind");
                } catch (IOException) { }
                Require(AppLog.CurrentOperation == outer);
                var sibling = AppLog.BeginOperation("qa-idempotent-dispose");
                sibling.Dispose(); sibling.Dispose();
                Require(AppLog.CurrentOperation == outer);
            }
            Require(AppLog.CurrentOperation == original);
        });
        await Test("parallel logging operations inherit parent without leaking sibling correlation", async () => {
            string? original = AppLog.CurrentOperation;
            using (AppLog.BeginOperation("qa-parallel-parent")) {
                string? parent = AppLog.CurrentOperation;
                var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                int entered = 0;
                async Task<string> Child() {
                    Require(AppLog.CurrentOperation == parent);
                    string child;
                    using (AppLog.BeginOperation("qa-parallel-child")) {
                        child = AppLog.CurrentOperation!;
                        Require(child != null && child != parent);
                        if (Interlocked.Increment(ref entered) == 2) ready.SetResult();
                        await ready.Task.WaitAsync(TimeSpan.FromSeconds(5));
                        Require(AppLog.CurrentOperation == child);
                    }
                    Require(AppLog.CurrentOperation == parent);
                    return child!;
                }
                string[] children = await Task.WhenAll(Task.Run(Child), Task.Run(Child));
                Require(children[0] != children[1] && AppLog.CurrentOperation == parent);
            }
            Require(AppLog.CurrentOperation == original);
        });
        await Test("exception diagnostic retains failure codes without messages, URLs or body secrets", () => {
            const string secret = "qa-unregistered-message-token";
            var socket = new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.ConnectionReset);
            var request = new HttpRequestException("https://qa-user:" + secret + "@example.invalid/?token=" + secret,
                socket, HttpStatusCode.BadGateway);
            var aggregate = new AggregateException(secret, request, new IOException("body=" + secret));
            string detail = AppLog.ExceptionCodes(aggregate);
            Require(detail.Contains(nameof(HttpRequestException)) && detail.Contains(nameof(IOException)));
            Require(detail.Contains(nameof(System.Net.Sockets.SocketError.ConnectionReset)) && detail.Contains("10054") && detail.Contains("502"));
            Require(!detail.Contains(secret) && !detail.Contains("qa-user") && !detail.Contains("example.invalid") && !detail.Contains("body="));
            Require(detail.Length < 4096);
            return Task.CompletedTask;
        });
        await Test("local network snapshot is bounded valid JSON with usable native routes and no credentials", () => {
            string snapshot = NetworkDiagnostics.Capture(s);
            Require(!snapshot.Contains(s.Username, StringComparison.Ordinal) && !snapshot.Contains(s.Password, StringComparison.Ordinal));
            Require(System.Text.Encoding.UTF8.GetByteCount(snapshot) <= 48000);
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "network-diagnostics-test.json"), snapshot, new System.Text.UTF8Encoding(false));
            using var doc = JsonDocument.Parse(snapshot);
            var root = doc.RootElement;
            void NoDiagnosticErrors(JsonElement element) {
                if (element.ValueKind == JsonValueKind.Object) {
                    Require(!element.TryGetProperty("error", out _));
                    foreach (var property in element.EnumerateObject()) NoDiagnosticErrors(property.Value);
                } else if (element.ValueKind == JsonValueKind.Array) {
                    foreach (var item in element.EnumerateArray()) NoDiagnosticErrors(item);
                }
            }
            NoDiagnosticErrors(root);
            Require(!root.TryGetProperty("error", out _) && !root.TryGetProperty("interfacesError", out _));
            Require(root.GetProperty("schema").GetInt32() == 1 && root.GetProperty("proxyAddressAvailable").GetBoolean());
            Require(root.GetProperty("interfaces").ValueKind == JsonValueKind.Array);
            var summary = root.GetProperty("routeSummary");
            Require(!summary.TryGetProperty("error", out _) && summary.GetProperty("errors").GetArrayLength() == 0);
            Require(summary.GetProperty("inspected").GetUInt32() <= summary.GetProperty("total").GetUInt32());
            foreach (var route in root.GetProperty("routes").EnumerateArray()) {
                string[] prefix = route.GetProperty("destination").GetString()!.Split('/');
                Require(prefix.Length == 2 && IPAddress.TryParse(prefix[0], out _));
                var address = IPAddress.Parse(prefix[0]);
                Require(int.TryParse(prefix[1], out int bits) && bits >= 0 && bits <= address.GetAddressBytes().Length * 8);
                Require(IPAddress.TryParse(route.GetProperty("nextHop").GetString(), out var nextHop) && nextHop.AddressFamily == address.AddressFamily);
                Require(route.GetProperty("ifIndex").GetUInt32() > 0 && route.GetProperty("interfaceError").ValueKind == JsonValueKind.Null);
                uint metric = route.GetProperty("routeMetric").GetUInt32();
                Require(metric == uint.MaxValue ? route.GetProperty("totalMetric").ValueKind == JsonValueKind.Null
                    : route.GetProperty("totalMetric").GetUInt64() == (ulong)metric + route.GetProperty("interfaceMetric").GetUInt32());
            }
            return Task.CompletedTask;
        });
        using var engine = new Engine();
        foreach (string protocol in new[] { "http", "socks" }) {
            foreach (bool hasExceptions in new[] { false, true }) {
                var config = (hasExceptions ? multiple : s) with { Protocol = protocol };
                await Test($"sing-box {protocol}, exclusions={hasExceptions}: proxy/DNS/default/UDP contract", async () => {
                    await engine.Check(config);
                    using var doc = JsonDocument.Parse(Engine.Configuration(config));
                    var root = doc.RootElement;
                    var outbounds = root.GetProperty("outbounds").EnumerateArray().ToArray();
                    Require(outbounds.Length == (hasExceptions ? 2 : 1));
                    Require(outbounds.Count(x => x.GetProperty("tag").GetString() == "proxy" && x.GetProperty("type").GetString() == protocol) == 1);
                    Require(root.GetProperty("dns").GetProperty("servers")[0].GetProperty("detour").GetString() == "proxy");
                    Require(root.GetProperty("dns").GetProperty("strategy").GetString() == "ipv4_only");
                    var route = root.GetProperty("route");
                    Require(route.GetProperty("final").GetString() == "proxy");
                    var rules = route.GetProperty("rules").EnumerateArray().ToArray();
                    int dns = Array.FindIndex(rules, x => x.GetProperty("action").GetString() == "hijack-dns");
                    int udp = Array.FindIndex(rules, x => x.TryGetProperty("network", out var n) && n.GetString() == "udp" && x.GetProperty("action").GetString() == "reject");
                    Require(dns >= 0 && udp > dns);
                    var directRules = rules.Where(x => x.TryGetProperty("outbound", out var o) && o.GetString() == "direct").ToArray();
                    if (hasExceptions) {
                        Require(outbounds.Count(x => x.GetProperty("type").GetString() == "direct" && x.GetProperty("tag").GetString() == "direct") == 1);
                        Require(directRules.Length == 1);
                        Require(directRules[0].GetProperty("process_path").EnumerateArray().Select(x => x.GetString()).SequenceEqual(config.ExcludedApplications));
                        int direct = Array.FindIndex(rules, x => x.TryGetProperty("outbound", out var o) && o.GetString() == "direct");
                        Require(direct > dns && direct < udp);
                    } else Require(directRules.Length == 0 && outbounds.All(x => x.GetProperty("type").GetString() != "direct"));
                });
            }
        }
        await engine.Stop();
        await Test("Engine check leaves no running tunnel; repeated Stop and Dispose clean runtime", async () => {
            using var cleanup = new Engine();
            await cleanup.Check(multiple);
            Require(File.Exists(Engine.ConfigPath) && !cleanup.Running);
            await cleanup.Stop(); await cleanup.Stop();
            Require(!File.Exists(Engine.ConfigPath) && !cleanup.Running);
            await cleanup.Check(s);
            Require(File.Exists(Engine.ConfigPath));
            cleanup.Dispose(); cleanup.Dispose();
            Require(!File.Exists(Engine.ConfigPath));
        });
        await Test("startup XML: escaped EXE, interactive user, visible unlimited logon task", () => {
            const string sid = "S-1-5-21-100-200-300-1001";
            const string executable = @"C:\Program Files\A&B\ProxyBridge.exe";
            string xml = StartupRegistration.BuildXml(executable, sid);
            Require(StartupRegistration.Matches(xml, executable, sid));
            Require(!StartupRegistration.Matches(xml, executable + ".other", sid));
            Require(!StartupRegistration.Matches(xml, executable, sid + "2"));
            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
            var doc = XDocument.Parse(xml);
            var task = doc.Root!;
            Require(task.Element(ns + "Settings")!.Element(ns + "Hidden")!.Value == "false");
            Require(task.Element(ns + "Settings")!.Element(ns + "ExecutionTimeLimit")!.Value == "PT0S");
            Require(task.Element(ns + "Settings")!.Element(ns + "RunOnlyIfNetworkAvailable")!.Value == "false");
            Require(task.Element(ns + "Triggers")!.Elements().Count() == 1);
            Require(!doc.Descendants().Any(x => x.Name.LocalName.Contains("Password", StringComparison.OrdinalIgnoreCase)));
            var actions = task.Element(ns + "Actions")!;
            actions.Add(new XElement(actions.Elements().Single()));
            Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            doc = XDocument.Parse(xml);
            doc.Descendants(ns + "Arguments").Single().Value = "--recover";
            Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            doc = XDocument.Parse(xml);
            doc.Descendants(ns + "LogonTrigger").Single().Element(ns + "Enabled")!.Value = "false";
            Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            doc = XDocument.Parse(xml);
            doc.Descendants(ns + "ExecutionTimeLimit").Single().Value = "PT1H";
            Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            foreach (var mutation in new[] { ("LogonType", "Password"), ("RunLevel", "LeastPrivilege"), ("Hidden", "true"), ("RunOnlyIfNetworkAvailable", "true"), ("StopIfGoingOnBatteries", "true") }) {
                doc = XDocument.Parse(xml);
                doc.Descendants(ns + mutation.Item1).Single().Value = mutation.Item2;
                Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            }
            doc = XDocument.Parse(xml);
            var triggers = doc.Root!.Element(ns + "Triggers")!;
            triggers.Add(new XElement(triggers.Elements().Single()));
            Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            return Task.CompletedTask;
        });
        await Test("speed formula: decimal Mbit/s and bounded 25 MB workload", () => {
            Require(Math.Abs(ProxySpeedTest.Mbps(25_000_000, TimeSpan.FromSeconds(2)) - 100) < 0.000001);
            Require(Math.Abs(ProxySpeedTest.Mbps(1_000_000, TimeSpan.FromSeconds(8)) - 1) < 0.000001);
            Require(ProxySpeedTest.Mbps(0, TimeSpan.FromSeconds(1)) == 0);
            Require(ProxySpeedTest.DownloadBytes == 25_000_000);
            Require(new Uri(ProxySpeedTest.Endpoint).Scheme == "https");
            return Task.CompletedTask;
        });
        await Test("Windows Task Scheduler validates startup schema without creating a task", () => {
            StartupRegistration.ValidateDefinition();
            return Task.CompletedTask;
        });
        var progress = new SilentProgress();
        await Test("mock speed success: three latency requests and exactly 25 MB downloaded", async () => {
            var handler = new SpeedHandler();
            var result = await ProxySpeedTest.RunAsync(progress, CancellationToken.None, handler);
            Require(handler.Requests == 4 && handler.Probes == 3);
            Require(result.BytesReceived == ProxySpeedTest.DownloadBytes);
            Require(double.IsFinite(result.DownloadMbps) && result.DownloadMbps > 0);
            Require(result.LatencyMs >= 0 && result.Endpoint == ProxySpeedTest.Endpoint);
        });
        await Test("mock speed rejects HTTP failure and truncated download without a result", async () => {
            bool rejected = false;
            try { await ProxySpeedTest.RunAsync(progress, CancellationToken.None, new SpeedHandler(failStatus: true)); }
            catch (HttpRequestException) { rejected = true; }
            Require(rejected);
            rejected = false;
            try { await ProxySpeedTest.RunAsync(progress, CancellationToken.None, new SpeedHandler(shortBody: true)); }
            catch (IOException) { rejected = true; }
            Require(rejected);
        });
        await Test("mock speed caller cancellation during download produces no result", async () => {
            using var cancellation = new CancellationTokenSource();
            var handler = new SpeedHandler(cancelDownload: cancellation);
            bool cancelled = false;
            try { await ProxySpeedTest.RunAsync(progress, cancellation.Token, handler); }
            catch (OperationCanceledException) { cancelled = cancellation.IsCancellationRequested; }
            Require(cancelled && handler.Requests == 4 && handler.Probes == 3);
        });
        await Test("mock speed rejects redirect, content encoding and wrong declared length", async () => {
            foreach (string fault in new[] { "redirect", "encoding", "length" }) {
                var handler = new SpeedHandler(fault: fault);
                bool rejected = false;
                try { await ProxySpeedTest.RunAsync(progress, CancellationToken.None, handler); }
                catch (HttpRequestException) when (fault == "redirect") { rejected = true; }
                catch (IOException) when (fault != "redirect") { rejected = true; }
                Require(rejected && handler.Requests == 4);
            }
        });
        await Test("mock speed pre-cancel sends no request and yields no result", async () => {
            using var before = new CancellationTokenSource();
            before.Cancel();
            var handler = new SpeedHandler();
            bool cancelled = false;
            try { await ProxySpeedTest.RunAsync(progress, before.Token, handler); }
            catch (OperationCanceledException) { cancelled = true; }
            Require(cancelled && handler.Requests == 0);
        });
        await Test("mock speed mid-stream cancellation yields no result after partial download", async () => {
            using var during = new CancellationTokenSource();
            var handler = new SpeedHandler(cancelDuringRead: during);
            bool cancelled = false;
            try { await ProxySpeedTest.RunAsync(progress, during.Token, handler); }
            catch (OperationCanceledException) { cancelled = during.IsCancellationRequested; }
            Require(cancelled && handler.DownloadStream is { BytesRead: > 0 and < ProxySpeedTest.DownloadBytes });
        });
        await Test("WFP dry runs preserve filter count and exact policy matches, no commit", () => {
            string stage = "read initial filter count";
            try {
            uint before = Guard.Status;
            stage = "match initial base policy";
            bool baseMatch = Guard.IsConfigured(s);
            stage = "match initial exclusion policy";
            bool? excludedMatch = File.Exists(app) ? Guard.IsConfigured(excluded) : null;
            bool? stoppedDnsMatch = File.Exists(app) ? Guard.IsConfigured(excluded, allowStoppedDns: true) : null;
            void CheckUnchanged() {
                stage += ": verify unchanged count and policy";
                Require(Guard.Status == before);
                Require(Guard.IsConfigured(s) == baseMatch);
                if (excludedMatch.HasValue) Require(Guard.IsConfigured(excluded) == excludedMatch.Value);
                if (stoppedDnsMatch.HasValue) Require(Guard.IsConfigured(excluded, allowStoppedDns: true) == stoppedDnsMatch.Value);
            }
            stage = "reject invalid port";
            Reject(() => Guard.Configure(s with { Port = 65536 }, dryRun: true)); CheckUnchanged();
            stage = "reject IPv6 proxy endpoint";
            Reject(() => Guard.Configure(s with { Host = "::1" }, dryRun: true)); CheckUnchanged();
            stage = "configure base policy dry run";
            Guard.Configure(s, dryRun: true); CheckUnchanged();
            if (File.Exists(app)) {
                stage = "configure exclusion policy dry run"; Guard.Configure(excluded, dryRun: true); CheckUnchanged();
                stage = "configure stopped DNS exclusion policy dry run"; Guard.Configure(excluded, dryRun: true, allowStoppedDns: true); CheckUnchanged();
            }
            else Record("SKIP: WFP exclusion dry run: System32/notepad.exe missing");
            stage = "enumerate interface GUIDs";
            var nic = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback && Guid.TryParse(n.Id, out _));
            if (nic == null) Record("SKIP: WFP TUN-condition dry run: no interface GUID available");
            else {
                var guid = Guid.Parse(nic.Id);
                stage = "convert interface GUID to LUID";
                Require(ConvertInterfaceGuidToLuid(ref guid, out ulong luid) == 0);
                stage = "match initial TUN policy";
                bool tunMatch = Guard.IsConfigured(s, luid);
                stage = "configure TUN policy dry run";
                Guard.Configure(s, luid, dryRun: true); CheckUnchanged();
                stage = "verify unchanged TUN policy match";
                Require(Guard.IsConfigured(s, luid) == tunMatch);
                if (File.Exists(app)) { stage = "configure TUN exclusion policy dry run"; Guard.Configure(excluded, luid, dryRun: true); CheckUnchanged(); }
            }
            return Task.CompletedTask;
            } catch (Exception ex) { throw new InvalidOperationException("WFP stage: " + stage + "; " + ex.Message, ex); }
        });
        Record("SKIP: real routing, crash/existing flows, DNS/IPv6/UDP, logon and throughput require coordinator-run integration; dry runs do not establish network isolation");
    }
    sealed class SilentProgress : IProgress<string> { public void Report(string value) { } }
    sealed class SpeedHandler(bool failStatus = false, bool shortBody = false, CancellationTokenSource? cancelDownload = null,
        string? fault = null, CancellationTokenSource? cancelDuringRead = null) : HttpMessageHandler
    {
        public int Requests { get; private set; }
        public int Probes { get; private set; }
        public CancellingStream? DownloadStream { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            Require(request.RequestUri!.GetLeftPart(UriPartial.Path) == ProxySpeedTest.Endpoint);
            Require(request.Headers.CacheControl?.NoCache == true && request.Headers.CacheControl.NoStore);
            bool probe = request.RequestUri.Query.StartsWith("?bytes=0&", StringComparison.Ordinal);
            if (probe) Probes++;
            else Require(request.RequestUri.Query.StartsWith("?bytes=" + ProxySpeedTest.DownloadBytes + "&", StringComparison.Ordinal));
            if (!probe && cancelDownload != null) {
                cancelDownload.Cancel();
                cancellationToken.ThrowIfCancellationRequested();
            }
            var response = new HttpResponseMessage(failStatus && !probe ? System.Net.HttpStatusCode.BadGateway : System.Net.HttpStatusCode.OK);
            if (!probe && fault == "redirect") {
                response.StatusCode = System.Net.HttpStatusCode.Redirect;
                response.Headers.Location = new Uri("https://example.invalid/no-follow");
            }
            Stream stream = !probe && cancelDuringRead != null
                ? DownloadStream = new CancellingStream(cancelDuringRead)
                : new MemoryStream(new byte[probe || failStatus || fault != null ? 0 : shortBody ? 128 : ProxySpeedTest.DownloadBytes], writable: false);
            response.Content = new StreamContent(stream);
            // A truncated body can claim the expected length; the reader must
            // detect EOF itself rather than trusting response headers.
            response.Content.Headers.ContentLength = probe ? 0 : ProxySpeedTest.DownloadBytes;
            if (!probe && fault == "length") response.Content.Headers.ContentLength = 123;
            if (!probe && fault == "encoding") response.Content.Headers.ContentEncoding.Add("gzip");
            return Task.FromResult(response);
        }
    }
    sealed class CancellingStream(CancellationTokenSource cancellation) : MemoryStream(new byte[ProxySpeedTest.DownloadBytes], writable: false)
    {
        public int BytesRead { get; private set; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int count = await base.ReadAsync(buffer[..Math.Min(buffer.Length, 1024)], cancellationToken);
            BytesRead += count;
            cancellation.Cancel();
            return count;
        }
    }
    [DllImport("iphlpapi.dll")] static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);
}
