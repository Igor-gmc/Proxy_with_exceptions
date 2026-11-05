using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using ProxyBridge;

internal static class Program
{
    const string TraceUrl = "https://1.1.1.1/cdn-cgi/trace";
    const string Firefox = @"C:\Program Files\Mozilla Firefox\firefox.exe";
    static readonly List<string> Results = [];
    static string output = "";
    static Settings? previous, expected;
    static ulong previousLuid, expectedLuid;
    static bool touched;
    static int exitCode;
    [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl)] static extern IntPtr CreateEngineJob();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);

    [STAThread]
    static int Main(string[] args)
    {
        if (EngineControlCommand.TryRun(args, out int controlExitCode))
        {
            return controlExitCode;
        }

        if (ActivityCaptureTest.TryRun(args, out int activityChildExit))
        {
            return activityChildExit;
        }

        if (IsolatedTunDiagnostic.TryRun(args, out int monitorChildExitCode))
        {
            return monitorChildExitCode;
        }

        if (IncidentTest.TryRun(args, out int incidentChildExitCode))
        {
            return incidentChildExitCode;
        }
        // Acquired and released on this synchronous thread. It stays owned
        // across all async checks and cleanup, preventing a new app session.
        using var mutex = new Mutex(false, @"Global\ProxyBridge-8CBA1041");
        bool owned;
        try
        { owned = mutex.WaitOne(0); }
        catch (AbandonedMutexException) { owned = true; }
        if (!owned)
        { Console.Error.WriteLine("Application active; integration test refused."); return 2; }
        try
        {
            if (args.Length == 2 && args[0] == "--diagnostic-capture-test")
            {
                output = Path.GetFullPath(args[1]);
                if (Directory.Exists(output))
                {
                    throw new IOException("Diagnostic output directory must be new.");
                }

                Directory.CreateDirectory(output);
                try
                { DiagnosticCaptureTest.RunAsync(output, Record).GetAwaiter().GetResult(); }
                catch (Exception ex) { Record("FAIL: diagnostic capture: " + SafeErrorChain(ex)); return 1; }
                return Results.Any(r => r.StartsWith("FAIL:", StringComparison.Ordinal)) ? 1 : 0;
            }
            if (args.Length == 2 && args[0] == "--activity-test")
            {
                output = Path.GetFullPath(args[1]);
                if (Directory.Exists(output))
                {
                    throw new IOException("Activity output directory must be new.");
                }

                Directory.CreateDirectory(output);
                try
                { ActivityCaptureTest.RunAsync(output, Record).GetAwaiter().GetResult(); }
                catch (Exception ex) { Record("FAIL: activity capture: " + SafeErrorChain(ex)); Record("OBSERVE: " + ex.Message); return 1; }
                return 0;
            }
            if (args.Length == 5 && args[0] == "--production-load" &&
                int.TryParse(args[1], out int loadSeconds) && loadSeconds is >= 60 and <= 900 &&
                int.TryParse(args[2], out int loadInterface) && loadInterface is > 0 and <= 0x00FFFFFF &&
                int.TryParse(args[3], out int loadConcurrency) && loadConcurrency is >= 1 and <= 8)
            {
                output = Path.GetFullPath(args[4]);
                if (Directory.Exists(output))
                {
                    throw new IOException("Load output directory must be new.");
                }

                Directory.CreateDirectory(output);
                BundledAssets.Prepare();
                NativeLibrary.SetDllImportResolver(typeof(Program).Assembly, (name, _, _) => name == "ProxyGuard.dll"
                    ? NativeLibrary.Load(Path.Combine(BundledAssets.DirectoryPath, name)) : IntPtr.Zero);
                try
                {
                    IncidentTest.RunAsync(ReadDiagnosticSettings(), output, Record,
                        null, loadSeconds, loadInterface, loadConcurrency).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    Record("FAIL: production load: " + SafeErrorChain(ex));
                    Record("OBSERVE: failure location: " + ex.StackTrace);
                    return 1;
                }
                return 0;
            }
            if (args.Length is 4 or 5 && args[0] == "--production-soak" &&
                int.TryParse(args[1], out int soakSeconds) && soakSeconds is >= 60 and <= 900 &&
                int.TryParse(args[2], out int soakInterface) && soakInterface is > 0 and <= 0x00FFFFFF &&
                (args.Length == 4 || args[4] is "mixed" or "gvisor" or "system"))
            {
                output = Path.GetFullPath(args[3]);
                if (Directory.Exists(output))
                {
                    throw new IOException("Soak output directory must be new.");
                }

                Directory.CreateDirectory(output);
                BundledAssets.Prepare();
                NativeLibrary.SetDllImportResolver(typeof(Program).Assembly, (name, _, _) => name == "ProxyGuard.dll"
                    ? NativeLibrary.Load(Path.Combine(BundledAssets.DirectoryPath, name)) : IntPtr.Zero);
                try
                {
                    IncidentTest.RunAsync(ReadDiagnosticSettings(), output, Record,
                        args.Length == 5 ? args[4] : null, soakSeconds, soakInterface).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    Record("FAIL: production soak: " + SafeErrorChain(ex));
                    return 1;
                }
                return 0;
            }
            if (args.Length == 4 && args[0] is "--isolated-tun" or "--isolated-tun-scoped" or "--isolated-tun-engine-guard" or "--isolated-tun-client-guard" or "--isolated-tun-connect-guard" or "--isolated-tun-receive-guard" or "--isolated-tun-reauth-guard" or "--isolated-tun-soak" && args[1] is "mixed" or "gvisor" && int.TryParse(args[2], out int isolatedInterface) && isolatedInterface > 0)
            {
                output = Path.GetFullPath(args[3]);
                if (Directory.Exists(output))
                {
                    throw new IOException("Diagnostic output directory must be new.");
                }

                Directory.CreateDirectory(output);
                BundledAssets.Prepare();
                uint blockMask = args[0] == "--isolated-tun-engine-guard" ? 1u : args[0] is "--isolated-tun-client-guard" or "--isolated-tun-connect-guard" or "--isolated-tun-receive-guard" ? 2u : 3u;
                uint layerMask = args[0] == "--isolated-tun-connect-guard" ? 3u : args[0] == "--isolated-tun-receive-guard" ? 12u : 15u;
                try
                { IsolatedTunDiagnostic.RunAsync(ReadDiagnosticSettings(), args[1], isolatedInterface, output, Record, scopedGuard: args[0] != "--isolated-tun", blockAppMask: blockMask, blockLayerMask: layerMask, allowTunReturn: args[0] is "--isolated-tun-reauth-guard" or "--isolated-tun-soak", sustained: args[0] == "--isolated-tun-soak").GetAwaiter().GetResult(); }
                catch (Exception ex)
                {
                    Record("FAIL: isolated TUN diagnostic: " + SafeErrorChain(ex));
                    Record("OBSERVE: failure location: " + ex.StackTrace);
                    return 1;
                }
                return 0;
            }
            if (args.Length == 3 && args[0] == "--proxy-destination-diagnostic" &&
                int.TryParse(args[1], out int destinationInterface) && destinationInterface is > 0 and <= 0x00FFFFFF)
            {
                output = Path.GetFullPath(args[2]);
                if (Directory.Exists(output))
                {
                    throw new IOException("Destination output directory must be new.");
                }

                Directory.CreateDirectory(output);
                try
                { ProxyDestinationDiagnostic.RunAsync(ReadDiagnosticSettings(), destinationInterface, output, Record).GetAwaiter().GetResult(); }
                catch (Exception ex) { Record("FAIL: proxy destination diagnostic: " + SafeErrorChain(ex)); return 1; }
                return Results.Any(r => r.StartsWith("FAIL:", StringComparison.Ordinal)) ? 1 : 0;
            }
            if (args.Length == 3 && args[0] == "--connection-path-diagnostic" && int.TryParse(args[1], out int interfaceIndex) && interfaceIndex > 0)
            {
                output = Path.GetFullPath(args[2]);
                if (Directory.Exists(output))
                {
                    throw new IOException("Diagnostic output directory must be new.");
                }

                Directory.CreateDirectory(output);
                try
                { ConnectionPathDiagnostic.RunAsync(ReadDiagnosticSettings(), interfaceIndex, Record).GetAwaiter().GetResult(); }
                catch (Exception ex) { Record("FAIL: connection path diagnostic: " + SafeErrorChain(ex)); return 1; }
                return 0;
            }
            if (args.Length == 3 && args[0] == "--tun-diagnostic" && args[2] is "mixed" or "gvisor" or "system")
            {
                output = Path.GetFullPath(args[1]);
                if (Directory.Exists(output))
                {
                    throw new IOException("Diagnostic output directory must be new.");
                }

                Directory.CreateDirectory(output);
                BundledAssets.Prepare();
                NativeLibrary.SetDllImportResolver(typeof(Program).Assembly, (name, _, _) => name == "ProxyGuard.dll"
                    ? NativeLibrary.Load(Path.Combine(BundledAssets.DirectoryPath, name)) : IntPtr.Zero);
                try
                { IncidentTest.RunAsync(ReadDiagnosticSettings(), output, Record, args[2]).GetAwaiter().GetResult(); }
                catch (Exception ex)
                {
                    Record("FAIL: TUN diagnostic: " + SafeErrorChain(ex));
                    return 1;
                }
                return 0;
            }
            if (args.Length == 2 && args[0] == "--incident-test")
            {
                output = Path.GetFullPath(args[1]);
                if (Directory.Exists(output))
                {
                    throw new IOException("Incident output directory must be new.");
                }

                Directory.CreateDirectory(output);
                BundledAssets.Prepare();
                NativeLibrary.SetDllImportResolver(typeof(Program).Assembly, (name, _, _) => name == "ProxyGuard.dll"
                    ? NativeLibrary.Load(Path.Combine(BundledAssets.DirectoryPath, name)) : IntPtr.Zero);
                try
                { IncidentTest.RunAsync(ReadDiagnosticSettings(), output, Record).GetAwaiter().GetResult(); }
                catch (Exception ex)
                {
                    Record("FAIL: incident regression: " + SafeErrorChain(ex));
                    return 1;
                }
                return 0;
            }
            if (args.Length == 1 && args[0] == "--proxy-diagnostic")
            {
                output = Path.Combine(AppContext.BaseDirectory, "proxy-diagnostic-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));
                Directory.CreateDirectory(output);
                try
                { DiagnoseProxy().GetAwaiter().GetResult(); }
                catch (Exception ex)
                {
                    Record("FAIL: diagnostic setup: " + SafeErrorChain(ex));
                    return 1;
                }
                return 0;
            }
            if (args.Length == 1 && args[0] == "--engine-stop-test")
            {
                output = Path.Combine(AppContext.BaseDirectory, "engine-stop-test-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));
                Directory.CreateDirectory(output);
                BundledAssets.Prepare();
                TestEngineStop().GetAwaiter().GetResult();
                return 0;
            }
            if (args.Length == 1 && args[0] == "--inspect-tun")
            {
                BundledAssets.Prepare();
                var adapters = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.Name == "ProxyBridge-TUN")
                    .Select(n => new
                    {
                        n.Name,
                        n.Id,
                        n.Description,
                        Status = n.OperationalStatus.ToString(),
                        Type = n.NetworkInterfaceType.ToString(),
                        Addresses = n.GetIPProperties().UnicastAddresses.Select(a => new
                        {
                            Address = a.Address.ToString(),
                            a.PrefixLength,
                            DadState = a.DuplicateAddressDetectionState.ToString()
                        }).ToArray()
                    }).ToArray();
                var observation = new { FilterCount = Guard.Status, DiscoveredLuid = Guard.TunLuid(), Adapters = adapters };
                File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "tun-inspection.json"), JsonSerializer.Serialize(observation, new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            if (args.Length > 1 && args[0] == "--save-exclusions")
            {
                // Separate, explicitly requested configuration action. No engine,
                // filters, routes or test are started from this branch.
                var saved = Settings.Load();
                var paths = Settings.NormalizeExcludedApplications(saved.ExcludedApplications.Concat(args.Skip(1)));
                (saved with { ExcludedApplications = paths }).Save();
                var verified = Settings.Load();
                if (!verified.ExcludedApplications.SequenceEqual(paths))
                {
                    throw new IOException("Saved exclusions did not verify.");
                }

                File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "saved-exclusions.json"), JsonSerializer.Serialize(paths, new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            if (args.Length is < 1 or > 2 || args.Length == 2 && args[1] != "--baseline-only")
            {
                throw new ArgumentException("Specify a new output directory and optional --baseline-only.");
            }

            string requestedOutput = Path.GetFullPath(args[0]);
            if (Directory.Exists(requestedOutput))
            {
                throw new IOException("Output directory must be new.");
            }

            Directory.CreateDirectory(requestedOutput);
            output = requestedOutput;
            BundledAssets.Prepare();
            // Native exports are resolved from the exact prepared payload.
            NativeLibrary.SetDllImportResolver(typeof(Program).Assembly, (name, _, _) => name == "ProxyGuard.dll"
                ? NativeLibrary.Load(Path.Combine(BundledAssets.DirectoryPath, name)) : IntPtr.Zero);
            Run(args.Contains("--baseline-only")).GetAwaiter().GetResult();
        }
        catch (Exception ex) { Record("FAIL: harness: " + ex.GetType().Name + " " + Redact(ex.Message)); exitCode = 1; }
        finally { mutex.ReleaseMutex(); }
        return exitCode;
    }

    [StructLayout(LayoutKind.Sequential)] struct DiagnosticBlob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true)]
    static extern bool CryptUnprotectData(ref DiagnosticBlob input,
        IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out DiagnosticBlob output);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);

    internal static Settings ReadDiagnosticSettings()
    {
        // Settings.Load also prepares directory ACLs. Diagnostics only read an
        // existing encrypted file; never create settings or modify those ACLs.
        byte[] encrypted = File.ReadAllBytes(Path.Combine(Settings.DataDir, "settings.dat"));
        var input = new DiagnosticBlob { Size = encrypted.Length, Data = Marshal.AllocHGlobal(encrypted.Length) };
        try
        {
            Marshal.Copy(encrypted, 0, input.Data, encrypted.Length);
            if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out var clear))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            byte[] bytes = new byte[clear.Size];
            try
            {
                Marshal.Copy(clear.Data, bytes, 0, bytes.Length);
                var settings = JsonSerializer.Deserialize<Settings>(bytes) ?? throw new InvalidDataException();
                settings.Validate();
                return settings;
            }
            finally
            {
                Array.Clear(bytes);
                Marshal.Copy(bytes, 0, clear.Data, bytes.Length);
                LocalFree(clear.Data);
            }
        }
        finally { Marshal.FreeHGlobal(input.Data); }
    }

    static string SafeErrorChain(Exception error)
    {
        // Messages can contain a proxy URI or echoed credential. Report only
        // types and numeric/socket codes, never server data or request bodies.
        var details = new List<string>();
        for (Exception? current = error; current != null; current = current.InnerException)
        {
            string detail = current.GetType().Name;
            if (current is SocketException socket)
            {
                detail += "(" + socket.SocketErrorCode + ")";
            }

            if (current is System.ComponentModel.Win32Exception win32)
            {
                detail += "[" + win32.NativeErrorCode + "]";
            }

            details.Add(detail);
        }
        return string.Join(" -> ", details);
    }

    static async Task DiagnoseProxy()
    {
        var settings = ReadDiagnosticSettings();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(100));
        string[] destinations = ["https://1.1.1.1/cdn-cgi/trace", "https://www.cloudflare.com/cdn-cgi/trace",
            "https://api.ipify.org", "https://www.microsoft.com/"];
        foreach (string protocol in new[] { "http", "socks5" })
        {
            foreach (string destination in destinations)
            {
                if (deadline.IsCancellationRequested)
                {
                    Record($"SKIP: {protocol} {destination}: overall deadline");
                    continue;
                }
                using var handler = new HttpClientHandler
                {
                    UseProxy = true,
                    AllowAutoRedirect = false,
                    Proxy = new WebProxy($"{protocol}://{settings.Host}:{settings.Port}")
                    {
                        Credentials = new NetworkCredential(settings.Username, settings.Password)
                    }
                };
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
                try
                {
                    using var response = await client.GetAsync(destination, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
                    Record($"{(response.IsSuccessStatusCode ? "PASS" : "FAIL")}: {protocol} {destination}: HTTP {(int)response.StatusCode}, TLS completed");
                }
                catch (Exception ex)
                {
                    Record($"FAIL: {protocol} {destination}: {SafeErrorChain(ex)}");
                }
            }
        }
        Record("OBSERVE: diagnostic completed; no TUN, WFP, routes, settings or certificate validation changes.");
    }

    static async Task TestEngineStop()
    {
        // Empty inbounds: no TUN, listening socket, route, DNS or WFP changes.
        if (Process.GetProcessesByName("sing-box").Length != 0)
        {
            throw new IOException("An existing sing-box process makes this test unsafe to attribute.");
        }

        using var engine = new Engine();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var lines = new System.Collections.Concurrent.ConcurrentQueue<string>();
        engine.Log += line =>
        {
            lines.Enqueue(line);
            if (line.Contains("sing-box started", StringComparison.Ordinal))
            {
                ready.TrySetResult();
            }
        };
        RuntimeStorage.Prepare();
        File.WriteAllText(Engine.ConfigPath, """
            {"log":{"level":"info","disabled":false},"inbounds":[],"outbounds":[]}
            """);
        try
        {
            engine.Start();
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if (!engine.Running)
            {
                throw new IOException("Engine exited before the stop request.");
            }

            await engine.Stop();
            if (engine.Running || engine.LastStopForced)
            {
                throw new IOException("Normal stop did not complete gracefully.");
            }

            if (!lines.Any(line => line.StartsWith("Штатная остановка движка:", StringComparison.Ordinal)) ||
                !lines.Any(line => line.EndsWith("код 0, принудительно=False.", StringComparison.Ordinal)) ||
                lines.Any(line => line.Contains("Помощник штатной остановки вернул код", StringComparison.Ordinal) ||
                    line.Contains("Штатная остановка не завершена:", StringComparison.Ordinal)))
            {
                throw new IOException("Graceful request and zero exit code were not both confirmed.");
            }

            Record("PASS: actual sing-box with empty inbounds started and stopped gracefully through production Engine and signal helper");
            if (File.Exists(Engine.ConfigPath))
            {
                throw new IOException("Runtime configuration remained after Stop.");
            }

            await engine.Stop();
            Record("PASS: repeated Stop succeeds and runtime configuration is removed");
        }
        finally
        {
            if (engine.Running)
            {
                await engine.Stop();
            }

            File.WriteAllLines(Path.Combine(output, "engine-output.txt"), lines);
        }
    }

    static void Record(string message)
    {
        lock (Results)
        {
            Results.Add(message);
            Console.WriteLine(message);
            if (Directory.Exists(output))
            {
                File.WriteAllLines(Path.Combine(output, "integration-test.txt"), Results);
            }
        }
    }
    static string Redact(string text)
    {
        foreach (var s in new[] { expected, previous, Settings.Default })
        {
            if (!string.IsNullOrEmpty(s?.Password))
            {
                text = text.Replace(s.Password, "***", StringComparison.Ordinal);
            }
        }

        return text;
    }
    static void Configure(Settings settings, ulong luid = 0)
    {
        previous = expected;
        previousLuid = expectedLuid;
        expected = settings;
        expectedLuid = luid;
        touched = true; // Covers commit success followed by an observation failure.
        Guard.Configure(settings, luid);
        if (!Guard.IsConfigured(settings, luid))
        {
            throw new IOException("Policy verification failed.");
        }
    }
    static async Task<string> Egress(Settings? proxy = null)
    {
        var handler = new HttpClientHandler { UseProxy = proxy != null, AllowAutoRedirect = false };
        if (proxy != null)
        {
            handler.Proxy = new WebProxy($"{(proxy.Protocol == "http" ? "http" : "socks5")}://{proxy.Host}:{proxy.Port}")
            {
                Credentials = new NetworkCredential(proxy.Username, proxy.Password)
            };
        }

        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(12) };
        var trace = await client.GetStringAsync(TraceUrl);
        var ip = trace.Split('\n').FirstOrDefault(l => l.StartsWith("ip="))?[3..].Trim();
        if (!IPAddress.TryParse(ip, out _))
        {
            throw new IOException("Trace returned no valid address.");
        }

        return ip;
    }
    static async Task<bool> Browser(string stage)
    {
        string profile = Path.Combine(output, stage + "-profile");
        Directory.CreateDirectory(profile);
        File.WriteAllText(Path.Combine(profile, "user.js"), """
            user_pref("network.proxy.type", 0);
            user_pref("network.trr.mode", 5);
            user_pref("browser.shell.checkDefaultBrowser", false);
            user_pref("browser.startup.homepage_override.mstone", "ignore");
            user_pref("datareporting.policy.dataSubmissionEnabled", false);
            user_pref("toolkit.telemetry.enabled", false);
            user_pref("network.captive-portal-service.enabled", false);
            user_pref("network.connectivity-service.enabled", false);
            user_pref("app.update.auto", false);
            """);
        string screenshot = Path.Combine(output, stage + ".png");
        var info = new ProcessStartInfo(Firefox) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var arg in new[] { "--headless", "--no-remote", "--profile", profile, "--screenshot", screenshot, "--window-size", "1000,900", TraceUrl })
        {
            info.ArgumentList.Add(arg);
        }

        IntPtr job = CreateEngineJob();
        if (job == IntPtr.Zero)
        {
            throw new IOException("Cannot create browser job.");
        }

        using var child = new Process { StartInfo = info };
        try
        {
            if (!child.Start())
            {
                throw new IOException("Cannot start Firefox.");
            }

            if (!AssignProcessToJobObject(job, child.Handle))
            {
                child.Kill(true);
                throw new IOException("Cannot own Firefox process tree.");
            }
            try
            { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25)); }
            catch (TimeoutException) { Record("OBSERVE: Firefox " + stage + " timed out; no success claimed."); return false; }
            bool captured = child.ExitCode == 0 && File.Exists(screenshot) && new FileInfo(screenshot).Length > 0;
            Record("OBSERVE: Firefox " + stage + (captured ? " screenshot captured; inspect trace IP." : " produced no successful screenshot."));
            return captured;
        }
        finally { CloseHandle(job); }
    }
    static async Task Run(bool baselineOnly)
    {
        uint initialFilters = Guard.Status;
        ulong initialTun = Guard.TunLuid();
        int initialEngines = Process.GetProcessesByName("sing-box").Length;
        Record($"OBSERVE: initial filters={initialFilters}; TUN LUID={initialTun}; engines={initialEngines}.");
        if (initialFilters != 0 || initialTun != 0 || initialEngines != 0)
        {
            throw new IOException("Existing protection, engine or TUN: test refused.");
        }

        if (!baselineOnly && System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Any(n =>
            n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up &&
            (n.Description.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase) || n.Name.Contains("hidemy.name", StringComparison.OrdinalIgnoreCase))))
        {
            throw new IOException("An active OpenVPN adapter is present; disable the other VPN before live testing.");
        }

        if (!File.Exists(Firefox))
        {
            throw new FileNotFoundException("Firefox missing.");
        }

        if (Process.GetProcessesByName("firefox").Length != 0)
        {
            throw new IOException("Existing Firefox process: test refused.");
        }

        var settings = Settings.Load() with { ExcludedApplications = [Firefox] };
        expected = settings;
        string direct = await Egress();
        string proxy = await Egress(settings);
        if (direct == proxy)
        {
            throw new IOException("Direct and proxy baselines are indistinguishable.");
        }

        Record("PASS: positive baselines on same HTTPS endpoint; direct=" + direct + "; proxy=" + proxy);
        if (!await Browser("baseline"))
        {
            throw new IOException("Firefox baseline screenshot missing; no filters applied.");
        }

        if (baselineOnly)
        { Record("OBSERVE: baseline-only finished without changing network policy."); return; }
        using var engine = new Engine();
        engine.Log += _ => { }; // No credentials or full engine log in test reports.
        try
        {
            await engine.Check(settings);
            Configure(settings);
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
                throw new IOException("TUN startup failed.");
            }

            Configure(settings, luid);
            string actual = await Egress();
            if (actual != proxy)
            {
                throw new IOException("Ordinary process did not use proxy egress.");
            }

            Record("PASS: ordinary process uses proxy egress through TUN: " + actual);
            await Browser("excluded-tun");
            Configure(settings);
            await engine.Stop();
            await CheckDirectTcpDenied();
            await Browser("excluded-stopped");
            Configure(settings with { ExcludedApplications = [] });
            await Browser("removed-stopped");
        }
        finally
        {
            try
            { await engine.Stop(); }
            catch
            {
                engine.Dispose();
                Record("FAIL: engine stop reported an error; job disposed before policy cleanup.");
                exitCode = 1;
            }
            if (touched && Guard.Status != 0)
            {
                bool ours = expected != null && Guard.IsConfigured(expected, expectedLuid)
                    || previous != null && Guard.IsConfigured(previous, previousLuid);
                if (!ours)
                {
                    throw new IOException("Unexpected policy; automatic removal refused. Use explicit recovery.");
                }

                Guard.Remove();
            }
            if (Guard.Status != 0)
            {
                throw new IOException("Cleanup left filters.");
            }

            Record("PASS: owned policy removed under uninterrupted application mutex; filter count=0.");
            if (await Egress() != direct)
            {
                throw new IOException("Restored egress differs from baseline.");
            }

            Record("PASS: original direct access restored.");
        }
        Record("SKIP: browser IP conclusions require screenshot inspection; DNS, existing flows, IPv6 and Yandex Music are separate checks.");
    }
    static async Task CheckDirectTcpDenied()
    {
        // Baseline HTTPS above already established TCP to this same address/port.
        // An HTTP error (e.g. 503) still proves traffic got through. A timeout,
        // TLS failure or reset does not prove WFP denial, so never label it PASS.
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        try
        {
            await tcp.ConnectAsync(IPAddress.Parse("1.1.1.1"), 443, deadline.Token);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
        {
            Record("PASS: Windows explicitly denied ordinary process TCP to the baseline endpoint after engine stop.");
            return;
        }
        catch (SocketException ex)
        {
            Record("SKIP: ordinary TCP failed ambiguously (" + ex.SocketErrorCode + "); this does not prove KillSwitch denial.");
            return;
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            Record("SKIP: ordinary TCP timed out; this does not prove KillSwitch denial.");
            return;
        }
        throw new IOException("Direct TCP succeeded after engine stop; expected protection did not deny this connection.");
    }
}
