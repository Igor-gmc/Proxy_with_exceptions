using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using ProxyBridge;

internal static class IsolatedTunDiagnostic
{
    [DllImport("ScopedGuard.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    static extern uint ScopedStartWithReauth(uint ip, ushort port, ulong luid, string engine, string parent, uint blockAppMask, uint blockLayerMask,
        [MarshalAs(UnmanagedType.Bool)] bool allowTunReturn);
    [DllImport("ScopedGuard.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern uint ScopedStop();
    [DllImport("ScopedGuard.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern uint ScopedStatus(out uint count);
    [DllImport("iphlpapi.dll")]
    static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);
    const string Synthetic = "203.0.113.254", TunAddress = "192.0.2.1", TunPeer = "192.0.2.2";
    const string Target = "https://1.0.0.1/cdn-cgi/trace", Monitor = "https://1.1.1.1/cdn-cgi/trace";
    const SocketOptionName IpUnicastInterface = (SocketOptionName)31;

    // Run before the integration mutex. Only the parent reads this private
    // stdout pipe; egress addresses must never be copied to report files.
    public static bool TryRun(string[] args, out int code)
    {
        code = 0;
        if (args.Length == 0 || args[0] is not ("--isolated-monitor" or "--isolated-proxy-monitor")) return false;
        bool proxyMonitor = args[0] == "--isolated-proxy-monitor";
        int index = 0;
        if (proxyMonitor ? args.Length is not (2 or 3) || !int.TryParse(args[1], out index) || index <= 0 || index > 0x00FFFFFF ||
            (args.Length == 3 && args[2] is not ("http" or "socks")) : args.Length != 1)
            { code = 2; return true; }
        try {
            if (proxyMonitor) {
                var settings = Program.ReadDiagnosticSettings();
                if (args.Length == 3) settings = settings with { Protocol = args[2] };
                AppLog.RegisterSecret(settings.Password);
                settings.Validate();
                Console.WriteLine(Trace(Target, settings, index).GetAwaiter().GetResult());
            } else Console.WriteLine(Trace(Monitor).GetAwaiter().GetResult());
        }
        catch (Exception ex) { Console.Error.WriteLine(SafeError(ex)); code = 1; }
        return true;
    }

    static async Task<string> MonitorTrace(string? helper, int physicalProxyIndex = 0)
    {
        if (helper == null && physicalProxyIndex != 0) throw new IOException("Physical proxy monitor requires the isolated helper.");
        if (helper == null) return await Trace(Monitor);
        var info = new ProcessStartInfo(helper) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = AppContext.BaseDirectory };
        info.ArgumentList.Add(physicalProxyIndex == 0 ? "--isolated-monitor" : "--isolated-proxy-monitor");
        if (physicalProxyIndex != 0) info.ArgumentList.Add(physicalProxyIndex.ToString(System.Globalization.CultureInfo.InvariantCulture));
        using var child = new Process { StartInfo = info };
        child.Start();
        var stdout = child.StandardOutput.ReadToEndAsync(); var stderr = child.StandardError.ReadToEndAsync();
        try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); }
        catch {
            if (!child.HasExited) child.Kill(true);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            throw;
        }
        string value = (await stdout).Trim();
        string failure = AppLog.Redact((await stderr).Trim());
        if (failure.Length > 512) failure = failure[..512];
        if (child.ExitCode != 0 || !IPAddress.TryParse(value, out var address))
            throw new IOException("External monitor helper failed, exit=" + child.ExitCode + "; " + failure);
        return address.ToString();
    }

    static async Task DiagnoseSustainedFailure(string helper, int physicalIndex, string proxyEgress, string normalEgress, Action<string> record)
    {
        async Task Observe(string label, int index, string expected)
        {
            var elapsed = Stopwatch.StartNew();
            try {
                if (await MonitorTrace(helper, index) != expected) throw new IOException("Egress differs from the corresponding baseline.");
                record($"PASS: sustained failure {label}; elapsedMs={elapsed.ElapsedMilliseconds}; egress matches baseline.");
            } catch (Exception ex) {
                record($"FAIL: sustained failure {label}; elapsedMs={elapsed.ElapsedMilliseconds}; " + SafeError(ex));
            }
        }
        await Task.WhenAll(Observe("physical explicit proxy", physicalIndex, proxyEgress), Observe("external OS monitor", 0, normalEgress));
    }

    static async Task PhysicalTcp(int interfaceIndex)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.SetSocketOption(SocketOptionLevel.IP, IpUnicastInterface, IPAddress.HostToNetworkOrder(interfaceIndex));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse("1.0.0.1"), 443), deadline.Token);
    }

    static async Task RequirePhysicalTcpDenied(int interfaceIndex, Action<string> record)
    {
        try { await PhysicalTcp(interfaceIndex); }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied) {
            record("PASS: scoped protection explicitly denies a fresh physical-interface TCP connection to the positive baseline endpoint (SocketAccessDenied).");
            return;
        } catch (SocketException ex) {
            record("SKIP: physical-interface TCP failed ambiguously (" + ex.SocketErrorCode + "); direct denial is not proven.");
            return;
        } catch (OperationCanceledException) {
            record("SKIP: physical-interface TCP timed out; direct denial is not proven.");
            return;
        }
        throw new IOException("Direct physical-interface TCP succeeded under scoped protection; return-traffic exception permits an unintended bypass.");
    }
    const string SnapshotScript = """
        $ErrorActionPreference='Stop'
        $fw=New-Object -ComObject HNetCfg.FwPolicy2
        $rules=@($fw.Rules | Where-Object { $_.Name -ceq ('sing-tun ('+$env:PB_DIAG_ENGINE+')') } | ForEach-Object {
            [pscustomobject]@{Name=$_.Name;ApplicationName=$_.ApplicationName;Enabled=$_.Enabled;Direction=$_.Direction;Action=$_.Action;Protocol=$_.Protocol;Profiles=$_.Profiles;LocalPorts=$_.LocalPorts;RemotePorts=$_.RemotePorts;LocalAddresses=$_.LocalAddresses;RemoteAddresses=$_.RemoteAddresses}
        })
        [pscustomobject]@{
            Routes=@(Get-NetRoute -PolicyStore ActiveStore | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
            Interfaces=@(Get-NetIPInterface | Select-Object InterfaceIndex,AddressFamily,NlMtu,WeakHostSend,WeakHostReceive,InterfaceMetric,AutomaticMetric,Forwarding)
            Dns=@(Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
            Firewall=$rules
        } | ConvertTo-Json -Depth 6 -Compress
        """;
    const string AddRouteScript = """
        $ErrorActionPreference='Stop'
        $idx=[int]$env:PB_DIAG_INDEX
        $nics=@(Get-NetAdapter -IncludeHidden | Where-Object ifIndex -eq $idx)
        if($nics.Count -ne 1){throw 'Diagnostic adapter missing or ambiguous'}
        $nic=$nics[0]
        if($nic.Name -cne $env:PB_DIAG_NAME){throw 'Diagnostic adapter identity changed'}
        if(@(Get-NetRoute -PolicyStore ActiveStore | Where-Object DestinationPrefix -eq '203.0.113.254/32').Count -ne 0){throw 'Synthetic route already exists'}
        $route=New-NetRoute -DestinationPrefix '203.0.113.254/32' -InterfaceIndex $idx -NextHop '192.0.2.2' -RouteMetric 1 -PolicyStore ActiveStore
        [pscustomobject]@{InterfaceIndex=$idx;InterfaceGuid=$nic.InterfaceGuid.ToString();DestinationPrefix=$route.DestinationPrefix;NextHop=$route.NextHop;RouteMetric=$route.RouteMetric} | ConvertTo-Json -Compress
        """;
    const string RemoveRouteScript = """
        $ErrorActionPreference='Stop'
        $idx=[int]$env:PB_DIAG_INDEX
        $nics=@(Get-NetAdapter -IncludeHidden | Where-Object ifIndex -eq $idx)
        if($nics.Count -ne 1){throw 'Diagnostic adapter missing or ambiguous'}
        $nic=$nics[0]
        if($nic.Name -cne $env:PB_DIAG_NAME -or $nic.InterfaceGuid.ToString() -ine $env:PB_DIAG_GUID){throw 'Diagnostic adapter identity changed'}
        $rows=@(Get-NetRoute -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -eq $idx -and $_.DestinationPrefix -eq '203.0.113.254/32' -and $_.NextHop -eq '192.0.2.2' -and $_.RouteMetric -eq 1 })
        if($rows.Count -ne 1){throw 'Captured diagnostic route is missing or ambiguous'}
        $rows[0] | Remove-NetRoute -Confirm:$false
        """;

    static async Task<string> PowerShell(string script, string name, int index = 0, string? guid = null)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe")) {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        info.ArgumentList.Add("-NoProfile"); info.ArgumentList.Add("-NonInteractive");
        info.ArgumentList.Add("-EncodedCommand"); info.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
        info.Environment["PB_DIAG_ENGINE"] = Engine.Executable;
        info.Environment["PB_DIAG_NAME"] = name;
        info.Environment["PB_DIAG_INDEX"] = index.ToString(System.Globalization.CultureInfo.InvariantCulture);
        info.Environment["PB_DIAG_GUID"] = guid ?? "";
        using var process = new Process { StartInfo = info };
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25)); }
        catch {
            if (!process.HasExited) process.Kill(true);
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            throw;
        }
        string result = await stdout;
        _ = await stderr; // Scripts contain no secrets; do not dump environment details into the report.
        if (process.ExitCode != 0) {
            string stage = script == SnapshotScript ? "network snapshot" : script == AddRouteScript ? "owned-route creation" : "owned-route removal";
            throw new IOException("Diagnostic " + stage + " failed, exit=" + process.ExitCode);
        }
        return result;
    }

    static async Task<JsonElement> Snapshot(string name, string file)
    {
        string json = await PowerShell(SnapshotScript, name);
        using var document = JsonDocument.Parse(json);
        File.WriteAllText(file, json, Encoding.UTF8);
        return document.RootElement.Clone();
    }

    static string[] Rows(JsonElement snapshot, string section, int excludeInterface = -1) => snapshot.GetProperty(section)
        .EnumerateArray().Where(row => !row.TryGetProperty("InterfaceIndex", out var index) || index.GetInt32() != excludeInterface)
        .Select(row => JsonSerializer.Serialize(row)).Order(StringComparer.Ordinal).ToArray();

    static void CompareSnapshots(JsonElement before, JsonElement after, int diagnosticIndex = -1)
    {
        foreach (string section in new[] { "Routes", "Interfaces", "Dns", "Firewall" })
            if (!Rows(before, section).SequenceEqual(Rows(after, section, diagnosticIndex)))
                throw new IOException("Existing network state changed during isolated diagnostic: " + section);
    }

    static void ValidateDiagnosticRoutes(JsonElement snapshot, int index)
    {
        int syntheticRoutes = 0;
        foreach (var route in snapshot.GetProperty("Routes").EnumerateArray().Where(r => r.GetProperty("InterfaceIndex").GetInt32() == index)) {
            string prefix = route.GetProperty("DestinationPrefix").GetString()!;
            if (prefix == Synthetic + "/32") {
                syntheticRoutes++;
                if (route.GetProperty("NextHop").GetString() != TunPeer || route.GetProperty("RouteMetric").GetInt32() != 1)
                    throw new IOException("Diagnostic synthetic route metadata changed.");
                continue;
            }
            if (prefix is "192.0.2.0/30" or "192.0.2.1/32" or "192.0.2.3/32" or "224.0.0.0/4" or "255.255.255.255/32") continue;
            string[] parts = prefix.Split('/');
            if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var address) && int.TryParse(parts[1], out int bits) &&
                address.AddressFamily == AddressFamily.InterNetworkV6 &&
                (address.IsIPv6LinkLocal && bits >= 64 || address.IsIPv6Multicast && bits >= 8)) continue;
            throw new IOException("Unexpected route on diagnostic adapter; isolated test aborted: " + prefix);
        }
        if (syntheticRoutes != 1) throw new IOException("Exactly one owned synthetic route must be present.");
    }

    static void ValidateExistingFirewall(JsonElement snapshot)
    {
        var rules = snapshot.GetProperty("Firewall").EnumerateArray().ToArray();
        if (rules.Length != 1) throw new IOException("Exactly one preexisting sing-tun firewall rule is required; no rule will be created by this harness.");
        var rule = rules[0];
        if (!string.Equals(rule.GetProperty("ApplicationName").GetString(), Engine.Executable, StringComparison.OrdinalIgnoreCase) ||
            !rule.GetProperty("Enabled").GetBoolean() || rule.GetProperty("Direction").GetInt32() != 1 ||
            rule.GetProperty("Action").GetInt32() != 1 || rule.GetProperty("Protocol").GetInt32() != 6 ||
            rule.GetProperty("Profiles").GetInt32() != int.MaxValue)
            throw new IOException("Existing sing-tun firewall rule does not match the expected inbound TCP rule.");
    }

    static bool Conflicts(string prefix)
    {
        var parts = prefix.Split('/');
        if (parts.Length != 2 || !int.TryParse(parts[1], out int bits) || bits <= 1 || bits > 32 ||
            !IPAddress.TryParse(parts[0], out var address) || address.AddressFamily != AddressFamily.InterNetwork) return false;
        uint Number(IPAddress ip) { byte[] b = ip.GetAddressBytes(); return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]; }
        uint network = Number(address), mask = uint.MaxValue << (32 - bits);
        return (network & mask) == (Number(IPAddress.Parse(Synthetic)) & mask) ||
            (network & mask) == (Number(IPAddress.Parse(TunAddress)) & mask) ||
            (network & 0xFFFFFFFC) == Number(IPAddress.Parse("192.0.2.0"));
    }

    static string Configuration(Settings settings, string stack, string name, string physicalName) => JsonSerializer.Serialize(new {
        log = new { level = "debug", timestamp = true },
        inbounds = new[] { new { type = "tun", tag = "diagnostic", interface_name = name, address = new[] { TunAddress + "/30" },
            mtu = 1500, auto_route = false, strict_route = false, dns_mode = "disabled", stack } },
        outbounds = new[] { new { type = settings.Protocol, tag = "proxy", server = settings.Host, server_port = settings.Port,
            username = settings.Username, password = settings.Password, bind_interface = physicalName } },
        route = new { final = "proxy", rules = new object[] {
            new { ip_cidr = new[] { Synthetic + "/32" }, port = 443, network = "tcp", action = "route", outbound = "proxy", override_address = "1.0.0.1", override_port = 443 },
            new { action = "reject" }
        } }
    });

    static async Task<string> Trace(string url, Settings? proxy = null, int interfaceIndex = 0, bool synthetic = false)
    {
        using var handler = new SocketsHttpHandler { UseProxy = proxy != null, AllowAutoRedirect = false, MaxResponseHeadersLength = 16 };
        if (proxy != null) handler.Proxy = new WebProxy($"{(proxy.Protocol == "http" ? "http" : "socks5")}://{proxy.Host}:{proxy.Port}") {
            Credentials = new NetworkCredential(proxy.Username, proxy.Password)
        };
        if (interfaceIndex != 0) handler.ConnectCallback = async (context, token) => {
            string requested = proxy?.Host ?? "1.0.0.1";
            int port = proxy?.Port ?? 443;
            if (context.DnsEndPoint.Host != requested || context.DnsEndPoint.Port != port)
                throw new IOException("Unexpected diagnostic endpoint.");
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try {
                socket.SetSocketOption(SocketOptionLevel.IP, IpUnicastInterface, IPAddress.HostToNetworkOrder(interfaceIndex));
                if (synthetic) socket.Bind(new IPEndPoint(IPAddress.Parse(TunAddress), 0));
                await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(synthetic ? Synthetic : requested), port), token);
                return new NetworkStream(socket, true);
            } catch { socket.Dispose(); throw; }
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        response.EnsureSuccessStatusCode();
        await response.Content.LoadIntoBufferAsync(4096, deadline.Token);
        string body = await response.Content.ReadAsStringAsync(deadline.Token);
        string? value = body.Split('\n').FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal))?[3..].Trim();
        if (!IPAddress.TryParse(value, out var address)) throw new IOException("Trace response has no valid address.");
        return address.ToString(); // Values are compared in memory, never logged.
    }

    static async Task CheckConfiguration()
    {
        var info = new ProcessStartInfo(Engine.Executable) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = Path.GetDirectoryName(Engine.Executable)! };
        info.ArgumentList.Add("check"); info.ArgumentList.Add("-c"); info.ArgumentList.Add(Engine.ConfigPath);
        using var process = new Process { StartInfo = info };
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); }
        catch { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); throw; }
        _ = await stdout; _ = await stderr;
        if (process.ExitCode != 0) throw new IOException("Isolated sing-box configuration check failed, exit=" + process.ExitCode);
    }

    public static async Task RunAsync(Settings settings, string stack, int physicalIndex, string output, Action<string> record, bool scopedGuard = false, uint blockAppMask = 3, uint blockLayerMask = 15, bool allowTunReturn = false, bool sustained = false)
    {
        settings.Validate();
        AppLog.RegisterSecret(settings.Password);
        if (stack is not ("mixed" or "gvisor")) throw new ArgumentException("Expected mixed or gvisor.");
        if (blockAppMask is < 1 or > 3) throw new ArgumentOutOfRangeException(nameof(blockAppMask));
        if (blockLayerMask is not (3 or 12 or 15)) throw new ArgumentOutOfRangeException(nameof(blockLayerMask));
        if (sustained && (!scopedGuard || !allowTunReturn || blockAppMask != 3 || blockLayerMask != 15))
            throw new ArgumentException("Sustained diagnostic requires the complete 33-filter scoped policy.");
        if (physicalIndex <= 0 || physicalIndex > 0x00FFFFFF) throw new ArgumentOutOfRangeException(nameof(physicalIndex));
        if (File.Exists(Engine.ConfigPath)) throw new IOException("An existing runtime config must not be replaced.");
        if (Guard.Status != 0) throw new IOException("Existing ProxyBridge protection: isolated diagnostic refused.");
        var processes = Process.GetProcessesByName("sing-box");
        try { if (processes.Length != 0) throw new IOException("Existing sing-box: isolated diagnostic refused."); }
        finally { foreach (var process in processes) process.Dispose(); }
        var physical = NetworkInterface.GetAllNetworkInterfaces().Single(n => n.OperationalStatus == OperationalStatus.Up &&
            n.Supports(NetworkInterfaceComponent.IPv4) &&
            n.GetIPProperties().GetIPv4Properties()?.Index == physicalIndex);
        string name = $"ProxyBridge-Diag-{Environment.ProcessId}-{stack}";
        if (NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == name)) throw new IOException("Diagnostic interface already exists.");
        output = Path.GetFullPath(output); Directory.CreateDirectory(output);
        var before = await Snapshot(name, Path.Combine(output, "network-before.json"));
        ValidateExistingFirewall(before);
        if (before.GetProperty("Routes").EnumerateArray().Any(r => Conflicts(r.GetProperty("DestinationPrefix").GetString()!)))
            throw new IOException("An existing route overlaps reserved diagnostic addresses.");
        using var engine = new Engine();
        var engineLines = new ConcurrentQueue<string>();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        engine.Log += line => {
            engineLines.Enqueue(AppLog.Redact(line, settings.Password));
            if (line.Contains("sing-box started", StringComparison.Ordinal)) ready.TrySetResult();
        };
        int diagnosticIndex = -1;
        string? routeGuid = null;
        string? monitorHelper = null, normalEgress = null;
        bool scopedAttempted = false, engineStarted = false;
        Exception? primary = null;
        try {
            if (scopedGuard) {
                string helper = Path.Combine(AppContext.BaseDirectory, $"IsolatedMonitor{Environment.ProcessId}.exe");
                if (File.Exists(helper)) throw new IOException("Monitor helper already exists; refusing to overwrite.");
                File.Copy(Environment.ProcessPath ?? throw new IOException("Integration apphost missing."), helper, false);
                monitorHelper = helper;
            }
            normalEgress = await MonitorTrace(monitorHelper);
            string proxyEgress = await Trace(Target, settings, physicalIndex);
            record("PASS: OS-route VPN monitor and physical-interface explicit proxy HTTPS baseline succeed (egress values withheld).");
            RuntimeStorage.Prepare();
            File.WriteAllText(Engine.ConfigPath, Configuration(settings, stack, name, physical.Name), new UTF8Encoding(false));
            await CheckConfiguration();
            engine.Start();
            engineStarted = true;
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(15));
            var diagnostic = NetworkInterface.GetAllNetworkInterfaces().Single(n => n.Name == name);
            if (diagnostic.OperationalStatus != OperationalStatus.Up || !diagnostic.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(IPAddress.Parse(TunAddress))))
                throw new IOException("Diagnostic adapter is not ready.");
            diagnosticIndex = diagnostic.GetIPProperties().GetIPv4Properties()!.Index;
            using (var captured = JsonDocument.Parse(await PowerShell(AddRouteScript, name, diagnosticIndex))) {
                var route = captured.RootElement;
                if (route.GetProperty("InterfaceIndex").GetInt32() != diagnosticIndex || route.GetProperty("DestinationPrefix").GetString() != Synthetic + "/32" ||
                    route.GetProperty("NextHop").GetString() != TunPeer || route.GetProperty("RouteMetric").GetInt32() != 1)
                    throw new IOException("Created diagnostic route did not match the requested route.");
                routeGuid = route.GetProperty("InterfaceGuid").GetString()!;
                File.WriteAllText(Path.Combine(output, "owned-route.json"), route.GetRawText(), Encoding.UTF8);
            }
            var during = await Snapshot(name, Path.Combine(output, "network-during.json"));
            ValidateDiagnosticRoutes(during, diagnosticIndex);
            CompareSnapshots(before, during, diagnosticIndex);
            if (await MonitorTrace(monitorHelper) != normalEgress) throw new IOException("OS-route VPN monitor changed during isolated diagnostic.");
            record("PASS: existing routes, DNS, MTU, host flags and firewall rule unchanged; OS-route monitor retains baseline egress.");
            if (scopedGuard) {
                if (allowTunReturn) {
                    await PhysicalTcp(physicalIndex);
                    record("PASS: fresh physical-interface TCP reaches the negative-test endpoint before scoped protection is installed.");
                }
                var guid = Guid.Parse(diagnostic.Id);
                uint error = ConvertInterfaceGuidToLuid(ref guid, out ulong luid);
                if (error != 0 || luid == 0) throw new IOException("Diagnostic interface LUID conversion failed, code=" + error);
                byte[] bytes = IPAddress.Parse(settings.Host).GetAddressBytes();
                uint ip = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
                scopedAttempted = true;
                error = ScopedStartWithReauth(ip, checked((ushort)settings.Port), luid, Engine.Executable,
                    Environment.ProcessPath ?? throw new IOException("Integration apphost missing."), blockAppMask, blockLayerMask, allowTunReturn);
                if (error != 0) throw new IOException($"Scoped diagnostic policy failed, code=0x{error:X8}");
                error = ScopedStatus(out uint count);
                uint expectedCount = 21u + (uint)(System.Numerics.BitOperations.PopCount(blockAppMask) * System.Numerics.BitOperations.PopCount(blockLayerMask)) + (allowTunReturn ? 4u : 0u);
                if (error != 0 || count != expectedCount) throw new IOException($"Scoped diagnostic filter count mismatch, code=0x{error:X8}, count={count}, expected={expectedCount}");
                record($"PASS: scoped diagnostic policy contains exactly {expectedCount} filters.");
                string blocked = blockAppMask == 1 ? "engine only" : blockAppMask == 2 ? "integration parent only" : "engine and integration parent";
                string layers = blockLayerMask == 3 ? "CONNECT v4/v6" : blockLayerMask == 12 ? "RECV v4/v6" : "CONNECT and RECV v4/v6";
                record($"OBSERVE: scoped BLOCK app mask={blockAppMask} ({blocked}), layer mask={blockLayerMask} ({layers}); all scoped PERMIT rules retained; external monitor is outside this scope.");
                record("OBSERVE: TUN return-traffic reauthorization candidate enabled=" + allowTunReturn + ".");
            }
            var syntheticTrace = Trace(Target, interfaceIndex: diagnosticIndex, synthetic: true);
            var concurrentMonitor = MonitorTrace(monitorHelper);
            try {
                await Task.WhenAll(syntheticTrace, concurrentMonitor);
                if (await concurrentMonitor != normalEgress) throw new IOException("Concurrent OS-route VPN monitor changed during synthetic request.");
                if (await syntheticTrace != proxyEgress) throw new IOException("Isolated TUN egress differs from explicit proxy baseline.");
            }
            catch {
                if (concurrentMonitor.IsCompletedSuccessfully && concurrentMonitor.Result == normalEgress)
                    record("PASS: one concurrent external OS-route monitor retained baseline egress despite the synthetic request failure.");
                else
                    record("FAIL: concurrent external OS-route monitor did not confirm baseline egress.");
                if (sustained) await DiagnoseSustainedFailure(monitorHelper!, physicalIndex, proxyEgress, normalEgress, record);
                throw;
            }
            record("PASS: isolated " + stack + " TUN forwards synthetic IPv4 HTTPS through the configured proxy.");
            record("PASS: one concurrent OS-route monitor request retained baseline egress during the synthetic request.");
            if (scopedGuard && allowTunReturn) await RequirePhysicalTcpDenied(physicalIndex, record);
            if (sustained) {
                var duration = Stopwatch.StartNew();
                async Task Observe(string label, Func<Task<string>> request, string expected)
                {
                    var elapsed = Stopwatch.StartNew();
                    try {
                        if (await request() != expected) throw new IOException("Egress differs from the corresponding baseline.");
                        record($"PASS: sustained {label}; elapsedMs={elapsed.ElapsedMilliseconds}; totalMs={duration.ElapsedMilliseconds}; egress matches baseline.");
                    } catch (Exception ex) {
                        record($"FAIL: sustained {label}; elapsedMs={elapsed.ElapsedMilliseconds}; totalMs={duration.ElapsedMilliseconds}; " + SafeError(ex));
                        throw;
                    }
                }
                async Task Round(string label, int count)
                {
                    var requests = Enumerable.Range(1, count).Select(i => Observe(label + " synthetic-" + i,
                        () => Trace(Target, interfaceIndex: diagnosticIndex, synthetic: true), proxyEgress)).ToArray();
                    var monitor = Observe(label + " external OS monitor", () => MonitorTrace(monitorHelper), normalEgress);
                    // Drain every bounded request before cleanup; never stop the engine under an in-flight test.
                    await Task.WhenAll(requests.Append(monitor));
                }
                try {
                    for (int i = 1; i <= 8; i++) {
                        await Task.Delay(TimeSpan.FromSeconds(8));
                        await Round("serial-" + i, 1);
                    }
                    await Round("concurrent-4", 4);
                    await Round("serial-recovery", 1);
                    record($"PASS: sustained duration and capped concurrency completed; elapsedMs={duration.ElapsedMilliseconds}.");
                } catch {
                    // These helper requests remain outside the scoped EXEs and run before scoped cleanup.
                    await DiagnoseSustainedFailure(monitorHelper!, physicalIndex, proxyEgress, normalEgress, record);
                    throw;
                }
            }
        } catch (Exception ex) {
            primary = ex;
            record("FAIL: isolated " + stack + " diagnostic: " + SafeError(ex));
            throw;
        } finally {
            var cleanup = new List<Exception>();
            if (scopedAttempted) {
                for (int attempt = 0; attempt < 2; attempt++) {
                    try {
                        uint error = ScopedStop();
                        if (error != 0) throw new IOException($"Scoped diagnostic cleanup failed, code=0x{error:X8}");
                        error = ScopedStatus(out uint count);
                        if (error != 0 || count != 0) throw new IOException($"Scoped diagnostic filters remain after cleanup, code=0x{error:X8}, count={count}");
                        record("PASS: scoped dynamic policy removed before route and engine cleanup; scoped filter count=0.");
                        break;
                    } catch (Exception ex) { cleanup.Add(ex); }
                }
            }
            if (routeGuid != null) {
                try { await PowerShell(RemoveRouteScript, name, diagnosticIndex, routeGuid); }
                catch (Exception ex) { cleanup.Add(ex); }
            }
            try {
                await engine.Stop();
                if (engineStarted) {
                    if (engine.Running || File.Exists(Engine.ConfigPath)) throw new IOException("Diagnostic engine or runtime config remains after Stop.");
                    if (!engine.LastStopForced) record("PASS: diagnostic engine stopped gracefully and its protected runtime config was removed.");
                }
            }
            catch (Exception ex) { cleanup.Add(ex); }
            if (engine.LastStopForced) cleanup.Add(new IOException("Diagnostic engine needed forced termination."));
            try { File.WriteAllLines(Path.Combine(output, "engine-output.txt"), engineLines, Encoding.UTF8); }
            catch (Exception ex) { cleanup.Add(ex); }
            try {
                var after = await Snapshot(name, Path.Combine(output, "network-after.json"));
                CompareSnapshots(before, after);
                if (Guard.Status != 0) throw new IOException("ProxyBridge filter count changed during isolated diagnostic.");
                if (normalEgress != null) {
                    if (await MonitorTrace(monitorHelper) != normalEgress) throw new IOException("OS-route VPN monitor changed after diagnostic cleanup.");
                    record("PASS: isolated diagnostic cleanup restores the network snapshot and preserves OS-route baseline egress.");
                }
            } catch (Exception ex) { cleanup.Add(ex); }
            if (monitorHelper != null) {
                try { File.Delete(monitorHelper); }
                catch (Exception ex) { cleanup.Add(ex); }
            }
            if (cleanup.Count != 0) {
                foreach (var error in cleanup) record("FAIL: isolated cleanup: " + SafeError(error));
                if (primary != null) cleanup.Insert(0, primary);
                throw new AggregateException("Isolated diagnostic cleanup incomplete.", cleanup);
            }
        }
    }

    static string SafeError(Exception error)
    {
        var result = new List<string>();
        for (Exception? current = error; current != null; current = current.InnerException)
            result.Add(current is SocketException socket ? $"SocketException({socket.SocketErrorCode},{socket.NativeErrorCode})"
                : current.GetType() == typeof(IOException) && current.InnerException == null
                    ? "IOException: " + AppLog.Redact(current.Message) : $"{current.GetType().Name}(0x{current.HResult:X8})");
        return string.Join(" -> ", result);
    }
}
