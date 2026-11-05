using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace ProxyBridge;
// Explicit, temporary integration test; never run on normal application startup.
internal static class NetworkTest
{
    public static async Task Run()
    {
        if (Guard.Status != 0) throw new InvalidOperationException("Сначала отключите существующий KillSwitch. Тест не меняет уже включённую защиту.");
        var lines = new List<string>();
        string output = Path.Combine(AppContext.BaseDirectory, "network-test.txt");
        void Record(string line) { lines.Add(line); File.WriteAllLines(output, lines); }
        // Separate elevated watchdog restores access if the test process crashes or hangs.
        using var watchdog = Process.Start(new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "ProxyBridge.exe")) {
            UseShellExecute = false, CreateNoWindow = true, ArgumentList = { "--test-watchdog", Environment.ProcessId.ToString() }
        }) ?? throw new IOException("Cannot start recovery watchdog");
        using var engine = new Engine();
        var messages = new System.Collections.Concurrent.ConcurrentQueue<string>();
        engine.Log += line => messages.Enqueue(AppLog.Redact(line, Settings.Default.Password));
        try {
            var s = Settings.Default;
            await engine.Check(s);
            async Task<string> Ip() {
                using var client = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(12) };
                string trace = await client.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace");
                return trace.Split('\n').First(x => x.StartsWith("ip="))[3..].Trim();
            }
            Record("Baseline HTTPS: " + await Ip());
            Guard.Configure(s);
            Record("WFP armed before engine start");
            engine.Start();
            ulong luid = 0;
            for (int i = 0; i < 60 && engine.Running; i++) { await Task.Delay(250); luid = Guard.TunLuid(); if (luid != 0) break; }
            if (luid == 0 || !engine.Running) throw new Exception("TUN failed to start");
            Guard.Configure(s, luid);
            Record("Tunnel HTTPS IP: " + await Ip());
            // Open an existing connection through TUN before the forced engine termination.
            using var existing = new TcpClient();
            await existing.ConnectAsync("1.1.1.1", 443).WaitAsync(TimeSpan.FromSeconds(8));
            await engine.Stop();
            // Intentionally leave the TUN-exemption filters in place: this exercises
            // the GUI-crash/engine-crash case without relying on monitor re-arming.
            Record("Engine killed; persistent filters remain: " + Guard.Status);
            foreach (var endpoint in new[] { ("1.1.1.1", 443), ("8.8.8.8", 53), (s.Host, s.Port), ("2606:4700:4700::1111", 443) }) {
                using var tcp = new TcpClient(endpoint.Item1.Contains(':') ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
                bool connected;
                try { await tcp.ConnectAsync(endpoint.Item1, endpoint.Item2).WaitAsync(TimeSpan.FromSeconds(3)); connected = true; }
                catch (Exception ex) when (ex is SocketException or TimeoutException) { connected = false; }
                if (connected) throw new Exception("LEAK: direct TCP succeeded to " + endpoint);
                Record("PASS: direct TCP blocked after engine death: " + endpoint);
            }
        } catch (Exception ex) { Record("FAIL: " + ex.Message); foreach (var message in messages) Record(message); Environment.ExitCode = 1; }
        finally {
            await engine.Stop();
            Guard.Remove();
            Record("Cleanup: own WFP filters removed, mask=" + Guard.Status);
            if (!watchdog.HasExited) { watchdog.Kill(); await watchdog.WaitForExitAsync(); }
        }
    }
}
