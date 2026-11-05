using System.Net;
using System.Net.Sockets;
using ProxyBridge;

internal static class ConnectionPathDiagnostic
{
    const SocketOptionName IpUnicastInterface = (SocketOptionName)31;
    // Compare explicit proxy access over the ordinary OS route with the
    // interface used by sing-tun's Windows default-interface monitor (/0).
    // This changes only each diagnostic socket's outgoing interface.
    public static async Task RunAsync(Settings settings, int physicalInterfaceIndex, Action<string> record)
    {
        settings.Validate();
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (physicalInterfaceIndex <= 0 || physicalInterfaceIndex > 0x00FFFFFF)
            throw new ArgumentOutOfRangeException(nameof(physicalInterfaceIndex));
        ArgumentNullException.ThrowIfNull(record);
        var proxyAddress = IPAddress.Parse(settings.Host);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(35));
        var targets = new[] {
            (Label: "literal HTTPS", Url: "https://1.1.1.1/cdn-cgi/trace"),
            (Label: "domain HTTPS", Url: "https://api.ipify.org")
        };
        foreach (bool physical in new[] { false, true }) {
            string path = physical ? "physical /0 interface" : "OS route";
            foreach (var target in targets) {
                if (deadline.IsCancellationRequested) {
                    record($"SKIP: {path}, {target.Label}: overall deadline.");
                    continue;
                }
                using var handler = new SocketsHttpHandler {
                    UseProxy = true,
                    Proxy = new WebProxy($"{(settings.Protocol == "http" ? "http" : "socks5")}://{settings.Host}:{settings.Port}") {
                        Credentials = new NetworkCredential(settings.Username, settings.Password)
                    },
                    AllowAutoRedirect = false,
                    MaxResponseHeadersLength = 16,
                    ConnectTimeout = TimeSpan.FromSeconds(8),
                    ConnectCallback = async (context, cancellationToken) => {
                        // Reject any direct connection attempt. The HTTP stack
                        // must ask this callback to connect to the proxy only.
                        if (context.DnsEndPoint.Port != settings.Port ||
                            !IPAddress.TryParse(context.DnsEndPoint.Host, out var requested) ||
                            !requested.Equals(proxyAddress))
                            throw new IOException("Unexpected diagnostic transport endpoint.");
                        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                        try {
                            if (physical) {
                                // Windows IP_UNICAST_IF expects the interface
                                // index in network byte order for AF_INET.
                                socket.SetSocketOption(SocketOptionLevel.IP, IpUnicastInterface,
                                    IPAddress.HostToNetworkOrder(physicalInterfaceIndex));
                            }
                            await socket.ConnectAsync(new IPEndPoint(requested, context.DnsEndPoint.Port), cancellationToken);
                            return new NetworkStream(socket, ownsSocket: true);
                        } catch {
                            socket.Dispose();
                            throw;
                        }
                    }
                };
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
                try {
                    using var response = await client.GetAsync(target.Url, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
                    record($"{(response.IsSuccessStatusCode ? "PASS" : "FAIL")}: {path}, {target.Label}: HTTP {(int)response.StatusCode}, TLS completed.");
                } catch (Exception ex) {
                    record($"FAIL: {path}, {target.Label}: {SafeError(ex)}.");
                }
            }
        }
        record("OBSERVE: path diagnostic finished; no TUN, WFP, routes, settings or TLS validation changes.");
    }

    static string SafeError(Exception error)
    {
        var parts = new List<string>();
        for (Exception? current = error; current != null; current = current.InnerException) {
            string part = current.GetType().Name;
            if (current is SocketException socket) part += $"({socket.SocketErrorCode},{socket.NativeErrorCode})";
            parts.Add(part);
        }
        return string.Join(" -> ", parts);
    }
}
