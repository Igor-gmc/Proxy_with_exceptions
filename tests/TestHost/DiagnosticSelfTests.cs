using System.Net;
using System.Text.Json;
namespace ProxyBridge;

internal static class DiagnosticSelfTests
{
    static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Test invariant failed.");
        }
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> Test, Settings s)
    {
        await Test("logging operation scope survives await and restores parent after exception and disposal", async () =>
        {
            string? original = AppLog.CurrentOperation;
            using (AppLog.BeginOperation("qa-outer"))
            {
                string? outer = AppLog.CurrentOperation;
                Require(!string.IsNullOrEmpty(outer) && outer != original);
                try
                {
                    using var inner = AppLog.BeginOperation("qa-inner");
                    string? innerId = AppLog.CurrentOperation;
                    Require(innerId != outer && innerId != null);
                    await Task.Yield();
                    Require(AppLog.CurrentOperation == innerId);
                    throw new IOException("synthetic scope unwind");
                }
                catch (IOException) { }
                Require(AppLog.CurrentOperation == outer);
                var sibling = AppLog.BeginOperation("qa-idempotent-dispose");
                sibling.Dispose();
                sibling.Dispose();
                Require(AppLog.CurrentOperation == outer);
            }
            Require(AppLog.CurrentOperation == original);
        });
        await Test("parallel logging operations inherit parent without leaking sibling correlation", async () =>
        {
            string? original = AppLog.CurrentOperation;
            using (AppLog.BeginOperation("qa-parallel-parent"))
            {
                string? parent = AppLog.CurrentOperation;
                var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                int entered = 0;
                async Task<string> Child()
                {
                    Require(AppLog.CurrentOperation == parent);
                    string child;
                    using (AppLog.BeginOperation("qa-parallel-child"))
                    {
                        child = AppLog.CurrentOperation!;
                        Require(child != null && child != parent);
                        if (Interlocked.Increment(ref entered) == 2)
                        {
                            ready.SetResult();
                        }

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
        await Test("exception diagnostic retains failure codes without messages, URLs or body secrets", () =>
        {
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
        await Test("local network snapshot is bounded valid JSON with usable native routes and no credentials", () =>
        {
            string snapshot = NetworkDiagnostics.Capture(s);
            Require(!snapshot.Contains(s.Username, StringComparison.Ordinal) && !snapshot.Contains(s.Password, StringComparison.Ordinal));
            Require(System.Text.Encoding.UTF8.GetByteCount(snapshot) <= 48000);
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "network-diagnostics-test.json"), snapshot, new System.Text.UTF8Encoding(false));
            using var doc = JsonDocument.Parse(snapshot);
            var root = doc.RootElement;
            void NoDiagnosticErrors(JsonElement element)
            {
                if (element.ValueKind == JsonValueKind.Object)
                {
                    Require(!element.TryGetProperty("error", out _));
                    foreach (var property in element.EnumerateObject())
                    {
                        NoDiagnosticErrors(property.Value);
                    }
                }
                else if (element.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in element.EnumerateArray())
                    {
                        NoDiagnosticErrors(item);
                    }
                }
            }
            NoDiagnosticErrors(root);
            Require(!root.TryGetProperty("error", out _) && !root.TryGetProperty("interfacesError", out _));
            Require(root.GetProperty("schema").GetInt32() == 1 && root.GetProperty("proxyAddressAvailable").GetBoolean());
            Require(root.GetProperty("interfaces").ValueKind == JsonValueKind.Array);
            var summary = root.GetProperty("routeSummary");
            Require(!summary.TryGetProperty("error", out _) && summary.GetProperty("errors").GetArrayLength() == 0);
            Require(summary.GetProperty("inspected").GetUInt32() <= summary.GetProperty("total").GetUInt32());
            foreach (var route in root.GetProperty("routes").EnumerateArray())
            {
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
    }
}
