using System.Text.Json;
namespace ProxyBridge;

internal static class EngineSelfTests
{
    static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Test invariant failed.");
        }
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> Test, Settings s, Settings multiple)
    {
        using var engine = new Engine();
        foreach (string protocol in new[] { "http", "socks" })
        {
            foreach (bool hasExceptions in new[] { false, true })
            {
                var config = (hasExceptions ? multiple : s) with { Protocol = protocol };
                await Test($"sing-box {protocol}, exclusions={hasExceptions}: proxy/DNS/default/UDP contract", async () =>
                {
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
                    if (hasExceptions)
                    {
                        Require(outbounds.Count(x => x.GetProperty("type").GetString() == "direct" && x.GetProperty("tag").GetString() == "direct") == 1);
                        Require(directRules.Length == 1);
                        Require(directRules[0].GetProperty("process_path").EnumerateArray().Select(x => x.GetString()).SequenceEqual(config.ExcludedApplications));
                        int direct = Array.FindIndex(rules, x => x.TryGetProperty("outbound", out var o) && o.GetString() == "direct");
                        Require(direct > dns && direct < udp);
                    }
                    else
                    {
                        Require(directRules.Length == 0 && outbounds.All(x => x.GetProperty("type").GetString() != "direct"));
                    }
                });
            }
        }
        await engine.Stop();
        await Test("Engine check leaves no running tunnel; repeated Stop and Dispose clean runtime", async () =>
        {
            using var cleanup = new Engine();
            await cleanup.Check(multiple);
            Require(File.Exists(Engine.ConfigPath) && !cleanup.Running);
            await cleanup.Stop();
            await cleanup.Stop();
            Require(!File.Exists(Engine.ConfigPath) && !cleanup.Running);
            await cleanup.Check(s);
            Require(File.Exists(Engine.ConfigPath));
            cleanup.Dispose();
            cleanup.Dispose();
            Require(!File.Exists(Engine.ConfigPath));
        });
    }
}
