using System.Text.Json;

namespace ProxyBridge;

internal static class ConfigurationTests
{
    static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Configuration invariant failed.");
        }
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> test)
    {
        foreach (string protocol in new[] { "http", "socks" })
        {
            foreach (bool hasExclusions in new[] { false, true })
            {
                await test($"configuration: {protocol}, exclusions={hasExclusions}, proxy/DNS/UDP contract", () =>
                {
                    var settings = new Settings("192.0.2.10", 1080, "qa-user", "synthetic-core-only", protocol)
                    {
                        ExcludedApplications = hasExclusions ? [@"C:\QA Apps\Browser\browser.exe"] : []
                    };
                    using var document = JsonDocument.Parse(Engine.Configuration(settings));
                    var root = document.RootElement;
                    var outbounds = root.GetProperty("outbounds").EnumerateArray().ToArray();
                    Require(outbounds.Length == (hasExclusions ? 2 : 1));
                    var proxy = outbounds.Single(item => item.GetProperty("tag").GetString() == "proxy");
                    Require(proxy.GetProperty("type").GetString() == protocol);
                    Require(proxy.GetProperty("server").GetString() == settings.Host);
                    Require(proxy.GetProperty("server_port").GetInt32() == settings.Port);
                    Require(proxy.GetProperty("username").GetString() == settings.Username);
                    Require(proxy.GetProperty("password").GetString() == settings.Password);
                    var dns = root.GetProperty("dns");
                    Require(dns.GetProperty("servers")[0].GetProperty("detour").GetString() == "proxy");
                    Require(dns.GetProperty("strategy").GetString() == "ipv4_only");
                    var route = root.GetProperty("route");
                    Require(route.GetProperty("final").GetString() == "proxy");
                    var rules = route.GetProperty("rules").EnumerateArray().ToArray();
                    int dnsRule = Array.FindIndex(rules, rule => rule.GetProperty("action").GetString() == "hijack-dns");
                    int udpRule = Array.FindIndex(rules, rule => rule.TryGetProperty("network", out var network) &&
                        network.GetString() == "udp" && rule.GetProperty("action").GetString() == "reject");
                    Require(dnsRule >= 0 && udpRule > dnsRule);
                    var directRules = rules.Where(rule => rule.TryGetProperty("outbound", out var outbound) &&
                        outbound.GetString() == "direct").ToArray();
                    if (hasExclusions)
                    {
                        Require(outbounds.Count(item => item.GetProperty("type").GetString() == "direct") == 1);
                        Require(directRules.Length == 1);
                        Require(directRules[0].GetProperty("process_path").EnumerateArray().Select(path => path.GetString())
                            .SequenceEqual(settings.ExcludedApplications));
                        int directRule = Array.FindIndex(rules, rule => rule.TryGetProperty("outbound", out var outbound) &&
                            outbound.GetString() == "direct");
                        Require(dnsRule < directRule && directRule < udpRule);
                    }
                    else
                    {
                        Require(directRules.Length == 0 && outbounds.All(item => item.GetProperty("type").GetString() != "direct"));
                    }

                    var tun = root.GetProperty("inbounds")[0];
                    Require(tun.GetProperty("interface_name").GetString() == "ProxyBridge-TUN");
                    Require(tun.GetProperty("auto_route").GetBoolean() && tun.GetProperty("strict_route").GetBoolean());
                    Require(tun.GetProperty("route_exclude_address").EnumerateArray().Select(item => item.GetString())
                        .SequenceEqual(new[] { settings.Host + "/32" }));
                    return Task.CompletedTask;
                });
            }
        }
    }
}
