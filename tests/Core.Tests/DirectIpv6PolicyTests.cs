using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace ProxyBridge;

internal static class DirectIpv6PolicyTests
{
    const string Excluded = @"C:\QA Apps\browser.exe";
    const string Other = @"C:\QA Apps\other.exe";

    sealed record Flow(string Process, string Destination, string[] DefaultAddresses,
        int Port = 443, string Network = "tcp");

    static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    // This exact allowlist is also used by frozen-baseline parity. It permits
    // one additive policy change, not normalization of arbitrary reject rules.
    internal static void RequireExactAddedRule(JsonNode? actual, string[] exclusions)
    {
        var expected = JsonNode.Parse("""
            {
              "type": "logical", "mode": "and",
              "rules": [
                { "process_path": [], "ip_version": 6, "ip_cidr": ["2000::/3"] },
                { "default_interface_address": ["0.0.0.0/0"] },
                { "default_interface_address": ["2000::/3"], "invert": true },
                { "default_interface_address": ["fc00::/7"], "invert": true }
              ],
              "action": "reject", "method": "default", "no_drop": true
            }
            """)!;
        expected["rules"]![0]!["process_path"] = new JsonArray(exclusions
            .Select(path => (JsonNode?)JsonValue.Create(path)).ToArray());
        Require(JsonNode.DeepEquals(expected, actual), "Unexpected additive direct IPv6 policy.");
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> test)
    {
        foreach (string protocol in new[] { "http", "socks" })
        {
            var settings = new Settings("192.0.2.10", 8080, "synthetic-user", "synthetic-password", protocol)
            {
                ExcludedApplications = [Excluded]
            };
            var config = JsonNode.Parse(Engine.Configuration(settings))!;
            var rules = config["route"]!["rules"]!.AsArray();

            await test($"direct IPv6 {protocol}: exact additive rule and priority", () =>
            {
                Require(rules.Count == 4, "Expected DNS, IPv6 fallback, direct and UDP rules.");
                Require(rules[0]!["action"]!.GetValue<string>() == "hijack-dns", "DNS must remain first.");
                RequireExactAddedRule(rules[1], settings.ExcludedApplications);
                Require(rules[2]!["outbound"]!.GetValue<string>() == "direct", "Direct exclusion must follow reject.");
                Require(rules[3]!["network"]!.GetValue<string>() == "udp", "UDP fallback must remain last.");
                return Task.CompletedTask;
            });

            async Task Case(string name, Flow flow, string expected) =>
                await test($"direct IPv6 {protocol}: {name}", () =>
                {
                    Require(Route(config, flow) == expected, $"Unexpected routing outcome for {name}.");
                    return Task.CompletedTask;
                });

            string[] ipv4 = ["192.0.2.20"];
            await Case("excluded global IPv6 on IPv4-only default rejects", new(Excluded, "2001:db8::10", ipv4), "reject");
            await Case("link-local interface IPv6 does not imply global reachability",
                new(Excluded, "2001:db8::10", ["192.0.2.20", "fe80::20"]), "reject");
            await Case("default interface missing preserves direct", new(Excluded, "2001:db8::10", []), "direct");
            await Case("IPv6-only default preserves direct", new(Excluded, "2001:db8::10", ["2001:db8::20"]), "direct");
            await Case("ULA-only default preserves direct", new(Excluded, "2001:db8::10", ["fd00::20"]), "direct");
            await Case("link-local-only default is not evidence of IPv4 connectivity",
                new(Excluded, "2001:db8::10", ["fe80::20"]), "direct");
            await Case("GUA without ULA preserves direct",
                new(Excluded, "2001:db8::10", ["192.0.2.20", "2001:db8::20"]), "direct");
            await Case("ULA without GUA preserves direct",
                new(Excluded, "2001:db8::10", ["192.0.2.20", "fd00::20"]), "direct");
            await Case("GUA and ULA preserve direct",
                new(Excluded, "2001:db8::10", ["192.0.2.20", "2001:db8::20", "fd00::20"]), "direct");
            await Case("nonexcluded global IPv6 keeps proxy", new(Other, "2001:db8::10", ipv4), "proxy");
            await Case("same executable basename is not an exclusion",
                new(@"C:\Other\browser.exe", "2001:db8::10", ipv4), "proxy");
            await Case("excluded IPv4 keeps direct", new(Excluded, "198.51.100.10", ipv4), "direct");
            await Case("DNS precedes excluded IPv6 rejection", new(Excluded, "2001:db8::53", ipv4, 53, "udp"), "hijack-dns");
            await Case("TCP DNS also precedes exclusions", new(Excluded, "2001:db8::53", ipv4, 53), "hijack-dns");
            await Case("nonexcluded UDP remains rejected", new(Other, "2001:db8::10", ipv4, 443, "udp"), "reject");
            await Case("excluded IPv4 UDP remains direct", new(Excluded, "198.51.100.10", ipv4, 443, "udp"), "direct");

            foreach (string destination in new[] { "2000::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" })
            {
                await Case($"global prefix boundary {destination} rejects", new(Excluded, destination, ipv4), "reject");
            }
            foreach (string destination in new[] { "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "4000::", "fc00::1", "fdff::1", "fe80::1", "ff02::1", "::1", "::ffff:192.0.2.1" })
            {
                await Case($"nonglobal destination {destination} preserves direct", new(Excluded, destination, ipv4), "direct");
            }

            await test($"direct IPv6 {protocol}: detects combined-prefix AND regression", () =>
            {
                var mutated = config.DeepClone();
                var conditions = mutated["route"]!["rules"]![1]!["rules"]!.AsArray();
                conditions[2]!["default_interface_address"] = new JsonArray("2000::/3", "fc00::/7");
                conditions.RemoveAt(3);
                // sing-box requires each prefix in this specific field to match
                // an interface address. A combined inverted array is NOT NOR.
                Require(Route(mutated, new(Excluded, "2001:db8::10", ["192.0.2.20", "2001:db8::20"])) == "reject",
                    "The oracle must expose the GUA-only combined-prefix regression.");
                Require(Route(mutated, new(Excluded, "2001:db8::10", ["192.0.2.20", "fd00::20"])) == "reject",
                    "The oracle must expose the ULA-only combined-prefix regression.");
                return Task.CompletedTask;
            });
        }
    }

    // Independent, deliberately small policy interpreter for synthetic flows.
    // It validates generated rule decisions, not OS connectivity or sing-box's
    // implementation; real-engine parsing/runtime validation is a separate check.
    static string Route(JsonNode config, Flow flow)
    {
        foreach (var rule in config["route"]!["rules"]!.AsArray())
        {
            if (!Matches(rule!.AsObject(), flow))
            {
                continue;
            }
            string action = rule["action"]!.GetValue<string>();
            return action == "route" ? rule["outbound"]!.GetValue<string>() : action;
        }
        return config["route"]!["final"]!.GetValue<string>();
    }

    static bool Matches(JsonObject rule, Flow flow)
    {
        bool matches = true;
        foreach (var (key, value) in rule)
        {
            matches &= key switch
            {
                "type" or "mode" or "action" or "outbound" or "method" or "no_drop" or "invert" => true,
                "rules" => rule["mode"]!.GetValue<string>() switch
                {
                    "and" => value!.AsArray().All(child => Matches(child!.AsObject(), flow)),
                    "or" => value!.AsArray().Any(child => Matches(child!.AsObject(), flow)),
                    _ => throw new InvalidOperationException("Unsupported logical rule mode.")
                },
                "process_path" => value!.AsArray().Any(path => path!.GetValue<string>() == flow.Process),
                "ip_version" => value!.GetValue<int>() == (IPAddress.Parse(flow.Destination).AddressFamily == AddressFamily.InterNetwork ? 4 : 6),
                "ip_cidr" => value!.AsArray().Any(prefix => Contains(prefix!.GetValue<string>(), flow.Destination)),
                "default_interface_address" => value!.AsArray().All(prefix => flow.DefaultAddresses.Any(address => Contains(prefix!.GetValue<string>(), address))),
                "port" => value!.GetValue<int>() == flow.Port,
                "network" => value!.GetValue<string>() == flow.Network,
                _ => throw new InvalidOperationException("Unsupported rule field in policy test: " + key)
            };
        }
        return rule["invert"]?.GetValue<bool>() == true ? !matches : matches;
    }

    static bool Contains(string prefix, string address)
    {
        string[] parts = prefix.Split('/');
        byte[] network = IPAddress.Parse(parts[0]).GetAddressBytes();
        byte[] candidate = IPAddress.Parse(address).GetAddressBytes();
        if (network.Length != candidate.Length)
        {
            return false;
        }
        int bits = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture);
        for (int bit = 0; bit < bits; bit++)
        {
            int mask = 1 << (7 - bit % 8);
            if ((network[bit / 8] & mask) != (candidate[bit / 8] & mask))
            {
                return false;
            }
        }
        return true;
    }
}
