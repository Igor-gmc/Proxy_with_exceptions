using System.Text.Json.Nodes;

namespace ProxyBridge;

internal static class AddressExclusionTests
{
    const string Other = @"C:\QA Apps\other.exe";
    const string Excluded = @"C:\QA Apps\browser.exe";

    static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    static void Reject(Action action)
    {
        try { action(); }
        catch (ArgumentException) { return; }
        throw new InvalidOperationException("Invalid address exception was accepted.");
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> test)
    {
        var baseline = new Settings("192.0.2.10", 1080, "qa-user", "synthetic-address-only", "http");
        var valid = new (string Input, string Value, string Cidr, int? Port)[]
        {
            ("192.168.1.0/24", "192.168.1.0/24", "192.168.1.0/24", null),
            ("192.168.1.199/24:8080", "192.168.1.0/24:8080", "192.168.1.0/24", 8080),
            ("192.168.1.10:1", "192.168.1.10:1", "192.168.1.10/32", 1),
            ("192.168.1.10/32:65535", "192.168.1.10:65535", "192.168.1.10/32", 65535),
            ("198.51.100.200/25", "198.51.100.128/25", "198.51.100.128/25", null),
            ("255.255.255.255/0", "0.0.0.0/0", "0.0.0.0/0", null),
            ("FD00:0:0:0:0:0:0:ABCD/64", "fd00::/64", "fd00::/64", null),
            ("[fd00::abcd/64]:8443", "[fd00::/64]:8443", "fd00::/64", 8443),
            ("[2001:db8::1/128]:65535", "[2001:db8::1]:65535", "2001:db8::1/128", 65535),
            ("2001:db8::1", "2001:db8::1", "2001:db8::1/128", null),
            ("2001:db8::1/0", "::/0", "::/0", null)
        };
        foreach (var entry in valid)
        {
            await test("address parse: " + entry.Input, () =>
            {
                var parsed = AddressExclusion.Parse(entry.Input);
                Require(parsed.Value == entry.Value && parsed.Cidr == entry.Cidr && parsed.Port == entry.Port,
                    "Canonical address, CIDR or port differs.");
                Require(AddressExclusion.TryParse(entry.Input, out var tried) && tried == parsed,
                    "TryParse disagrees with Parse.");
                Require(AddressExclusion.Parse(parsed.Value) == parsed, "Canonical input is not idempotent.");
                return Task.CompletedTask;
            });
        }

        await test("address validation rejects malformed, ambiguous and DNS inputs", () =>
        {
            string[] invalid = ["", " ", "localhost", "https://192.168.1.1", "192.168.1", "127.1", "0xC0A80101", "192.168.001.1",
                "192.168.1.256", "192.168.1.1/33", "192.168.1.1/-1", "192.168.1.1/", "192.168.1.1:0",
                "192.168.1.1:65536", "192.168.1.1:-1", "192.168.1.1:53", "192.168.1.1/24:53", "192.168.1.1:80:90",
                "192.168.1.1:80/24", "192.168.1.1/24/24", "fd00::1/129", "fd00::1/-1", "fe80::1%12",
                "[fe80::1%12]:80", "::ffff:192.168.1.1", "[::ffff:192.168.1.1]:80", "[fd00::1]:53",
                "[fd00::1]:0", "[fd00::1]:65536", "[fd00::1]", "[fd00::1]:", "[192.168.1.1]:80"];
            foreach (string input in invalid)
            {
                Reject(() => AddressExclusion.Parse(input));
                Require(!AddressExclusion.TryParse(input, out _), "TryParse accepted malformed input.");
            }
            Reject(() => { _ = baseline with { ExcludedAddresses = null! }; });
            Reject(() => { _ = baseline with { ExcludedAddresses = [null!] }; });
            return Task.CompletedTask;
        });

        await test("address settings canonicalize and deduplicate without merging different ports", () =>
        {
            var settings = baseline with { ExcludedAddresses = ["192.168.1.99/24", "192.168.1.0/24",
                "192.168.1.9/24:80", "192.168.1.0/24:443", "FD00::1/64", "fd00::/64"] };
            Require(settings.ExcludedAddresses.SequenceEqual(new[] { "192.168.1.0/24", "192.168.1.0/24:80",
                "192.168.1.0/24:443", "fd00::/64" }), "Normalization changed explicit rule meaning.");
            Require((baseline with { ExcludedAddresses = Enumerable.Repeat("192.168.1.0/24", 100).ToArray() })
                .ExcludedAddresses.Length == 1, "Limit should apply to unique rules.");
            var sixtyFour = baseline with { ExcludedAddresses = Enumerable.Range(1, 64).Select(i => "198.51.100." + i).ToArray() };
            sixtyFour.Validate();
            Reject(() => { _ = baseline with { ExcludedAddresses = Enumerable.Range(1, 65).Select(i => "198.51.100." + i).ToArray() }; });
            return Task.CompletedTask;
        });

        await test("address-only explicit stop retains rules without enabling shared DNS", async () =>
        {
            var settings = baseline with { ExcludedAddresses = ["192.168.1.0/24"] };
            var requests = new List<(Settings Settings, ulong Luid, bool Dns)>();
            var operations = new ProtectionOperations(() => 1, () => false,
                (value, luid, dns) => requests.Add((value, luid, dns)),
                (_, luid, dns) => luid == 0 && !dns,
                () => Task.CompletedTask,
                () => throw new InvalidOperationException("An explicit stop must not remove protection."),
                () => { });
            var controller = new ProtectionController(settings, operations);
            controller.RequestBlock();
            var result = await controller.RearmAsync();
            Require(result.Succeeded && result.PolicyVerified && !result.Released, "Address-only stop did not preserve protection.");
            Require(requests.Count > 0 && requests.All(request => !request.Dns && request.Luid == 0 &&
                request.Settings.ExcludedAddresses.SequenceEqual(settings.ExcludedAddresses)),
                "Stop enabled shared DNS or lost the address exceptions.");
            Require(!controller.StoppedDnsAllowed && controller.IsExpectedPolicy(), "Stopped state disagrees with address-only policy.");
        });

        foreach (string protocol in new[] { "http", "socks" })
        {
            var settings = baseline with
            {
                Protocol = protocol,
                ExcludedAddresses = ["192.168.1.0/24", "198.51.100.0/25:8443", "203.0.113.9:443", "[fd00::/64]:8080", "2001:db8::/32"]
            };
            var config = JsonNode.Parse(Engine.Configuration(settings))!;
            await test($"address configuration {protocol}: DNS, direct outbound, route bounds", () =>
            {
                Require(config["dns"]!["servers"]![0]!["detour"]!.GetValue<string>() == "proxy", "DNS bypasses proxy.");
                Require(config["route"]!["rules"]![0]!["action"]!.GetValue<string>() == "hijack-dns", "DNS rule is not first.");
                Require(config["outbounds"]!.AsArray().Count(item => item!["tag"]!.GetValue<string>() == "direct") == 1,
                    "Address-only settings lack exactly one direct outbound.");
                Require(config["inbounds"]![0]!["route_exclude_address"]!.AsArray().Select(item => item!.GetValue<string>())
                    .SequenceEqual(new[] { baseline.Host + "/32" }), "Address rules bypass TUN routing.");
                Require(config["route"]!["final"]!.GetValue<string>() == "proxy", "Default route was broadened.");
                return Task.CompletedTask;
            });

            async Task Case(string name, string destination, int port, string network, string expected,
                string[]? interfaces = null, string process = Other) =>
                await test($"address routing {protocol}: {name}", () =>
                {
                    var flow = new DirectIpv6PolicyTests.Flow(process, destination, interfaces ?? ["192.0.2.20"], port, network);
                    Require(DirectIpv6PolicyTests.Route(config, flow) == expected, "Unexpected address routing decision.");
                    return Task.CompletedTask;
                });

            await Case("requested LAN first address", "192.168.1.0", 80, "tcp", "direct");
            await Case("requested LAN last address", "192.168.1.255", 65535, "udp", "direct");
            await Case("before LAN stays proxy", "192.168.0.255", 80, "tcp", "proxy");
            await Case("after LAN UDP rejected", "192.168.2.0", 80, "udp", "reject");
            await Case("LAN TCP DNS hijacked", "192.168.1.1", 53, "tcp", "hijack-dns");
            await Case("LAN UDP DNS hijacked", "192.168.1.1", 53, "udp", "hijack-dns");
            await Case("CIDR and port match", "198.51.100.127", 8443, "tcp", "direct");
            await Case("wrong port stays proxy", "198.51.100.127", 443, "tcp", "proxy");
            await Case("wrong port UDP rejected", "198.51.100.127", 443, "udp", "reject");
            await Case("right port outside CIDR stays proxy", "198.51.100.128", 8443, "tcp", "proxy");
            await Case("host and port match", "203.0.113.9", 443, "udp", "direct");
            await Case("host rule cannot borrow other rule port", "203.0.113.9", 8443, "tcp", "proxy");
            await Case("LAN never permits unsupported protocol", "192.168.1.1", 80, "icmp", "proxy");
            await Case("ULA matched port direct", "fd00::1234", 8080, "tcp", "direct");
            await Case("ULA wrong port stays proxy", "fd00::1234", 443, "tcp", "proxy");
            await Case("ULA outside prefix stays proxy", "fd00:0:0:1::1", 8080, "tcp", "proxy");
            await Case("global IPv6 IPv4-only fallback", "2001:db8::1", 443, "tcp", "reject");
            await Case("global IPv6 GUA uplink direct", "2001:db8::1", 443, "tcp", "direct", ["192.0.2.20", "2001:db8:1::1"]);
            await Case("global IPv6 ULA uplink direct", "2001:db8::1", 443, "tcp", "direct", ["192.0.2.20", "fd00::1"]);
            await Case("unmatched global IPv6 remains proxy", "2001:db9::1", 443, "tcp", "proxy");
            await Case("global IPv6 DNS precedes fallback", "2001:db8::53", 53, "udp", "hijack-dns");

            await test($"address routing {protocol}: EXE and destination rules are independent", () =>
            {
                var mixed = JsonNode.Parse(Engine.Configuration(settings with { ExcludedApplications = [Excluded] }))!;
                Require(DirectIpv6PolicyTests.Route(mixed, new(Excluded, "203.0.113.10", ["192.0.2.20"], 80)) == "direct",
                    "Address rules restricted an existing EXE exception.");
                Require(DirectIpv6PolicyTests.Route(mixed, new(Other, "192.168.1.10", ["192.0.2.20"], 80)) == "direct",
                    "Destination exception incorrectly requires an excluded EXE.");
                Require(DirectIpv6PolicyTests.Route(mixed, new(Other, "203.0.113.10", ["192.0.2.20"], 80)) == "proxy",
                    "Unmatched process and destination escaped proxy.");
                return Task.CompletedTask;
            });
        }
    }
}
