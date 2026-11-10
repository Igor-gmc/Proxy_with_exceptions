using System.Text.Json;

namespace ProxyBridge;

/// <summary>Builds the sing-box policy without touching processes, files or network state.</summary>
internal static class EngineConfiguration
{
    static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string Create(Settings settings)
    {
        settings.Validate();
        return JsonSerializer.Serialize(new
        {
            log = new
            {
                level = "warn",
                timestamp = true
            },
            dns = CreateDns(),
            inbounds = new[] { CreateTunInbound(settings.Host) },
            outbounds = CreateOutbounds(settings),
            route = new
            {
                auto_detect_interface = true,
                final = "proxy",
                rules = CreateRoutingRules(settings)
            }
        }, JsonOptions);
    }

    static object CreateDns() => new
    {
        servers = new[]
        {
            new
            {
                type = "https",
                tag = "remote-dns",
                server = "1.1.1.1",
                server_port = 443,
                path = "/dns-query",
                detour = "proxy",
                tls = new { enabled = true, server_name = "cloudflare-dns.com" }
            }
        },
        final = "remote-dns",
        strategy = "ipv4_only"
    };

    static object CreateTunInbound(string proxyHost) => new
    {
        type = "tun",
        tag = "tun",
        interface_name = "ProxyBridge-TUN",
        address = new[] { "172.29.231.1/30", "fdfe:dcba:7231::1/126" },
        mtu = 1500,
        auto_route = true,
        strict_route = true,
        dns_mode = "hijack",
        route_exclude_address = new[] { proxyHost + "/32" }
    };

    static List<object> CreateOutbounds(Settings settings)
    {
        var outbounds = new List<object>
        {
            new
            {
                type = settings.Protocol,
                tag = "proxy",
                server = settings.Host,
                server_port = settings.Port,
                username = settings.Username,
                password = settings.Password
            }
        };
        if (settings.ExcludedApplications.Length > 0 || settings.ExcludedAddresses.Length > 0)
        {
            outbounds.Add(new
            {
                type = "direct",
                tag = "direct"
            });
        }

        return outbounds;
    }

    static List<object> CreateRoutingRules(Settings settings)
    {
        // DNS interception precedes exclusions; unsupported UDP is rejected last.
        var rules = new List<object> { new { port = 53, action = "hijack-dns" } };
        if (settings.ExcludedApplications.Length > 0)
        {
            // Reject public IPv6 when the current default IPv4 uplink lacks
            // GUA/ULA addresses; this does not test general route reachability.
            rules.Add(new
            {
                type = "logical",
                mode = "and",
                rules = new object[]
                {
                    new
                    {
                        process_path = settings.ExcludedApplications,
                        ip_version = 6,
                        ip_cidr = new[] { "2000::/3" }
                    },
                    new { default_interface_address = new[] { "0.0.0.0/0" } },
                    new { default_interface_address = new[] { "2000::/3" }, invert = true },
                    new { default_interface_address = new[] { "fc00::/7" }, invert = true }
                },
                action = "reject",
                method = "default",
                no_drop = true
            });
            rules.Add(new
            {
                process_path = settings.ExcludedApplications,
                action = "route",
                outbound = "direct"
            });
        }

        foreach (string value in settings.ExcludedAddresses)
        {
            var address = AddressExclusion.Parse(value);
            var match = new Dictionary<string, object>
            {
                ["network"] = new[] { "tcp", "udp" },
                ["ip_cidr"] = new[] { address.Cidr }
            };
            if (address.Port is int port)
            {
                match["port"] = port;
            }

            if (address.IsIPv6)
            {
                rules.Add(new
                {
                    type = "logical",
                    mode = "and",
                    rules = new object[]
                    {
                        match,
                        new { ip_version = 6, ip_cidr = new[] { "2000::/3" } },
                        new { default_interface_address = new[] { "0.0.0.0/0" } },
                        new { default_interface_address = new[] { "2000::/3" }, invert = true },
                        new { default_interface_address = new[] { "fc00::/7" }, invert = true }
                    },
                    action = "reject",
                    method = "default",
                    no_drop = true
                });
            }

            rules.Add(new Dictionary<string, object>(match)
            {
                ["action"] = "route",
                ["outbound"] = "direct"
            });
        }

        rules.Add(new
        {
            network = "udp",
            action = "reject"
        });
        return rules;
    }
}
