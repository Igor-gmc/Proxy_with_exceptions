using System.Text.Json.Nodes;

namespace ProxyBridge;

internal static class ConfigurationParityTests
{
    // Frozen from the pre-refactoring implementation at commit 0c20081.
    // Values are synthetic; arrays retain their meaningful routing order.
    internal static async Task RunAsync(Func<string, Func<Task>, Task> test)
    {
        foreach (string protocol in new[] { "http", "socks" })
        {
            foreach (bool exclusions in new[] { false, true })
            {
                string fixture = protocol + (exclusions ? "-exclusions" : "-proxy-only") + ".json.txt";
                await test("configuration parity: " + fixture, () =>
                {
                    using var stream = typeof(ConfigurationParityTests).Assembly.GetManifestResourceStream("ConfigurationBaseline." + fixture)
                        ?? throw new InvalidOperationException("Frozen configuration fixture is missing.");
                    var expected = JsonNode.Parse(stream);
                    var settings = new Settings("192.0.2.10", 8080, "synthetic-user", "synthetic-password", protocol)
                    {
                        ExcludedApplications = exclusions ? [@"C:\QA Apps\browser.exe"] : []
                    };
                    var actual = JsonNode.Parse(Engine.Configuration(settings));
                    if (exclusions)
                    {
                        var actualRules = actual!["route"]!["rules"]!.AsArray();
                        var baselineRules = expected!["route"]!["rules"]!.AsArray();
                        if (actualRules.Count != baselineRules.Count + 1)
                        {
                            throw new InvalidOperationException("Expected exactly one additive IPv6 direct rule.");
                        }
                        DirectIpv6PolicyTests.RequireExactAddedRule(actualRules[1], settings.ExcludedApplications);
                        actualRules.RemoveAt(1);
                    }
                    if (!JsonNode.DeepEquals(expected, actual))
                    {
                        throw new InvalidOperationException("Generated configuration differs from the pre-refactoring baseline.");
                    }

                    return Task.CompletedTask;
                });
            }
        }
    }
}
