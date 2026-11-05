namespace ProxyBridge;

internal static class ShippingAssemblyTests
{
    internal static Task RunAsync(Func<string, Func<Task>, Task> test) =>
        test("assembly boundary: shipping code contains no test suites or TestHost dependency", () =>
        {
            var assembly = typeof(Settings).Assembly;
            string[] forbidden = ["SelfTest", "MonitorUiTests", "ProtectionControllerTests", "ConnectionProbeTests",
                "NetworkTest", "UiTestSuite", "SettingsTests", "TestHostProgram"];
            foreach (string name in forbidden)
            {
                if (assembly.GetType("ProxyBridge." + name, throwOnError: false) != null)
                {
                    throw new InvalidOperationException("A test-only type is present in the shipping assembly.");
                }
            }

            if (assembly.GetReferencedAssemblies().Any(reference =>
                reference.Name == "ProxyBridge.TestHost" || reference.Name == "ProxyBridge.Core.Tests"))
            {
                throw new InvalidOperationException("Shipping code references a test host.");
            }

            return Task.CompletedTask;
        });
}
