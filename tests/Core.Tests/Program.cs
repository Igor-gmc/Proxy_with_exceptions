using System.Runtime.InteropServices;
using System.Text;
using ProxyBridge;

// Pure policy, configuration and mocked transport checks. No UI, native guard,
// engine process, user settings, Task Scheduler or real network operations.
if (args.Length > 1)
{
    throw new ArgumentException("Expected at most one new output directory under artifacts.");
}

string artifacts = Path.GetFullPath("artifacts");
string output = Path.GetFullPath(args.Length == 1 ? args[0] :
    Path.Combine(artifacts, "core-tests-" + Guid.NewGuid().ToString("N")));
if (!output.StartsWith(artifacts + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
    Directory.Exists(output) || File.Exists(output))
{
    throw new ArgumentException("Output must be a new directory under artifacts.");
}

Directory.CreateDirectory(output);

NativeLibrary.SetDllImportResolver(typeof(Guard).Assembly, (name, _, _) =>
{
    if (name.Equals("ProxyGuard.dll", StringComparison.OrdinalIgnoreCase))
    {
        throw new DllNotFoundException("Native guard calls are forbidden in the core test host.");
    }

    return IntPtr.Zero;
});

var results = new List<string>();
int failures = 0;
async Task Test(string name, Func<Task> action)
{
    try
    {
        await action();
        results.Add("PASS: " + name);
    }
    catch (Exception error)
    {
        failures++;
        results.Add("FAIL: " + name + " (" + error.GetType().Name + ")");
    }
    Console.WriteLine(results[^1]);
    File.WriteAllLines(Path.Combine(output, "results.txt"), results, new UTF8Encoding(false));
}

var settings = new Settings("192.0.2.10", 1080, "qa-user", "synthetic-core-only", "http");
await ProtectionControllerTests.RunAsync(Test, settings);
await ConnectionProbeTests.RunAsync(Test);
await ConfigurationTests.RunAsync(Test);
await ConfigurationParityTests.RunAsync(Test);
await ApplicationCommandTests.RunAsync(Test);
await ShippingAssemblyTests.RunAsync(Test);
await TunReadinessTests.RunAsync(Test);
await ProxySpeedTests.RunAsync(Test);
Console.WriteLine($"SUMMARY: {results.Count - failures} PASS, {failures} FAIL; no live network or native guard calls.");
return failures == 0 ? 0 : 1;
