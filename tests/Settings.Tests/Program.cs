using System.Text;
using ProxyBridge;

// Separate settings-only host. Never enters the application, prepares its
// payload, acquires its mutex, starts a process, or calls the network guard.
if (args.Length > 1)
{
    throw new ArgumentException("Expected at most one new output directory under artifacts.");
}

string artifacts = Path.GetFullPath("artifacts");
string output = Path.GetFullPath(args.Length == 1 ? args[0] :
    Path.Combine(artifacts, "settings-tests-" + Guid.NewGuid().ToString("N")));
if (!output.StartsWith(artifacts + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
{
    throw new ArgumentException("Test output must be inside the working directory's artifacts folder.");
}

if (Directory.Exists(output) || File.Exists(output))
{
    throw new IOException("Test output directory must be new.");
}

Directory.CreateDirectory(output);

var report = new List<string>();
int failures = 0;
string? originalDirectory = Settings.TestDirectory;
async Task Test(string name, Func<Task> action)
{
    string? previousDirectory = Settings.TestDirectory;
    Settings.TestDirectory = Path.Combine(output, "case-" + report.Count.ToString("D2"));
    try
    {
        await action();
        report.Add("PASS: " + name);
    }
    catch (Exception error)
    {
        failures++;
        // Preserve only the type: even test failures must not echo credentials.
        report.Add("FAIL: " + name + " (" + error.GetType().Name + ")");
    }
    finally
    {
        Settings.TestDirectory = previousDirectory;
    }
    Console.WriteLine(report[^1]);
    File.WriteAllLines(Path.Combine(output, "results.txt"), report, new UTF8Encoding(false));
}

try
{
    Settings.TestDirectory = output;
    await SettingsTests.RunAsync(Test);
}
finally
{
    Settings.TestDirectory = originalDirectory;
}
Console.WriteLine($"SUMMARY: {report.Count - failures} PASS, {failures} FAIL; isolated settings only, no engine or network operations.");
return failures == 0 ? 0 : 1;
