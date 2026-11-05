using System.ComponentModel;
using System.Text;
using ProxyBridge;

// Separate settings-only host. Never enters the application, prepares its
// payload, acquires its mutex, starts a process, or calls the network guard.
if (args.Length > 1) throw new ArgumentException("Expected at most one new output directory under artifacts.");
string artifacts = Path.GetFullPath("artifacts");
string output = Path.GetFullPath(args.Length == 1 ? args[0] :
    Path.Combine(artifacts, "settings-tests-" + Guid.NewGuid().ToString("N")));
if (!output.StartsWith(artifacts + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
    throw new ArgumentException("Test output must be inside the working directory's artifacts folder.");
if (Directory.Exists(output) || File.Exists(output)) throw new IOException("Test output directory must be new.");
Directory.CreateDirectory(output);

var report = new List<string>();
int failures = 0;
string? originalDirectory = Settings.TestDirectory;
void Require(bool condition)
{
    if (!condition) throw new InvalidOperationException("Settings assertion failed.");
}
async Task Test(string name, Func<Task> action)
{
    string? previousDirectory = Settings.TestDirectory;
    Settings.TestDirectory = Path.Combine(output, "case-" + report.Count.ToString("D2"));
    try {
        await action();
        report.Add("PASS: " + name);
    } catch (Exception error) {
        failures++;
        // Preserve only the type: even test failures must not echo credentials.
        report.Add("FAIL: " + name + " (" + error.GetType().Name + ")");
    } finally {
        Settings.TestDirectory = previousDirectory;
    }
    Console.WriteLine(report[^1]);
    File.WriteAllLines(Path.Combine(output, "results.txt"), report, new UTF8Encoding(false));
}

try {
    Settings.TestDirectory = output;
    await SelfTest.RunInitialSettingsTestsAsync(Test);
    await Test("synthetic settings survive encrypted save/load without plaintext credentials", () => {
        var sample = new Settings("192.0.2.10", 8080, "qa-settings-user", "qa-settings-secret-42", "http") {
            ActivityLoggingEnabled = false
        };
        sample.Save();
        var loaded = Settings.Load();
        loaded.Validate();
        Require(loaded.Host == sample.Host && loaded.Port == sample.Port && loaded.Protocol == sample.Protocol);
        Require(loaded.Username == sample.Username && loaded.Password == sample.Password);
        Require(loaded.ExcludedApplications.Length == 0 && !loaded.ActivityLoggingEnabled);
        string path = Path.Combine(Settings.DataDir, "settings.dat");
        byte[] encrypted = File.ReadAllBytes(path);
        Require(encrypted.Length > 0 && !Encoding.UTF8.GetString(encrypted).Contains(sample.Password, StringComparison.Ordinal));
        Require(!File.Exists(path + ".tmp"));
        bool rejected = false;
        try { Settings.Default.Save(); } catch (ArgumentException) { rejected = true; }
        Require(rejected && File.ReadAllBytes(path).SequenceEqual(encrypted));
        Require(Settings.Load().Password == sample.Password);
        return Task.CompletedTask;
    });
    await Test("corrupt settings fail without falling back to defaults or replacing the file", () => {
        Settings.PrepareDirectory();
        string path = Path.Combine(Settings.DataDir, "settings.dat");
        byte[] corrupt = [0, 1, 2, 3, 4, 5];
        File.WriteAllBytes(path, corrupt);
        bool rejected = false;
        try { _ = Settings.Load(); } catch (Win32Exception) { rejected = true; }
        Require(rejected && File.ReadAllBytes(path).SequenceEqual(corrupt));
        Require(!File.Exists(path + ".tmp"));
        return Task.CompletedTask;
    });
} finally {
    Settings.TestDirectory = originalDirectory;
}
Console.WriteLine($"SUMMARY: {report.Count - failures} PASS, {failures} FAIL; isolated settings only, no engine or network operations.");
return failures == 0 ? 0 : 1;
