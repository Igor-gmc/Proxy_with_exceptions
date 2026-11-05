using System.Text;
using ProxyBridge;

string output = Path.GetFullPath(args.Length == 1 ? args[0] :
    Path.Combine("artifacts", "diagnostics-tests-" + Guid.NewGuid().ToString("N")));
if (Directory.Exists(output))
{
    throw new IOException("Test output directory must be new.");
}

Directory.CreateDirectory(output);
var report = new List<string>();
int failures = 0;
await DiagnosticsTests.RunAsync(async (name, action) =>
{
    string directory = Path.Combine(output, "case-" + report.Count.ToString("D2"));
    Directory.CreateDirectory(directory);
    try
    { await action(directory); report.Add("PASS: " + name); }
    catch (Exception error)
    {
        failures++;
        // Exception messages may contain synthetic secrets; report types only.
        report.Add("FAIL: " + name + " (" + error.GetType().Name + ")");
    }
    Console.WriteLine(report[^1]);
    File.WriteAllLines(Path.Combine(output, "results.txt"), report, new UTF8Encoding(false));
});
Console.WriteLine($"SUMMARY: {report.Count - failures} PASS, {failures} FAIL; pure tests, no native collectors, subprocesses or network started.");
return failures == 0 ? 0 : 1;
