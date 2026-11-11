using System.Text;
using System.Text.RegularExpressions;
using ProxyBridge;

const long productionLimit = 25_000_000;
string output = Path.GetFullPath(args.Length == 1 ? args[0] : Path.Combine("artifacts", "logging-tests-" + Guid.NewGuid().ToString("N")));
Directory.CreateDirectory(output);
var report = new List<string>();
var strictUtf8 = new UTF8Encoding(false, true);
int failures = 0;

void Require(bool condition, string reason)
{
    if (!condition)
    {
        throw new InvalidOperationException(reason);
    }
}
void Test(string name, Action<string> action)
{
    string directory = Path.Combine(output, "case-" + report.Count.ToString("D2"));
    Directory.CreateDirectory(directory);
    try
    { action(Path.Combine(directory, "ProxyBridge.log")); report.Add("PASS: " + name); }
    catch (Exception error)
    {
        failures++;
        // Exception messages may contain a synthetic secret or path: retain type only.
        report.Add("FAIL: " + name + " (" + error.GetType().Name + ")");
    }
    Console.WriteLine(report[^1]);
    File.WriteAllLines(Path.Combine(output, "results.txt"), report, new UTF8Encoding(false));
}
string Read(string path) => strictUtf8.GetString(File.ReadAllBytes(path));
void Seed(string path, long length, string marker)
{
    using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
    stream.Write(Encoding.UTF8.GetBytes(marker));
    stream.SetLength(length);
}

Test("UTF-8 text, date, timezone and process ID survive a fresh file", path =>
{
    var writer = new BoundedLogFile(path);
    Require(writer.Write("Проверка журнала: ёж 🦔"), "Write failed");
    string text = Read(path);
    Require(text.Contains("Проверка журнала: ёж 🦔", StringComparison.Ordinal), "Unicode changed");
    Require(Regex.IsMatch(text, @"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"), "Missing date/time");
    Require(Regex.IsMatch(text, @"[+-]\d{2}:\d{2}|\d{2}:\d{2}:\d{2}(?:\.\d+)?Z"), "Missing timezone");
    Require(text.Contains(Environment.ProcessId.ToString(), StringComparison.Ordinal), "Missing PID");
    Require(text.EndsWith('\n'), "Missing line ending");
});

Test("New logger instance appends to an existing session", path =>
{
    Require(new BoundedLogFile(path).Write("FIRST-SESSION-SENTINEL"), "Initial write failed");
    Require(new BoundedLogFile(path).Write("SECOND-SESSION-SENTINEL"), "Restart write failed");
    string text = Read(path);
    Require(text.Contains("FIRST-SESSION-SENTINEL") && text.Contains("SECOND-SESSION-SENTINEL"), "Session was lost");
});

Test("Production 25 MB file appends below its limit and rotates to .1 on overflow", path =>
{
    const string old = "PREVIOUS-CONTENTS-SENTINEL";
    Seed(path, productionLimit - 4096, old);
    var writer = new BoundedLogFile(path);
    Require(writer.Write("BELOW-LIMIT-SENTINEL"), "Below-limit write failed");
    Require(new FileInfo(path).Length > productionLimit - 4096 && new FileInfo(path).Length <= productionLimit, "Incorrect append length");
    using (var input = File.OpenRead(path))
    {
        byte[] prefix = new byte[Encoding.UTF8.GetByteCount(old)];
        input.ReadExactly(prefix);
        Require(Encoding.UTF8.GetString(prefix) == old, "Premature overwrite");
    }
    Seed(path, productionLimit - 1, old);
    Require(writer.Write("AFTER-OVERFLOW-SENTINEL"), "Overflow write failed");
    string text = Read(path);
    Require(new FileInfo(path).Length <= productionLimit, "Limit exceeded");
    Require(text.Contains("AFTER-OVERFLOW-SENTINEL") && !text.Contains(old), "Rotation did not start a new file");
    Require(text.Contains("previous records moved to " + Path.GetFileName(path) + ".1"), "Rotation marker missing");
    string previous = path + ".1";
    Require(File.Exists(previous) && new FileInfo(previous).Length == productionLimit - 1, "Previous generation not preserved");
    using (var input = File.OpenRead(previous))
    {
        byte[] prefix = new byte[Encoding.UTF8.GetByteCount(old)];
        input.ReadExactly(prefix);
        Require(Encoding.UTF8.GetString(prefix) == old, "Previous generation content changed");
    }
    Require(Directory.GetFiles(Path.GetDirectoryName(path)!).Length == 2, "Only one previous generation may be kept");
    Seed(path, productionLimit - 1, "SECOND-OVERFLOW-SENTINEL");
    Require(writer.Write("AFTER-SECOND-OVERFLOW"), "Second overflow write failed");
    Require(Read(previous).StartsWith("SECOND-OVERFLOW-SENTINEL", StringComparison.Ordinal), "Older generation not replaced");
    Require(Directory.GetFiles(Path.GetDirectoryName(path)!).Length == 2, "Rotation accumulated archives");
});

Test("Existing oversized file is replaced before the next record", path =>
{
    Seed(path, productionLimit + 1, "OVERSIZED-OLD-SENTINEL");
    Require(new BoundedLogFile(path).Write("OVERSIZED-REPLACED-SENTINEL"), "Write failed");
    Require(new FileInfo(path).Length <= productionLimit, "Oversized file retained");
    string text = Read(path);
    Require(!text.Contains("OVERSIZED-OLD-SENTINEL") && text.Contains("OVERSIZED-REPLACED-SENTINEL"), "Wrong contents after overwrite");
});

Test("Huge multi-byte record is bounded and remains valid UTF-8", path =>
{
    string message = "HUGE-ENTRY-START " + string.Concat(Enumerable.Repeat("я🦔", 500_000));
    Require(new BoundedLogFile(path).Write(message), "Huge write failed");
    Require(new FileInfo(path).Length <= 65_536, "Entry exceeds 64 KiB");
    string text = Read(path);
    Require(text.Contains("HUGE-ENTRY-START") && text.EndsWith('\n'), "Invalid truncated record");
    Require(!text.Contains('\uFFFD'), "UTF-8 was split or replaced");
});

Test("Small configured limit also bounds an oversized Unicode entry", path =>
{
    var writer = new BoundedLogFile(path, 4096);
    Require(writer.Write(string.Concat(Enumerable.Repeat("Проверка 🦔 ", 20_000))), "Write failed");
    Require(new FileInfo(path).Length <= 4096, "Configured limit exceeded");
    Require(Read(path).EndsWith('\n'), "Invalid last line");
    Require(writer.Write("NEXT-RECORD-SENTINEL"), "Next write failed");
    Require(new FileInfo(path).Length <= 4096 && Read(path).Contains("NEXT-RECORD-SENTINEL"), "Limit not maintained");
});

Test("Concurrent writes retain each complete record exactly once", path =>
{
    var writer = new BoundedLogFile(path);
    Parallel.For(0, 400, index => Require(writer.Write($"RECORD-{index:D4}-END"), "Concurrent write failed"));
    string text = Read(path);
    for (int index = 0; index < 400; index++)
    {
        Require(Regex.Matches(text, $"RECORD-{index:D4}-END").Count == 1, "Missing or duplicate record");
    }

    Require(text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length == 400, "Interleaved records");
});

Test("Current, previous and overlapping secrets are completely masked", path =>
{
    var writer = new BoundedLogFile(path);
    writer.RegisterSecret(null);
    writer.RegisterSecret("");
    writer.RegisterSecret("qa-overlap");
    writer.RegisterSecret("qa-overlap-SUFFIX");
    writer.RegisterSecret("qa-previous-secret");
    writer.RegisterSecret("qa-current-secret");
    writer.RegisterSecret("qa-cross");
    writer.RegisterSecret("cross-END");
    Require(writer.Write("Secrets: qa-overlap-SUFFIX / qa-overlap / qa-previous-secret / qa-current-secret / qa-cross-END"), "Write failed");
    string text = Read(path);
    Require(!text.Contains("qa-overlap") && !text.Contains("SUFFIX") && !text.Contains("qa-previous-secret") && !text.Contains("qa-current-secret"), "Secret or suffix leaked");
    Require(!text.Contains("qa-cross") && !text.Contains("cross-END") && !text.Contains("-END"), "Crossing secret fragments leaked");
    Require(text.Contains("***"), "Mask missing");
});

Test("URL-encoded and JSON-escaped secrets are masked", path =>
{
    var writer = new BoundedLogFile(path);
    const string synthetic = "qa \"юникод\"/\\secret";
    writer.RegisterSecret(synthetic);
    string escapedUrl = Uri.EscapeDataString(synthetic);
    string escapedJson = System.Text.Json.JsonSerializer.Serialize(synthetic)[1..^1];
    Require(writer.Write("raw=" + synthetic + " url=" + escapedUrl + " json=" + escapedJson), "Write failed");
    string text = Read(path);
    Require(!text.Contains(synthetic) && !text.Contains(escapedUrl) && !text.Contains(escapedJson), "Encoded secret leaked");
    Require(text.Contains("raw=*** url=*** json=***"), "Encoded variants not completely masked");
});

Test("UI extra secrets mask both overlap orders without retaining partial input", _ =>
{
    const string shortSecret = "qa-ui-overlap";
    const string longSecret = "qa-ui-overlap-SUFFIX";
    var savedLong = new SecretMask();
    savedLong.Register(longSecret);
    Require(savedLong.Redact(longSecret + " / " + shortSecret, shortSecret, longSecret) == "*** / ***", "Current-short/saved-long leaked");
    Require(savedLong.Redact(shortSecret) == shortSecret, "Current partial input retained permanently");
    Require(savedLong.Redact(longSecret) == "***", "Saved secret forgotten");
    var savedShort = new SecretMask();
    savedShort.Register(shortSecret);
    Require(savedShort.Redact(longSecret + " / " + shortSecret, longSecret, shortSecret) == "*** / ***", "Current-long/saved-short leaked");
    const string temporary = "qa-ephemeral-unrelated-value";
    Require(savedShort.Redact(temporary, null, "", temporary) == "***", "Extra secret not masked");
    Require(savedShort.Redact(temporary) == temporary, "Ephemeral secret retained permanently");
});

Test("Locked file reports failure safely and recovers after unlocking", path =>
{
    var writer = new BoundedLogFile(path);
    Require(writer.Write("BEFORE-LOCK-SENTINEL"), "Initial write failed");
    using (var locked = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
    {
        Require(!writer.Write("WHILE-LOCKED-SENTINEL"), "Lock failure was hidden");
        Require(!string.IsNullOrWhiteSpace(writer.LastError), "Missing failure diagnostic");
    }
    Require(writer.Write("AFTER-LOCK-SENTINEL"), "Recovery write failed");
    Require(string.IsNullOrEmpty(writer.LastError), "Stale failure diagnostic");
    string text = Read(path);
    Require(text.Contains("BEFORE-LOCK-SENTINEL") && text.Contains("AFTER-LOCK-SENTINEL") && !text.Contains("WHILE-LOCKED-SENTINEL"), "Unexpected recovered contents");
});

Test("Invalid destination never exposes the sensitive path in LastError", path =>
{
    string blocked = Path.Combine(Path.GetDirectoryName(path)!, "qa-path-secret");
    File.WriteAllText(blocked, "blocks a directory");
    var writer = new BoundedLogFile(Path.Combine(blocked, "ProxyBridge.log"));
    writer.RegisterSecret("qa-path-secret");
    Require(!writer.Write("should fail"), "Invalid destination accepted");
    Require(!string.IsNullOrEmpty(writer.LastError) && !writer.LastError.Contains("qa-path-secret", StringComparison.Ordinal), "Sensitive error details exposed");
    File.Delete(blocked);
    Directory.CreateDirectory(blocked);
    Require(writer.Write("RECOVERED-DESTINATION-SENTINEL"), "Destination recovery failed");
    Require(string.IsNullOrEmpty(writer.LastError), "Stale error after recovery");
});

Console.WriteLine($"RESULT: {report.Count - failures} PASS, {failures} FAIL");
Console.WriteLine("Artifacts: " + output);
return failures == 0 ? 0 : 1;
