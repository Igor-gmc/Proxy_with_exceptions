using System.Text;

namespace ProxyBridge;

internal readonly record struct LogFileEntry(DateTimeOffset Time, string Message);

// One writer per file. The application mutex excludes other production instances.
internal sealed class BoundedLogFile(string filePath, long maxBytes = 25_000_000)
{
    readonly object gate = new();
    readonly SecretMask secrets = new();
    static readonly UTF8Encoding Utf8 = new(false);
    string? lastError;
    public string? LastError { get { lock (gate) return lastError; } }
    public void RegisterSecret(string? secret) => secrets.Register(secret);

    public bool Write(string message) => WriteBatch([new(DateTimeOffset.Now, message)]);
    public bool WriteBatch(IReadOnlyList<LogFileEntry> entries)
    {
        lock (gate) {
            try {
                if (maxBytes < 256) throw new ArgumentOutOfRangeException(nameof(maxBytes));
                string fullPath = Path.GetFullPath(filePath);
                Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
                using var file = new FileStream(fullPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
                foreach (var item in entries) {
                string prefix = $"{item.Time:yyyy-MM-dd HH:mm:ss.fff zzz} [PID {Environment.ProcessId}] ";
                byte[] rollover = Utf8.GetBytes(prefix + "[LOG RESET: size limit reached; previous records overwritten]\r\n");
                int entryLimit = (int)Math.Min(64 * 1024, maxBytes - rollover.Length);
                string clean = secrets.Redact(item.Message);
                // Escape embedded line breaks so engine output cannot forge separate records.
                string entry = prefix + clean.Replace("\r", "\\r").Replace("\n", "\\n");
                byte[] suffix = Utf8.GetBytes(" [TRUNCATED]\r\n");
                byte[] bytes;
                if (Utf8.GetByteCount(entry) + 2 <= entryLimit) bytes = Utf8.GetBytes(entry + "\r\n");
                else {
                    bytes = new byte[entryLimit];
                    Utf8.GetEncoder().Convert(entry.AsSpan(), bytes.AsSpan(0, entryLimit - suffix.Length), true,
                        out _, out int written, out _);
                    suffix.CopyTo(bytes, written);
                    Array.Resize(ref bytes, written + suffix.Length);
                }
                if (file.Length > maxBytes - bytes.Length) {
                    file.SetLength(0);
                    file.Write(rollover);
                }
                file.Position = file.Length;
                file.Write(bytes);
                }
                file.Flush(flushToDisk: true);
                lastError = null;
                return true;
            } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                System.Security.SecurityException or ArgumentException or NotSupportedException) {
                // Do not echo an exception message: it may contain confidential paths/input.
                lastError = $"{ex.GetType().Name} (0x{ex.HResult:X8})";
                return false;
            }
        }
    }
}

internal sealed class SecretMask
{
    readonly object gate = new();
    readonly HashSet<string> values = new(StringComparer.Ordinal);
    public void Register(string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        lock (gate) {
            values.Add(value);
            values.Add(Uri.EscapeDataString(value));
            string json = System.Text.Json.JsonSerializer.Serialize(value);
            values.Add(json[1..^1]);
        }
    }
    public string Redact(string text, params string?[] extraSecrets)
    {
        lock (gate) {
            // Mark matches in the original text, including overlapping secrets.
            // Repeated Replace could expose a suffix when passwords overlap.
            bool[]? hidden = null;
            foreach (string value in values.Concat(extraSecrets.Where(s => !string.IsNullOrEmpty(s)).Select(s => s!)).Distinct(StringComparer.Ordinal)) {
                int start = 0;
                while (start <= text.Length - value.Length) {
                    int index = text.IndexOf(value, start, StringComparison.Ordinal);
                    if (index < 0) break;
                    hidden ??= new bool[text.Length];
                    Array.Fill(hidden, true, index, value.Length);
                    start = index + 1;
                }
            }
            if (hidden == null) return text;
            var result = new StringBuilder(text.Length);
            for (int i = 0; i < text.Length; i++) {
                if (!hidden[i]) result.Append(text[i]);
                else if (i == 0 || !hidden[i - 1]) result.Append("***");
            }
            return result.ToString();
        }
    }
}
