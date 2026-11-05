using System.Text;
using System.Text.Json;

namespace ProxyBridge;

internal sealed class DiagnosticIncidentStore(string directory, int maxFiles = 5,
    long maxTotalBytes = 60_000_000, long maxFileBytes = 12_000_000)
{
    const string Prefix = "ProxyBridge-incident-";
    static readonly UTF8Encoding Utf8 = new(false);
    public string Write(DiagnosticIncident incident)
    {
        if (maxFiles < 1 || maxFileBytes < 1024 || maxTotalBytes < maxFileBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maxFiles));
        }

        if (incident.Id.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
        {
            throw new ArgumentException("Invalid incident identifier.");
        }

        BundledAssets.RejectReparsePoints(directory);
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, Prefix + incident.Id + ".jsonl");
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            string header = JsonSerializer.Serialize(new
            {
                schema = 1,
                kind = "incident.begin",
                incident.Id,
                incident.Reason,
                incident.TriggerTime,
                incident.TriggerTicks,
                timestampFrequency = System.Diagnostics.Stopwatch.Frequency,
                context = incident.Context,
                evidence = "bounded observations recorded before trigger; cached policy is not a fresh audit",
                availableRecords = incident.Before.Length,
                firstRetainedEvent = incident.Before.FirstOrDefault()?.EventTime,
                version = AppVersion.Display
            });
            // Reserve a footer even when the evidence exceeds the file budget.
            if (!WriteLine(stream, header, reserve: 256))
            {
                throw new IOException("Incident header exceeds file budget.");
            }

            int saved = 0;
            foreach (var entry in incident.Before)
            {
                if (!WriteLine(stream, entry.Json, reserve: 256))
                {
                    break;
                }

                saved++;
            }
            WriteLine(stream, JsonSerializer.Serialize(new
            {
                kind = "incident.pre-window-end",
                retainedRecords = saved,
                truncated = saved != incident.Before.Length,
                followingEvidence = "observed-after-trigger"
            }));
            stream.Flush(true);
        }
        Prune(path);
        return path;
    }
    bool WriteLine(Stream stream, string json, int reserve = 0)
    {
        byte[] data = Utf8.GetBytes(DiagnosticDiskStamp.Add(json) + "\r\n");
        if (stream.Length + data.Length + reserve > maxFileBytes)
        {
            return false;
        }

        stream.Write(data);
        return true;
    }
    public void Append(string path, IReadOnlyList<DiagnosticRingEntry> entries)
    {
        string expected = Path.GetFullPath(directory) + Path.DirectorySeparatorChar;
        if (!Path.GetFullPath(path).StartsWith(expected, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(path).StartsWith(Prefix, StringComparison.Ordinal))
        {
            throw new IOException("Foreign incident path.");
        }

        BundledAssets.RejectReparsePoints(path);
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.Read))
        {
            stream.Position = stream.Length;
            foreach (var entry in entries)
            {
                if (!WriteLine(stream, entry.Json, reserve: 128))
                {
                    WriteLine(stream, "{\"kind\":\"incident.post-window-truncated\",\"reason\":\"file-byte-limit\"}");
                    break;
                }
            }

            stream.Flush(true);
        }
        Prune(path);
    }
    void Prune(string current)
    {
        var files = new DirectoryInfo(directory).GetFiles(Prefix + "*.jsonl")
            .Where(f => (f.Attributes & FileAttributes.ReparsePoint) == 0)
            .OrderByDescending(f => f.Name, StringComparer.Ordinal).ToList();
        long bytes = files.Sum(f => f.Length);
        while (files.Count > maxFiles || bytes > maxTotalBytes)
        {
            var oldest = files.LastOrDefault(f => !string.Equals(f.FullName, current, StringComparison.OrdinalIgnoreCase));
            if (oldest == null)
            {
                break;
            }

            bytes -= oldest.Length;
            oldest.Delete();
            files.Remove(oldest);
        }
    }
}
