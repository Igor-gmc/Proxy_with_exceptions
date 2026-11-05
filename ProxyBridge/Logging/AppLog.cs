using System.Diagnostics;

namespace ProxyBridge;

internal static class AppLog
{
    static readonly SecretMask Secrets = new();
    static readonly AsyncLocal<string?> Operation = new();
    static readonly string Session = Guid.NewGuid().ToString("N")[..12];
    static readonly long Started = Stopwatch.GetTimestamp();
    static long nextOperation;
    static readonly Lazy<AsyncLogWriter> Writer = new(() =>
    {
        BoundedLogFile? file = null;
        return new AsyncLogWriter(entries =>
        {
            if (file == null)
            {
                BundledAssets.RejectReparsePoints(Settings.DataDir);
                Settings.PrepareDirectory();
                file = new BoundedLogFile(FilePath);
            }
            return file.WriteBatch(entries);
        }, () => file?.LastError);
    });
    public static string FilePath => Path.Combine(Settings.DataDir, "ProxyBridge.log");
    public static string? LastError => Writer.IsValueCreated ? Writer.Value.Stats.LastError : null;
    public static AsyncLogStats? Stats => Writer.IsValueCreated ? Writer.Value.Stats : null;
    internal static string? CurrentOperation => Operation.Value;
    public static IDisposable BeginOperation(string name)
    {
        string? previous = Operation.Value;
        string id = Interlocked.Increment(ref nextOperation).ToString(System.Globalization.CultureInfo.InvariantCulture);
        Operation.Value = id;
        Write($"OP BEGIN name={name}; parent={previous ?? "none"}");
        return new OperationScope(previous, name);
    }
    sealed class OperationScope(string? previous, string name) : IDisposable
    {
        readonly long began = Stopwatch.GetTimestamp();
        bool disposed;
        public void Dispose()
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            try
            {
                Write($"OP END name={name}; elapsedMs={Stopwatch.GetElapsedTime(began).TotalMilliseconds:F0}; outcome=see-state-and-errors");
            }
            finally { Operation.Value = previous; }
        }
    }
    // Diagnostic failure must not change the result of a protection operation.
    // Read-only local APIs: no DNS, HTTP, subprocesses or network mutations.
    public static void Snapshot(string stage, Settings? settings = null)
    {
        try
        {
            var began = Stopwatch.GetTimestamp();
            string filters;
            try
            {
                filters = Guard.Status.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }
            catch (Exception ex) { filters = $"unknown:{ex.GetType().Name}:0x{ex.HResult:X8}"; }
            Write($"SNAPSHOT BEGIN stage={stage}; filters={filters}; protocol={settings?.Protocol ?? "unknown"}; proxyHost={settings?.Host ?? "unknown"}; proxyPort={settings?.Port}; exclusions={settings?.ExcludedApplications.Length}; credentials=omitted");
            Write("NETWORK " + NetworkDiagnostics.Capture(settings));
            Write($"SNAPSHOT END stage={stage}; elapsedMs={Stopwatch.GetElapsedTime(began).TotalMilliseconds:F0}; observational=true");
        }
        catch (Exception ex)
        {
            Write($"SNAPSHOT unavailable stage={stage}; error={ex.GetType().Name}; hresult=0x{ex.HResult:X8}");
        }
    }
    internal static string ExceptionCodes(Exception error)
    {
        // Never include exception messages, response bodies, URL userinfo or headers.
        var result = new List<string>();
        var pending = new Queue<Exception>();
        pending.Enqueue(error);
        while (pending.Count != 0 && result.Count < 12)
        {
            var current = pending.Dequeue();
            string code = $"{current.GetType().Name}(0x{current.HResult:X8})";
            if (current is System.Net.Sockets.SocketException socket)
            {
                code += $"[socket={socket.SocketErrorCode};native={socket.NativeErrorCode}]";
            }

            if (current is HttpRequestException http)
            {
                code += $"[http={(int?)http.StatusCode};requestError={http.HttpRequestError}]";
            }

            result.Add(code);
            if (current is AggregateException aggregate)
            {
                foreach (var inner in aggregate.InnerExceptions.Take(12))
                {
                    pending.Enqueue(inner);
                }
            }
            else if (current.InnerException != null)
            {
                pending.Enqueue(current.InnerException);
            }
        }
        return string.Join(" -> ", result);
    }
    public static void RegisterSecret(string? secret) => Secrets.Register(secret);
    public static string Redact(string message, params string?[] extraSecrets) => Secrets.Redact(message, extraSecrets);
    public static bool Error(string context, Exception error) => Write($"ERROR {context}: {error}");
    static LogFileEntry Prepare(DateTimeOffset time, long monoTicks, string message)
    {
        string clean = Redact(message);
        if (clean.Length > 32_000)
        {
            clean = clean[..32_000] + " [TRUNCATED BEFORE QUEUE]";
        }

        DiagnosticJournal.Record("app.log", new
        {
            session = Session,
            message = clean
        }, time, monoTicks);
        return new(time, $"[session={Session} op={Operation.Value ?? "none"} monoMs={Stopwatch.GetElapsedTime(Started, monoTicks).TotalMilliseconds:F0}] {clean}");
    }
    // True means accepted by the bounded queue, not a durable-write receipt.
    public static bool Write(string message) => WriteAt(DateTimeOffset.Now, Stopwatch.GetTimestamp(), message);
    public static bool WriteAt(DateTimeOffset time, long monoTicks, string message) => Writer.Value.TryWrite(Prepare(time, monoTicks, message));
    public static Task<bool> WriteConfirmedAsync(string message, CancellationToken cancellationToken = default) =>
        Writer.Value.WriteConfirmedAsync(Prepare(DateTimeOffset.Now, Stopwatch.GetTimestamp(), message), cancellationToken);
    public static Task StopAsync() => Writer.IsValueCreated ? Writer.Value.StopAsync(TimeSpan.FromSeconds(2)) : Task.CompletedTask;
}
