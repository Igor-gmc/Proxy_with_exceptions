using System.Net;
using System.Text;
using System.Diagnostics;

namespace ProxyBridge;

internal static class ConnectionProbe
{
    const int MaxResponseBytes = 4096;
    static readonly (string Url, bool Trace)[] Endpoints = [
        ("https://1.1.1.1/cdn-cgi/trace", true),
        ("https://api.ipify.org", false),
        ("https://www.cloudflare.com/cdn-cgi/trace", true)
    ];

    // UseProxy=false sends traffic through the protected system TUN, with no
    // fallback to a system proxy. The caller verifies the WFP policy and engine
    // before and after this check. One endpoint failure is not a tunnel failure.
    internal static Task CheckAsync(CancellationToken cancellationToken = default,
        Action<string>? log = null, HttpMessageHandler? testHandler = null) =>
        CheckCoreAsync(null, null, cancellationToken, log, testHandler);

    internal static Task CheckObservedAsync(ProbeContext context, Action<ProbeObservation> observer,
        CancellationToken cancellationToken = default, Action<string>? log = null, HttpMessageHandler? testHandler = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(observer);
        return CheckCoreAsync(context, observer, cancellationToken, log, testHandler);
    }

    static async Task CheckCoreAsync(ProbeContext? context, Action<ProbeObservation>? observer,
        CancellationToken cancellationToken, Action<string>? log, HttpMessageHandler? testHandler)
    {
        long probeId = ProbeObservationSink.NextId();
        if (cancellationToken.IsCancellationRequested)
            ProbeObservationSink.Publish(observer, new(DateTimeOffset.Now, Stopwatch.GetTimestamp(), probeId, 0,
                context?.EngineGeneration ?? 0, "health", ProbePhase.Setup, ProbeOutcome.Canceled, 0));
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        using var client = new HttpClient(testHandler ?? new HttpClientHandler {
            UseProxy = false, AllowAutoRedirect = false, MaxResponseHeadersLength = 16
        }) { Timeout = Timeout.InfiniteTimeSpan };
        var failures = new List<Exception>();
        int attemptNumber = 0;
        void Report(string message)
        {
            try { log?.Invoke(message); }
            catch (Exception) { /* Observability must not change probe results. */ }
        }
        foreach (var endpoint in Endpoints) {
            attemptNumber++;
            cancellationToken.ThrowIfCancellationRequested();
            if (deadline.IsCancellationRequested) break;
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            attempt.CancelAfter(TimeSpan.FromSeconds(5));
            long began = Stopwatch.GetTimestamp();
            string stage = "request";
            ProbePhase phase = ProbePhase.Request;
            long phaseBegan = began;
            int? status = null;
            int received = 0;
            void Observe(ProbeOutcome outcome, Exception? error = null)
            {
                long now = Stopwatch.GetTimestamp();
                ProbeObservationSink.Publish(observer, new(DateTimeOffset.Now, now, probeId, attemptNumber,
                    context?.EngineGeneration ?? 0, "health-" + attemptNumber, phase, outcome,
                    outcome == ProbeOutcome.Started ? 0 : now - phaseBegan, status,
                    ProbeObservationSink.NativeCode(error), ErrorCodes: error == null ? null : AppLog.ExceptionCodes(error), Bytes: received));
            }
            void BeginPhase(ProbePhase next)
            {
                Observe(ProbeOutcome.Succeeded);
                phase = next;
                phaseBegan = Stopwatch.GetTimestamp();
                Observe(ProbeOutcome.Started);
            }
            Observe(ProbeOutcome.Started);
            Report($"HTTPS BEGIN endpoint={endpoint.Url}; attemptTimeoutMs=5000; totalBudgetMs=15000");
            try {
                using var response = await client.GetAsync(endpoint.Url, HttpCompletionOption.ResponseHeadersRead, attempt.Token);
                stage = "headers";
                status = (int)response.StatusCode;
                BeginPhase(ProbePhase.Headers);
                response.EnsureSuccessStatusCode();
                if (response.Content.Headers.ContentLength is long length && length > MaxResponseBytes)
                    throw new IOException("Ответ проверки HTTPS слишком велик.");
                stage = "body";
                BeginPhase(ProbePhase.Body);
                await using var stream = await response.Content.ReadAsStreamAsync(attempt.Token);
                byte[] buffer = new byte[MaxResponseBytes + 1];
                while (received < buffer.Length) {
                    int count = await stream.ReadAsync(buffer.AsMemory(received), attempt.Token);
                    if (count == 0) break;
                    received += count;
                }
                if (received > MaxResponseBytes) throw new IOException("Ответ проверки HTTPS слишком велик.");
                stage = "validate";
                BeginPhase(ProbePhase.Validate);
                string body = Encoding.UTF8.GetString(buffer, 0, received);
                bool valid = endpoint.Trace
                    ? body.Split('\n').Any(line => line.StartsWith("ip=", StringComparison.Ordinal)
                        && IPAddress.TryParse(line[3..].Trim(), out _))
                    : IPAddress.TryParse(body.Trim(), out _);
                if (!valid) throw new IOException("Ответ проверки HTTPS не содержит корректный IP-адрес.");
                attempt.Token.ThrowIfCancellationRequested();
                Observe(ProbeOutcome.Succeeded);
                Report($"Проверка HTTPS: {endpoint.Url} — успешно; elapsedMs={Stopwatch.GetElapsedTime(began).TotalMilliseconds:F0}; http={status}; bytes={received}.");
                return;
            } catch (OperationCanceledException ex) when (cancellationToken.IsCancellationRequested) {
                Observe(ProbeOutcome.Canceled, ex);
                Report($"HTTPS CANCEL endpoint={endpoint.Url}; source=caller; stage={stage}; elapsedMs={Stopwatch.GetElapsedTime(began).TotalMilliseconds:F0}");
                throw new OperationCanceledException("HTTPS probe canceled by caller.", ex, cancellationToken);
            } catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException) {
                bool timedOut = ex is OperationCanceledException && attempt.IsCancellationRequested;
                Observe(timedOut ? ProbeOutcome.TimedOut : ProbeOutcome.Failed, ex);
                string reason = timedOut ? "тайм-аут" : ex.GetType().Name;
                string timeout = timedOut ? deadline.IsCancellationRequested ? "total-budget" : "attempt" : "none";
                Report($"Проверка HTTPS: {endpoint.Url} — {reason}; stage={stage}; elapsedMs={Stopwatch.GetElapsedTime(began).TotalMilliseconds:F0}; http={status}; bytes={received}; timeout={timeout}; errors={AppLog.ExceptionCodes(ex)}; проверяем следующий адрес.");
                failures.Add(new IOException($"HTTPS {endpoint.Url}: {reason}", ex));
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        throw new AggregateException("Проверка HTTPS через туннель не пройдена ни на одном доступном контрольном адресе.", failures);
    }
}
