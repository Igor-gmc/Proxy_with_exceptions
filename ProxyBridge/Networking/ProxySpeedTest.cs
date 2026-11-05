using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;

namespace ProxyBridge;

internal sealed record SpeedTestResult(double DownloadMbps, double LatencyMs, long BytesReceived, TimeSpan Duration, string Endpoint);

internal static class ProxySpeedTest
{
    internal const int DownloadBytes = 25_000_000;
    internal const string Endpoint = "https://speed.cloudflare.com/__down";

    // The caller requires a healthy protected TUN. There is no system-proxy or
    // direct fallback, and ProxyBridge itself cannot be an excluded application.
    public static async Task<SpeedTestResult> RunAsync(IProgress<string> progress, CancellationToken cancellationToken, HttpMessageHandler? testHandler = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        var token = deadline.Token;
        using var client = new HttpClient(testHandler ?? new HttpClientHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None
        })
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        client.DefaultRequestHeaders.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
        try
        {
            token.ThrowIfCancellationRequested();
            progress.Report("Тест Cloudflare: HTTPS-задержка и загрузка до 25 МБ, максимум 45 с.");
            var samples = new List<double>();
            for (int i = 0; i < 3; i++)
            {
                var watch = Stopwatch.StartNew();
                using var probe = await client.GetAsync(Url(0), HttpCompletionOption.ResponseHeadersRead, token);
                probe.EnsureSuccessStatusCode();
                samples.Add(watch.Elapsed.TotalMilliseconds);
            }
            samples.Sort();
            double latency = samples[1];
            progress.Report($"HTTPS-задержка (медиана 3 запросов): {latency:F0} мс. Загрузка…");
            using var response = await client.GetAsync(Url(DownloadBytes), HttpCompletionOption.ResponseHeadersRead, token);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is long length && length != DownloadBytes)
            {
                throw new IOException("Тестовый сервер вернул неожиданный размер данных.");
            }

            if (response.Content.Headers.ContentEncoding.Count != 0)
            {
                throw new IOException("Тестовый сервер вернул сжатые данные; скорость не рассчитана.");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(token);
            var buffer = new byte[65536];
            long received = 0;
            var transfer = Stopwatch.StartNew();
            double lastReport = 0;
            while (received < DownloadBytes)
            {
                int count = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, DownloadBytes - received)), token);
                if (count == 0)
                {
                    throw new IOException("Загрузка прервалась до получения тестовых данных.");
                }

                received += count;
                if (transfer.Elapsed.TotalSeconds - lastReport >= 1)
                {
                    progress.Report($"Получено {received / 1_000_000.0:F1} / 25 МБ · {Mbps(received, transfer.Elapsed):F2} Мбит/с");
                    lastReport = transfer.Elapsed.TotalSeconds;
                }
            }
            transfer.Stop();
            token.ThrowIfCancellationRequested();
            return new(Mbps(received, transfer.Elapsed), latency, received, transfer.Elapsed, Endpoint);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("Тест скорости не завершился за 45 с. Результат не рассчитан.");
        }
    }

    static string Url(int bytes) => $"{Endpoint}?bytes={bytes}&cachebust={Guid.NewGuid():N}";
    internal static double Mbps(long bytes, TimeSpan elapsed) => bytes * 8.0 / Math.Max(elapsed.TotalSeconds, 0.000001) / 1_000_000;
}
