using System.Net;
namespace ProxyBridge;

internal static class ProxySpeedTests
{
    static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Test invariant failed.");
        }
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> Test)
    {
        await Test("speed formula: decimal Mbit/s and bounded 25 MB workload", () =>
        {
            Require(Math.Abs(ProxySpeedTest.Mbps(25_000_000, TimeSpan.FromSeconds(2)) - 100) < 0.000001);
            Require(Math.Abs(ProxySpeedTest.Mbps(1_000_000, TimeSpan.FromSeconds(8)) - 1) < 0.000001);
            Require(ProxySpeedTest.Mbps(0, TimeSpan.FromSeconds(1)) == 0);
            Require(ProxySpeedTest.DownloadBytes == 25_000_000);
            Require(new Uri(ProxySpeedTest.Endpoint).Scheme == "https");
            return Task.CompletedTask;
        });
        var progress = new SilentProgress();
        await Test("mock speed success: three latency requests and exactly 25 MB downloaded", async () =>
        {
            var handler = new SpeedHandler();
            var result = await ProxySpeedTest.RunAsync(progress, CancellationToken.None, handler);
            Require(handler.Requests == 4 && handler.Probes == 3);
            Require(result.BytesReceived == ProxySpeedTest.DownloadBytes);
            Require(double.IsFinite(result.DownloadMbps) && result.DownloadMbps > 0);
            Require(result.LatencyMs >= 0 && result.Endpoint == ProxySpeedTest.Endpoint);
        });
        await Test("mock speed rejects HTTP failure and truncated download without a result", async () =>
        {
            bool rejected = false;
            try
            { await ProxySpeedTest.RunAsync(progress, CancellationToken.None, new SpeedHandler(failStatus: true)); }
            catch (HttpRequestException) { rejected = true; }
            Require(rejected);
            rejected = false;
            try
            { await ProxySpeedTest.RunAsync(progress, CancellationToken.None, new SpeedHandler(shortBody: true)); }
            catch (IOException) { rejected = true; }
            Require(rejected);
        });
        await Test("mock speed caller cancellation during download produces no result", async () =>
        {
            using var cancellation = new CancellationTokenSource();
            var handler = new SpeedHandler(cancelDownload: cancellation);
            bool cancelled = false;
            try
            { await ProxySpeedTest.RunAsync(progress, cancellation.Token, handler); }
            catch (OperationCanceledException) { cancelled = cancellation.IsCancellationRequested; }
            Require(cancelled && handler.Requests == 4 && handler.Probes == 3);
        });
        await Test("mock speed rejects redirect, content encoding and wrong declared length", async () =>
        {
            foreach (string fault in new[] { "redirect", "encoding", "length" })
            {
                var handler = new SpeedHandler(fault: fault);
                bool rejected = false;
                try
                { await ProxySpeedTest.RunAsync(progress, CancellationToken.None, handler); }
                catch (HttpRequestException) when (fault == "redirect") { rejected = true; }
                catch (IOException) when (fault != "redirect") { rejected = true; }
                Require(rejected && handler.Requests == 4);
            }
        });
        await Test("mock speed pre-cancel sends no request and yields no result", async () =>
        {
            using var before = new CancellationTokenSource();
            before.Cancel();
            var handler = new SpeedHandler();
            bool cancelled = false;
            try
            { await ProxySpeedTest.RunAsync(progress, before.Token, handler); }
            catch (OperationCanceledException) { cancelled = true; }
            Require(cancelled && handler.Requests == 0);
        });
        await Test("mock speed mid-stream cancellation yields no result after partial download", async () =>
        {
            using var during = new CancellationTokenSource();
            var handler = new SpeedHandler(cancelDuringRead: during);
            bool cancelled = false;
            try
            { await ProxySpeedTest.RunAsync(progress, during.Token, handler); }
            catch (OperationCanceledException) { cancelled = during.IsCancellationRequested; }
            Require(cancelled && handler.DownloadStream is { BytesRead: > 0 and < ProxySpeedTest.DownloadBytes });
        });
    }
    sealed class SilentProgress : IProgress<string> { public void Report(string value) { } }
    sealed class SpeedHandler(bool failStatus = false, bool shortBody = false, CancellationTokenSource? cancelDownload = null,
        string? fault = null, CancellationTokenSource? cancelDuringRead = null) : HttpMessageHandler
    {
        public int Requests { get; private set; }
        public int Probes { get; private set; }
        public CancellingStream? DownloadStream { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            Require(request.RequestUri!.GetLeftPart(UriPartial.Path) == ProxySpeedTest.Endpoint);
            Require(request.Headers.CacheControl?.NoCache == true && request.Headers.CacheControl.NoStore);
            bool probe = request.RequestUri.Query.StartsWith("?bytes=0&", StringComparison.Ordinal);
            if (probe)
            {
                Probes++;
            }
            else
            {
                Require(request.RequestUri.Query.StartsWith("?bytes=" + ProxySpeedTest.DownloadBytes + "&", StringComparison.Ordinal));
            }

            if (!probe && cancelDownload != null)
            {
                cancelDownload.Cancel();
                cancellationToken.ThrowIfCancellationRequested();
            }
            var response = new HttpResponseMessage(failStatus && !probe ? System.Net.HttpStatusCode.BadGateway : System.Net.HttpStatusCode.OK);
            if (!probe && fault == "redirect")
            {
                response.StatusCode = System.Net.HttpStatusCode.Redirect;
                response.Headers.Location = new Uri("https://example.invalid/no-follow");
            }
            Stream stream = !probe && cancelDuringRead != null
                ? DownloadStream = new CancellingStream(cancelDuringRead)
                : new MemoryStream(new byte[probe || failStatus || fault != null ? 0 : shortBody ? 128 : ProxySpeedTest.DownloadBytes], writable: false);
            response.Content = new StreamContent(stream);
            // A truncated body can claim the expected length; the reader must
            // detect EOF itself rather than trusting response headers.
            response.Content.Headers.ContentLength = probe ? 0 : ProxySpeedTest.DownloadBytes;
            if (!probe && fault == "length")
            {
                response.Content.Headers.ContentLength = 123;
            }

            if (!probe && fault == "encoding")
            {
                response.Content.Headers.ContentEncoding.Add("gzip");
            }

            return Task.FromResult(response);
        }
    }
    sealed class CancellingStream(CancellationTokenSource cancellation) : MemoryStream(new byte[ProxySpeedTest.DownloadBytes], writable: false)
    {
        public int BytesRead { get; private set; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int count = await base.ReadAsync(buffer[..Math.Min(buffer.Length, 1024)], cancellationToken);
            BytesRead += count;
            cancellation.Cancel();
            return count;
        }
    }
}
