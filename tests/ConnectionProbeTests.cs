using System.Net;
using System.Net.Sockets;

namespace ProxyBridge;

// Injected HTTP handlers only: no DNS, sockets, WFP or TUN are used.
internal static class ConnectionProbeTests
{
    static void Require(bool value, string message)
    {
        if (!value)
        {
            throw new InvalidOperationException(message);
        }
    }
    static HttpResponseMessage Response(string body, HttpStatusCode status = HttpStatusCode.OK) => new(status) { Content = new StringContent(body) };
    static async Task<T> Reject<T>(Func<Task> action) where T : Exception
    {
        try
        { await action(); }
        catch (T error) { return error; }
        throw new InvalidOperationException("Expected " + typeof(T).Name);
    }
    internal static async Task RunAsync(Func<string, Func<Task>, Task> test)
    {
        await test("HTTPS probe: TLS reset on first endpoint falls back to independent valid endpoint", async () =>
        {
            var log = new List<string>();
            using var handler = new Handler((i, _, _) => i == 1
                ? throw new HttpRequestException("synthetic-sensitive-detail", new SocketException((int)SocketError.ConnectionReset))
                : Task.FromResult(Response("203.0.113.9")));
            await ConnectionProbe.CheckAsync(log: log.Add, testHandler: handler);
            Require(handler.Requests.Count == 2 && handler.Requests.All(u => u.Scheme == "https") && handler.Requests[0].Host != handler.Requests[1].Host,
                "Failed endpoint did not fall back to independent HTTPS endpoint");
            string diagnostic = string.Join('\n', log);
            Require(diagnostic.Contains(nameof(SocketError.ConnectionReset)) && diagnostic.Contains("10054"),
                "TLS reset lost its actionable socket error code");
            Require(!diagnostic.Contains("synthetic-sensitive-detail") && !diagnostic.Contains("203.0.113.9"),
                "Probe diagnostic exposed exception message or returned address");
        });
        await test("HTTPS probe: redirect, invalid IP and failure cannot produce connected success", async () =>
        {
            using var handler = new Handler((i, _, _) =>
            {
                var response = Response(i == 2 ? "not-an-ip" : "ip=203.0.113.9", i == 1 ? HttpStatusCode.Redirect : i == 3 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
                if (i == 1)
                {
                    response.Headers.Location = new Uri("https://untrusted.invalid/");
                }

                return Task.FromResult(response);
            });
            var error = await Reject<AggregateException>(() => ConnectionProbe.CheckAsync(testHandler: handler));
            Require(handler.Requests.Count == 3 && error.InnerExceptions.Count == 3 && handler.Requests.All(u => u.Host != "untrusted.invalid"),
                "Redirect/invalid body/HTTP error was accepted or followed");
        });
        await test("HTTPS probe: oversized streaming body without Content-Length is bounded and rejected", async () =>
        {
            var stream = new BodyStream(100_000);
            using var handler = new Handler((i, _, _) => Task.FromResult(i == 1
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }
                : Response("203.0.113.9")));
            await ConnectionProbe.CheckAsync(testHandler: handler);
            Require(handler.Requests.Count == 2 && stream.BytesRead == 4097, "Unknown-length response was accepted or consumed without a bound");
        });
        await test("HTTPS probe: valid trace succeeds without unnecessary fallback", async () =>
        {
            using var handler = new Handler((_, _, _) => Task.FromResult(Response("fl=qa\nip=203.0.113.10\ntls=TLSv1.3\n")));
            await ConnectionProbe.CheckAsync(testHandler: handler);
            Require(handler.Requests.Count == 1, "Valid trace triggered unnecessary fallback");
        });
        await test("HTTPS probe: failure diagnostics retain status and phases without body or header secrets", async () =>
        {
            const string secret = "qa-unregistered-probe-secret";
            var log = new List<string>();
            using var handler = new Handler((i, _, _) =>
            {
                if (i == 1)
                {
                    throw new HttpRequestException(secret, new SocketException((int)SocketError.ConnectionReset));
                }

                var response = Response(secret, i == 2 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
                response.Headers.TryAddWithoutValidation("Set-Cookie", "token=" + secret);
                response.ReasonPhrase = secret;
                return Task.FromResult(response);
            });
            var failure = await Reject<AggregateException>(() => ConnectionProbe.CheckAsync(log: log.Add, testHandler: handler));
            string diagnostic = string.Join('\n', log);
            Require(handler.Requests.Count == 3 && failure.InnerExceptions.Count == 3,
                "Detailed diagnostics changed the failure/fallback contract");
            Require(diagnostic.Contains("10054") && diagnostic.Contains("503") && diagnostic.Contains("stage=request")
                && diagnostic.Contains("stage=headers") && diagnostic.Contains("stage=validate") && diagnostic.Contains("elapsedMs="),
                "Diagnostics cannot distinguish transport, HTTP status and response validation failures");
            Require(!diagnostic.Contains(secret) && !diagnostic.Contains("Set-Cookie") && !diagnostic.Contains("token="),
                "Probe diagnostic leaked message, response body or response headers");
        });
        await test("HTTPS probe: failing diagnostic sink cannot alter success, fallback or cancellation", async () =>
        {
            int logCalls = 0;
            void BrokenLog(string _)
            { logCalls++; throw new IOException("synthetic log write failure"); }
            using var success = new Handler((i, _, _) => i == 1
                ? throw new HttpRequestException("synthetic request failure")
                : Task.FromResult(Response("203.0.113.9")));
            await ConnectionProbe.CheckAsync(log: BrokenLog, testHandler: success);
            Require(success.Requests.Count == 2 && logCalls > 0, "Log failure changed successful fallback or logging was bypassed");
            using var allFail = new Handler((_, _, _) => throw new HttpRequestException("synthetic request failure"));
            var failure = await Reject<AggregateException>(() => ConnectionProbe.CheckAsync(log: BrokenLog, testHandler: allFail));
            Require(allFail.Requests.Count == 3 && failure.InnerExceptions.All(e => e.InnerException is HttpRequestException),
                "Log failure replaced transport errors or changed failure retry count");
            using var cancel = new CancellationTokenSource();
            using var canceled = new Handler((_, _, token) => { cancel.Cancel(); token.ThrowIfCancellationRequested(); return Task.FromResult(Response("")); });
            await Reject<OperationCanceledException>(() => ConnectionProbe.CheckAsync(cancel.Token, BrokenLog, canceled));
            Require(canceled.Requests.Count == 1, "Logging exception swallowed caller cancellation");
        });
        await test("HTTPS probe: caller cancellation before send and during body aborts fallback", async () =>
        {
            using var before = new CancellationTokenSource();
            before.Cancel();
            using var never = new Handler((_, _, _) => throw new InvalidOperationException("Send after cancellation"));
            var beforeError = await Reject<OperationCanceledException>(() => ConnectionProbe.CheckAsync(before.Token, testHandler: never));
            Require(beforeError.CancellationToken == before.Token, "Pre-send cancellation lost the caller token identity");
            Require(never.Requests.Count == 0, "Pre-canceled probe sent a request");
            using var during = new CancellationTokenSource();
            var body = new BodyStream(100_000, during);
            using var handler = new Handler((_, _, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) }));
            var duringError = await Reject<OperationCanceledException>(() => ConnectionProbe.CheckAsync(during.Token, testHandler: handler));
            Require(duringError.CancellationToken == during.Token, "Body cancellation retained an internal timeout token instead of the caller token");
            Require(handler.Requests.Count == 1, "Caller cancellation was swallowed and triggered fallback");
        });
    }
    sealed class Handler(Func<int, HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);
            return send(Requests.Count, request, cancellationToken);
        }
    }
    sealed class BodyStream(int length, CancellationTokenSource? cancel = null) : Stream
    {
        public int BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = Math.Min(count, length - BytesRead);
            Array.Fill(buffer, (byte)'x', offset, read);
            BytesRead += read;
            return read;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancel?.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            int read = Math.Min(buffer.Length, length - BytesRead);
            buffer.Span[..read].Fill((byte)'x');
            BytesRead += read;
            return ValueTask.FromResult(read);
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
