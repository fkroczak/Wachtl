using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using Wachtl.Probe.Config;

namespace Wachtl.Probe.Bandwidth;

/// <summary>
/// WAN-Messung per HTTP: mehrere parallele Downloads bzw. Uploads über die eingestellte Dauer.
/// Die erste Sekunde (Verbindungsaufbau, TCP-Anlauf) zählt nicht mit.
/// </summary>
public sealed class HttpSpeedTest : IDisposable
{
    private static readonly TimeSpan Warmup = TimeSpan.FromSeconds(1);
    private readonly HttpClient _http;

    public HttpSpeedTest(string? proxy)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(10),
            AutomaticDecompression = DecompressionMethods.None,
            MaxConnectionsPerServer = 64,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            UseProxy = !string.IsNullOrWhiteSpace(proxy),
            Proxy = string.IsNullOrWhiteSpace(proxy) ? null : new WebProxy(proxy),
        };
        _http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"wachtl-probe/{AppInfo.Version}");
    }

    public async Task<double?> LatencyAsync(string url, CancellationToken ct)
    {
        var samples = new List<double>();
        for (var i = 0; i < 6; i++)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(5));
                using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
                sw.Stop();
                if (i > 0 && response.IsSuccessStatusCode)
                {
                    samples.Add(sw.Elapsed.TotalMilliseconds);   // erste Anfrage baut nur die Verbindung auf
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
            {
            }
        }

        if (samples.Count == 0)
        {
            return null;
        }

        samples.Sort();
        return Math.Round(samples[samples.Count / 2], 1);
    }

    public async Task<BandwidthMeasurement> DownloadAsync(string url, int streams, int durationS, CancellationToken ct)
    {
        var result = new BandwidthMeasurement { Direction = "down", Protocol = "http", Peer = new Uri(url).Host };
        long bytes = 0;
        string? firstError = null;
        var (mbps, seconds) = await MeasureAsync(streams, durationS, async token =>
        {
            using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                firstError ??= $"HTTP {(int)response.StatusCode} von {result.Peer}";
                await Task.Delay(500, token).ConfigureAwait(false);
                return;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            var buffer = new byte[64 * 1024];
            int read;
            while ((read = await stream.ReadAsync(buffer, token).ConfigureAwait(false)) > 0)
            {
                Interlocked.Add(ref bytes, read);
            }
        }, () => Interlocked.Read(ref bytes), e => firstError ??= e, ct).ConfigureAwait(false);
        Finish(result, mbps, seconds, firstError);
        return result;
    }

    public async Task<BandwidthMeasurement> UploadAsync(string url, int streams, int durationS, CancellationToken ct)
    {
        var result = new BandwidthMeasurement { Direction = "up", Protocol = "http", Peer = new Uri(url).Host };
        long bytes = 0;
        string? firstError = null;
        var payload = new byte[64 * 1024];
        Random.Shared.NextBytes(payload);
        var (mbps, seconds) = await MeasureAsync(streams, durationS, async token =>
        {
            using var content = new CountingContent(payload, 16 * 1024 * 1024, n => Interlocked.Add(ref bytes, n));
            using var response = await _http.PostAsync(url, content, token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                firstError ??= $"HTTP {(int)response.StatusCode} von {result.Peer}";
                await Task.Delay(500, token).ConfigureAwait(false);
            }
        }, () => Interlocked.Read(ref bytes), e => firstError ??= e, ct).ConfigureAwait(false);
        Finish(result, mbps, seconds, firstError);
        return result;
    }

    private static void Finish(BandwidthMeasurement result, double? mbps, double seconds, string? error)
    {
        result.DurationS = Math.Round(seconds, 1);
        if (mbps is double m && m > 0)
        {
            result.Mbps = Math.Round(m, 2);
        }
        else
        {
            result.Error = error ?? "keine Daten übertragen";
        }
    }

    /// <summary>Startet <paramref name="streams"/> Schleifen, bis die Dauer abgelaufen ist; Durchsatz ohne Anlaufzeit.</summary>
    private static async Task<(double? Mbps, double Seconds)> MeasureAsync(int streams, int durationS,
        Func<CancellationToken, Task> transfer, Func<long> counter, Action<string> onError, CancellationToken ct)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var duration = TimeSpan.FromSeconds(Math.Max(2, durationS)) + Warmup;
        stop.CancelAfter(duration);
        var sw = Stopwatch.StartNew();
        long warmBytes = 0;
        var warmAt = TimeSpan.Zero;
        var workers = Enumerable.Range(0, Math.Clamp(streams, 1, 32)).Select(_ => Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    await transfer(stop.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stop.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException)
                {
                    onError(ex.InnerException?.Message ?? ex.Message);
                    try
                    {
                        await Task.Delay(500, stop.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                }
            }
        })).ToList();

        try
        {
            await Task.Delay(Warmup, stop.Token).ConfigureAwait(false);
            warmBytes = counter();
            warmAt = sw.Elapsed;
        }
        catch (OperationCanceledException)
        {
        }

        await Task.WhenAll(workers).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var seconds = (sw.Elapsed - warmAt).TotalSeconds;
        var measured = counter() - warmBytes;
        return (seconds > 0 && measured > 0 ? measured * 8 / seconds / 1_000_000 : null, sw.Elapsed.TotalSeconds);
    }

    public void Dispose() => _http.Dispose();

    /// <summary>Upload-Inhalt fester Länge, der mitzählt, was bereits gesendet wurde.</summary>
    private sealed class CountingContent : HttpContent
    {
        private readonly byte[] _chunk;
        private readonly long _length;
        private readonly Action<int> _sent;

        public CountingContent(byte[] chunk, long length, Action<int> sent)
        {
            _chunk = chunk;
            _length = length;
            _sent = sent;
            Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
        {
            long written = 0;
            while (written < _length)
            {
                var n = (int)Math.Min(_chunk.Length, _length - written);
                await stream.WriteAsync(_chunk.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
                written += n;
                _sent(n);
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _length;
            return true;
        }
    }
}
