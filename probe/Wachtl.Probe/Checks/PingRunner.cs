using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Config;
using Wachtl.Probe.Metrics;

namespace Wachtl.Probe.Checks;

/// <summary>Führt einen Ping-Check in festem Intervall aus und schreibt die Ergebnisse in den Puffer.</summary>
public sealed class PingRunner : IAsyncDisposable
{
    private static readonly byte[] Payload = new byte[32];
    private static readonly TimeSpan JitterInterval = TimeSpan.FromSeconds(60);

    private readonly ISampleSink _sink;
    private readonly GatewayResolver _gateway;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _task;

    public PingRunner(CheckConfig check, ISampleSink sink, GatewayResolver gateway, ILogger logger)
    {
        Check = check;
        _sink = sink;
        _gateway = gateway;
        _logger = logger;
        _task = Task.Run(() => RunAsync(_cts.Token));
    }

    public CheckConfig Check { get; }

    private async Task RunAsync(CancellationToken ct)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(1, Check.IntervalS));
        var timeout = TimeSpan.FromMilliseconds(Math.Clamp(Check.TimeoutMs, 100, (int)interval.TotalMilliseconds));
        var options = new PingOptions(ttl: 128, dontFragment: false);
        var jitter = new JitterCalculator();
        var nextJitter = DateTimeOffset.UtcNow + JitterInterval;
        var lastError = string.Empty;

        _logger.LogInformation("Ping-Check {Id} gestartet: {Target} alle {Interval} s", Check.Id, Check.Target, Check.IntervalS);
        using var ping = new Ping();
        using var timer = new PeriodicTimer(interval);
        try
        {
            do
            {
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var (success, rtt, ttl, error) = await PingOnceAsync(ping, timeout, options, ct).ConfigureAwait(false);

                _sink.Add(MetricLine.Format(MetricLine.PingUp, Check.Id, success ? 1 : 0, timestamp));
                if (success)
                {
                    _sink.Add(MetricLine.Format(MetricLine.PingRtt, Check.Id, rtt, timestamp));
                    if (ttl is int t)
                    {
                        _sink.Add(MetricLine.Format(MetricLine.PingTtl, Check.Id, t, timestamp));
                    }

                    jitter.Add(rtt);
                }

                if (error != lastError)
                {
                    if (!string.IsNullOrEmpty(error))
                    {
                        _logger.LogWarning("Ping {Target} (Check {Id}): {Error}", Check.Target, Check.Id, error);
                    }
                    else if (!string.IsNullOrEmpty(lastError))
                    {
                        _logger.LogInformation("Ping {Target} (Check {Id}) wieder erfolgreich", Check.Target, Check.Id);
                    }

                    lastError = error;
                }

                if (DateTimeOffset.UtcNow >= nextJitter)
                {
                    if (jitter.TakeAndReset() is double j)
                    {
                        _sink.Add(MetricLine.Format(MetricLine.PingJitter, Check.Id, j, timestamp));
                    }

                    nextJitter += JitterInterval;
                }
            }
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normales Beenden
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ping-Check {Id} unerwartet beendet", Check.Id);
        }
    }

    private async Task<(bool Success, double Rtt, int? Ttl, string Error)> PingOnceAsync(
        Ping ping, TimeSpan timeout, PingOptions options, CancellationToken ct)
    {
        IPAddress? address;
        if (Check.Target == "gateway")
        {
            address = _gateway.Get();
            if (address is null)
            {
                return (false, 0, null, "kein Default-Gateway gefunden");
            }
        }
        else if (!IPAddress.TryParse(Check.Target, out address))
        {
            try
            {
                var resolved = await Dns.GetHostAddressesAsync(Check.Target, System.Net.Sockets.AddressFamily.InterNetwork, ct)
                    .ConfigureAwait(false);
                address = resolved.FirstOrDefault();
            }
            catch (Exception ex) when (ex is System.Net.Sockets.SocketException or ArgumentException)
            {
                return (false, 0, null, "DNS-Auflösung fehlgeschlagen: " + ex.Message);
            }

            if (address is null)
            {
                return (false, 0, null, "DNS liefert keine IPv4-Adresse");
            }
        }

        var stopwatch = Stopwatch.StartNew();
        try
        {
            var reply = await ping.SendPingAsync(address, timeout, Payload, options, ct).ConfigureAwait(false);
            stopwatch.Stop();
            if (reply.Status != IPStatus.Success)
            {
                return (false, 0, null, reply.Status.ToString());
            }

            // Windows liefert RoundtripTime nur in ganzen ms. Für LAN-Ziele (< 2 ms)
            // nehmen wir die genauere Stoppuhr-Messung.
            var rtt = reply.RoundtripTime >= 2
                ? reply.RoundtripTime
                : Math.Round(stopwatch.Elapsed.TotalMilliseconds, 3);
            return (true, rtt, reply.Options?.Ttl, string.Empty);
        }
        catch (PingException ex)
        {
            return (false, 0, null, ex.InnerException?.Message ?? ex.Message);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        try
        {
            await _task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        _cts.Dispose();
        _logger.LogInformation("Ping-Check {Id} beendet", Check.Id);
    }
}
