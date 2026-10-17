using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Config;
using Wachtl.Probe.Metrics;
using Wachtl.Probe.Tray;

namespace Wachtl.Probe.Checks;

/// <summary>Führt einen Ping-Check in festem Intervall aus und schreibt die Ergebnisse in den Puffer.</summary>
public sealed class PingRunner : IAsyncDisposable
{
    private readonly ISampleSink _sink;
    private readonly GatewayResolver _gateway;
    private readonly ILogger _logger;
    private readonly LiveStats? _live;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _task;

    public PingRunner(CheckConfig check, ISampleSink sink, GatewayResolver gateway, ILogger logger, LiveStats? live = null)
    {
        _live = live;
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
        var payload = new byte[Math.Clamp(Check.Int("size_bytes", 32), 0, 1472)];
        var options = new PingOptions(ttl: Math.Clamp(Check.Int("ttl", 128), 1, 255), dontFragment: false);
        var jitterInterval = TimeSpan.FromSeconds(Math.Clamp(Check.Int("jitter_window_s", 60), 10, 3600));
        var jitter = new JitterCalculator();
        var nextJitter = DateTimeOffset.UtcNow + jitterInterval;
        var lastError = string.Empty;

        _logger.LogInformation("Ping-Check {Id} gestartet: {Target} alle {Interval} s", Check.Id, Check.Target, Check.IntervalS);
        using var ping = new Ping();
        using var timer = new PeriodicTimer(interval);
        try
        {
            do
            {
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var (address, resolveError) = await PingHelper.ResolveAsync(Check.Target, _gateway, ct).ConfigureAwait(false);
                var reply = address is null
                    ? new PingResult(false, 0, null, null, IPStatus.Unknown, resolveError)
                    : await PingHelper.SendAsync(ping, address, timeout, payload, options, ct).ConfigureAwait(false);

                _sink.Add(MetricLine.Format(MetricLine.PingUp, Check.Id, reply.Success ? 1 : 0, timestamp));
                _live?.RecordPing(Check, reply.Success, reply.RttMs);
                if (reply.Success)
                {
                    _sink.Add(MetricLine.Format(MetricLine.PingRtt, Check.Id, reply.RttMs, timestamp));
                    if (reply.Ttl is int t)
                    {
                        _sink.Add(MetricLine.Format(MetricLine.PingTtl, Check.Id, t, timestamp));
                    }

                    jitter.Add(reply.RttMs);
                }

                if (reply.Error != lastError)
                {
                    if (!string.IsNullOrEmpty(reply.Error))
                    {
                        _logger.LogWarning("Ping {Target} (Check {Id}): {Error}", Check.Target, Check.Id, reply.Error);
                    }
                    else if (!string.IsNullOrEmpty(lastError))
                    {
                        _logger.LogInformation("Ping {Target} (Check {Id}) wieder erfolgreich", Check.Target, Check.Id);
                    }

                    lastError = reply.Error;
                }

                if (DateTimeOffset.UtcNow >= nextJitter)
                {
                    if (jitter.TakeAndReset() is double j)
                    {
                        _sink.Add(MetricLine.Format(MetricLine.PingJitter, Check.Id, j, timestamp));
                    }

                    nextJitter += jitterInterval;
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
