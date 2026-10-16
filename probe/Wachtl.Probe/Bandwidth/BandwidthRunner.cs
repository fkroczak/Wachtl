using Microsoft.Extensions.Logging;
using Wachtl.Probe.Config;

namespace Wachtl.Probe.Bandwidth;

/// <summary>
/// Bandbreiten-Check (iperf3 oder WAN-Speedtest): misst nach Zeitplan oder auf Anforderung
/// und meldet das Ergebnis an den Server. Es läuft immer nur eine Bandbreitenmessung je Probe.
/// </summary>
public sealed class BandwidthRunner : IAsyncDisposable
{
    private static readonly SemaphoreSlim OneAtATime = new(1, 1);

    private readonly Func<BandwidthResult, CancellationToken, Task> _report;
    private readonly string? _proxy;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _manual = new(0, 1);
    private readonly Task _task;

    public BandwidthRunner(CheckConfig check, string? proxy, Func<BandwidthResult, CancellationToken, Task> report, ILogger logger)
    {
        Check = check;
        _proxy = proxy;
        _report = report;
        _logger = logger;
        _task = Task.Run(() => RunAsync(_cts.Token));
    }

    public CheckConfig Check { get; }

    public void RunNow()
    {
        if (_manual.CurrentCount == 0)
        {
            _manual.Release();
        }
    }

    private async Task RunAsync(CancellationToken ct)
    {
        var scheduleMin = Check.Int("schedule_min", 60);
        _logger.LogInformation("Bandbreiten-Check {Id} ({Type}) gestartet: {Target}, {Plan}", Check.Id, Check.Type, Check.Target,
            scheduleMin > 0 ? $"alle {scheduleMin} min" : "nur manuell");
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var next = Schedule.NextRun(DateTime.Now, scheduleMin, Check.Int("offset_min", 0),
                    Check.Str("window_start", "00:00"), Check.Str("window_end", "23:59"), Check.Str("weekdays", "1234567"));
                var wait = next is DateTime n ? n - DateTime.Now : Timeout.InfiniteTimeSpan;
                if (wait != Timeout.InfiniteTimeSpan && wait < TimeSpan.Zero)
                {
                    wait = TimeSpan.Zero;
                }

                // lange Wartezeiten stückeln, damit Zeitumstellung und Ruhezustand den Plan nicht verschieben
                if (wait == Timeout.InfiniteTimeSpan || wait > TimeSpan.FromMinutes(5))
                {
                    if (await _manual.WaitAsync(TimeSpan.FromMinutes(5), ct).ConfigureAwait(false))
                    {
                        await MeasureAndReportAsync("manual", ct).ConfigureAwait(false);
                    }

                    continue;
                }

                var manual = await _manual.WaitAsync(wait, ct).ConfigureAwait(false);
                await MeasureAndReportAsync(manual ? "manual" : "schedule", ct).ConfigureAwait(false);
                if (!manual)
                {
                    await Task.Delay(TimeSpan.FromSeconds(61), ct).ConfigureAwait(false);   // nicht zweimal im selben Slot
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Bandbreiten-Check {Id} unerwartet beendet", Check.Id);
        }
    }

    private async Task MeasureAndReportAsync(string trigger, CancellationToken ct)
    {
        await OneAtATime.WaitAsync(ct).ConfigureAwait(false);
        BandwidthResult result;
        try
        {
            _logger.LogInformation("Bandbreiten-Check {Id}: Messung startet ({Trigger})", Check.Id, trigger);
            result = new BandwidthResult
            {
                CheckId = Check.Id,
                Ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Trigger = trigger,
                Results = await MeasureAsync(ct).ConfigureAwait(false),
            };
        }
        finally
        {
            OneAtATime.Release();
        }

        foreach (var r in result.Results)
        {
            if (r.Error is null)
            {
                _logger.LogInformation("Bandbreiten-Check {Id}: {Direction} {Mbps} Mbit/s", Check.Id, r.Direction, r.Mbps);
            }
            else
            {
                _logger.LogWarning("Bandbreiten-Check {Id}: {Direction} fehlgeschlagen: {Error}", Check.Id, r.Direction, r.Error);
            }
        }

        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                await _report(result, ct).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.LogDebug("Ergebnis nicht gesendet ({Message}), neuer Versuch", ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(30 * (attempt + 1)), ct).ConfigureAwait(false);
            }
        }

        _logger.LogWarning("Bandbreiten-Ergebnis von Check {Id} konnte nicht gesendet werden", Check.Id);
    }

    internal async Task<List<BandwidthMeasurement>> MeasureAsync(CancellationToken ct)
    {
        var direction = Check.Str("direction", "both");
        var directions = direction == "both" ? new[] { "down", "up" } : new[] { direction };
        var useIperf = Check.Type == "iperf" || Check.Str("method", "http") == "iperf";
        var list = new List<BandwidthMeasurement>();

        if (useIperf)
        {
            var protocol = Check.Str("protocol", "tcp");
            if (Check.Peer?.Error is { Length: > 0 } || string.IsNullOrWhiteSpace(Check.Peer?.Host))
            {
                var message = Check.Peer?.Error ?? "Gegenstelle unbekannt";
                list.AddRange(directions.Select(d => new BandwidthMeasurement { Direction = d, Protocol = protocol, Error = message }));
                return list;
            }

            var options = new IperfOptions(
                Check.Peer!.Host!, Check.Peer.Port ?? 5201, protocol,
                Math.Clamp(Check.Int("duration_s", 10), 1, 120), Math.Clamp(Check.Int("omit_s", 1), 0, 30),
                Check.Int("streams", 1), Check.Double("udp_mbps", 100), Check.Int("window_kb", 0),
                Math.Clamp(Check.Int("timeout_s", 60), 10, 600));
            foreach (var d in directions)
            {
                list.Add(await Iperf.RunAsync(options, d, ct).ConfigureAwait(false));
            }

            return list;
        }

        var duration = Math.Clamp(Check.Int("duration_s", 10), 2, 120);
        var streams = Math.Clamp(Check.Int("streams", 4), 1, 32);
        using var http = new HttpSpeedTest(Check.Bool("use_proxy", false) ? _proxy : null);
        using var overall = CancellationTokenSource.CreateLinkedTokenSource(ct);
        overall.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(Check.Int("timeout_s", 90), 10, 600)));
        double? latency = null;
        if (Check.Str("latency_url", string.Empty) is { Length: > 0 } latencyUrl)
        {
            latency = await http.LatencyAsync(latencyUrl, overall.Token).ConfigureAwait(false);
        }

        foreach (var d in directions)
        {
            var url = Check.Str(d == "down" ? "down_url" : "up_url", string.Empty);
            if (string.IsNullOrEmpty(url))
            {
                continue;
            }

            try
            {
                var m = d == "down"
                    ? await http.DownloadAsync(url, streams, duration, overall.Token).ConfigureAwait(false)
                    : await http.UploadAsync(url, streams, duration, overall.Token).ConfigureAwait(false);
                m.LatencyMs = latency;
                list.Add(m);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                list.Add(new BandwidthMeasurement { Direction = d, Protocol = "http", Error = "Abbruch: Zeitlimit des Checks erreicht" });
            }
        }

        return list;
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
        _logger.LogInformation("Bandbreiten-Check {Id} beendet", Check.Id);
    }
}
