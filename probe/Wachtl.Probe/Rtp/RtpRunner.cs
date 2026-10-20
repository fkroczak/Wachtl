using Microsoft.Extensions.Logging;
using Wachtl.Probe.Bandwidth;
using Wachtl.Probe.Config;

namespace Wachtl.Probe.Rtp;

/// <summary>
/// Sprachtest (RTP) nach Zeitplan oder auf Anforderung „Jetzt testen“. Läuft unabhängig von Bandbreitenmessungen –
/// Sprache während eines Speedtests zeigt, ob die Leitung Sprache priorisiert.
/// </summary>
public sealed class RtpRunner : IAsyncDisposable
{
    private readonly Func<RtpResult, CancellationToken, Task> _report;
    private readonly Func<CheckConfig, CancellationToken, Task<RtpMeasurement>> _measure;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _manual = new(0, 1);
    private readonly Task _task;

    public RtpRunner(CheckConfig check, Func<RtpResult, CancellationToken, Task> report, ILogger logger,
        Func<CheckConfig, CancellationToken, Task<RtpMeasurement>>? measure = null)
    {
        Check = check;
        _report = report;
        _logger = logger;
        _measure = measure ?? MeasureAsync;
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

    public static RtpOptions? Options(CheckConfig check, out string? error)
    {
        error = null;
        if (check.Peer?.Error is { Length: > 0 } peerError)
        {
            error = peerError;
            return null;
        }

        if (string.IsNullOrWhiteSpace(check.Peer?.Host))
        {
            error = "Gegenstelle unbekannt";
            return null;
        }

        return new RtpOptions(check.Peer!.Host!, check.Peer.Port ?? RtpProtocol.DefaultPort, check.Str("codec", "g711"),
            Math.Clamp(check.Int("ptime_ms", 20), 10, 60), Math.Clamp(check.Int("duration_s", 30), 5, 300),
            Math.Clamp(check.Int("dscp", 46), 0, 63));
    }

    internal static async Task<RtpMeasurement> MeasureAsync(CheckConfig check, CancellationToken ct)
    {
        if (Options(check, out var error) is { } options)
        {
            return await RtpTest.RunAsync(options, ct).ConfigureAwait(false);
        }

        return new RtpMeasurement
        {
            Codec = check.Str("codec", "g711"), PtimeMs = check.Int("ptime_ms", 20), DurationS = check.Int("duration_s", 30),
            Error = error,
        };
    }

    private async Task RunAsync(CancellationToken ct)
    {
        var scheduleMin = Check.Int("schedule_min", 15);
        _logger.LogInformation("Sprachtest {Id} gestartet: {Target}, {Plan}", Check.Id, Check.Target,
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
            _logger.LogError(ex, "Sprachtest {Id} unerwartet beendet", Check.Id);
        }
    }

    internal async Task MeasureAndReportAsync(string trigger, CancellationToken ct)
    {
        _logger.LogInformation("Sprachtest {Id}: Test startet ({Trigger})", Check.Id, trigger);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var measurement = await _measure(Check, ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested)
        {
            return;
        }

        if (measurement.Error is null)
        {
            _logger.LogInformation("Sprachtest {Id}: MOS {Mos}, Laufzeit {Rtt} ms, Verlust {Loss} %, Jitter {Jitter} ms", Check.Id,
                measurement.Mos, measurement.RttMs, measurement.LossPct, measurement.JitterMs);
        }
        else
        {
            _logger.LogWarning("Sprachtest {Id} fehlgeschlagen: {Error}", Check.Id, measurement.Error);
        }

        var result = new RtpResult { CheckId = Check.Id, Ts = ts, Trigger = trigger, Result = measurement };
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

        _logger.LogWarning("Ergebnis von Sprachtest {Id} konnte nicht gesendet werden", Check.Id);
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
        _logger.LogInformation("Sprachtest {Id} beendet", Check.Id);
    }
}
