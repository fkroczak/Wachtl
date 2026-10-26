using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Bandwidth;
using Wachtl.Probe.Config;

namespace Wachtl.Probe.NetScan;

/// <summary>
/// Netzwerkscan nach Zeitplan oder auf Anforderung „Jetzt messen“ (docs/NETZWERKSCAN.md).
/// Es läuft nie mehr als ein Scan gleichzeitig, auch nicht über mehrere Netzwerkscan-Checks hinweg.
/// </summary>
public sealed class NetScanRunner : IAsyncDisposable
{
    /// <summary>Sperre für alle Runner: nie zwei Scans gleichzeitig.</summary>
    private static readonly SemaphoreSlim Gate = new(1, 1);

    private readonly Func<NetScanResult, CancellationToken, Task> _report;
    private readonly Func<CheckConfig, ILogger, CancellationToken, Task<NetScanResult>> _scan;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _manual = new(0, 1);
    private readonly Task _task;

    public NetScanRunner(CheckConfig check, Func<NetScanResult, CancellationToken, Task> report, ILogger logger,
        Func<CheckConfig, ILogger, CancellationToken, Task<NetScanResult>>? scan = null)
    {
        Check = check;
        _report = report;
        _logger = logger;
        _scan = scan ?? ScanAsync;
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

    /// <summary>Einstellungen aus Ziel und Parametern; null und <paramref name="error"/> bei ungültiger Portliste.</summary>
    public static NetScanOptions? Options(CheckConfig check, out string? error)
    {
        var ports = PortList.Parse(PortsParam(check), out error);
        if (ports is null)
        {
            return null;
        }

        return new NetScanOptions(
            string.IsNullOrWhiteSpace(check.Target) ? "auto" : check.Target.Trim(),
            ports,
            check.Bool("port_scan", true),
            Math.Clamp(check.Int("timeout_ms", 500), 50, 10_000),
            Math.Clamp(check.Int("parallel", 64), 1, 512),
            Math.Clamp(check.Int("max_hosts", 1024), 1, 65_536));
    }

    private static string? PortsParam(CheckConfig check)
    {
        if (!check.Params.TryGetValue("ports", out var v))
        {
            return null;
        }

        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.GetRawText(),
            JsonValueKind.Array => string.Join(",", v.EnumerateArray().Select(e =>
                e.ValueKind == JsonValueKind.String ? e.GetString() : e.GetRawText())),
            _ => null,
        };
    }

    /// <summary>Netze bestimmen, Grenzen prüfen, scannen. Fehler stehen in <see cref="NetScanResult.Error"/>.</summary>
    internal static async Task<NetScanResult> ScanAsync(CheckConfig check, ILogger logger, CancellationToken ct)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = new NetScanResult();
        try
        {
            var options = Options(check, out var error);
            if (options is null)
            {
                result.Error = error;
                return result;
            }

            var subnets = SubnetPlanner.Plan(options.Target, SubnetPlanner.LocalAddresses, out error);
            if (subnets is null)
            {
                result.Error = error;
                return result;
            }

            result.Subnets = subnets.Select(s => s.ToString()).ToList();
            var count = SubnetPlanner.CountHosts(subnets);
            if (count > options.MaxHosts)
            {
                result.Error = string.Create(CultureInfo.InvariantCulture,
                    $"Zu viele Adressen: {count} in {string.Join(", ", result.Subnets)} (höchstens {options.MaxHosts}) – Netz verkleinern oder max_hosts erhöhen");
                return result;
            }

            if (count == 0)
            {
                result.Error = "Keine Adressen zu scannen";
                return result;
            }

            result.Hosts = await NetScanner.ScanAsync(options, subnets, logger, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogError(ex, "Netzwerkscan {Id} fehlgeschlagen", check.Id);
            result.Error = "Scan fehlgeschlagen: " + ex.Message;
            result.Hosts = new List<NetScanHost>();
        }
        finally
        {
            result.DurationS = Math.Round(stopwatch.Elapsed.TotalSeconds, 1);
        }

        return result;
    }

    private async Task RunAsync(CancellationToken ct)
    {
        var scheduleMin = Check.Int("schedule_min", 15);
        _logger.LogInformation("Netzwerkscan {Id} gestartet: {Target}, {Plan}", Check.Id,
            string.IsNullOrWhiteSpace(Check.Target) ? "auto" : Check.Target, scheduleMin > 0 ? $"alle {scheduleMin} min" : "nur manuell");
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
                        await ScanAndReportAsync("manual", ct).ConfigureAwait(false);
                    }

                    continue;
                }

                var manual = await _manual.WaitAsync(wait, ct).ConfigureAwait(false);
                await ScanAndReportAsync(manual ? "manual" : "schedule", ct).ConfigureAwait(false);
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
            _logger.LogError(ex, "Netzwerkscan {Id} unerwartet beendet", Check.Id);
        }
    }

    internal async Task ScanAndReportAsync(string trigger, CancellationToken ct)
    {
        NetScanResult result;
        await Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _logger.LogInformation("Netzwerkscan {Id}: Scan startet ({Trigger})", Check.Id, trigger);
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            result = await _scan(Check, _logger, ct).ConfigureAwait(false);
            result.CheckId = Check.Id;
            result.Ts = ts;
            result.Trigger = trigger;
        }
        finally
        {
            Gate.Release();
        }

        if (ct.IsCancellationRequested)
        {
            return;
        }

        if (result.Error is null)
        {
            _logger.LogInformation("Netzwerkscan {Id}: {Hosts} Geräte, {Ports} offene Ports in {Subnets}, Dauer {Seconds} s", Check.Id,
                result.Hosts.Count, result.Hosts.Sum(h => h.Ports.Count), string.Join(", ", result.Subnets), result.DurationS);
        }
        else
        {
            _logger.LogWarning("Netzwerkscan {Id} fehlgeschlagen: {Error}", Check.Id, result.Error);
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

        _logger.LogWarning("Ergebnis von Netzwerkscan {Id} konnte nicht gesendet werden", Check.Id);
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
        _logger.LogInformation("Netzwerkscan {Id} beendet", Check.Id);
    }
}
