using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Config;
using Wachtl.Probe.Metrics;

namespace Wachtl.Probe.Checks;

/// <summary>
/// Pfad-Check: ermittelt die Router bis zum Ziel (Traceroute über ICMP mit steigender TTL)
/// und pingt danach jeden Hop dauerhaft. Der Pfad wird regelmäßig, bei Verlust am Ziel
/// und auf Anforderung neu ermittelt.
/// </summary>
public sealed class PathRunner : IAsyncDisposable
{
    private const int LossRetraceAfter = 3;              // Fehlschläge am Ziel in Folge
    private static readonly TimeSpan MinRetraceGap = TimeSpan.FromSeconds(60);
    private const int MaxSilentHops = 6;                  // Traceroute abbrechen nach so vielen stummen Hops in Folge

    private readonly ISampleSink _sink;
    private readonly GatewayResolver _gateway;
    private readonly Func<PathResult, CancellationToken, Task> _report;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _retrace = new(0, 1);
    private readonly Task _task;
    private string _retraceReason = "manual";

    public PathRunner(CheckConfig check, ISampleSink sink, GatewayResolver gateway,
        Func<PathResult, CancellationToken, Task> report, ILogger logger)
    {
        Check = check;
        _sink = sink;
        _gateway = gateway;
        _report = report;
        _logger = logger;
        _task = Task.Run(() => RunAsync(_cts.Token));
    }

    public CheckConfig Check { get; }

    /// <summary>Pfad beim nächsten Takt neu ermitteln („Neu ermitteln“ im Web-UI).</summary>
    public void RequestRetrace(string reason = "manual")
    {
        _retraceReason = reason;
        if (_retrace.CurrentCount == 0)
        {
            _retrace.Release();
        }
    }

    private sealed class HopState
    {
        public HopState(int hop, IPAddress address, bool isDestination)
        {
            Hop = hop;
            Address = address;
            IsDestination = isDestination;
        }

        public int Hop { get; }
        public IPAddress Address { get; }
        public bool IsDestination { get; }
        public Ping Ping { get; } = new();
        public JitterCalculator Jitter { get; } = new();
    }

    private async Task RunAsync(CancellationToken ct)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(1, Check.IntervalS));
        var timeout = TimeSpan.FromMilliseconds(Math.Clamp(Check.TimeoutMs, 100, (int)interval.TotalMilliseconds));
        var traceEvery = TimeSpan.FromMinutes(Math.Clamp(Check.Int("trace_interval_min", 10), 1, 1440));
        var retraceOnLoss = Check.Bool("retrace_on_loss", true);
        var payload = new byte[Math.Clamp(Check.Int("hop_size_bytes", 32), 0, 1472)];
        var options = new PingOptions(128, false);
        var jitterEvery = TimeSpan.FromSeconds(60);

        _logger.LogInformation("Pfad-Check {Id} gestartet: {Target}, Hops alle {Interval} s, Pfad alle {Trace} min",
            Check.Id, Check.Target, Check.IntervalS, traceEvery.TotalMinutes);

        var hops = new List<HopState>();
        var reason = "start";
        var nextTrace = DateTimeOffset.MinValue;
        var lastTrace = DateTimeOffset.MinValue;
        var nextJitter = DateTimeOffset.UtcNow + jitterEvery;
        var destinationFailures = 0;
        using var timer = new PeriodicTimer(interval);
        try
        {
            do
            {
                var now = DateTimeOffset.UtcNow;
                if (_retrace.Wait(0))
                {
                    reason = _retraceReason;
                    nextTrace = DateTimeOffset.MinValue;
                }

                if (now >= nextTrace)
                {
                    var result = await TraceAsync(reason, ct).ConfigureAwait(false);
                    lastTrace = DateTimeOffset.UtcNow;
                    nextTrace = lastTrace + traceEvery;
                    reason = "schedule";
                    destinationFailures = 0;
                    if (result is not null)
                    {
                        Dispose(hops);
                        hops = await BuildHopListAsync(result, ct).ConfigureAwait(false);
                        _ = ReportAsync(result, ct);
                    }
                }

                if (hops.Count == 0)
                {
                    continue;
                }

                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var replies = await Task.WhenAll(hops.Select(h =>
                    PingHelper.SendAsync(h.Ping, h.Address, timeout, payload, options, ct))).ConfigureAwait(false);
                for (var i = 0; i < hops.Count; i++)
                {
                    var hop = hops[i];
                    var reply = replies[i];
                    var ip = hop.Address.ToString();
                    _sink.Add(MetricLine.FormatHop(MetricLine.HopUp, Check.Id, hop.Hop, ip, reply.Success ? 1 : 0, timestamp));
                    if (reply.Success)
                    {
                        _sink.Add(MetricLine.FormatHop(MetricLine.HopRtt, Check.Id, hop.Hop, ip, reply.RttMs, timestamp));
                        hop.Jitter.Add(reply.RttMs);
                    }

                    if (hop.IsDestination)
                    {
                        destinationFailures = reply.Success ? 0 : destinationFailures + 1;
                    }
                }

                if (DateTimeOffset.UtcNow >= nextJitter)
                {
                    foreach (var hop in hops)
                    {
                        if (hop.Jitter.TakeAndReset() is double j)
                        {
                            _sink.Add(MetricLine.FormatHop(MetricLine.HopJitter, Check.Id, hop.Hop, hop.Address.ToString(), j, timestamp));
                        }
                    }

                    nextJitter += jitterEvery;
                }

                if (retraceOnLoss && destinationFailures >= LossRetraceAfter && DateTimeOffset.UtcNow - lastTrace >= MinRetraceGap)
                {
                    _logger.LogInformation("Pfad-Check {Id}: Ziel {Target} antwortet nicht, Pfad wird neu ermittelt", Check.Id, Check.Target);
                    reason = "loss";
                    nextTrace = DateTimeOffset.MinValue;
                }
            }
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Pfad-Check {Id} unerwartet beendet", Check.Id);
        }
        finally
        {
            Dispose(hops);
        }
    }

    private static void Dispose(List<HopState> hops)
    {
        foreach (var h in hops)
        {
            h.Ping.Dispose();
        }
    }

    /// <summary>Traceroute per ICMP. Gibt null zurück, wenn das Ziel nicht aufgelöst werden kann.</summary>
    internal async Task<PathResult?> TraceAsync(string reason, CancellationToken ct)
    {
        var (destination, error) = await PingHelper.ResolveAsync(Check.Target, _gateway, ct).ConfigureAwait(false);
        if (destination is null)
        {
            _logger.LogWarning("Pfad-Check {Id}: {Error}", Check.Id, error);
            return null;
        }

        var maxHops = Math.Clamp(Check.Int("max_hops", 20), 1, 64);
        var attempts = Math.Clamp(Check.Int("probes_per_hop", 2), 1, 5);
        var timeout = TimeSpan.FromMilliseconds(Math.Clamp(Check.Int("trace_timeout_ms", 1000), 100, 5000));
        var payload = new byte[32];
        var result = new List<PathHop>();
        var reached = false;
        var silent = 0;
        using var ping = new Ping();
        for (var ttl = 1; ttl <= maxHops && !reached; ttl++)
        {
            PathHop hop = new() { Hop = ttl };
            for (var attempt = 0; attempt < attempts; attempt++)
            {
                var reply = await PingHelper.SendAsync(ping, destination, timeout, payload, new PingOptions(ttl, false), ct)
                    .ConfigureAwait(false);
                if (reply.Success)
                {
                    hop = new PathHop { Hop = ttl, Ip = (reply.From ?? destination).ToString(), RttMs = reply.RttMs };
                    reached = true;
                    break;
                }

                if (reply.Status is IPStatus.TtlExpired or IPStatus.TimeExceeded && reply.From is not null)
                {
                    hop = new PathHop { Hop = ttl, Ip = reply.From.ToString(), RttMs = reply.RttMs };
                    break;
                }
            }

            result.Add(hop);
            silent = hop.Ip is null ? silent + 1 : 0;
            if (silent >= MaxSilentHops)
            {
                break;
            }
        }

        // stumme Hops am Ende entfernen (Ziel blockt ICMP oder liegt hinter max_hops)
        while (result.Count > 0 && result[^1].Ip is null)
        {
            result.RemoveAt(result.Count - 1);
        }

        if (result.Count == 0)
        {
            result.Add(new PathHop { Hop = 1 });
        }

        _logger.LogInformation("Pfad-Check {Id}: {Count} Hops bis {Target}, Ziel {Reached}", Check.Id, result.Count,
            Check.Target, reached ? "erreicht" : "nicht erreicht");
        return new PathResult
        {
            CheckId = Check.Id,
            Ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Reason = reason,
            Reached = reached,
            Hops = result,
        };
    }

    private async Task<List<HopState>> BuildHopListAsync(PathResult trace, CancellationToken ct)
    {
        var mode = Check.Str("ping_hops", "all");
        var firstN = Math.Clamp(Check.Int("first_n", 5), 1, 64);
        var skipPrivate = Check.Bool("skip_private", false);
        var list = new List<HopState>();
        if (mode == "none")
        {
            return list;
        }

        foreach (var hop in trace.Hops)
        {
            if (hop.Ip is null || !IPAddress.TryParse(hop.Ip, out var address))
            {
                continue;
            }

            var isDestination = trace.Reached && hop == trace.Hops[^1];
            if (!isDestination && mode == "first" && hop.Hop > firstN)
            {
                continue;
            }

            if (!isDestination && skipPrivate && IsPrivate(address))
            {
                continue;
            }

            list.Add(new HopState(hop.Hop, address, isDestination));
        }

        // Ziel nicht erreicht (ICMP mit TTL gefiltert): Ziel trotzdem als letzten Hop anpingen
        if (!trace.Reached)
        {
            var (destination, _) = await PingHelper.ResolveAsync(Check.Target, _gateway, ct).ConfigureAwait(false);
            if (destination is not null)
            {
                var next = (trace.Hops.Count == 0 ? 0 : trace.Hops[^1].Hop) + 1;
                list.Add(new HopState(Math.Min(next, 64), destination, true));
            }
        }

        return list;
    }

    internal static bool IsPrivate(IPAddress address)
    {
        var b = address.GetAddressBytes();
        return b.Length == 4 && (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)
                                 || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || b[0] == 169 && b[1] == 254);
    }

    private async Task ReportAsync(PathResult result, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 5 && !ct.IsCancellationRequested; attempt++)
        {
            try
            {
                await _report(result, ct).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.LogDebug("Pfad-Ergebnis nicht gesendet ({Message}), neuer Versuch", ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(30 * (attempt + 1)), ct).ConfigureAwait(false);
            }
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
        _logger.LogInformation("Pfad-Check {Id} beendet", Check.Id);
    }
}
