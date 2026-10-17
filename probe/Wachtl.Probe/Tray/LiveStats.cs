using System.Net.NetworkInformation;
using Wachtl.Probe.Config;

namespace Wachtl.Probe.Tray;

/// <summary>Ping eines Internet-Ziels für das Tray-Menü: letzte Antwortzeit und Verlust der letzten Minute.</summary>
public sealed class LivePing
{
    public string Target { get; init; } = string.Empty;
    public bool Up { get; init; }
    public double? RttMs { get; init; }
    public double LossPct { get; init; }
}

/// <summary>Ergebnis des letzten WAN-Speedtests.</summary>
public sealed class LiveSpeedtest
{
    public double? DownMbps { get; init; }
    public double? UpMbps { get; init; }
    public long Ts { get; init; }
}

/// <summary>Teil von GET /tray/v1/status: aktuelle Werte für das Menü des Tray-Symbols.</summary>
public sealed class LiveInternet
{
    public List<LivePing> Pings { get; init; } = new();

    /// <summary>Aktueller Datenverkehr der Netzwerkkarte(n) mit Gateway, null solange noch kein Vergleichswert da ist.</summary>
    public double? RxMbps { get; init; }
    public double? TxMbps { get; init; }
    public LiveSpeedtest? Speedtest { get; init; }
}

/// <summary>
/// Hält die aktuellen Werte für das Tray-Menü im Speicher: Pings zu den Internet-Referenzen (letzte 60 s),
/// den letzten Speedtest und die momentane Datenrate. Nichts davon geht an den Server.
/// </summary>
public sealed class LiveStats
{
    public static readonly TimeSpan PingWindow = TimeSpan.FromSeconds(60);
    public const int MaxPings = 3;

    private readonly object _lock = new();
    private readonly Dictionary<long, PingTrack> _pings = new();
    private readonly Func<(long Rx, long Tx)?> _readCounters;
    private readonly Func<DateTimeOffset> _clock;
    private LiveSpeedtest? _speedtest;
    private (DateTimeOffset At, long Rx, long Tx)? _lastCounters;
    private (double Rx, double Tx)? _lastRate;

    public LiveStats(Func<(long Rx, long Tx)?>? readCounters = null, Func<DateTimeOffset>? clock = null)
    {
        _readCounters = readCounters ?? ReadCounters;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    private sealed class PingTrack
    {
        public string Target = string.Empty;
        public readonly Queue<(DateTimeOffset At, bool Up, double Rtt)> Samples = new();
    }

    /// <summary>Vom Ping-Check aufgerufen; nur Rolle „Referenz (Internet)“ zählt.</summary>
    public void RecordPing(CheckConfig check, bool up, double rttMs)
    {
        if (check.Role != "reference")
        {
            return;
        }

        var now = _clock();
        lock (_lock)
        {
            if (!_pings.TryGetValue(check.Id, out var track))
            {
                track = new PingTrack();
                _pings[check.Id] = track;
            }

            track.Target = check.Target;
            track.Samples.Enqueue((now, up, rttMs));
            while (track.Samples.Count > 0 && now - track.Samples.Peek().At > PingWindow)
            {
                track.Samples.Dequeue();
            }
        }
    }

    /// <summary>Checks, die es nicht mehr gibt, aus der Anzeige nehmen.</summary>
    public void KeepChecks(IEnumerable<long> checkIds)
    {
        var keep = checkIds.ToHashSet();
        lock (_lock)
        {
            foreach (var id in _pings.Keys.Where(id => !keep.Contains(id)).ToList())
            {
                _pings.Remove(id);
            }
        }
    }

    /// <summary>Vom Bandbreiten-Check aufgerufen; nur der WAN-Speedtest zählt.</summary>
    public void RecordBandwidth(CheckConfig check, BandwidthResult result)
    {
        if (check.Type != "speedtest")
        {
            return;
        }

        double? Value(string direction) =>
            result.Results.FirstOrDefault(r => r.Direction == direction && r.Error is null && r.Mbps is not null)?.Mbps;

        var down = Value("down");
        var up = Value("up");
        if (down is null && up is null)
        {
            return;
        }

        lock (_lock)
        {
            _speedtest = new LiveSpeedtest { DownMbps = down, UpMbps = up, Ts = result.Ts };
        }
    }

    public LiveInternet Snapshot()
    {
        var now = _clock();
        var rate = TrafficRate(now);
        lock (_lock)
        {
            var pings = _pings.OrderBy(kv => kv.Key).Take(MaxPings).Select(kv =>
            {
                var samples = kv.Value.Samples.Where(s => now - s.At <= PingWindow).ToList();
                var last = samples.LastOrDefault();
                return new LivePing
                {
                    Target = kv.Value.Target,
                    Up = samples.Count > 0 && last.Up,
                    RttMs = samples.Count > 0 && last.Up ? Math.Round(last.Rtt, 1) : null,
                    LossPct = samples.Count == 0 ? 0 : Math.Round(100.0 * samples.Count(s => !s.Up) / samples.Count, 1),
                };
            }).Where(p => p.Up || p.LossPct > 0).ToList();

            return new LiveInternet
            {
                Pings = pings,
                RxMbps = rate?.Rx,
                TxMbps = rate?.Tx,
                Speedtest = _speedtest,
            };
        }
    }

    /// <summary>Datenrate seit dem letzten Abruf (frühestens nach 1 s neu, Abstände über 120 s gelten nicht).</summary>
    private (double Rx, double Tx)? TrafficRate(DateTimeOffset now)
    {
        lock (_lock)
        {
            if (_lastCounters is { } prev && (now - prev.At).TotalSeconds < 1)
            {
                return _lastRate;
            }
        }

        (long Rx, long Tx)? counters;
        try
        {
            counters = _readCounters();
        }
        catch (Exception)
        {
            counters = null;
        }

        lock (_lock)
        {
            if (counters is not { } c)
            {
                _lastCounters = null;
                _lastRate = null;
                return null;
            }

            (double, double)? rate = null;
            if (_lastCounters is { } prev)
            {
                var seconds = (now - prev.At).TotalSeconds;
                var dRx = c.Rx - prev.Rx;
                var dTx = c.Tx - prev.Tx;
                if (seconds is >= 1 and <= 120 && dRx >= 0 && dTx >= 0)
                {
                    rate = (Math.Round(dRx * 8 / seconds / 1_000_000, 2), Math.Round(dTx * 8 / seconds / 1_000_000, 2));
                }
            }

            _lastCounters = (now, c.Rx, c.Tx);
            _lastRate = rate;
            return rate;
        }
    }

    /// <summary>Byte-Zähler aller aktiven Netzwerkkarten mit Standard-Gateway (der Weg ins Internet).</summary>
    private static (long Rx, long Tx)? ReadCounters()
    {
        long rx = 0, tx = 0;
        var any = false;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up
                || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            var props = nic.GetIPProperties();
            if (!props.GatewayAddresses.Any(g => !g.Address.Equals(System.Net.IPAddress.Any)
                                                 && !g.Address.Equals(System.Net.IPAddress.IPv6Any)))
            {
                continue;
            }

            var stats = nic.GetIPStatistics();
            rx += stats.BytesReceived;
            tx += stats.BytesSent;
            any = true;
        }

        return any ? (rx, tx) : null;
    }
}
