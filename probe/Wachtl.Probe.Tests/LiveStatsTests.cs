using System.Text.Json;
using Wachtl.Probe.Config;
using Wachtl.Probe.Transport;
using Wachtl.Probe.Tray;
using Wachtl.Tray.Core;
using TrayLive = Wachtl.Tray.Core.LiveInternet;

namespace Wachtl.Probe.Tests;

public class LiveStatsTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.FromUnixTimeSeconds(1_792_230_000);

    private static CheckConfig Check(long id, string role = "reference", string target = "1.1.1.1", string type = "ping") =>
        new() { Id = id, Role = role, Target = target, Type = type };

    [Fact]
    public void PingsOfReferencesWithLossOverLastMinute()
    {
        var now = T0;
        var live = new LiveStats(() => null, () => now);
        var cf = Check(1);
        var gw = Check(2, role: "gateway", target: "gateway");
        for (var i = 0; i < 100; i++)
        {
            now = T0.AddSeconds(i);
            live.RecordPing(cf, up: i % 10 != 0, rttMs: 12.34); // jede 10. Antwort fehlt
            live.RecordPing(gw, up: true, rttMs: 1);
        }

        var p = Assert.Single(live.Snapshot().Pings);   // Gateway zählt nicht als Internet
        Assert.Equal("1.1.1.1", p.Target);
        Assert.True(p.Up);
        Assert.Equal(12.3, p.RttMs);
        Assert.InRange(p.LossPct, 9, 11.5);              // nur die letzten 60 s

        live.RecordPing(cf, up: false, rttMs: 0);
        Assert.Null(live.Snapshot().Pings[0].RttMs);

        now = now.AddMinutes(5);                          // keine frischen Werte: Zeile verschwindet
        Assert.Empty(live.Snapshot().Pings);
    }

    [Fact]
    public void RemovedChecksDisappear()
    {
        var live = new LiveStats(() => null, () => T0);
        live.RecordPing(Check(1), true, 10);
        live.RecordPing(Check(2, target: "8.8.8.8"), true, 20);
        live.KeepChecks(new long[] { 2 });
        Assert.Equal("8.8.8.8", Assert.Single(live.Snapshot().Pings).Target);
    }

    [Fact]
    public void SpeedtestOnlyFromWanCheck()
    {
        var live = new LiveStats(() => null, () => T0);
        var result = new BandwidthResult
        {
            Ts = 1_792_229_000,
            Results =
            {
                new BandwidthMeasurement { Direction = "down", Mbps = 245.6 },
                new BandwidthMeasurement { Direction = "up", Error = "HTTP 403" },
            },
        };
        live.RecordBandwidth(Check(5, type: "iperf"), result);
        Assert.Null(live.Snapshot().Speedtest);
        live.RecordBandwidth(Check(6, type: "speedtest"), result);
        var st = live.Snapshot().Speedtest!;
        Assert.Equal(245.6, st.DownMbps);
        Assert.Null(st.UpMbps);
        Assert.Equal(1_792_229_000, st.Ts);
    }

    [Fact]
    public void TrafficRateFromCounters()
    {
        var now = T0;
        (long, long)? counters = (1_000_000, 500_000);
        var live = new LiveStats(() => counters, () => now);
        Assert.Null(live.Snapshot().RxMbps);              // erster Abruf: noch kein Vergleich

        now = T0.AddSeconds(2);
        counters = (1_000_000 + 2_500_000, 500_000 + 250_000); // 2 s: 10 Mbit/s runter, 1 Mbit/s hoch
        var s = live.Snapshot();
        Assert.Equal(10, s.RxMbps);
        Assert.Equal(1, s.TxMbps);

        now = T0.AddSeconds(2.5);                         // unter 1 s: letzter Wert
        Assert.Equal(10, live.Snapshot().RxMbps);

        now = T0.AddSeconds(4);
        counters = (10, 10);                              // Zähler zurückgesetzt (Karte neu verbunden)
        Assert.Null(live.Snapshot().RxMbps);

        counters = null;
        now = T0.AddSeconds(6);
        Assert.Null(live.Snapshot().RxMbps);
    }

    [Fact]
    public void StatusJsonReachesTray()
    {
        var live = new Wachtl.Probe.Tray.LiveInternet
        {
            Pings = { new Wachtl.Probe.Tray.LivePing { Target = "1.1.1.1", Up = true, RttMs = 12.3, LossPct = 1.5 } },
            RxMbps = 3.21, TxMbps = 0.4,
            Speedtest = new Wachtl.Probe.Tray.LiveSpeedtest { DownMbps = 245.6, UpMbps = 38.2, Ts = T0.ToUnixTimeSeconds() },
        };
        var json = JsonSerializer.Serialize(new TrayStatusResponse { Enrolled = true, Internet = live }, ApiClient.JsonOptions);
        var parsed = Json.Read<TrayStatus>(json)!.Internet!;
        Assert.Equal(12.3, parsed.Pings![0].RttMs);
        Assert.Equal(3.21, parsed.RxMbps);
        Assert.Equal(38.2, parsed.Speedtest!.UpMbps);
    }

    [Fact]
    public void MenuLines()
    {
        var at = DateTimeOffset.FromUnixTimeSeconds(1_792_230_000).ToLocalTime().DateTime;
        var lines = LiveTexts.Lines(new TrayLive
        {
            Pings = new List<Wachtl.Tray.Core.LivePing>
            {
                new() { Target = "1.1.1.1", Up = true, RttMs = 12.34 },
                new() { Target = "8.8.8.8", Up = true, RttMs = 8.04, LossPct = 3.3 },
                new() { Target = "9.9.9.9", Up = false, LossPct = 100 },
            },
            RxMbps = 3.21, TxMbps = 125.4,
            Speedtest = new Wachtl.Tray.Core.LiveSpeedtest { DownMbps = 245.6, UpMbps = 38.2, Ts = 1_792_230_000 },
        }, at);
        Assert.Equal(new[]
        {
            "Ping 1.1.1.1: 12 ms",
            "Ping 8.8.8.8: 8,0 ms · 3,3 % Verlust",
            "Ping 9.9.9.9: keine Antwort · 100 % Verlust",
            "Jetzt: ↓ 3,2 Mbit/s   ↑ 125 Mbit/s",
            "Speedtest " + at.ToString("HH:mm") + ": ↓ 246 Mbit/s   ↑ 38 Mbit/s",
        }, lines);
        Assert.True(lines.Count <= LiveTexts.MaxLines);

        var empty = LiveTexts.Lines(new TrayLive(), at);
        Assert.Equal(new[] { "Ping Internet: keine Messung", "Jetzt: Datenrate wird gemessen …", "Speedtest: noch keine Messung" }, empty);
        Assert.Empty(LiveTexts.Lines(null, at));         // älterer Dienst oder Server: kein Abschnitt
    }
}
