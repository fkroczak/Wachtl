using System.Text.Json;
using Wachtl.Probe.Bandwidth;
using Wachtl.Probe.Checks;
using Wachtl.Probe.Config;
using Wachtl.Probe.Metrics;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tests;

public class ScheduleTests
{
    [Fact]
    public void HourlyWithOffset()
    {
        var next = Schedule.NextRun(new DateTime(2026, 10, 14, 10, 20, 0), 60, 17, "00:00", "23:59", "1234567");
        Assert.Equal(new DateTime(2026, 10, 14, 10, 17, 0).AddHours(1), next);
    }

    [Fact]
    public void RespectsWindowAndWeekdays()
    {
        // Freitag 18:30, nur werktags 08:00–18:00 -> Montag 08:00
        var next = Schedule.NextRun(new DateTime(2026, 10, 16, 18, 30, 0), 60, 0, "08:00", "18:00", "12345");
        Assert.Equal(new DateTime(2026, 10, 19, 8, 0, 0), next);
    }

    [Fact]
    public void OvernightWindow()
    {
        var next = Schedule.NextRun(new DateTime(2026, 10, 14, 12, 0, 0), 120, 0, "22:00", "04:00", "1234567");
        Assert.Equal(new DateTime(2026, 10, 14, 22, 0, 0), next);
    }

    [Fact]
    public void ManualOnlyHasNoSchedule()
    {
        Assert.Null(Schedule.NextRun(DateTime.Now, 0, 0, "00:00", "23:59", "1234567"));
    }

    [Fact]
    public void WeeklyCountsFromMonday()
    {
        // Mittwoch, alle 7 Tage mit Versatz 1 Tag + 3 h -> Dienstag 03:00 der nächsten Woche
        var next = Schedule.NextRun(new DateTime(2026, 10, 14, 12, 0, 0), 10080, 1620, "00:00", "23:59", "1234567");
        Assert.Equal(new DateTime(2026, 10, 20, 3, 0, 0), next);
    }
}

public class IperfParseTests
{
    [Fact]
    public void ParsesTcp()
    {
        const string json = """
            {"start": {}, "end": {"sum_sent": {"seconds": 10.0, "bits_per_second": 95000000, "retransmits": 12},
                                   "sum_received": {"seconds": 10.02, "bits_per_second": 94120000}}}
            """;
        var r = new BandwidthMeasurement { Direction = "down", Protocol = "tcp" };
        Iperf.Parse(json, r);
        Assert.Null(r.Error);
        Assert.Equal(94.12, r.Mbps);
        Assert.Equal(12, r.Retransmits);
        Assert.Equal(10.0, r.DurationS);
    }

    [Fact]
    public void ParsesUdp()
    {
        const string json = """
            {"end": {"sum": {"seconds": 10, "bits_per_second": 49800000, "jitter_ms": 0.42, "lost_percent": 1.5}}}
            """;
        var r = new BandwidthMeasurement { Direction = "up", Protocol = "udp" };
        Iperf.Parse(json, r);
        Assert.Equal(49.8, r.Mbps);
        Assert.Equal(0.42, r.JitterMs);
        Assert.Equal(1.5, r.LossPct);
    }

    [Fact]
    public void ReportsError()
    {
        var r = new BandwidthMeasurement { Protocol = "tcp" };
        Iperf.Parse("""{"start": {}, "end": {}, "error": "unable to connect to server: Connection refused"}""", r);
        Assert.Contains("Connection refused", r.Error);
        var empty = new BandwidthMeasurement();
        Iperf.Parse("", empty);
        Assert.NotNull(empty.Error);
    }

    [Fact]
    public void BuildsArguments()
    {
        var o = new IperfOptions("10.0.0.5", 5300, "udp", 15, 2, 4, 50.5, 0, 60);
        var args = Iperf.ClientArguments(o, reverse: true);
        Assert.Equal("10.0.0.5", args[1]);
        Assert.Contains("-R", args);
        Assert.Contains("50.5M", args);
        Assert.Contains("-u", args);
        Assert.Equal("4", args[args.ToList().IndexOf("-P") + 1]);
    }
}

public class CheckParamsTests
{
    [Fact]
    public void ReadsTypedParamsAndPeer()
    {
        const string json = """
            {"probe_id": 1, "etag": "x", "iperf_server": {"enabled": true, "port": 5300},
             "checks": [{"id": 9, "type": "iperf", "target": "wachtl-server", "role": "target", "interval_s": 3600, "timeout_ms": 60000,
                         "params": {"duration_s": 15, "protocol": "udp", "udp_mbps": 20.5, "retrace_on_loss": false},
                         "peer": {"host": "wachtl.kunde.local", "port": 5201, "error": null}}]}
            """;
        var config = JsonSerializer.Deserialize<ProbeConfig>(json, ApiClient.JsonOptions)!;
        var c = config.Checks[0];
        Assert.True(config.IperfServer.Enabled);
        Assert.Equal(5300, config.IperfServer.Port);
        Assert.Equal(15, c.Int("duration_s", 10));
        Assert.Equal("udp", c.Str("protocol", "tcp"));
        Assert.Equal(20.5, c.Double("udp_mbps", 100));
        Assert.False(c.Bool("retrace_on_loss", true));
        Assert.Equal(7, c.Int("missing", 7));
        Assert.Equal("wachtl.kunde.local", c.Peer!.Host);
        Assert.Contains("duration_s=15", c.Key);
    }

    [Fact]
    public void HeartbeatCarriesAddressesAndCommandsParse()
    {
        var json = JsonSerializer.Serialize(new HeartbeatRequest { Addresses = new() { "10.0.0.2" } }, ApiClient.JsonOptions);
        Assert.Contains("\"addresses\":[\"10.0.0.2\"]", json);
        var resp = JsonSerializer.Deserialize<HeartbeatResponse>(
            """{"config_etag": "a", "server_time": 1, "commands": [{"id": 3, "type": "run_check", "check_id": 9}]}""",
            ApiClient.JsonOptions)!;
        Assert.Equal("run_check", resp.Commands[0].Type);
        Assert.Equal(9, resp.Commands[0].CheckId);
    }

    [Fact]
    public void FormatsHopMetricAndResults()
    {
        Assert.Equal("wachtl_hop_rtt_ms{check_id=\"4\",hop=\"3\",hop_ip=\"62.1.2.3\"} 9.5 1000",
            MetricLine.FormatHop(MetricLine.HopRtt, 4, 3, "62.1.2.3", 9.5, 1000));
        var json = JsonSerializer.Serialize(new PathResult { CheckId = 4, Hops = new() { new PathHop { Hop = 1, Ip = "10.0.0.1", RttMs = 0.4 } } },
            ApiClient.JsonOptions);
        Assert.Contains("\"rtt_ms\":0.4", json);
        Assert.Contains("\"check_id\":4", json);
    }

    [Fact]
    public void DetectsPrivateAddresses()
    {
        Assert.True(PathRunner.IsPrivate(System.Net.IPAddress.Parse("192.168.1.1")));
        Assert.True(PathRunner.IsPrivate(System.Net.IPAddress.Parse("100.64.3.1")));
        Assert.False(PathRunner.IsPrivate(System.Net.IPAddress.Parse("62.1.2.3")));
    }
}
