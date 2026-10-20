using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Wachtl.Probe.Config;
using Wachtl.Probe.Rtp;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tests;

public class RtpTests
{
    /// <summary>
    /// Gemeinsamer Prüffall mit server/tests/test_rtp.py: 10 gesendet, Nr. 9 auf dem Hinweg verloren, Nr. 4 auf dem
    /// Rückweg, Nr. 6 kommt nach Nr. 7 an. Uhr des Reflektors 4 s versetzt.
    /// </summary>
    private static Dictionary<int, RtpRecord> Vector()
    {
        int?[] up = { 10, 12, 10, 11, null, 10, 15, 10, 10 };
        int?[] down = { 10, 10, 11, 10, null, 12, 30, 10, 10 };
        var records = new Dictionary<int, RtpRecord>();
        for (var i = 0; i < 9; i++)
        {
            if (up[i] is not int u)
            {
                continue;
            }

            long t1 = 1_000_000 + i * 20_000;
            records[i] = new RtpRecord(t1, 5_000_000 + i * 20_000 + u * 1000, (uint)(i + 1), t1 + (u + down[i]!.Value) * 1000);
        }

        return records;
    }

    [Fact]
    public void AnalysisMatchesServerProbe()
    {
        var m = new RtpMeasurement();
        RtpAnalysis.Analyze(m, 10, Vector(), 9, RtpCodec.G711, 20);
        Assert.Null(m.Error);
        Assert.Equal(("wachtl", 10, 8), (m.Mode, m.Sent, m.Received));
        Assert.Equal(23.88, m.RttMs);
        Assert.Equal(45.0, m.RttMaxMs);
        Assert.Equal(20.0, m.LossPct);
        Assert.Equal(1, m.OutOfOrder);
        Assert.Equal(10.0, m.UpLossPct);
        Assert.Equal(11.11, m.DownLossPct);
        Assert.Equal(2.29, m.UpJitterMs);
        Assert.Equal(6.0, m.DownJitterMs);
        Assert.Equal(6.0, m.JitterMs);
        Assert.Equal(63.0, m.RFactor);
        Assert.Equal(3.25, m.Mos);

        var g729 = new RtpMeasurement();
        RtpAnalysis.Analyze(g729, 10, Vector(), null, RtpCodec.G729, 20);
        Assert.Equal((10.0, 50.0, 2.58), (g729.UpLossPct!.Value, g729.RFactor!.Value, g729.Mos!.Value));
    }

    [Fact]
    public void EchoModeAndNoAnswer()
    {
        var echo = Vector().ToDictionary(p => p.Key, p => p.Value with { T2Us = 0, Count = 0 });
        var m = new RtpMeasurement();
        RtpAnalysis.Analyze(m, 10, echo, null, RtpCodec.G711, 20);
        Assert.Equal("echo", m.Mode);
        Assert.Null(m.UpLossPct);
        Assert.Equal((20.0, 7.43, 2.57), (m.LossPct!.Value, m.JitterMs!.Value, m.Mos!.Value));

        var none = new RtpMeasurement();
        RtpAnalysis.Analyze(none, 50, new Dictionary<int, RtpRecord>(), null, RtpCodec.G711, 20);
        Assert.Contains("keine Antwort", none.Error);
        Assert.Equal(100.0, none.LossPct);
    }

    [Theory]
    [InlineData(20, 5, 0, "g711", 4.38)]
    [InlineData(20, 5, 1, "g711", 4.3)]
    [InlineData(20, 5, 5, "g711", 3.87)]
    [InlineData(20, 5, 0, "g729", 4.06)]
    [InlineData(200, 40, 0, "g711", 3.71)]
    public void MosScale(double delay, double jitter, double loss, string codec, double expected)
    {
        Assert.Equal(expected, Math.Round(RtpAnalysis.Mos(RtpAnalysis.RFactor(delay, jitter, loss, RtpCodec.Get(codec), 20)), 2));
    }

    [Fact]
    public void PacketLayoutMatchesProtocol()
    {
        var packet = RtpProtocol.Build(RtpCodec.G711, 20, 0x1_0005, 0xDEADBEEF, 123456, first: true);
        Assert.Equal(12 + 160, packet.Length);
        Assert.Equal(new byte[] { 0x80, 0x80, 0x00, 0x05 }, packet[..4]);
        Assert.Equal("WTL1"u8.ToArray(), packet[12..16]);
        var parsed = RtpProtocol.Parse(packet)!.Value;
        Assert.Equal(((ushort)5, 0xDEADBEEFu, 123456L, 0L, 0u, false), (parsed.Seq, parsed.Ssrc, parsed.T1Us, parsed.T2Us, parsed.Count, parsed.Query));
        Assert.Equal(12 + 24, RtpProtocol.Build(RtpCodec.G729, 20, 1, 1, 1).Length);
        Assert.Equal(18, RtpProtocol.Build(RtpCodec.G729, 20, 1, 1, 1)[1]);
        Assert.Null(RtpProtocol.Parse(packet.AsSpan(0, 30)));
        var foreign = (byte[])packet.Clone();
        foreign[12] = (byte)'X';
        Assert.Null(RtpProtocol.Parse(foreign));
    }

    [Fact]
    public void ReflectorStateCountsQueriesAndLimitsRate()
    {
        var state = new RtpReflectorState(100);
        byte[] last = Array.Empty<byte>();
        for (var i = 0; i < 3; i++)
        {
            last = RtpProtocol.Build(RtpCodec.G711, 20, i, 7, 1000 + i);
            Assert.True(state.Handle(last, "10.0.0.5", 40000, 100));
        }

        var reply = RtpProtocol.Parse(last)!.Value;
        Assert.Equal((3u, 1002L, 100_000_000L), (reply.Count, reply.T1Us, reply.T2Us));
        var query = RtpProtocol.Build(RtpCodec.G711, 20, 3, 7, 0, query: true);
        Assert.True(state.Handle(query, "10.0.0.5", 40000, 100));
        Assert.Equal(3u, RtpProtocol.Parse(query)!.Value.Count);
        Assert.False(state.Handle("hallo"u8.ToArray(), "10.0.0.5", 40000, 100));

        var limited = new RtpReflectorState(50);
        var answered = 0;
        for (var i = 0; i < RtpReflectorState.PerSourcePps + 50; i++)
        {
            answered += limited.Handle(RtpProtocol.Build(RtpCodec.G711, 20, i, 1, 0), "192.0.2.1", 1, 50) ? 1 : 0;
        }

        Assert.Equal(RtpReflectorState.PerSourcePps, answered);
        Assert.True(limited.Handle(RtpProtocol.Build(RtpCodec.G711, 20, 0, 1, 0), "192.0.2.2", 1, 50));
    }

    private static int FreeUdpPort()
    {
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        s.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)s.LocalEndPoint!).Port;
    }

    [Fact]
    public async Task LoopbackAgainstOwnReflector()
    {
        var port = FreeUdpPort();
        await using var reflector = new RtpReflector(port, NullLogger.Instance);
        var m = await RtpTest.RunAsync(new RtpOptions("127.0.0.1", port, "g711", 20, 1, 46), CancellationToken.None);
        Assert.Null(m.Error);
        Assert.Equal(("wachtl", 50, 50), (m.Mode, m.Sent, m.Received));
        Assert.Equal((0.0, 0.0), (m.UpLossPct!.Value, m.DownLossPct!.Value));
        Assert.True(m.Mos > 4.3, $"MOS {m.Mos}");
    }

    [Fact]
    public async Task ClosedPortIsReported()
    {
        var m = await RtpTest.RunAsync(new RtpOptions("127.0.0.1", FreeUdpPort(), "g711", 20, 1, 0), CancellationToken.None);
        Assert.NotNull(m.Error);
        Assert.Equal(0, m.Received);
    }

    [Fact]
    public async Task PeerErrorFromServerIsReported()
    {
        var check = JsonSerializer.Deserialize<CheckConfig>("""
            {"id": 9, "type": "rtp", "target": "wachtl-server", "params": {"codec": "g729", "duration_s": 10},
             "peer": {"host": null, "port": null, "error": "RTP-Reflektor auf dem Wachtl-Server ist abgeschaltet"}}
            """, ApiClient.JsonOptions)!;
        var m = await RtpRunner.MeasureAsync(check, CancellationToken.None);
        Assert.Equal("RTP-Reflektor auf dem Wachtl-Server ist abgeschaltet", m.Error);
        Assert.Equal("g729", m.Codec);
    }

    [Fact]
    public async Task RunnerReportsInSnakeCase()
    {
        var check = new CheckConfig { Id = 4, Type = "rtp", Target = "wachtl-server" };
        RtpResult? sent = null;
        await using var runner = new RtpRunner(check, (r, _) => { sent = r; return Task.CompletedTask; }, NullLogger.Instance,
            (_, _) => Task.FromResult(new RtpMeasurement { Mos = 4.4, RFactor = 92.7, UpLossPct = 0, PtimeMs = 20 }));
        await runner.MeasureAndReportAsync("manual", CancellationToken.None);
        var json = JsonSerializer.Serialize(sent, ApiClient.JsonOptions);
        Assert.Contains("\"check_id\":4", json);
        Assert.Contains("\"trigger\":\"manual\"", json);
        Assert.Contains("\"r_factor\":92.7", json);
        Assert.Contains("\"up_loss_pct\":0", json);
        Assert.Contains("\"ptime_ms\":20", json);
    }

    [Fact]
    public void ConfigCarriesReflector()
    {
        var config = JsonSerializer.Deserialize<ProbeConfig>("""{"probe_id": 1, "rtp_reflector": {"enabled": true, "port": 15004}}""",
            ApiClient.JsonOptions)!;
        Assert.True(config.RtpReflector.Enabled);
        Assert.Equal(15004, config.RtpReflector.Port);
        Assert.False(JsonSerializer.Deserialize<ProbeConfig>("{}", ApiClient.JsonOptions)!.RtpReflector.Enabled);
    }
}
