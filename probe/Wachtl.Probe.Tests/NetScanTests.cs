using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Wachtl.Probe.Config;
using Wachtl.Probe.NetScan;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tests;

public class NetScanTests
{
    private static CheckConfig Check(string json) => JsonSerializer.Deserialize<CheckConfig>(json, ApiClient.JsonOptions)!;

    // -- Netze ---------------------------------------------------------------
    [Fact]
    public void CidrIsNormalizedAndExpanded()
    {
        Assert.True(SubnetPlanner.TryParseCidr(" 192.168.10.77/24 ", out var net));
        Assert.Equal("192.168.10.0/24", net.ToString());
        var hosts = net.Hosts().Select(h => SubnetPlanner.ToIp(h).ToString()).ToList();
        Assert.Equal(254, hosts.Count);
        Assert.Equal("192.168.10.1", hosts[0]);
        Assert.Equal("192.168.10.254", hosts[^1]);
        Assert.Equal(254, net.HostCount);
    }

    [Theory]
    [InlineData("10.0.0.0/30", 2, "10.0.0.1")]
    [InlineData("10.0.0.0/31", 2, "10.0.0.0")]
    [InlineData("10.0.0.5/32", 1, "10.0.0.5")]
    [InlineData("10.0.0.5", 1, "10.0.0.5")]
    public void SmallNetworks(string cidr, int count, string first)
    {
        Assert.True(SubnetPlanner.TryParseCidr(cidr, out var net));
        var hosts = net.Hosts().ToList();
        Assert.Equal(count, hosts.Count);
        Assert.Equal(count, net.HostCount);
        Assert.Equal(first, SubnetPlanner.ToIp(hosts[0]).ToString());
    }

    [Theory]
    [InlineData("300.1.1.1/24")]
    [InlineData("1.2.3/24")]
    [InlineData("10")]
    [InlineData("1.2.3.4/33")]
    [InlineData("1.2.3.4/")]
    [InlineData("1.2.3.4/-1")]
    [InlineData("abc")]
    [InlineData("fe80::1/64")]
    public void InvalidCidrIsRejected(string cidr) => Assert.False(SubnetPlanner.TryParseCidr(cidr, out _));

    [Fact]
    public void TargetListIsParsedAndNestedNetsMerged()
    {
        var nets = SubnetPlanner.ParseTargets("192.168.1.0/24, 10.0.0.5/32", out var error)!;
        Assert.Null(error);
        Assert.Equal(new[] { "10.0.0.5/32", "192.168.1.0/24" }, nets.Select(n => n.ToString()));

        var merged = SubnetPlanner.ParseTargets("10.0.0.0/16,10.0.1.0/24, 10.0.0.0/16", out _)!;
        Assert.Equal("10.0.0.0/16", Assert.Single(merged).ToString());

        Assert.Null(SubnetPlanner.ParseTargets("192.168.1.0/24, quatsch", out error));
        Assert.Contains("quatsch", error);
    }

    [Fact]
    public void AutoPlanClampsAndSkipsLoopbackAndApipa()
    {
        var nets = SubnetPlanner.PlanAuto(new[]
        {
            new LocalAddress(IPAddress.Parse("192.168.1.50"), 24, null),
            new LocalAddress(IPAddress.Parse("127.0.0.1"), 8, null),
            new LocalAddress(IPAddress.Parse("169.254.3.4"), 16, null),
            new LocalAddress(IPAddress.Parse("10.20.30.40"), 16, null),
            new LocalAddress(IPAddress.Parse("192.168.1.51"), 24, null),
            new LocalAddress(IPAddress.Parse("172.16.5.5"), 32, null),
        });
        Assert.Equal(new[] { "10.20.28.0/22", "192.168.1.0/24" }, nets.Select(n => n.ToString()));
        Assert.Equal(1022 + 254, SubnetPlanner.CountHosts(nets));
    }

    [Fact]
    public void AutoWithoutNetworksIsAnError()
    {
        Assert.Null(SubnetPlanner.Plan("auto", () => Array.Empty<LocalAddress>(), out var error));
        Assert.NotNull(error);
        var nets = SubnetPlanner.Plan(" AUTO ", () => new[] { new LocalAddress(IPAddress.Parse("192.168.5.9"), 24, null) }, out error)!;
        Assert.Equal("192.168.5.0/24", Assert.Single(nets).ToString());
        Assert.Equal("10.1.0.0/24", Assert.Single(SubnetPlanner.Plan("10.1.0.0/24", () => throw new InvalidOperationException(), out _)!).ToString());
    }

    [Fact]
    public void HugeNetworkIsCountedWithoutExpanding()
    {
        Assert.True(SubnetPlanner.TryParseCidr("10.0.0.0/8", out var net));
        Assert.Equal(16_777_214, SubnetPlanner.CountHosts(new[] { net }));
        Assert.True(SubnetPlanner.TryParseCidr("0.0.0.0/0", out var all));
        Assert.Equal(4_294_967_294, SubnetPlanner.CountHosts(new[] { all }));
    }

    // -- Ports ---------------------------------------------------------------
    [Fact]
    public void PortListWithRangesAndDuplicates()
    {
        Assert.Equal(new[] { 22, 80, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010 },
            PortList.Parse("22,80,8000-8010", out _));
        Assert.Equal(new[] { 79, 80, 81 }, PortList.Parse("80, 80,79-81", out _));
        Assert.Equal(27, PortList.Parse("", out _)!.Count);
        Assert.Equal(27, PortList.Parse(null, out _)!.Count);
        Assert.Equal(1024, PortList.Parse("1-1024", out _)!.Count);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("70000")]
    [InlineData("a")]
    [InlineData("10-5")]
    [InlineData("1-2000")]
    [InlineData("1-1000,2000-2100")]
    [InlineData("80-")]
    public void InvalidPortListIsAnError(string spec)
    {
        Assert.Null(PortList.Parse(spec, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    // -- ARP -----------------------------------------------------------------
    [Fact]
    public void ArpOutputGerman()
    {
        const string text = "\r\nSchnittstelle: 192.168.178.20 --- 0xb\r\n" +
                            "  Internetadresse       Physische Adresse     Typ\r\n" +
                            "  192.168.178.1         3c-a6-2f-11-22-33     dynamisch \r\n" +
                            "  192.168.178.44        00-00-00-00-00-00     ungültig  \r\n" +
                            "  192.168.178.255       ff-ff-ff-ff-ff-ff     statisch  \r\n" +
                            "  224.0.0.22            01-00-5e-00-00-16     statisch  \r\n";
        var table = ArpTable.ParseArpOutput(text);
        Assert.Single(table);
        Assert.Equal("3C:A6:2F:11:22:33", table["192.168.178.1"]);
    }

    [Fact]
    public void ArpOutputEnglish()
    {
        const string text = "Interface: 10.0.0.5 --- 0x4\n" +
                            "  Internet Address      Physical Address      Type\n" +
                            "  10.0.0.1              aa-bb-cc-dd-ee-01     dynamic\n" +
                            "  10.0.0.7              aa-bb-cc-dd-ee-07     static\n";
        var table = ArpTable.ParseArpOutput(text);
        Assert.Equal(2, table.Count);
        Assert.Equal("AA:BB:CC:DD:EE:07", table["10.0.0.7"]);
    }

    [Fact]
    public void ProcNetArp()
    {
        const string text = "IP address       HW type     Flags       HW address            Mask     Device\n" +
                            "192.168.1.1      0x1         0x2         aa:bb:cc:00:11:22     *        eth0\n" +
                            "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n" +
                            "192.168.1.10     0x1         0x6         aa:bb:cc:00:11:33     *        eth0\n";
        var table = ArpTable.ParseProcNetArp(text);
        Assert.Equal(2, table.Count);
        Assert.Equal("AA:BB:CC:00:11:22", table["192.168.1.1"]);
        Assert.False(table.ContainsKey("192.168.1.9"));
    }

    [Theory]
    [InlineData("aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF")]
    [InlineData("0:1b:2c:3d:4e:5f", "00:1B:2C:3D:4E:5F")]
    [InlineData("00-00-00-00-00-00", null)]
    [InlineData("ff-ff-ff-ff-ff-ff", null)]
    [InlineData("01-00-5e-00-00-fb", null)]
    [InlineData("33:33:00:00:00:01", null)]
    [InlineData("aa-bb-cc", null)]
    [InlineData("zz-bb-cc-dd-ee-ff", null)]
    public void MacNormalization(string raw, string? expected) => Assert.Equal(expected, ArpTable.NormalizeMac(raw));

    // -- Dienste -------------------------------------------------------------
    [Fact]
    public void HttpResponseIsParsed()
    {
        var data = Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nserver:  nginx/1.24 \r\n\r\n" +
                                          "<html><head><TITLE lang=\"de\">\n  FRITZ!Box &amp; Co &#228;\n</TITLE></head></html>");
        var h = ServiceProbe.ParseHttp(data);
        Assert.Equal(200, h.Status);
        Assert.Equal("nginx/1.24", h.Server);
        Assert.Equal("FRITZ!Box & Co ä", h.Title);
    }

    [Fact]
    public void HttpHeadWithoutBodyAndBareNewlines()
    {
        var h = ServiceProbe.ParseHttp(Encoding.ASCII.GetBytes("HTTP/1.0 401 Unauthorized\nWWW-Authenticate: Basic\n\n"));
        Assert.Equal(new HttpInfo(401, null, null), h);
        Assert.Equal(default(HttpInfo), ServiceProbe.ParseHttp(Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_9.6\r\n")));
        Assert.Null(ServiceProbe.ParseHttp(Encoding.ASCII.GetBytes("HTTP/1.1 abc\r\n\r\n")).Status);
    }

    [Fact]
    public void TitleIsTrimmedTo200Characters()
    {
        var title = ServiceProbe.ExtractTitle("<title>" + new string('x', 500) + "</title>");
        Assert.Equal(200, title!.Length);
        Assert.Equal("abgeschnitten", ServiceProbe.ExtractTitle("<html><title>abgeschnitten"));
        Assert.Null(ServiceProbe.ExtractTitle("<html><title>  </title>"));
        Assert.Null(ServiceProbe.ExtractTitle("<html></html>"));
    }

    [Fact]
    public void TlsIsRecognized()
    {
        Assert.True(ServiceProbe.LooksLikeTls(new byte[] { 0x16, 0x03, 0x03, 0x00, 0x2a }));
        Assert.True(ServiceProbe.LooksLikeTls(new byte[] { 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46 }));
        Assert.True(ServiceProbe.LooksLikeTls(new byte[] { 0x16 }));
        Assert.False(ServiceProbe.LooksLikeTls(Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request")));
        Assert.False(ServiceProbe.LooksLikeTls(new byte[] { 0x16, 0x41 }));
        Assert.False(ServiceProbe.LooksLikeTls(Array.Empty<byte>()));
    }

    [Fact]
    public void BannerIsCleaned()
    {
        Assert.Equal("SSH-2.0-OpenSSH_9.6", ServiceProbe.CleanText("SSH-2.0-OpenSSH_9.6\r\n"));
        Assert.Equal("220 FTP bereit", ServiceProbe.CleanText("220 \u0000FTP\u0007 bereit\r\n\r\n"));
        Assert.Equal("RFB 003.008", ServiceProbe.CleanBytes(Encoding.ASCII.GetBytes("RFB 003.008\n")));
        Assert.Equal(200, ServiceProbe.CleanText(new string('a', 300))!.Length);
        Assert.Null(ServiceProbe.CleanText("\r\n\u0001"));
        Assert.Null(ServiceProbe.CleanText(null));
    }

    // -- Runner und Ergebnis ----------------------------------------------------
    [Fact]
    public void OptionsFromParams()
    {
        var check = Check("""
            {"id": 7, "type": "netscan", "target": "192.168.1.0/24, 10.0.0.5/32",
             "params": {"ports": "22,80-82", "port_scan": false, "timeout_ms": 300, "parallel": 16, "max_hosts": 300}}
            """);
        var o = NetScanRunner.Options(check, out var error)!;
        Assert.Null(error);
        Assert.Equal(new[] { 22, 80, 81, 82 }, o.Ports);
        Assert.Equal(("192.168.1.0/24, 10.0.0.5/32", false, 300, 16, 300), (o.Target, o.PortScan, o.TimeoutMs, o.Parallel, o.MaxHosts));

        var defaults = NetScanRunner.Options(Check("""{"id": 8, "type": "netscan", "target": ""}"""), out _)!;
        Assert.Equal(("auto", true, 500, 64, 1024, 27), (defaults.Target, defaults.PortScan, defaults.TimeoutMs, defaults.Parallel,
            defaults.MaxHosts, defaults.Ports.Count));
    }

    [Fact]
    public async Task TooManyHostsIsReportedAsError()
    {
        var check = Check("""{"id": 9, "type": "netscan", "target": "10.0.0.0/16", "params": {"max_hosts": 1024}}""");
        var result = await NetScanRunner.ScanAsync(check, NullLogger.Instance, CancellationToken.None);
        Assert.Contains("Zu viele Adressen", result.Error);
        Assert.Empty(result.Hosts);
        Assert.Equal(new[] { "10.0.0.0/16" }, result.Subnets);

        var badPorts = await NetScanRunner.ScanAsync(Check("""{"id": 9, "type": "netscan", "target": "10.0.0.0/30", "params": {"ports": "1-x"}}"""),
            NullLogger.Instance, CancellationToken.None);
        Assert.Contains("1-x", badPorts.Error);
        Assert.Empty(badPorts.Hosts);
    }

    [Fact]
    public async Task RunnerReportsInSnakeCase()
    {
        var check = new CheckConfig { Id = 42, Type = "netscan", Target = "auto" };
        NetScanResult? sent = null;
        await using var runner = new NetScanRunner(check, (r, _) => { sent = r; return Task.CompletedTask; }, NullLogger.Instance,
            (_, _, _) => Task.FromResult(new NetScanResult
            {
                DurationS = 37.4,
                Subnets = new() { "192.168.10.0/24" },
                Hosts = new()
                {
                    new NetScanHost
                    {
                        Ip = "192.168.10.1", Mac = "AA:BB:CC:DD:EE:FF", RttMs = 0.6, Via = new() { "icmp", "arp" },
                        Ports = new()
                        {
                            new NetScanPort { Port = 443, Tls = true, HttpStatus = 200, HttpServer = "nginx", HttpTitle = "FRITZ!Box", TlsSubject = "CN=fritz.box" },
                        },
                    },
                },
            }));
        await runner.ScanAndReportAsync("manual", CancellationToken.None);
        var json = JsonSerializer.Serialize(sent, ApiClient.JsonOptions);
        Assert.Contains("\"check_id\":42", json);
        Assert.Contains("\"trigger\":\"manual\"", json);
        Assert.Contains("\"duration_s\":37.4", json);
        Assert.Contains("\"subnets\":[\"192.168.10.0/24\"]", json);
        Assert.Contains("\"error\":null", json);
        Assert.Contains("\"hostname\":null", json);
        Assert.Contains("\"rtt_ms\":0.6", json);
        Assert.Contains("\"via\":[\"icmp\",\"arp\"]", json);
        Assert.Contains("\"self\":false", json);
        Assert.Contains("\"http_status\":200", json);
        Assert.Contains("\"http_server\":\"nginx\"", json);
        Assert.Contains("\"http_title\":\"FRITZ!Box\"", json);
        Assert.Contains("\"tls_subject\":\"CN=fritz.box\"", json);
        Assert.Contains("\"banner\":null", json);
        Assert.Contains("\"tls\":true", json);
        Assert.True(sent!.Ts > 1_700_000_000);
    }

    // -- echte Verbindungen auf 127.0.0.1 ---------------------------------------
    [Fact]
    public async Task BannerOfLocalServiceIsRead()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            var hello = Encoding.ASCII.GetBytes("SSH-2.0-WachtlTest_1.0\r\n");
            await c.GetStream().WriteAsync(hello);
            await Task.Delay(500);
        });

        var (client, alive) = await NetScanner.ConnectAsync(IPAddress.Loopback, port, TimeSpan.FromSeconds(2), CancellationToken.None);
        Assert.True(alive);
        using (client)
        {
            var info = await ServiceProbe.DetectAsync(client!, IPAddress.Loopback, port, TimeSpan.FromSeconds(2), CancellationToken.None);
            Assert.Equal("SSH-2.0-WachtlTest_1.0", info.Banner);
            Assert.False(info.Tls);
            Assert.Null(info.HttpStatus);
        }

        await server;
        listener.Stop();
    }

    [Fact]
    public async Task HttpOfLocalServiceIsRead()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var stop = new CancellationTokenSource();
        var server = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                TcpClient c;
                try
                {
                    c = await listener.AcceptTcpClientAsync(stop.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                _ = Task.Run(async () =>
                {
                    using (c)
                    {
                        var stream = c.GetStream();
                        var buffer = new byte[4096];
                        var request = new StringBuilder();
                        try
                        {
                            while (!request.ToString().Contains("\r\n\r\n"))
                            {
                                var n = await stream.ReadAsync(buffer);
                                if (n == 0)
                                {
                                    return;
                                }

                                request.Append(Encoding.ASCII.GetString(buffer, 0, n));
                            }

                            var head = request.ToString().StartsWith("HEAD", StringComparison.Ordinal);
                            var response = "HTTP/1.0 200 OK\r\nServer: WachtlTest\r\nContent-Type: text/html\r\n\r\n" +
                                           (head ? string.Empty : "<html><title>Hallo &amp; Welt</title></html>");
                            await stream.WriteAsync(Encoding.UTF8.GetBytes(response));
                        }
                        catch (IOException)
                        {
                        }
                    }
                });
            }
        });

        var (client, _) = await NetScanner.ConnectAsync(IPAddress.Loopback, port, TimeSpan.FromSeconds(2), CancellationToken.None);
        using (client)
        {
            var info = await ServiceProbe.DetectAsync(client!, IPAddress.Loopback, port, TimeSpan.FromSeconds(2), CancellationToken.None,
                isHttp: true);
            Assert.Equal(200, info.HttpStatus);
            Assert.Equal("WachtlTest", info.HttpServer);
            Assert.Equal("Hallo & Welt", info.HttpTitle);
            Assert.False(info.Tls);
            Assert.Null(info.Banner);
        }

        stop.Cancel();
        await server;
        listener.Stop();
    }

    [Fact]
    public async Task ClosedPortIsNotOpen()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var (client, _) = await NetScanner.ConnectAsync(IPAddress.Loopback, port, TimeSpan.FromMilliseconds(500), CancellationToken.None);
        Assert.Null(client);
    }
}
