using System.Net.NetworkInformation;
using Wachtl.Probe.Config;
using Wachtl.Probe.Diagnostics;

namespace Wachtl.Probe.Tests;

public class ConnectivityMonitorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 26, 12, 0, 0, TimeSpan.Zero);

    private static readonly CheckConfig Gateway = new() { Id = 1, Target = "gateway", Role = "gateway", IntervalS = 1 };
    private static readonly CheckConfig Google = new() { Id = 2, Target = "8.8.8.8", Role = "reference", IntervalS = 1 };
    private static readonly CheckConfig Cloudflare = new() { Id = 3, Target = "1.1.1.1", Role = "reference", IntervalS = 1 };
    private static readonly CheckConfig Server = new() { Id = 4, Target = "10.0.0.5", Role = "target", IntervalS = 1 };

    private readonly List<ClientFinding> _out = new();
    private readonly ConnectivityMonitor _m;
    private int _second;

    public ConnectivityMonitorTests()
    {
        _m = new ConnectivityMonitor(f => _out.AddRange(f), () => T0.AddSeconds(_second));
    }

    /// <summary>Eine Sekunde: jeder Check pingt einmal, true = Antwort.</summary>
    private void Second(bool gateway = true, bool google = true, bool cloudflare = true, bool server = true)
    {
        var at = T0.AddSeconds(_second++);
        _m.RecordPing(Gateway, gateway, at);
        _m.RecordPing(Google, google, at);
        _m.RecordPing(Cloudflare, cloudflare, at);
        _m.RecordPing(Server, server, at);
    }

    private void Seconds(int n, bool gateway = true, bool google = true, bool cloudflare = true, bool server = true)
    {
        for (var i = 0; i < n; i++)
        {
            Second(gateway, google, cloudflare, server);
        }
    }

    [Fact]
    public void SingleLostPingIsReportedImmediately()
    {
        Seconds(5);
        Second(google: false);
        Assert.Empty(_out); // noch offen, ob Verlust oder Ausfall
        Second();
        var loss = Assert.Single(_out);
        Assert.True(loss.Event);
        Assert.Equal(ConnectivityKinds.PacketLoss, loss.Kind);
        Assert.Equal("warning", loss.Severity);
        Assert.Equal("Paketverlust zu 8.8.8.8", loss.Title);
        Assert.StartsWith("1 Ping zu 8.8.8.8 ohne Antwort", loss.Balloon);
    }

    [Fact]
    public void FurtherLossInTheSameMinuteIsSummarized()
    {
        Seconds(2);
        Second(google: false);
        Seconds(10);
        Second(google: false);
        Second(google: false);
        Seconds(10);
        Assert.Single(_out); // nur der erste sofort
        Seconds(60);
        Assert.Equal(2, _out.Count);
        Assert.Equal("Weiter Paketverlust zu 8.8.8.8", _out[1].Title);
        Assert.Contains("Weitere 2 Pings", _out[1].Message);
        Seconds(70);
        Assert.Equal(2, _out.Count); // ruhige Minute: nichts mehr
        Second(google: false);
        Second();
        Assert.Equal(3, _out.Count); // neuer Verlust wieder sofort
        Assert.Equal("Paketverlust zu 8.8.8.8", _out[2].Title);
    }

    [Fact]
    public void GatewayDownHidesInternetAndTargets()
    {
        Seconds(3);
        Seconds(4, gateway: false, google: false, cloudflare: false, server: false);
        Assert.Empty(_out);
        Second(gateway: false, google: false, cloudflare: false, server: false); // 5 s ohne Antwort
        Assert.Empty(_out); // erst nach ConnectivityMonitor.Settle bestätigt
        Seconds(2, gateway: false, google: false, cloudflare: false, server: false);
        var down = Assert.Single(_out);
        Assert.Equal(ConnectivityKinds.GatewayDown, down.Kind);
        Assert.Equal("critical", down.Severity);
        Assert.False(down.Event);
        Assert.Equal(new[] { "gateway" }, _m.ActiveKeys);
        Seconds(28, gateway: false, google: false, cloudflare: false, server: false);
        Assert.Single(_out);

        Seconds(3);
        var back = Assert.Single(_out.Skip(1)); // kein kurzes „Internet ausgefallen“ beim Wiederkommen
        Assert.Equal(down.FindingId, back.FindingId);
        Assert.Equal("resolved", back.State);
        Assert.Equal("Netzwerk wieder da", back.Title);
        Assert.Contains("35 s", back.Message);
        Assert.Empty(_m.ActiveKeys);
        Assert.DoesNotContain(_out, f => f.Kind == ConnectivityKinds.PacketLoss); // Ausfall ist kein Paketverlust
    }

    [Fact]
    public void AllReferencesDownIsInternetOutage()
    {
        Seconds(3);
        Seconds(10, google: false, cloudflare: false);
        var down = Assert.Single(_out); // nicht zuerst „8.8.8.8 nicht erreichbar“
        Assert.Equal(ConnectivityKinds.InternetDown, down.Kind);
        Assert.Contains("8.8.8.8, 1.1.1.1", down.Message);
        Seconds(3);
        Assert.Equal(2, _out.Count);
        Assert.Equal("Internet wieder erreichbar", _out[1].Title);
        Assert.False(_out[1].Quiet);
    }

    [Fact]
    public void SingleTargetDownIsWarning()
    {
        Seconds(3);
        Seconds(10, server: false);
        var down = Assert.Single(_out);
        Assert.Equal(ConnectivityKinds.TargetDown, down.Kind);
        Assert.Equal("warning", down.Severity);
        Assert.Equal("10.0.0.5 nicht erreichbar", down.Title);
        Second();
        Assert.Equal("Wieder erreichbar: 10.0.0.5", _out[1].Title);
    }

    [Fact]
    public void InternetOutageTurningIntoGatewayOutageIsNotReportedAsRecovered()
    {
        Seconds(3);
        Seconds(10, google: false, cloudflare: false);
        Assert.Equal(ConnectivityKinds.InternetDown, Assert.Single(_out).Kind);
        Seconds(10, gateway: false, google: false, cloudflare: false, server: false);
        Assert.Equal(3, _out.Count);
        var hidden = _out.Single(f => f.Kind == ConnectivityKinds.InternetDown && f.State == "resolved");
        Assert.True(hidden.Quiet); // keine Sprechblase „Internet wieder erreichbar“, das Internet ist ja weiter weg
        Assert.Contains(_out, f => f.Kind == ConnectivityKinds.GatewayDown && f.IsActive);
    }

    [Fact]
    public void SlowIntervalNeedsAtLeastTwoFails()
    {
        Assert.Equal(5, ConnectivityMonitor.FailsNeeded(1));
        Assert.Equal(3, ConnectivityMonitor.FailsNeeded(2));
        Assert.Equal(2, ConnectivityMonitor.FailsNeeded(60));
    }

    [Fact]
    public void DisabledPublishesNothingButKeepsTrack()
    {
        _m.Enabled = false;
        Seconds(3);
        Seconds(10, server: false);
        Assert.Empty(_out);
        Assert.Single(_m.ActiveKeys);
    }

    [Fact]
    public void RemovedCheckResolvesItsOutage()
    {
        Seconds(3);
        Seconds(10, server: false);
        _m.KeepChecks(new long[] { 1, 2, 3 });
        Assert.Equal("resolved", _out[^1].State);
        Assert.Empty(_m.ActiveKeys);
    }

    private static AdapterSnapshot Snap(params AdapterState[] adapters) => new(T0, adapters);

    private static AdapterState Lan(string ip) => new()
    {
        Id = "lan", Name = "Ethernet", Description = "Intel", Type = NetworkInterfaceType.Ethernet, Status = LinkStatus.Up,
        Ipv4 = new[] { ip }, HasGateway = true, SpeedBps = 1_000_000_000,
    };

    private static AdapterState Wifi(string ip) => new()
    {
        Id = "wifi", Name = "WLAN", Description = "Intel Wi-Fi", Type = NetworkInterfaceType.Wireless80211, Status = LinkStatus.Up,
        Ipv4 = new[] { ip }, HasGateway = true,
    };

    [Fact]
    public void NetworkChangeIsReportedWhenStable()
    {
        var d = new NetworkChangeDetector();
        Assert.Null(d.Check(Snap(Lan("192.168.1.20"))));
        Assert.Null(d.Check(Snap(Lan("192.168.1.20"))));
        Assert.Null(d.Check(Snap())); // kein Netz: melden andere Hinweise
        Assert.Null(d.Check(Snap(Wifi("192.168.1.35"))));
        var change = d.Check(Snap(Wifi("192.168.1.35")));
        Assert.NotNull(change);
        Assert.True(change!.Event);
        Assert.Equal(ConnectivityKinds.NetworkChanged, change.Kind);
        Assert.Contains("jetzt WLAN „WLAN“ (192.168.1.35), vorher LAN „Ethernet“ (192.168.1.20)", change.Message);
        Assert.Null(d.Check(Snap(Wifi("192.168.1.35"))));
    }

    [Fact]
    public void ReconnectWithSameNetworkIsNoChange()
    {
        var d = new NetworkChangeDetector();
        d.Check(Snap(Lan("192.168.1.20")));
        Assert.Null(d.Check(Snap()));
        Assert.Null(d.Check(Snap()));
        Assert.Null(d.Check(Snap(Lan("192.168.1.20"))));
        Assert.Null(d.Check(Snap(Lan("192.168.1.20"))));
    }
}
