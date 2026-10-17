using System.Net.NetworkInformation;
using System.Text.Json;
using Wachtl.Probe.Config;
using Wachtl.Probe.Diagnostics;
using Wachtl.Probe.Transport;
using Wachtl.Probe.Tray;

namespace Wachtl.Probe.Tests;

public class FindingEvaluatorTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.FromUnixTimeSeconds(1_792_230_000);
    private readonly FindingEvaluator _eval = new();
    private DateTimeOffset _now = T0;

    private static AdapterState Eth(LinkStatus status = LinkStatus.Up, long speed = 1_000_000_000, string ip = "192.168.1.20",
        bool gateway = true, string id = "eth0", string name = "Ethernet", string description = "Intel(R) Ethernet Connection I219-V") => new()
    {
        Id = id,
        Name = name,
        Description = description,
        Type = NetworkInterfaceType.Ethernet,
        Status = status,
        SpeedBps = speed,
        Ipv4 = status == LinkStatus.Up && ip.Length > 0 ? new[] { ip } : Array.Empty<string>(),
        HasGateway = status == LinkStatus.Up && gateway,
    };

    private static AdapterState Wifi(LinkStatus status = LinkStatus.Up) => new()
    {
        Id = "wlan0",
        Name = "WLAN",
        Description = "Intel(R) Wi-Fi 6 AX201 160MHz",
        Type = NetworkInterfaceType.Wireless80211,
        Status = status,
        SpeedBps = 300_000_000,
        Ipv4 = status == LinkStatus.Up ? new[] { "10.0.0.5" } : Array.Empty<string>(),
        HasGateway = status == LinkStatus.Up,
    };

    /// <summary>Eine Abfrage; danach rückt die Uhr 5 s vor.</summary>
    private IReadOnlyList<ClientFinding> Poll(params AdapterState[] adapters) => PollWith(null, adapters);

    private IReadOnlyList<ClientFinding> PollWith(IReadOnlyList<NicResetEvent>? resets, params AdapterState[] adapters)
    {
        var result = _eval.Evaluate(new AdapterSnapshot(_now, adapters, resets));
        _now = _now.AddSeconds(5);
        return result;
    }

    private IReadOnlyList<ClientFinding> PollFor(TimeSpan duration, params AdapterState[] adapters)
    {
        var all = new List<ClientFinding>();
        var end = _now + duration;
        while (_now < end)
        {
            all.AddRange(Poll(adapters));
        }

        return all;
    }

    [Fact]
    public void HealthyAdapterProducesNothing()
    {
        Assert.Empty(PollFor(TimeSpan.FromMinutes(5), Eth(), Wifi()));
    }

    [Fact]
    public void CableUnpluggedFiresImmediatelyAndResolvesAfterStableLink()
    {
        Poll(Eth());
        // sofort an den Server, aber erst „info“ (keine Sprechblase): Standby, Abdocken, Deaktivieren
        var first = Assert.Single(Poll(Eth(LinkStatus.Down)));
        Assert.Equal(FindingKinds.CableUnplugged, first.Kind);
        Assert.Equal("info", first.Severity);
        Assert.Empty(Poll(Eth(LinkStatus.Down)));
        Assert.Empty(Poll(Eth(LinkStatus.Down)));
        var fired = Assert.Single(Poll(Eth(LinkStatus.Down))); // nach 15 s ohne Link kritisch
        Assert.Equal(first.FindingId, fired.FindingId);
        Assert.Equal("critical", fired.Severity);
        Assert.Equal("active", fired.State);
        Assert.Equal("Ethernet", fired.Adapter);
        Assert.Equal("Intel(R) Ethernet Connection I219-V", fired.AdapterDescription);
        Assert.Null(fired.ResolvedAt);
        Assert.True(Guid.TryParse(fired.FindingId, out _));
        Assert.Contains("Kabel", fired.Solution);

        Assert.Empty(PollFor(TimeSpan.FromMinutes(2), Eth(LinkStatus.Down)));
        Assert.Empty(Poll(Eth())); // erst nach einer weiteren Abfrage mit Link erledigt
        var resolved = Assert.Single(Poll(Eth()));
        Assert.Equal(fired.FindingId, resolved.FindingId);
        Assert.Equal("resolved", resolved.State);
        Assert.Equal("Netzwerkkabel wieder verbunden", resolved.Title);
        Assert.Contains("Unterbrechung 2 Min.", resolved.Message);
        Assert.Equal(fired.Title, resolved.Details["problem"]);
        Assert.NotNull(resolved.ResolvedAt);
    }

    [Fact]
    public void NoCableFindingForAdapterNeverSeenUpOrDisabled()
    {
        Assert.Empty(PollFor(TimeSpan.FromMinutes(1), Eth(LinkStatus.Down)));

        var eval = new FindingEvaluator();
        eval.Evaluate(new AdapterSnapshot(T0, new[] { Eth() }));
        // deaktiviert: verschwindet aus der Liste bzw. Status Disabled
        Assert.Empty(eval.Evaluate(new AdapterSnapshot(T0.AddSeconds(5), new[] { Eth(LinkStatus.Disabled) })));
        Assert.Empty(eval.Evaluate(new AdapterSnapshot(T0.AddSeconds(10), Array.Empty<AdapterState>())));
    }

    [Fact]
    public void UnplugWhileWifiCarriesOnIsOnlyInfo()
    {
        Poll(Eth(), Wifi());
        var fired = Assert.Single(Poll(Eth(LinkStatus.Down), Wifi()));
        Assert.Equal("info", fired.Severity);
        Assert.Contains("„WLAN“", fired.Message);

        // jetzt fällt auch das WLAN weg: wird kritisch (gleiche ID)
        var changes = PollFor(TimeSpan.FromSeconds(25), Eth(LinkStatus.Down), Wifi(LinkStatus.Down));
        var escalated = Assert.Single(changes, c => c.Kind == FindingKinds.CableUnplugged);
        Assert.Equal(fired.FindingId, escalated.FindingId);
        Assert.Equal("critical", escalated.Severity);
        Assert.Contains(changes, c => c.Kind == FindingKinds.WifiDisconnected && c.Severity == "warning");
    }

    [Fact]
    public void WifiDisconnectIsDebounced()
    {
        Poll(Wifi());
        Assert.Empty(Poll(Wifi(LinkStatus.Down)));
        Assert.Empty(Poll(Wifi())); // kurzer Aussetzer beim Roaming
        Assert.Empty(PollFor(TimeSpan.FromSeconds(15), Wifi(LinkStatus.Down))); // Aufwachen aus dem Standby dauert
        var fired = Assert.Single(Poll(Wifi(LinkStatus.Down)));
        Assert.Equal(FindingKinds.WifiDisconnected, fired.Kind);
        Assert.Equal("warning", fired.Severity);
    }

    [Fact]
    public void SameFindingIsSuppressedFor30MinutesAfterResolution()
    {
        Poll(Eth());
        Assert.Single(Poll(Eth(LinkStatus.Down)));
        PollFor(TimeSpan.FromSeconds(10), Eth());
        Assert.Empty(Poll(Eth(LinkStatus.Down))); // wieder gezogen, innerhalb von 30 min: keine neue Meldung
        PollFor(TimeSpan.FromSeconds(10), Eth());

        _now = _now.AddMinutes(31);
        var again = Assert.Single(Poll(Eth(LinkStatus.Down)));
        Assert.Equal(FindingKinds.CableUnplugged, again.Kind);
    }

    [Fact]
    public void SuppressionEndsWhenSeverityIncreases()
    {
        Poll(Eth(), Wifi());
        Assert.Equal("info", Assert.Single(Poll(Eth(LinkStatus.Down), Wifi())).Severity);
        PollFor(TimeSpan.FromSeconds(10), Eth(), Wifi());
        // jetzt ohne WLAN: nach 15 s kritisch, also trotz Sperrfrist
        Assert.DoesNotContain(PollFor(TimeSpan.FromSeconds(15), Eth(LinkStatus.Down)), f => f.Kind == FindingKinds.CableUnplugged);
        var fired = Assert.Single(Poll(Eth(LinkStatus.Down)), f => f.Kind == FindingKinds.CableUnplugged);
        Assert.Equal("critical", fired.Severity);
    }

    [Fact]
    public void ThreeDropsInTenMinutesIsFlapping()
    {
        Poll(Eth());
        var all = new List<ClientFinding>();
        for (var i = 0; i < 3; i++)
        {
            all.AddRange(Poll(Eth(LinkStatus.Down)));
            all.AddRange(PollFor(TimeSpan.FromMinutes(1), Eth()));
        }

        var flap = Assert.Single(all, f => f.Kind == FindingKinds.LinkFlapping);
        Assert.Equal("warning", flap.Severity);
        Assert.Equal("3", flap.Details["count"]);
        Assert.Contains("Energie zu sparen", flap.Solution);
        Assert.Single(all, f => f.Kind == FindingKinds.CableUnplugged && f.IsActive); // nur das erste Ziehen

        var later = PollFor(TimeSpan.FromMinutes(11), Eth());
        var resolved = Assert.Single(later, f => f.Kind == FindingKinds.LinkFlapping);
        Assert.Equal("resolved", resolved.State);
        Assert.Equal(flap.FindingId, resolved.FindingId);
    }

    [Fact]
    public void SpeedDropAndRecovery()
    {
        PollFor(TimeSpan.FromSeconds(15), Eth());
        Assert.Empty(Poll(Eth(speed: 100_000_000))); // eine Abfrage reicht nicht
        var drop = Assert.Single(Poll(Eth(speed: 100_000_000)));
        Assert.Equal(FindingKinds.LinkSpeedChanged, drop.Kind);
        Assert.Equal("warning", drop.Severity);
        Assert.Equal("1000", drop.Details["old_mbps"]);
        Assert.Equal("100", drop.Details["new_mbps"]);
        Assert.Contains("1 Gbit/s → 100 Mbit/s", drop.Title);
        Assert.Contains("Cat 5e", drop.Solution);

        // keine zweite Meldung „langsam“ für denselben Abfall
        Assert.Empty(PollFor(TimeSpan.FromMinutes(2), Eth(speed: 100_000_000)));

        var up = PollFor(TimeSpan.FromSeconds(10), Eth());
        var resolved = Assert.Single(up);
        Assert.Equal("resolved", resolved.State);
        Assert.Equal(drop.FindingId, resolved.FindingId);
        Assert.Equal("Netzwerkgeschwindigkeit wieder normal", resolved.Title);
    }

    [Fact]
    public void ReconnectAtLowerSpeedIsSpeedChange()
    {
        PollFor(TimeSpan.FromSeconds(15), Eth());
        Poll(Eth(LinkStatus.Down));
        var changes = PollFor(TimeSpan.FromSeconds(15), Eth(speed: 100_000_000));
        Assert.Contains(changes, f => f.Kind == FindingKinds.CableUnplugged && f.State == "resolved");
        Assert.Contains(changes, f => f.Kind == FindingKinds.LinkSpeedChanged && f.IsActive);
    }

    [Fact]
    public void LowSpeedAfter30SecondsOnce()
    {
        Assert.Empty(PollFor(TimeSpan.FromSeconds(30), Eth(speed: 100_000_000)));
        var low = Assert.Single(PollFor(TimeSpan.FromSeconds(10), Eth(speed: 100_000_000)));
        Assert.Equal(FindingKinds.LinkSpeedLow, low.Kind);
        Assert.Equal("info", low.Severity); // 100 Mbit/s: nur für den Server, keine Sprechblase
        Assert.Equal("100", low.Details["speed_mbps"]);

        // Kabel kurz gezogen, wieder 100 Mbit/s: nicht noch einmal „langsam“
        _now = _now.AddMinutes(40);
        Poll(Eth(LinkStatus.Down, speed: 100_000_000));
        var again = PollFor(TimeSpan.FromMinutes(2), Eth(speed: 100_000_000));
        Assert.DoesNotContain(again, f => f.Kind == FindingKinds.LinkSpeedLow && f.IsActive);
    }

    [Fact]
    public void ResumeFromSleepIsNoFlappingAndNoSpeedFinding()
    {
        PollFor(TimeSpan.FromSeconds(30), Eth());
        var all = new List<ClientFinding>();
        for (var i = 0; i < 3; i++)
        {
            // Einschlafen: Link weg, dann 20 min keine Abfrage
            all.AddRange(Poll(Eth(LinkStatus.Down)));
            _now = _now.AddMinutes(20);
            // Aufwachen: kurz ohne Link, dann 10 Mbit/s (Wake-on-LAN), dann wieder 1 Gbit/s
            all.AddRange(Poll(Eth(LinkStatus.Down)));
            all.AddRange(PollFor(TimeSpan.FromSeconds(20), Eth(speed: 10_000_000)));
            all.AddRange(PollFor(TimeSpan.FromMinutes(2), Eth()));
        }

        Assert.DoesNotContain(all, f => f.Kind is FindingKinds.LinkFlapping or FindingKinds.LinkSpeedChanged or FindingKinds.LinkSpeedLow);
        Assert.DoesNotContain(all, f => f.IsActive && f.Severity != "info");
    }

    [Fact]
    public void SpeedAfterResumeIsJudgedWithNewBaseline()
    {
        PollFor(TimeSpan.FromSeconds(30), Eth());
        _now = _now.AddMinutes(20);
        // nach dem Aufwachen dauerhaft 10 Mbit/s: kein „gefallen“, aber nach der Schonfrist „langsam“
        var changes = PollFor(TimeSpan.FromMinutes(3), Eth(speed: 10_000_000));
        Assert.DoesNotContain(changes, f => f.Kind == FindingKinds.LinkSpeedChanged);
        var low = Assert.Single(changes, f => f.Kind == FindingKinds.LinkSpeedLow);
        Assert.Equal("critical", low.Severity);
        Assert.True(low.DetectedAt >= (T0 + TimeSpan.FromSeconds(30) + TimeSpan.FromMinutes(20) + TimeSpan.FromSeconds(60)).ToUnixTimeSeconds());
    }

    [Fact]
    public void ReportedSpeedDropResolvesAfterResume()
    {
        PollFor(TimeSpan.FromSeconds(15), Eth());
        var drop = Assert.Single(PollFor(TimeSpan.FromSeconds(15), Eth(speed: 100_000_000)));
        Assert.Equal(FindingKinds.LinkSpeedChanged, drop.Kind);
        Assert.Equal("warning", drop.Severity);
        _now = _now.AddMinutes(20);
        var resolved = Assert.Single(PollFor(TimeSpan.FromMinutes(2), Eth()), f => f.Kind == FindingKinds.LinkSpeedChanged);
        Assert.Equal("resolved", resolved.State);
    }

    [Fact]
    public void NdisResetsAroundSleepDoNotCount()
    {
        PollWith(Array.Empty<NicResetEvent>(), Eth());
        var suspend = _now;
        _now = _now.AddMinutes(5);
        var resume = _now;
        var events = new[]
        {
            new NicResetEvent(suspend.AddSeconds(2), "Intel(R) Ethernet Connection I219-V"),
            new NicResetEvent(resume.AddSeconds(10), "Intel(R) Ethernet Connection I219-V"),
        };
        Assert.DoesNotContain(PollFor(TimeSpan.FromMinutes(2), Eth()), f => f.Kind == FindingKinds.NicReset);
        var list = new List<ClientFinding>();
        while (_now < resume.AddMinutes(2))
        {
            list.AddRange(PollWith(events, Eth()));
        }

        Assert.DoesNotContain(list, f => f.Kind == FindingKinds.NicReset);
        // danach zwei weitere Zurücksetzen im Betrieb: gemeldet
        var more = events.Concat(new[] { new NicResetEvent(_now, null), new NicResetEvent(_now.AddSeconds(1), null) }).ToArray();
        Assert.Equal(FindingKinds.NicReset, Assert.Single(PollWith(more, Eth())).Kind);
    }

    [Fact]
    public void TenMegabitIsCritical()
    {
        var low = Assert.Single(PollFor(TimeSpan.FromSeconds(45), Eth(speed: 10_000_000)));
        Assert.Equal(FindingKinds.LinkSpeedLow, low.Kind);
        Assert.Equal("critical", low.Severity);
        Assert.Contains("10 Mbit/s", low.Title);
    }

    [Fact]
    public void WifiSpeedIsNotJudged()
    {
        Assert.Empty(PollFor(TimeSpan.FromMinutes(1), Wifi()));
    }

    [Fact]
    public void ApipaAfterDebounce()
    {
        Assert.Empty(Poll(Eth(ip: "169.254.10.20", gateway: false)));
        var apipa = Assert.Single(Poll(Eth(ip: "169.254.10.20", gateway: false)));
        Assert.Equal(FindingKinds.Apipa, apipa.Kind);
        Assert.Equal("critical", apipa.Severity);
        Assert.Contains("169.254.10.20", apipa.Message);
        Assert.Contains("ipconfig /renew", apipa.Solution);

        var resolved = Assert.Single(Poll(Eth()));
        Assert.Equal("resolved", resolved.State);
        Assert.Contains("192.168.1.20", resolved.Message);
    }

    [Fact]
    public void ApipaOnSecondaryNicIsOnlyInfoWhileOtherConnectionWorks()
    {
        var second = Eth(ip: "169.254.10.20", gateway: false, id: "eth1", name: "Ethernet 2");
        var apipa = Assert.Single(PollFor(TimeSpan.FromSeconds(10), Eth(), second));
        Assert.Equal(FindingKinds.Apipa, apipa.Kind);
        Assert.Equal("info", apipa.Severity);
    }

    [Fact]
    public void DeviceBeingRemovedIsNoDriverError()
    {
        var removing = new AdapterState { Id = "nic1", Name = "Ethernet 3", WmiPhysical = true, Status = LinkStatus.NotPresent, PnpErrorCode = 21 };
        Assert.Empty(PollFor(TimeSpan.FromMinutes(1), removing));
    }

    [Fact]
    public void NoGatewayOnlyWhenNoInterfaceHasOne()
    {
        var finding = Assert.Single(PollFor(TimeSpan.FromSeconds(10), Eth(gateway: false)));
        Assert.Equal(FindingKinds.NoGateway, finding.Kind);
        Assert.Equal("warning", finding.Severity);
        Assert.Equal("Ethernet", finding.Adapter);

        // Gateway über eine virtuelle Schnittstelle (Hyper-V-Switch) zählt
        var eval = new FindingEvaluator();
        var vEthernet = new AdapterState
        {
            Id = "v1", Name = "vEthernet (Extern)", Description = "Hyper-V Virtual Ethernet Adapter", Type = NetworkInterfaceType.Ethernet,
            Ipv4 = new[] { "192.168.1.30" }, HasGateway = true, SpeedBps = 10_000_000_000,
        };
        for (var i = 0; i < 5; i++)
        {
            Assert.Empty(eval.Evaluate(new AdapterSnapshot(T0.AddSeconds(5 * i), new[] { Eth(gateway: false), vEthernet })));
        }
    }

    [Fact]
    public void NicErrorsUseOneMinuteDeltaAndHandleCounterReset()
    {
        long errors = 1_000_000; // hoher Altbestand zählt nicht
        long packets = 50_000_000;
        AdapterState Counting() => Eth() with { ErrorPackets = errors, TotalPackets = packets };

        for (var i = 0; i < 24; i++)
        {
            Assert.Empty(Poll(Counting()));
            packets += 10_000;
        }

        // Zähler zurückgesetzt (Treiber neu geladen): kein riesiges negatives oder positives Delta
        errors = 10;
        packets = 1000;
        Assert.Empty(PollFor(TimeSpan.FromSeconds(30), Counting()));

        var found = new List<ClientFinding>();
        for (var i = 0; i < 30 && found.Count == 0; i++)
        {
            errors += 20; // 240 je Minute
            packets += 2_000; // 1 %
            found.AddRange(Poll(Counting()));
        }

        var finding = Assert.Single(found);
        Assert.Equal(FindingKinds.NicErrors, finding.Kind);
        Assert.Equal("warning", finding.Severity);
        Assert.True(long.Parse(finding.Details["errors_per_min"]) > 50);

        // wieder sauber: nach einer Minute erledigt
        var clean = new List<ClientFinding>();
        for (var i = 0; i < 20; i++)
        {
            packets += 2_000;
            clean.AddRange(Poll(Counting()));
        }

        Assert.Equal("resolved", Assert.Single(clean).State);
    }

    [Fact]
    public void FewErrorsOnBusyLinkAreFine()
    {
        long errors = 0;
        long packets = 0;
        for (var i = 0; i < 40; i++)
        {
            errors += 10; // 120 je Minute, aber nur 0,1 %
            packets += 10_000;
            Assert.Empty(Poll(Eth() with { ErrorPackets = errors, TotalPackets = packets }));
        }
    }

    [Theory]
    [InlineData(10, "Das Gerät kann nicht gestartet werden")]
    [InlineData(28, "kein Treiber installiert")]
    [InlineData(43, "Problem gemeldet")]
    public void DriverErrorFromDeviceManager(int code, string text)
    {
        var broken = new AdapterState
        {
            Id = "nic1", Name = "Ethernet 2", Description = "Realtek PCIe GbE Family Controller", WmiPhysical = true,
            Status = LinkStatus.NotPresent, PnpErrorCode = code,
        };
        Assert.Empty(Poll(broken));
        var finding = Assert.Single(Poll(broken));
        Assert.Equal(FindingKinds.DriverError, finding.Kind);
        Assert.Equal("critical", finding.Severity);
        Assert.Contains(text, finding.Message);
        Assert.Contains("Realtek PCIe GbE Family Controller", finding.Message);
        Assert.Equal(code.ToString(), finding.Details["error_code"]);

        var fixedAdapter = Assert.Single(Poll(broken with { Status = LinkStatus.Down, PnpErrorCode = 0 }));
        Assert.Equal("resolved", fixedAdapter.State);
    }

    [Fact]
    public void DisabledDeviceIsNoDriverError()
    {
        var disabled = new AdapterState { Id = "nic1", Name = "Ethernet 2", WmiPhysical = true, Status = LinkStatus.Disabled, PnpErrorCode = 22 };
        Assert.Empty(PollFor(TimeSpan.FromMinutes(1), disabled));
    }

    [Fact]
    public void RepeatedNdisResetsAreReported()
    {
        var one = new[] { new NicResetEvent(T0, "Intel(R) Ethernet Connection I219-V") };
        Assert.Empty(PollWith(one, Eth()));
        var two = new[] { one[0], new NicResetEvent(T0.AddSeconds(30), "Intel(R) Ethernet Connection I219-V") };
        var finding = Assert.Single(PollWith(two, Eth()));
        Assert.Equal(FindingKinds.NicReset, finding.Kind);
        Assert.Equal("warning", finding.Severity);
        Assert.Equal("Ethernet", finding.Adapter);
        Assert.Contains("2-mal", finding.Message);
        Assert.Contains("Treiber", finding.Solution);

        _now = T0.AddMinutes(16);
        Assert.Equal("resolved", Assert.Single(PollWith(two, Eth())).State);
        // Ereignisprotokoll nicht lesbar: kein Urteil
        Assert.Empty(PollWith(null, Eth()));
    }

    [Theory]
    [InlineData("Hyper-V Virtual Ethernet Adapter", "vEthernet (Default Switch)")]
    [InlineData("VMware Virtual Ethernet Adapter for VMnet8", "VMware Network Adapter VMnet8")]
    [InlineData("VirtualBox Host-Only Ethernet Adapter", "Ethernet 3")]
    [InlineData("TAP-Windows Adapter V9", "OpenVPN TAP")]
    [InlineData("WireGuard Tunnel", "wg0")]
    [InlineData("Fortinet SSL VPN Virtual Ethernet Adapter", "Ethernet 4")]
    [InlineData("WAN Miniport (IP)", "WAN Miniport")]
    [InlineData("Bluetooth Device (Personal Area Network)", "Bluetooth-Netzwerkverbindung")]
    [InlineData("Npcap Loopback Adapter", "Npcap")]
    [InlineData("Microsoft Wi-Fi Direct Virtual Adapter", "LAN-Verbindung* 1")]
    public void VirtualAdaptersAreIgnored(string description, string name)
    {
        var virt = Eth(description: description, name: name);
        Assert.False(virt.IsPhysical);
        Poll(virt);
        Assert.Empty(PollFor(TimeSpan.FromMinutes(1), virt with { Status = LinkStatus.Down, Ipv4 = Array.Empty<string>(), HasGateway = false }));
    }

    [Fact]
    public void TunnelTypeAndWmiNonPhysicalAreIgnored()
    {
        Assert.False((Eth() with { Type = NetworkInterfaceType.Tunnel }).IsPhysical);
        Assert.False((Eth() with { WmiPhysical = false }).IsPhysical);
        Assert.True(Eth().IsPhysical);
        Assert.True(Wifi().IsPhysical);
    }

    [Fact]
    public void FindingFieldsStayWithinLimits()
    {
        var longName = new string('n', 400);
        Poll(Eth(name: longName));
        var fired = Assert.Single(Poll(Eth(LinkStatus.Down, name: longName)));
        Assert.True(fired.Title.Length <= ClientFinding.MaxTitle);
        Assert.True(fired.Message.Length <= ClientFinding.MaxText);
        Assert.True(fired.Solution.Length <= ClientFinding.MaxText);

        foreach (var kind in FindingKinds.All)
        {
            Assert.Matches("^[a-z_]+$", kind);
        }
    }
}

public sealed class ClientFindingsTransportTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "wachtl-findings-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    private string PendingPath => Path.Combine(_dir, "findings-pending.json");

    private static ClientFinding Finding(int i, string state = "active") => new()
    {
        FindingId = $"id-{i}",
        Kind = FindingKinds.CableUnplugged,
        Severity = "critical",
        State = state,
        Adapter = "Ethernet",
        Title = "Netzwerkkabel getrennt",
        DetectedAt = 1_792_230_000 + i,
        ResolvedAt = state == "resolved" ? 1_792_230_100 : null,
        Details = new() { ["old_mbps"] = "1000" },
    };

    [Fact]
    public void UploadMatchesServerContract()
    {
        var json = JsonSerializer.Serialize(new FindingsUpload { Findings = { Finding(1) } }, ApiClient.JsonOptions);
        using var doc = JsonDocument.Parse(json);
        var f = doc.RootElement.GetProperty("findings")[0];
        foreach (var name in new[] { "finding_id", "kind", "severity", "state", "adapter", "adapter_description", "title", "message", "solution", "details", "detected_at", "resolved_at" })
        {
            Assert.True(f.TryGetProperty(name, out _), name);
        }

        Assert.Equal(JsonValueKind.Null, f.GetProperty("resolved_at").ValueKind);
        Assert.Equal(1_792_230_001, f.GetProperty("detected_at").GetInt64());
        Assert.Equal("1000", f.GetProperty("details").GetProperty("old_mbps").GetString());
        Assert.Equal(12, f.EnumerateObject().Count());
    }

    [Fact]
    public void PendingKeepsLatestStatePerFindingAndPersists()
    {
        var pending = new PendingFindings(PendingPath);
        pending.Add(new[] { Finding(1), Finding(2) });
        pending.Add(new[] { Finding(1, "resolved") });
        var reloaded = new PendingFindings(PendingPath).Snapshot();
        Assert.Equal(new[] { "id-2", "id-1" }, reloaded.Select(f => f.FindingId));
        Assert.Equal("resolved", reloaded[1].State);
        Assert.Contains("\"finding_id\"", File.ReadAllText(PendingPath));
    }

    [Fact]
    public void PendingIgnoresNullEntriesInDamagedFile()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(PendingPath, "[null, {\"finding_id\": \"id-1\", \"kind\": \"apipa\"}]");
        Assert.Equal("id-1", Assert.Single(new PendingFindings(PendingPath).Snapshot()).FindingId);
    }

    [Fact]
    public void PendingKeepsNewest200()
    {
        var pending = new PendingFindings(PendingPath);
        pending.Add(Enumerable.Range(0, 205).Select(i => Finding(i)));
        var reloaded = new PendingFindings(PendingPath).Snapshot();
        Assert.Equal(PendingFindings.MaxEntries, reloaded.Count);
        Assert.Equal("id-5", reloaded[0].FindingId);
    }

    [Fact]
    public async Task FlushSendsBatchesOf50AndStopsOnRetry()
    {
        var pending = new PendingFindings(PendingPath);
        pending.Add(Enumerable.Range(0, 120).Select(i => Finding(i)));
        var batches = new List<int>();
        var outcomes = new Queue<ReportSendOutcome>(new[] { ReportSendOutcome.Delivered, ReportSendOutcome.Retry });
        var delivered = await pending.FlushAsync((b, ct) =>
        {
            batches.Add(b.Count);
            return Task.FromResult(new ReportSendResult(outcomes.Dequeue()));
        }, default);
        Assert.Equal(50, delivered);
        Assert.Equal(new[] { 50, 50 }, batches);
        Assert.Equal(70, pending.Count);

        delivered = await pending.FlushAsync((b, ct) => Task.FromResult(new ReportSendResult(ReportSendOutcome.Delivered)), default);
        Assert.Equal(70, delivered);
        Assert.Equal(0, pending.Count);
        Assert.False(File.Exists(PendingPath));
    }

    [Fact]
    public async Task RejectedBatchIsDroppedButNewerStateKept()
    {
        var pending = new PendingFindings(PendingPath);
        pending.Add(new[] { Finding(1) });
        var delivered = await pending.FlushAsync((b, ct) =>
        {
            pending.Add(new[] { Finding(1, "resolved") }); // neuer Stand während des Sendens
            return Task.FromResult(new ReportSendResult(ReportSendOutcome.Rejected, "ungültig"));
        }, default);
        Assert.Equal(0, delivered);
        Assert.Equal("resolved", Assert.Single(pending.Snapshot()).State);
    }

    [Fact]
    public async Task NoServerConnectionMeansRetry()
    {
        var result = await new ProbeStatus().SendFindingsAsync(new[] { Finding(1) }, default);
        Assert.Equal(ReportSendOutcome.Retry, result.Outcome);
    }

    [Fact]
    public void FeedNumbersEveryChange()
    {
        var feed = new FindingFeed(startSeq: 100);
        Assert.Equal(101, feed.Publish(Finding(1)));
        Assert.Equal(102, feed.Publish(Finding(2)));
        Assert.Equal(103, feed.Publish(Finding(1, "resolved")));

        var all = feed.Since(0);
        Assert.Equal(new long[] { 102, 103 }, all.Findings.Select(f => f.Seq));
        Assert.Equal(103, all.LatestSeq);
        Assert.Equal("resolved", Assert.Single(feed.Since(102).Findings).State);
        Assert.Empty(feed.Since(103).Findings);

        for (var i = 0; i < 60; i++)
        {
            feed.Publish(Finding(10 + i));
        }

        Assert.Equal(FindingFeed.MaxEntries, feed.Since(0).Findings.Count);
    }

    [Fact]
    public void ConfigDefaultsWhenServerDoesNotSendClientFindings()
    {
        var old = JsonSerializer.Deserialize<ProbeConfig>("{\"probe_id\":1,\"checks\":[]}", ApiClient.JsonOptions)!;
        Assert.True(old.ClientFindings.Enabled);
        Assert.True(old.ClientFindings.Notify);

        var off = JsonSerializer.Deserialize<ProbeConfig>("{\"client_findings\":{\"enabled\":true,\"notify\":false}}", ApiClient.JsonOptions)!;
        Assert.True(off.ClientFindings.Enabled);
        Assert.False(off.ClientFindings.Notify);
    }
}
