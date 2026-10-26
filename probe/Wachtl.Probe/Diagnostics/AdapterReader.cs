using System.Diagnostics.Eventing.Reader;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace Wachtl.Probe.Diagnostics;

/// <summary>
/// Liest den Zustand der Netzwerkkarten aus Windows: NetworkInterface (alle 5 s), Geräte-Manager über WMI
/// (alle 30 s und nach Netzwerkereignissen) und NDIS-Ereignisse aus dem System-Protokoll (jede Minute).
/// Fehler beim Lesen beenden nie den Dienst – sie werden einmal protokolliert, die Quelle fällt dann einfach weg.
/// </summary>
public sealed partial class AdapterReader
{
    private static readonly TimeSpan WmiInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan EventInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan EventLookback = TimeSpan.FromMinutes(15);
    private const int MaxEvents = 100;

    private readonly ILogger _logger;
    private Dictionary<string, WmiAdapter>? _wmi;
    private DateTimeOffset _wmiAt = DateTimeOffset.MinValue;
    private bool _wmiLogged;
    private List<NicResetEvent>? _resets;
    private DateTimeOffset _resetsAt = DateTimeOffset.MinValue;
    private bool _eventsLogged;
    private bool _nicLogged;
    private string _nicSignature = string.Empty;

    public AdapterReader(ILogger logger)
    {
        _logger = logger;
    }

    private sealed record WmiAdapter(string Guid, string ConnectionName, string Name, bool Physical, int ErrorCode, bool? NetEnabled);

    /// <param name="refreshDevices">nach einem Netzwerkereignis: Geräte-Manager sofort neu lesen</param>
    public AdapterSnapshot Read(DateTimeOffset now, bool refreshDevices)
    {
        var adapters = new List<AdapterState>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        NetworkInterface[] nics;
        try
        {
            nics = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch (NetworkInformationException ex)
        {
            if (!_nicLogged)
            {
                _nicLogged = true;
                _logger.LogWarning("Netzwerkkarten nicht lesbar: {Message}", ex.Message);
            }

            nics = Array.Empty<NetworkInterface>();
        }

        // Karte verschwunden, neu oder Link geändert: Geräte-Manager sofort neu lesen. Sonst stammt „deaktiviert“ aus
        // einer bis zu 30 s alten Abfrage, und eine eben deaktivierte Karte sähe aus wie eine abgezogene.
        var signature = Signature(nics);
        var changed = signature != _nicSignature;
        _nicSignature = signature;
        if (OperatingSystem.IsWindows() && (refreshDevices || changed || now - _wmiAt >= WmiInterval))
        {
            _wmi = ReadWmi();
            _wmiAt = now;
        }

        if (OperatingSystem.IsWindows() && now - _resetsAt >= EventInterval)
        {
            _resets = ReadResets(now);
            _resetsAt = now;
        }

        var wmi = _wmi;
        foreach (var nic in nics)
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            var state = FromNic(nic);
            if (wmi is not null)
            {
                if (wmi.TryGetValue(NormalizeGuid(nic.Id), out var w))
                {
                    state = state with
                    {
                        WmiPhysical = w.Physical,
                        PnpErrorCode = w.ErrorCode,
                        Status = w.ErrorCode == 22 || w.NetEnabled == false ? LinkStatus.Disabled : state.Status,
                    };
                }
            }

            seen.Add(NormalizeGuid(nic.Id));
            adapters.Add(state);
        }

        // Geräte, die Windows nicht als Schnittstelle führt: Treiber startet nicht, deaktiviert … Deaktivierte auch dann, wenn
        // WMI sie nicht als physisch führt – die Bewertung kennt die Karte von vorher und braucht nur den Zustand.
        if (wmi is not null)
        {
            foreach (var w in wmi.Values.Where(w => (w.Physical || w.ErrorCode == 22 || w.NetEnabled == false) && !seen.Contains(w.Guid)))
            {
                adapters.Add(new AdapterState
                {
                    Id = w.Guid,
                    Name = string.IsNullOrEmpty(w.ConnectionName) ? w.Name : w.ConnectionName,
                    Description = w.Name,
                    Type = GuessType(w.Name),
                    WmiPhysical = w.Physical,
                    Status = w.ErrorCode == 22 || w.NetEnabled == false ? LinkStatus.Disabled : LinkStatus.NotPresent,
                    PnpErrorCode = w.ErrorCode,
                });
            }
        }

        return new AdapterSnapshot(now, adapters, _resets);
    }

    private static string Signature(NetworkInterface[] nics)
    {
        try
        {
            return string.Join(";", nics.Select(n => NormalizeGuid(n.Id) + "=" + n.OperationalStatus).OrderBy(x => x, StringComparer.Ordinal));
        }
        catch (NetworkInformationException)
        {
            return string.Empty;
        }
    }

    private static AdapterState FromNic(NetworkInterface nic)
    {
        var ipv4 = new List<string>();
        var hasGateway = false;
        try
        {
            var props = nic.GetIPProperties();
            ipv4.AddRange(props.UnicastAddresses
                .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(u.Address))
                .Select(u => u.Address.ToString()));
            hasGateway = props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
        {
        }

        long? errors = null;
        long? packets = null;
        try
        {
            var st = nic.GetIPStatistics();
            // ohne IncomingPacketsDiscarded: Windows zählt dort auch gefilterte Rahmen (fremde VLANs, Multicast,
            // Hyper-V-Switch) – auf gesunden Karten oft Tausende je Minute
            errors = st.IncomingPacketsWithErrors + st.OutgoingPacketsWithErrors;
            packets = st.UnicastPacketsReceived + st.NonUnicastPacketsReceived + st.UnicastPacketsSent + st.NonUnicastPacketsSent;
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
        {
        }

        long speed;
        try
        {
            speed = nic.Speed;
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
        {
            speed = -1;
        }

        return new AdapterState
        {
            Id = NormalizeGuid(nic.Id),
            Name = nic.Name,
            Description = nic.Description,
            Type = nic.NetworkInterfaceType,
            Status = nic.OperationalStatus == OperationalStatus.Up ? LinkStatus.Up : LinkStatus.Down,
            SpeedBps = speed,
            Ipv4 = ipv4,
            HasGateway = hasGateway,
            ErrorPackets = errors,
            TotalPackets = packets,
        };
    }

    private Dictionary<string, WmiAdapter>? ReadWmi()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            var result = new Dictionary<string, WmiAdapter>(StringComparer.OrdinalIgnoreCase);
            using var searcher = new ManagementObjectSearcher(
                "SELECT GUID, Name, NetConnectionID, PhysicalAdapter, ConfigManagerErrorCode, NetEnabled FROM Win32_NetworkAdapter");
            searcher.Options.Timeout = TimeSpan.FromSeconds(10);
            using var collection = searcher.Get();
            foreach (var item in collection)
            {
                using (item)
                {
                    var guid = item["GUID"] as string;
                    if (string.IsNullOrEmpty(guid))
                    {
                        continue;
                    }

                    var code = item["ConfigManagerErrorCode"] is { } c ? Convert.ToInt32(c, System.Globalization.CultureInfo.InvariantCulture) : 0;
                    result[NormalizeGuid(guid)] = new WmiAdapter(
                        NormalizeGuid(guid),
                        item["NetConnectionID"] as string ?? string.Empty,
                        item["Name"] as string ?? string.Empty,
                        item["PhysicalAdapter"] is true,
                        code,
                        item["NetEnabled"] as bool?);
                }
            }

            return result;
        }
        catch (Exception ex)
        {
            if (!_wmiLogged)
            {
                _wmiLogged = true;
                _logger.LogWarning("Geräte-Manager (WMI Win32_NetworkAdapter) nicht lesbar, Treiberfehler werden nicht erkannt: {Message}", ex.Message);
            }

            return null;
        }
    }

    private List<NicResetEvent>? ReadResets(DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            var ms = (long)EventLookback.TotalMilliseconds;
            var query = new EventLogQuery("System", PathType.LogName,
                $"*[System[Provider[@Name='Microsoft-Windows-NDIS'] and (EventID=10400) and TimeCreated[timediff(@SystemTime) <= {ms}]]]")
            {
                ReverseDirection = true,
            };
            var result = new List<NicResetEvent>();
            using var reader = new EventLogReader(query);
            for (var i = 0; i < MaxEvents; i++)
            {
                using var record = reader.ReadEvent();
                if (record is null)
                {
                    break;
                }

                var at = record.TimeCreated is { } t ? new DateTimeOffset(t.ToUniversalTime(), TimeSpan.Zero) : now;
                result.Add(new NicResetEvent(at, AdapterFromEvent(record)));
            }

            return result;
        }
        catch (Exception ex)
        {
            if (!_eventsLogged)
            {
                _eventsLogged = true;
                _logger.LogWarning("System-Ereignisprotokoll nicht lesbar, Zurücksetzen der Netzwerkkarte wird nicht erkannt: {Message}", ex.Message);
            }

            return null;
        }
    }

    /// <summary>Kartenname aus der Ereignismeldung („Die Netzwerkschnittstelle "…" wird zurückgesetzt …“).</summary>
    private static string? AdapterFromEvent(EventRecord record)
    {
        try
        {
            var text = record.FormatDescription();
            if (!string.IsNullOrEmpty(text) && QuotedName().Match(text) is { Success: true } m)
            {
                return m.Groups[1].Value.Trim();
            }
        }
        catch (Exception)
        {
            // Meldungstexte des Anbieters fehlen – dann eben ohne Kartenname
        }

        return null;
    }

    [GeneratedRegex("[\"„“»]([^\"„“«»]{3,200})[\"“”«]")]
    private static partial Regex QuotedName();

    private static NetworkInterfaceType GuessType(string name) =>
        name.Contains("wi-fi", StringComparison.OrdinalIgnoreCase) || name.Contains("wireless", StringComparison.OrdinalIgnoreCase)
        || name.Contains("wlan", StringComparison.OrdinalIgnoreCase) || name.Contains("802.11", StringComparison.OrdinalIgnoreCase)
            ? NetworkInterfaceType.Wireless80211
            : NetworkInterfaceType.Ethernet;

    /// <summary>„{GUID}“ und „GUID“ gleich behandeln.</summary>
    internal static string NormalizeGuid(string id) => id.Trim().Trim('{', '}').ToLowerInvariant();
}
