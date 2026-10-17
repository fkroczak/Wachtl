using System.Net.NetworkInformation;

namespace Wachtl.Probe.Diagnostics;

public enum LinkStatus
{
    /// <summary>Verbindung steht.</summary>
    Up,

    /// <summary>Kein Link (Kabel ausgesteckt, WLAN getrennt).</summary>
    Down,

    /// <summary>Vom Benutzer deaktiviert (Geräte-Manager-Code 22).</summary>
    Disabled,

    /// <summary>Nur im Geräte-Manager sichtbar, z. B. weil der Treiber nicht startet.</summary>
    NotPresent,
}

/// <summary>Zustand einer Netzwerkkarte zu einem Zeitpunkt – reine Daten, ohne Windows-Abhängigkeit.</summary>
public sealed record AdapterState
{
    /// <summary>Schnittstellen-GUID wie in NetworkInterface.Id bzw. Win32_NetworkAdapter.GUID.</summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>Verbindungsname, z. B. „Ethernet“ oder „WLAN“.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Gerätename, z. B. „Intel(R) Ethernet Connection I219-V“.</summary>
    public string Description { get; init; } = string.Empty;

    public NetworkInterfaceType Type { get; init; } = NetworkInterfaceType.Ethernet;

    /// <summary>Win32_NetworkAdapter.PhysicalAdapter, null wenn WMI nicht lesbar war.</summary>
    public bool? WmiPhysical { get; init; }

    public LinkStatus Status { get; init; } = LinkStatus.Up;

    /// <summary>Verbindungsgeschwindigkeit in Bit/s, -1 = unbekannt.</summary>
    public long SpeedBps { get; init; } = -1;

    public IReadOnlyList<string> Ipv4 { get; init; } = Array.Empty<string>();

    public bool HasGateway { get; init; }

    /// <summary>Summe aus empfangenen fehlerhaften, empfangenen verworfenen und gesendeten fehlerhaften Paketen (kumulativ).</summary>
    public long? ErrorPackets { get; init; }

    /// <summary>Summe aller gesendeten und empfangenen Pakete (kumulativ).</summary>
    public long? TotalPackets { get; init; }

    /// <summary>Geräte-Manager-Fehlercode (ConfigManagerErrorCode), 0 = in Ordnung.</summary>
    public int PnpErrorCode { get; init; }

    public bool IsEthernet => AdapterClassifier.IsEthernet(Type);

    public bool IsWifi => Type == NetworkInterfaceType.Wireless80211;

    public bool IsPhysical => AdapterClassifier.IsPhysical(this);

    /// <summary>Hat eine IPv4-Adresse, die nicht aus 169.254.0.0/16 stammt.</summary>
    public bool HasRoutableIpv4 => Ipv4.Any(ip => !AdapterClassifier.IsApipa(ip));
}

/// <summary>Zurücksetzen der Netzwerkkarte laut System-Ereignisprotokoll (Microsoft-Windows-NDIS, ID 10400).</summary>
public sealed record NicResetEvent(DateTimeOffset At, string? Adapter);

/// <summary>Alle Netzwerkkarten zu einem Zeitpunkt. <c>Resets</c> null = Ereignisprotokoll nicht lesbar.</summary>
public sealed record AdapterSnapshot(DateTimeOffset At, IReadOnlyList<AdapterState> Adapters, IReadOnlyList<NicResetEvent>? Resets = null);

/// <summary>Unterscheidet echte Netzwerkkarten von virtuellen (VPN, Hyper-V, VMware …).</summary>
public static class AdapterClassifier
{
    private static readonly string[] VirtualPatterns =
    {
        "hyper-v", "vethernet", "virtual", "vmware", "virtualbox", "vbox", "tap-", "tap adapter", "tap-windows",
        "openvpn", "wireguard", "wintun", "vpn", "wan miniport", "bluetooth", "npcap", "loopback", "pseudo",
        "teredo", "isatap", "6to4", "kernel debug", "tailscale", "zerotier", "anyconnect", "fortinet", "forticlient",
        "globalprotect", "pangp", "juniper", "sonicwall", "checkpoint", "docker", "wsl", "ras async", "microsoft km-test",
    };

    public static bool IsEthernet(NetworkInterfaceType type) => type is NetworkInterfaceType.Ethernet
        or NetworkInterfaceType.Ethernet3Megabit or NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.FastEthernetFx
        or NetworkInterfaceType.GigabitEthernet;

    /// <summary>Nur echte Ethernet-/WLAN-Karten (bzw. von WMI als physisch gemeldete Geräte) werden bewertet.</summary>
    public static bool IsPhysical(AdapterState adapter)
    {
        if (adapter.Type is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp
            or NetworkInterfaceType.Slip)
        {
            return false;
        }

        if (adapter.WmiPhysical == false)
        {
            return false;
        }

        if (IsVirtualName(adapter.Description) || IsVirtualName(adapter.Name))
        {
            return false;
        }

        return IsEthernet(adapter.Type) || adapter.Type == NetworkInterfaceType.Wireless80211 || adapter.WmiPhysical == true;
    }

    public static bool IsVirtualName(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        foreach (var pattern in VirtualPatterns)
        {
            if (text.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static bool IsApipa(string ip) => ip.StartsWith("169.254.", StringComparison.Ordinal);
}
