using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Wachtl.Probe.NetScan;

/// <summary>IPv4-Netz in CIDR-Schreibweise (Netzadresse als Zahl, Präfixlänge).</summary>
public readonly record struct Ipv4Net(uint Network, int Prefix)
{
    public uint Mask => SubnetPlanner.MaskOf(Prefix);

    /// <summary>Anzahl aller Adressen im Netz.</summary>
    public long AddressCount => 1L << (32 - Prefix);

    /// <summary>Anzahl scanbarer Adressen: ohne Netz- und Broadcast-Adresse bis /30, bei /31 und /32 alle.</summary>
    public long HostCount => Prefix >= 31 ? AddressCount : AddressCount - 2;

    public bool Contains(uint ip) => (ip & Mask) == Network;

    /// <summary>Alle scanbaren Adressen aufsteigend.</summary>
    public IEnumerable<uint> Hosts()
    {
        if (Prefix >= 31)
        {
            for (long i = 0; i < AddressCount; i++)
            {
                yield return Network + (uint)i;
            }

            yield break;
        }

        for (long i = 1; i < AddressCount - 1; i++)
        {
            yield return Network + (uint)i;
        }
    }

    public static Ipv4Net Of(uint ip, int prefix) => new(ip & SubnetPlanner.MaskOf(prefix), prefix);

    public override string ToString() => $"{SubnetPlanner.ToIp(Network)}/{Prefix}";
}

/// <summary>Eigene IPv4-Adresse einer aktiven Netzwerkkarte mit Präfixlänge und MAC-Adresse der Karte.</summary>
public sealed record LocalAddress(IPAddress Address, int Prefix, string? Mac);

/// <summary>
/// Bestimmt die zu scannenden Netze: „auto“ (eigene Netze, höchstens /22 um die eigene Adresse, ohne Loopback/APIPA)
/// oder eine Komma-getrennte Liste von Netzen in CIDR-Schreibweise.
/// </summary>
public static class SubnetPlanner
{
    /// <summary>Größere eigene Netze werden bei „auto“ auf dieses Präfix um die eigene Adresse gekürzt.</summary>
    public const int AutoMinPrefix = 22;

    public static uint MaskOf(int prefix) => prefix <= 0 ? 0u : uint.MaxValue << (32 - prefix);

    public static uint ToUInt(IPAddress address) => BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());

    public static IPAddress ToIp(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return new IPAddress(bytes);
    }

    public static bool IsLoopback(uint ip) => ip >> 24 == 127;

    /// <summary>169.254.0.0/16 – automatische Adresse ohne DHCP.</summary>
    public static bool IsApipa(uint ip) => ip >> 16 == 0xA9FE;

    /// <summary>„a.b.c.d/p“ oder „a.b.c.d“ (= /32). Hostbits werden auf die Netzadresse gekürzt.</summary>
    public static bool TryParseCidr(string? text, out Ipv4Net net)
    {
        net = default;
        var value = (text ?? string.Empty).Trim();
        var slash = value.IndexOf('/');
        var ipText = slash >= 0 ? value[..slash].Trim() : value;
        var prefix = 32;
        if (slash >= 0 && !int.TryParse(value[(slash + 1)..].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out prefix))
        {
            return false;
        }

        if (prefix is < 0 or > 32 || !IsDottedQuad(ipText) || !IPAddress.TryParse(ipText, out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        net = Ipv4Net.Of(ToUInt(ip), prefix);
        return true;
    }

    /// <summary>Genau vier Zahlen 0–255 mit Punkten (IPAddress.TryParse nimmt auch „10“ oder „10.1“).</summary>
    private static bool IsDottedQuad(string text)
    {
        var parts = text.Split('.');
        return parts.Length == 4 && parts.All(p => p.Length is > 0 and <= 3 && p.All(char.IsAsciiDigit) && int.Parse(p, CultureInfo.InvariantCulture) <= 255);
    }

    /// <summary>Komma-getrennte Netzliste. null und <paramref name="error"/>, wenn ein Eintrag ungültig ist.</summary>
    public static List<Ipv4Net>? ParseTargets(string target, out string? error)
    {
        error = null;
        var nets = new List<Ipv4Net>();
        foreach (var part in target.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TryParseCidr(part, out var net))
            {
                error = $"Ungültiges Netz „{part}“ – erwartet z. B. 192.168.10.0/24";
                return null;
            }

            nets.Add(net);
        }

        if (nets.Count == 0)
        {
            error = "Kein Netz angegeben";
            return null;
        }

        return RemoveNested(nets);
    }

    /// <summary>
    /// Netze für „auto“: je eigener Adresse das Netz der Karte, höchstens /<see cref="AutoMinPrefix"/> um die eigene Adresse.
    /// Loopback, APIPA und /32 (z. B. VPN-Punkt-zu-Punkt) werden übersprungen.
    /// </summary>
    public static List<Ipv4Net> PlanAuto(IEnumerable<LocalAddress> addresses)
    {
        var nets = new List<Ipv4Net>();
        foreach (var a in addresses)
        {
            if (a.Address.AddressFamily != AddressFamily.InterNetwork || a.Prefix is < 1 or > 31)
            {
                continue;
            }

            var ip = ToUInt(a.Address);
            if (IsLoopback(ip) || IsApipa(ip) || ip == 0 || ip >> 28 >= 0xE)
            {
                continue;
            }

            nets.Add(Ipv4Net.Of(ip, Math.Max(a.Prefix, AutoMinPrefix)));
        }

        return RemoveNested(nets);
    }

    /// <summary>Ziel des Checks auflösen: „auto“ (oder leer) bzw. Netzliste.</summary>
    public static List<Ipv4Net>? Plan(string? target, Func<IEnumerable<LocalAddress>> localAddresses, out string? error)
    {
        error = null;
        var value = (target ?? string.Empty).Trim();
        if (value.Length == 0 || value.Equals("auto", StringComparison.OrdinalIgnoreCase))
        {
            var nets = PlanAuto(localAddresses());
            if (nets.Count == 0)
            {
                error = "Keine eigenen IPv4-Netze gefunden (Netzwerkkarte verbunden?)";
                return null;
            }

            return nets;
        }

        return ParseTargets(value, out error);
    }

    /// <summary>Doppelte und in anderen enthaltene Netze entfernen, nach Adresse sortiert.</summary>
    public static List<Ipv4Net> RemoveNested(IEnumerable<Ipv4Net> nets)
    {
        var kept = new List<Ipv4Net>();
        foreach (var net in nets.OrderBy(n => n.Prefix).ThenBy(n => n.Network))
        {
            if (!kept.Any(k => k.Prefix <= net.Prefix && k.Contains(net.Network)))
            {
                kept.Add(net);
            }
        }

        return kept.OrderBy(n => n.Network).ToList();
    }

    /// <summary>Anzahl scanbarer Adressen (ohne die Liste aufzubauen – Schutz vor riesigen Netzen).</summary>
    public static long CountHosts(IEnumerable<Ipv4Net> nets) => RemoveNested(nets).Sum(n => n.HostCount);

    /// <summary>Alle scanbaren Adressen, eindeutig und aufsteigend.</summary>
    public static List<uint> ExpandHosts(IEnumerable<Ipv4Net> nets) =>
        RemoveNested(nets).SelectMany(n => n.Hosts()).Distinct().OrderBy(x => x).ToList();

    /// <summary>IPv4-Adressen aktiver Netzwerkkarten (ohne Loopback und Tunnel) mit Präfix und MAC.</summary>
    public static List<LocalAddress> LocalAddresses()
    {
        var result = new List<LocalAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up ||
                    nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                string? mac = null;
                try
                {
                    mac = ArpTable.FormatMac(nic.GetPhysicalAddress().GetAddressBytes());
                }
                catch (NetworkInformationException)
                {
                }

                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        result.Add(new LocalAddress(ua.Address, ua.PrefixLength, mac));
                    }
                }
            }
        }
        catch (NetworkInformationException)
        {
        }

        return result;
    }
}
