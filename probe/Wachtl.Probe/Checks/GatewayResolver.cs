using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Wachtl.Probe.Checks;

/// <summary>Ermittelt das IPv4-Default-Gateway und hält es 30 Sekunden im Cache.</summary>
public sealed class GatewayResolver
{
    private static readonly TimeSpan CacheTime = TimeSpan.FromSeconds(30);
    private readonly object _lock = new();
    private IPAddress? _cached;
    private DateTime _validUntil = DateTime.MinValue;

    public IPAddress? Get()
    {
        lock (_lock)
        {
            if (DateTime.UtcNow < _validUntil)
            {
                return _cached;
            }

            _cached = Resolve();
            _validUntil = DateTime.UtcNow + CacheTime;
            return _cached;
        }
    }

    internal static IPAddress? Resolve()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up ||
                nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            var gateway = nic.GetIPProperties().GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
            if (gateway is not null)
            {
                return gateway;
            }
        }

        return null;
    }

    /// <summary>
    /// Lokale IPv4-Adressen aktiver Netzwerkkarten (für iperf3 zwischen Probes).
    /// Karten mit Default-Gateway zuerst.
    /// </summary>
    public static List<string> LocalAddresses()
    {
        var withGateway = new List<string>();
        var others = new List<string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up ||
                nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            var props = nic.GetIPProperties();
            var hasGateway = props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));
            foreach (var ua in props.UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(ua.Address))
                {
                    continue;
                }

                var bytes = ua.Address.GetAddressBytes();
                if (bytes[0] == 169 && bytes[1] == 254)
                {
                    continue;
                }

                (hasGateway ? withGateway : others).Add(ua.Address.ToString());
            }
        }

        return withGateway.Concat(others).Distinct().Take(8).ToList();
    }
}
