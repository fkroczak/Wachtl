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
}
