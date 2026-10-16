using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Wachtl.Probe.Checks;

public readonly record struct PingResult(bool Success, double RttMs, int? Ttl, IPAddress? From, IPStatus Status, string Error);

/// <summary>Gemeinsame Ping-Hilfen für Dauerpings, Traceroute und Hop-Pings.</summary>
public static class PingHelper
{
    /// <summary>Zieladresse auflösen: IP, Hostname (IPv4) oder „gateway“.</summary>
    public static async Task<(IPAddress? Address, string Error)> ResolveAsync(string target, GatewayResolver gateway, CancellationToken ct)
    {
        if (target == "gateway")
        {
            var gw = gateway.Get();
            return gw is null ? (null, "kein Default-Gateway gefunden") : (gw, string.Empty);
        }

        if (IPAddress.TryParse(target, out var ip))
        {
            return (ip, string.Empty);
        }

        try
        {
            var resolved = await Dns.GetHostAddressesAsync(target, AddressFamily.InterNetwork, ct).ConfigureAwait(false);
            var first = resolved.FirstOrDefault();
            return first is null ? (null, "DNS liefert keine IPv4-Adresse") : (first, string.Empty);
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            return (null, "DNS-Auflösung fehlgeschlagen: " + ex.Message);
        }
    }

    /// <summary>
    /// Ein Ping. Bei TTL-Ablauf (Traceroute) ist <c>Success</c> false, <c>From</c> enthält dann den antwortenden Router.
    /// </summary>
    public static async Task<PingResult> SendAsync(Ping ping, IPAddress address, TimeSpan timeout, byte[] payload,
        PingOptions options, CancellationToken ct)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            var reply = await ping.SendPingAsync(address, timeout, payload, options, ct).ConfigureAwait(false);
            stopwatch.Stop();
            // Windows liefert RoundtripTime nur in ganzen ms (bei TTL-Ablauf oft 0) – für kleine Werte die Stoppuhr nehmen.
            var rtt = reply.RoundtripTime >= 2 ? reply.RoundtripTime : Math.Round(stopwatch.Elapsed.TotalMilliseconds, 3);
            var from = reply.Address is { } a && !a.Equals(IPAddress.Any) ? a : null;
            return reply.Status == IPStatus.Success
                ? new PingResult(true, rtt, reply.Options?.Ttl, from, reply.Status, string.Empty)
                : new PingResult(false, rtt, null, from, reply.Status, reply.Status.ToString());
        }
        catch (PingException ex)
        {
            return new PingResult(false, 0, null, null, IPStatus.Unknown, ex.InnerException?.Message ?? ex.Message);
        }
    }
}
