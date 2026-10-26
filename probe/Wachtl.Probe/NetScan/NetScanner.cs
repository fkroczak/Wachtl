using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Checks;

namespace Wachtl.Probe.NetScan;

/// <summary>
/// Ein Scan: Geräteerkennung (ICMP, TCP auf 80/443/445/22, ARP-Tabelle), Reverse-DNS, Portscan per TCP-Connect
/// und Diensterkennung. Nur TCP-Connect, keine SYN-Scans, nur die übergebenen Netze.
/// </summary>
public static class NetScanner
{
    /// <summary>Ports für Geräte, die Ping blockieren.</summary>
    internal static readonly int[] DiscoveryPorts = { 80, 443, 445, 22 };

    private static readonly TimeSpan DnsTimeout = TimeSpan.FromSeconds(1);

    private sealed class HostState
    {
        public double? RttMs;
        public bool Icmp;
        public bool Tcp;
        public bool Arp;
        public string? Mac;
        public string? Hostname;
        public readonly List<NetScanPort> Ports = new();
    }

    public static async Task<List<NetScanHost>> ScanAsync(NetScanOptions o, IReadOnlyList<Ipv4Net> subnets, ILogger logger,
        CancellationToken ct)
    {
        var addresses = SubnetPlanner.ExpandHosts(subnets);
        var timeout = TimeSpan.FromMilliseconds(o.TimeoutMs);
        var parallel = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, o.Parallel), CancellationToken = ct };
        var found = new ConcurrentDictionary<uint, HostState>();

        // 1. Geräteerkennung: Ping, sonst TCP-Verbindungsversuch
        var payload = new byte[32];
        Array.Fill(payload, (byte)'w');
        await Parallel.ForEachAsync(addresses, parallel, async (ip, token) =>
        {
            var address = SubnetPlanner.ToIp(ip);
            try
            {
                using var ping = new Ping();
                var reply = await PingHelper.SendAsync(ping, address, timeout, payload, new PingOptions(64, true), token)
                    .ConfigureAwait(false);
                if (reply.Success && (reply.From is null || reply.From.Equals(address)))
                {
                    found[ip] = new HostState { Icmp = true, RttMs = Math.Round(reply.RttMs, 2) };
                    return;
                }
            }
            catch (Exception ex) when (!token.IsCancellationRequested && ex is not OperationCanceledException)
            {
                // Ping nicht möglich (z. B. ICMP gesperrt) – TCP versuchen
            }

            if (await AnyTcpAsync(address, timeout, token).ConfigureAwait(false))
            {
                found[ip] = new HostState { Tcp = true };
            }
        }).ConfigureAwait(false);

        // 2. ARP-Tabelle: MAC-Adressen, Geräte nur mit ARP-Eintrag zählen auch
        var scanned = new HashSet<uint>(addresses);
        var arp = await ArpTable.ReadAsync(logger, ct).ConfigureAwait(false);
        foreach (var (ip, mac) in arp)
        {
            if (!scanned.Contains(ip))
            {
                continue;
            }

            var state = found.GetOrAdd(ip, _ => new HostState());
            state.Arp = true;
            state.Mac = mac;
        }

        // eigene Adressen: MAC der Netzwerkkarte
        var self = new Dictionary<uint, string?>();
        foreach (var local in SubnetPlanner.LocalAddresses())
        {
            self[SubnetPlanner.ToUInt(local.Address)] = local.Mac;
        }

        foreach (var (ip, state) in found)
        {
            if (self.TryGetValue(ip, out var mac))
            {
                state.Mac ??= mac;
            }
        }

        // 3. Namen per Reverse-DNS
        await Parallel.ForEachAsync(found.ToArray(), parallel, async (pair, token) =>
        {
            var ipText = SubnetPlanner.ToIp(pair.Key).ToString();
            try
            {
                var entry = await Dns.GetHostEntryAsync(ipText, token).WaitAsync(DnsTimeout, token).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(entry.HostName) && entry.HostName != ipText)
                {
                    pair.Value.Hostname = ServiceProbe.CleanText(entry.HostName);
                }
            }
            catch (Exception) when (!token.IsCancellationRequested)
            {
                // kein PTR-Eintrag oder Zeitüberschreitung
            }
        }).ConfigureAwait(false);

        // 4./5. Portscan und Diensterkennung
        if (o.PortScan && o.Ports.Count > 0 && !found.IsEmpty)
        {
            var pairs = found.Keys.OrderBy(k => k).SelectMany(ip => o.Ports.Select(port => (Ip: ip, Port: port)));
            await Parallel.ForEachAsync(pairs, parallel, async (pair, token) =>
            {
                var address = SubnetPlanner.ToIp(pair.Ip);
                var (client, _) = await ConnectAsync(address, pair.Port, timeout, token).ConfigureAwait(false);
                if (client is null)
                {
                    return;
                }

                NetScanPort info;
                using (client)
                {
                    info = await ServiceProbe.DetectAsync(client, address, pair.Port, timeout, token).ConfigureAwait(false);
                }

                var state = found[pair.Ip];
                lock (state.Ports)
                {
                    state.Ports.Add(info);
                }
            }).ConfigureAwait(false);
        }

        return found.OrderBy(p => p.Key).Select(p =>
        {
            var s = p.Value;
            var via = new List<string>();
            if (s.Icmp)
            {
                via.Add("icmp");
            }

            if (s.Arp)
            {
                via.Add("arp");
            }

            if (s.Tcp)
            {
                via.Add("tcp");
            }

            return new NetScanHost
            {
                Ip = SubnetPlanner.ToIp(p.Key).ToString(),
                Mac = s.Mac,
                Hostname = s.Hostname,
                RttMs = s.RttMs,
                Via = via,
                Self = self.ContainsKey(p.Key),
                Ports = s.Ports.OrderBy(x => x.Port).ToList(),
            };
        }).ToList();
    }

    /// <summary>
    /// Antwortet das Gerät auf einem der <see cref="DiscoveryPorts"/> (Verbindung oder Ablehnung)?
    /// Versuche laufen gleichzeitig; die erste Antwort beendet die übrigen.
    /// </summary>
    private static async Task<bool> AnyTcpAsync(IPAddress address, TimeSpan timeout, CancellationToken ct)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var pending = DiscoveryPorts.Select(async port =>
        {
            try
            {
                var (client, alive) = await ConnectAsync(address, port, timeout, stop.Token).ConfigureAwait(false);
                client?.Dispose();
                return alive;
            }
            catch (OperationCanceledException)
            {
                return false;
            }
        }).ToList();

        var answered = false;
        while (pending.Count > 0)
        {
            var done = await Task.WhenAny(pending).ConfigureAwait(false);
            pending.Remove(done);
            if (await done.ConfigureAwait(false) && !answered)
            {
                answered = true;
                stop.Cancel();
            }
        }

        ct.ThrowIfCancellationRequested();
        return answered;
    }

    /// <summary>
    /// TCP-Verbindung mit Zeitlimit. <c>Client</c> ist bei Erfolg gesetzt; <c>Alive</c> ist auch bei aktiver Ablehnung (RST) true –
    /// dann gibt es das Gerät, nur der Port ist zu.
    /// </summary>
    internal static async Task<(TcpClient? Client, bool Alive)> ConnectAsync(IPAddress address, int port, TimeSpan timeout,
        CancellationToken ct)
    {
        var client = new TcpClient(AddressFamily.InterNetwork) { NoDelay = true };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await client.ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
            return (client, true);
        }
        catch (Exception ex)
        {
            client.Dispose();
            ct.ThrowIfCancellationRequested();
            // Ablehnung (RST) = Gerät da, Port zu; Zeitüberschreitung u. a. = keine Antwort
            return (null, ex is SocketException { SocketErrorCode: SocketError.ConnectionRefused });
        }
    }
}
