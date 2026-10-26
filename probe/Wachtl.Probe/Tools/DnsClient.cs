using System.Globalization;
using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace Wachtl.Probe.Tools;

public sealed record DnsRecord(string Section, string Name, string Type, uint Ttl, string Data);

public sealed record DnsAnswer(string Rcode, bool Truncated, bool Authoritative, List<DnsRecord> Records, bool Tcp = false);

/// <summary>
/// Kleiner DNS-Client für das Werkzeug „DNS“: eine Frage per UDP (bei abgeschnittener Antwort per TCP), Antwort lesbar
/// aufbereitet. Windows kann von sich aus nur A/AAAA/PTR – MX, TXT, SRV, SOA, CAA brauchen die eigene Abfrage.
/// Gegenstück: dns_query/dns_parse in server/wachtl/serverprobe/tools.py.
/// </summary>
public static class DnsClient
{
    public static readonly IReadOnlyDictionary<string, ushort> Types = new Dictionary<string, ushort>
    {
        ["A"] = 1, ["NS"] = 2, ["CNAME"] = 5, ["SOA"] = 6, ["PTR"] = 12, ["MX"] = 15, ["TXT"] = 16, ["AAAA"] = 28,
        ["SRV"] = 33, ["CAA"] = 257,
    };

    private static readonly string[] Rcodes = { "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED" };

    /// <summary>DNS-Server der aktiven Netzwerkkarten.</summary>
    public static List<IPAddress> SystemResolvers()
    {
        var list = new List<IPAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                foreach (var dns in nic.GetIPProperties().DnsAddresses)
                {
                    if (!list.Contains(dns) && !(dns.IsIPv6SiteLocal && dns.ToString().StartsWith("fec0", StringComparison.Ordinal)))
                    {
                        list.Add(dns);
                    }
                }
            }
        }
        catch (NetworkInformationException)
        {
        }

        return list;
    }

    public static (ushort Id, byte[] Query) BuildQuery(string name, ushort type)
    {
        var id = (ushort)Random.Shared.Next(0, 65536);
        var buf = new List<byte>(64);
        var header = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, id);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), 0x0100);   // Rekursion erwünscht
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), 1);
        buf.AddRange(header);
        var idn = new IdnMapping();
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var raw = Encoding.ASCII.GetBytes(label.Length == 0 ? label : idn.GetAscii(label));
            buf.Add((byte)raw.Length);
            buf.AddRange(raw);
        }

        buf.Add(0);
        buf.Add((byte)(type >> 8));
        buf.Add((byte)type);
        buf.Add(0);
        buf.Add(1);
        return (id, buf.ToArray());
    }

    public static async Task<DnsAnswer> AskAsync(IPAddress server, string name, ushort type, TimeSpan timeout, CancellationToken ct)
    {
        var (id, query) = BuildQuery(name, type);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        byte[] data;
        using (var udp = new UdpClient(server.AddressFamily))
        {
            await udp.SendAsync(query, new IPEndPoint(server, 53), cts.Token).ConfigureAwait(false);
            while (true)
            {
                var r = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
                if (r.Buffer.Length >= 2 && BinaryPrimitives.ReadUInt16BigEndian(r.Buffer) == id)
                {
                    data = r.Buffer;
                    break;
                }
            }
        }

        var answer = Parse(data, id);
        if (!answer.Truncated)
        {
            return answer;
        }

        using var tcp = new TcpClient(server.AddressFamily);
        await tcp.ConnectAsync(server, 53, cts.Token).ConfigureAwait(false);
        var stream = tcp.GetStream();
        var len = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(len, (ushort)query.Length);
        await stream.WriteAsync(len, cts.Token).ConfigureAwait(false);
        await stream.WriteAsync(query, cts.Token).ConfigureAwait(false);
        await stream.ReadExactlyAsync(len, cts.Token).ConfigureAwait(false);
        var body = new byte[BinaryPrimitives.ReadUInt16BigEndian(len)];
        await stream.ReadExactlyAsync(body, cts.Token).ConfigureAwait(false);
        return Parse(body, id) with { Tcp = true };
    }

    public static DnsAnswer Parse(byte[] msg, ushort id)
    {
        if (msg.Length < 12)
        {
            throw new FormatException("Antwort zu kurz");
        }

        if (BinaryPrimitives.ReadUInt16BigEndian(msg) != id)
        {
            throw new FormatException("Antwort gehört nicht zur Anfrage");
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(2));
        int qd = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(4)), an = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(6)),
            ns = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(8));
        var off = 12;
        for (var i = 0; i < qd; i++)
        {
            off = ReadName(msg, off, out _) + 4;
        }

        var records = new List<DnsRecord>();
        for (var i = 0; i < an + ns; i++)
        {
            off = ReadName(msg, off, out var name);
            var type = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(off));
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(msg.AsSpan(off + 4));
            var rdlen = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(off + 8));
            off += 10;
            var typeName = Types.FirstOrDefault(t => t.Value == type).Key ?? type.ToString();
            records.Add(new DnsRecord(i < an ? "answer" : "authority", name, typeName, ttl, Rdata(msg, type, off, rdlen)));
            off += rdlen;
        }

        var rcode = flags & 0xF;
        return new DnsAnswer(rcode < Rcodes.Length ? Rcodes[rcode] : rcode.ToString(), (flags & 0x0200) != 0,
            (flags & 0x0400) != 0, records);
    }

    private static int ReadName(byte[] msg, int off, out string name)
    {
        var labels = new List<string>();
        var end = -1;
        for (var depth = 0; ; )
        {
            if (off >= msg.Length || depth > 20)
            {
                throw new FormatException("Antwort beschädigt");
            }

            var n = msg[off];
            if ((n & 0xC0) == 0xC0)
            {
                if (end < 0)
                {
                    end = off + 2;
                }

                off = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(off)) & 0x3FFF;
                depth++;
                continue;
            }

            if (n == 0)
            {
                if (end < 0)
                {
                    end = off + 1;
                }

                break;
            }

            labels.Add(Encoding.ASCII.GetString(msg, off + 1, n));
            off += n + 1;
        }

        name = string.Join('.', labels) + ".";
        return end;
    }

    private static string Rdata(byte[] msg, ushort type, int off, int len)
    {
        var rd = msg.AsSpan(off, len);
        switch (type)
        {
            case 1 when len == 4:
            case 28 when len == 16:
                return new IPAddress(rd).ToString();
            case 2 or 5 or 12:
                ReadName(msg, off, out var target);
                return target;
            case 15:
                ReadName(msg, off + 2, out var mx);
                return $"{BinaryPrimitives.ReadUInt16BigEndian(rd)} {mx}";
            case 16:
            {
                var parts = new List<string>();
                for (var i = 0; i < len;)
                {
                    int n = rd[i];
                    parts.Add("\"" + Encoding.UTF8.GetString(rd.Slice(i + 1, Math.Min(n, len - i - 1))) + "\"");
                    i += n + 1;
                }

                return string.Join(' ', parts);
            }
            case 6:
            {
                var o = ReadName(msg, off, out var mname);
                o = ReadName(msg, o, out var rname);
                var v = msg.AsSpan(o);
                return $"{mname} {rname} {BinaryPrimitives.ReadUInt32BigEndian(v)} {BinaryPrimitives.ReadUInt32BigEndian(v[4..])} " +
                       $"{BinaryPrimitives.ReadUInt32BigEndian(v[8..])} {BinaryPrimitives.ReadUInt32BigEndian(v[12..])} " +
                       $"{BinaryPrimitives.ReadUInt32BigEndian(v[16..])}";
            }
            case 33:
                ReadName(msg, off + 6, out var srv);
                return $"{BinaryPrimitives.ReadUInt16BigEndian(rd)} {BinaryPrimitives.ReadUInt16BigEndian(rd[2..])} " +
                       $"{BinaryPrimitives.ReadUInt16BigEndian(rd[4..])} {srv}";
            case 257 when len >= 2:
            {
                int tl = rd[1];
                return $"{rd[0]} {Encoding.ASCII.GetString(rd.Slice(2, tl))} \"{Encoding.UTF8.GetString(rd[(2 + tl)..])}\"";
            }
            default:
                return Convert.ToHexString(rd).ToLowerInvariant();
        }
    }
}
