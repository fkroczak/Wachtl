using System.Buffers.Binary;

namespace Wachtl.Probe.Rtp;

/// <summary>Codec des simulierten Gesprächs: Paketgröße und Werte für das E-Modell (ITU-T G.113).</summary>
public sealed record RtpCodec(string Key, byte PayloadType, int BytesPerMs, int LookaheadMs, double Ie, double Bpl)
{
    public static readonly RtpCodec G711 = new("g711", 0, 8, 0, 0, 25.1);
    public static readonly RtpCodec G729 = new("g729", 18, 1, 5, 11, 19);

    public static RtpCodec Get(string key) => key == "g729" ? G729 : G711;

    public int PayloadBytes(int ptimeMs) => Math.Max(RtpProtocol.Fields, BytesPerMs * ptimeMs);
}

/// <summary>Antwort des Reflektors bzw. gelesenes Wachtl-RTP-Paket.</summary>
public readonly record struct RtpPacket(ushort Seq, uint Ssrc, bool Query, long T1Us, long T2Us, uint Count);

/// <summary>
/// RTP-Sprachtest: Paketformat und Reflexion – identisch mit server/wachtl/rtp/__init__.py.
/// Nach dem RTP-Kopf (12 Byte) folgen: Kennung „WTL1“ (Sprache) bzw. „WTLQ“ (Abfrage am Ende),
/// Sendezeit der Probe (µs), Empfangszeit am Reflektor (µs, 0 = nicht reflektiert) und Zähler des Reflektors.
/// </summary>
public static class RtpProtocol
{
    public const int Header = 12;
    public const int Fields = 24;
    public const int MinPacket = Header + Fields;
    public const int MaxPacket = 1500;
    public const int DefaultPort = 5004;
    private const uint MagicData = 0x57544C31;   // "WTL1"
    private const uint MagicQuery = 0x57544C51;  // "WTLQ"

    public static byte[] Build(RtpCodec codec, int ptimeMs, int seq, uint ssrc, long t1Us, bool query = false, bool first = false)
    {
        var packet = new byte[Header + codec.PayloadBytes(ptimeMs)];
        packet[0] = 0x80;
        packet[1] = (byte)((first ? 0x80 : 0) | codec.PayloadType);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)seq);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4), unchecked((uint)((long)seq * ptimeMs * 8)));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8), ssrc);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12), query ? MagicQuery : MagicData);
        BinaryPrimitives.WriteInt64BigEndian(packet.AsSpan(16), t1Us);
        packet.AsSpan(MinPacket).Fill(codec.Key == "g711" ? (byte)0xFF : (byte)0);   // PCMU-Stille bzw. Nullen
        return packet;
    }

    public static RtpPacket? Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < MinPacket || data.Length > MaxPacket || data[0] >> 6 != 2)
        {
            return null;
        }

        var magic = BinaryPrimitives.ReadUInt32BigEndian(data[12..]);
        if (magic != MagicData && magic != MagicQuery)
        {
            return null;
        }

        return new RtpPacket(BinaryPrimitives.ReadUInt16BigEndian(data[2..]), BinaryPrimitives.ReadUInt32BigEndian(data[8..]),
            magic == MagicQuery, BinaryPrimitives.ReadInt64BigEndian(data[16..]), BinaryPrimitives.ReadInt64BigEndian(data[24..]),
            BinaryPrimitives.ReadUInt32BigEndian(data[32..]));
    }

    /// <summary>Reflektor: Empfangszeit und Zähler eintragen, Größe bleibt gleich (keine Verstärkung).</summary>
    public static void Reflect(Span<byte> data, long t2Us, uint count)
    {
        BinaryPrimitives.WriteInt64BigEndian(data[24..], Math.Max(1, t2Us));
        BinaryPrimitives.WriteUInt32BigEndian(data[32..], count);
    }
}

/// <summary>Messwerte eines Tests (Felder wie das Ergebnis der Server-Probe).</summary>
public sealed class RtpMeasurement
{
    public string? Peer { get; set; }
    public string Codec { get; set; } = "g711";
    public int PtimeMs { get; set; }
    public int DurationS { get; set; }
    public string? Mode { get; set; }
    public int Sent { get; set; }
    public int Received { get; set; }
    public double? RttMs { get; set; }
    public double? RttMaxMs { get; set; }
    public double? LossPct { get; set; }
    public double? UpLossPct { get; set; }
    public double? DownLossPct { get; set; }
    public double? JitterMs { get; set; }
    public double? UpJitterMs { get; set; }
    public double? DownJitterMs { get; set; }
    public int? OutOfOrder { get; set; }
    public double? RFactor { get; set; }
    public double? Mos { get; set; }
    public string? Error { get; set; }
}

public sealed class RtpResult
{
    public long CheckId { get; init; }
    public long Ts { get; init; }
    public string Trigger { get; init; } = "schedule";
    public RtpMeasurement Result { get; init; } = new();
}

/// <summary>Empfangene Antwort: Sende-, Reflektor- und Empfangszeit in µs, Zähler des Reflektors.</summary>
public readonly record struct RtpRecord(long T1Us, long T2Us, uint Count, long T4Us);

/// <summary>Auswertung und MOS – gleiche Rechnung wie analyze() in server/wachtl/rtp/__init__.py.</summary>
public static class RtpAnalysis
{
    public static double RFactor(double oneWayMs, double jitterMs, double lossPct, RtpCodec codec, int ptimeMs)
    {
        var ta = Math.Max(0, oneWayMs) + 2 * Math.Max(0, jitterMs) + ptimeMs + codec.LookaheadMs;
        var delay = 0.024 * ta + (ta > 177.3 ? 0.11 * (ta - 177.3) : 0);
        var loss = Math.Clamp(lossPct, 0, 100);
        var equipment = codec.Ie + (95 - codec.Ie) * loss / (loss + codec.Bpl);
        return 93.2 - delay - equipment;
    }

    public static double Mos(double r) => r <= 0 ? 1.0 : r >= 100 ? 4.5 : 1 + 0.035 * r + 7e-6 * r * (r - 60) * (100 - r);

    private static double? MeanAbsDiff(IReadOnlyList<double> values)
    {
        if (values.Count < 2)
        {
            return null;
        }

        var sum = 0.0;
        for (var i = 1; i < values.Count; i++)
        {
            sum += Math.Abs(values[i] - values[i - 1]);
        }

        return sum / (values.Count - 1);
    }

    private static double Pct(double part, double whole) =>
        whole > 0 ? Math.Round(Math.Clamp(part * 100 / whole, 0, 100), 2) : 0;

    private static double? Round(double? v, int digits) => v is null ? null : Math.Round(v.Value, digits);

    public static void Analyze(RtpMeasurement m, int sent, IReadOnlyDictionary<int, RtpRecord> records, uint? finalCount,
        RtpCodec codec, int ptimeMs)
    {
        m.Sent = sent;
        m.Received = records.Count;
        if (sent == 0)
        {
            m.Error = "keine Pakete gesendet";
            return;
        }

        if (records.Count == 0)
        {
            m.Error = "keine Antwort von der Gegenstelle (UDP-Port gesperrt oder Reflektor aus)";
            m.LossPct = 100;
            return;
        }

        var order = records.Keys.OrderBy(i => i).ToList();
        var rtts = order.Select(i => (records[i].T4Us - records[i].T1Us) / 1000.0).ToList();
        m.RttMs = Math.Round(rtts.Average(), 2);
        m.RttMaxMs = Math.Round(rtts.Max(), 2);
        m.LossPct = Pct(sent - records.Count, sent);
        var arrival = order.OrderBy(i => records[i].T4Us).ToList();
        m.OutOfOrder = arrival.Zip(arrival.Skip(1)).Count(p => p.Second < p.First);
        var oneWay = m.RttMs.Value / 2;
        double r;
        if (order.All(i => records[i].T2Us != 0))
        {
            m.Mode = "wachtl";
            long count = finalCount ?? order.Max(i => records[i].Count);
            count = Math.Max(records.Count, Math.Min(count, sent));
            m.UpLossPct = Pct(sent - count, sent);
            m.DownLossPct = Pct(count - records.Count, count);
            m.UpJitterMs = Round(MeanAbsDiff(order.Select(i => (records[i].T2Us - records[i].T1Us) / 1000.0).ToList()), 2);
            m.DownJitterMs = Round(MeanAbsDiff(order.Select(i => (records[i].T4Us - records[i].T2Us) / 1000.0).ToList()), 2);
            m.JitterMs = m.UpJitterMs is null && m.DownJitterMs is null
                ? null
                : Math.Max(m.UpJitterMs ?? double.MinValue, m.DownJitterMs ?? double.MinValue);
            r = Math.Min(RFactor(oneWay, m.UpJitterMs ?? 0, m.UpLossPct.Value, codec, ptimeMs),
                RFactor(oneWay, m.DownJitterMs ?? 0, m.DownLossPct.Value, codec, ptimeMs));
        }
        else
        {
            // einfacher UDP-Echo-Dienst: nur Hin- und Rückweg zusammen
            m.Mode = "echo";
            m.JitterMs = Round(MeanAbsDiff(rtts), 2);
            r = RFactor(oneWay, m.JitterMs ?? 0, m.LossPct.Value, codec, ptimeMs);
        }

        m.RFactor = Math.Round(r, 1);
        m.Mos = Math.Round(Mos(r), 2);
    }
}
