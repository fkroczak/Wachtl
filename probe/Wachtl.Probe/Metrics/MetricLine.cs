using System.Globalization;

namespace Wachtl.Probe.Metrics;

/// <summary>
/// Erzeugt Zeilen im Prometheus-Textformat. Die Probe sendet nur das Label
/// <c>check_id</c>; alle weiteren Labels setzt der Server.
/// </summary>
public static class MetricLine
{
    public const string PingUp = "wachtl_ping_up";
    public const string PingRtt = "wachtl_ping_rtt_ms";
    public const string PingTtl = "wachtl_ping_ttl";
    public const string PingJitter = "wachtl_ping_jitter_ms";
    public const string HopUp = "wachtl_hop_up";
    public const string HopRtt = "wachtl_hop_rtt_ms";
    public const string HopJitter = "wachtl_hop_jitter_ms";

    public static string Format(string name, long checkId, double value, long timestampMs) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{name}{{check_id=\"{checkId}\"}} {value.ToString("0.###", CultureInfo.InvariantCulture)} {timestampMs}");

    /// <summary>Hop-Messwert eines Pfad-Checks (zusätzlich Hop-Nummer und Router-Adresse).</summary>
    public static string FormatHop(string name, long checkId, int hop, string hopIp, double value, long timestampMs) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{name}{{check_id=\"{checkId}\",hop=\"{hop}\",hop_ip=\"{hopIp}\"}} {value.ToString("0.###", CultureInfo.InvariantCulture)} {timestampMs}");
}
