using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Wachtl.Probe.Config;

public sealed class CheckConfig
{
    public long Id { get; init; }
    public string Type { get; init; } = "ping";
    public string Target { get; init; } = string.Empty;
    public string Role { get; init; } = "target";
    public int IntervalS { get; init; } = 1;
    public int TimeoutMs { get; init; } = 1000;
    public Dictionary<string, JsonElement> Params { get; init; } = new();
    public PeerConfig? Peer { get; init; }

    /// <summary>Ändert sich einer dieser Werte, wird der Check neu gestartet.</summary>
    [JsonIgnore]
    public string Key
    {
        get
        {
            var basic = $"{Id}|{Type}|{Target}|{IntervalS}|{TimeoutMs}";
            if (Params.Count == 0 && Peer is null)
            {
                return basic;
            }

            var extra = string.Join(";", Params.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => $"{p.Key}={p.Value.GetRawText()}"));
            return $"{basic}|{extra}|{Peer?.Host}:{Peer?.Port}:{Peer?.Error}";
        }
    }

    public int Int(string key, int fallback)
    {
        if (Params.TryGetValue(key, out var v))
        {
            if (v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d))
            {
                return (int)Math.Round(d);
            }

            if (v.ValueKind == JsonValueKind.String && int.TryParse(v.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var i))
            {
                return i;
            }
        }

        return fallback;
    }

    public double Double(string key, double fallback)
    {
        if (Params.TryGetValue(key, out var v))
        {
            if (v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d))
            {
                return d;
            }

            if (v.ValueKind == JsonValueKind.String && double.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var p))
            {
                return p;
            }
        }

        return fallback;
    }

    public bool Bool(string key, bool fallback) =>
        Params.TryGetValue(key, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? v.GetBoolean()
            : fallback;

    public string Str(string key, string fallback) =>
        Params.TryGetValue(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? fallback : fallback;
}

public sealed class PeerConfig
{
    public string? Host { get; init; }
    public int? Port { get; init; }
    public string? Error { get; init; }
}

public sealed class IperfServerConfig
{
    public bool Enabled { get; init; }
    public int Port { get; init; } = 5201;
}

/// <summary>RTP-Reflektor: Gegenstelle für Sprachtests anderer Probes (an, wenn die Probe Gegenstelle ist).</summary>
public sealed class RtpReflectorConfig
{
    public bool Enabled { get; init; }
    public int Port { get; init; } = 5004;
}

/// <summary>Client-Hinweise (Netzwerkkarte, Kabel, DHCP …): erkennen, an den Server senden, im Tray anzeigen.</summary>
public sealed class ClientFindingsConfig
{
    /// <summary>false: keine Erkennung, nichts wird gesendet.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>false: keine Sprechblasen im Tray (der Server erhält die Hinweise trotzdem).</summary>
    public bool Notify { get; init; } = true;

    /// <summary>Ausfälle, Paketverlust und Netzwerkwechsel, die die Probe an ihren Pings erkennt, im Tray zeigen.</summary>
    public bool Connectivity { get; init; } = true;
}

public sealed class ProbeConfig
{
    public long ProbeId { get; init; }
    public List<CheckConfig> Checks { get; init; } = new();
    public IperfServerConfig IperfServer { get; init; } = new();
    public RtpReflectorConfig RtpReflector { get; init; } = new();
    public ClientFindingsConfig ClientFindings { get; init; } = new();
    public List<string> ServerUrls { get; init; } = new();
    public int UploadIntervalS { get; init; } = 10;
    public int HeartbeatIntervalS { get; init; } = 30;
    public int ConfigPollS { get; init; } = 300;
    public string Etag { get; init; } = string.Empty;
}

public sealed class EnrollRequest
{
    public string EnrollmentToken { get; init; } = string.Empty;
    public string Hostname { get; init; } = string.Empty;
    public string Os { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
}

public sealed class EnrollResponse
{
    public long ProbeId { get; init; }
    public string Token { get; init; } = string.Empty;
    public string SiteName { get; init; } = string.Empty;
}

public sealed class HeartbeatRequest
{
    public string Version { get; init; } = string.Empty;
    public string Os { get; init; } = string.Empty;
    public string Hostname { get; init; } = string.Empty;
    public long BufferItems { get; init; }
    public long UptimeS { get; init; }
    public List<string> Addresses { get; init; } = new();
}

public sealed class HeartbeatResponse
{
    public string ConfigEtag { get; init; } = string.Empty;
    public long ServerTime { get; init; }
    public List<ProbeCommand> Commands { get; init; } = new();

    /// <summary>Wartende Einzeltests aus dem Web-UI (Werkzeuge) – dann sofort GET tools/next.</summary>
    public int ToolsPending { get; init; }
}

public sealed class ProbeCommand
{
    public long Id { get; init; }
    public string Type { get; init; } = string.Empty;
    public long? CheckId { get; init; }
}

public sealed class PathHop
{
    public int Hop { get; init; }
    public string? Ip { get; init; }
    public double? RttMs { get; init; }
}

public sealed class PathResult
{
    public long CheckId { get; init; }
    public long Ts { get; init; }
    public string Reason { get; init; } = "schedule";
    public bool Reached { get; init; }
    public List<PathHop> Hops { get; init; } = new();
}

public sealed class BandwidthMeasurement
{
    public string Direction { get; init; } = "down";
    public double? Mbps { get; set; }
    public double? JitterMs { get; set; }
    public double? LossPct { get; set; }
    public long? Retransmits { get; set; }
    public double? LatencyMs { get; set; }
    public double? DurationS { get; set; }
    public string Protocol { get; init; } = "tcp";
    public string? Peer { get; init; }
    public string? Error { get; set; }
}

public sealed class BandwidthResult
{
    public long CheckId { get; init; }
    public long Ts { get; init; }
    public string Trigger { get; init; } = "schedule";
    public List<BandwidthMeasurement> Results { get; init; } = new();
}

/// <summary>Dauerhafter Zustand der Probe nach dem Enrollment.</summary>
public sealed class ProbeState
{
    /// <summary>Bevorzugte Adresse (die zuletzt funktionierende).</summary>
    public string ServerUrl { get; set; } = string.Empty;

    /// <summary>Alle bekannten Adressen des Servers (Namen und IPs), der Reihe nach versucht.</summary>
    public List<string> ServerUrls { get; set; } = new();

    public string SpkiPin { get; set; } = string.Empty;
    public long ProbeId { get; set; }
    public string ProtectedToken { get; set; } = string.Empty;
    public string? Proxy { get; set; }
    public string SiteName { get; set; } = string.Empty;
    public DateTimeOffset EnrolledAt { get; set; }

    /// <summary>Adressen für den Client: bevorzugte zuerst, dann die übrigen.</summary>
    public IEnumerable<Uri> AllServers()
    {
        var all = new List<string>();
        if (!string.IsNullOrWhiteSpace(ServerUrl))
        {
            all.Add(ServerUrl);
        }

        all.AddRange(ServerUrls);
        foreach (var url in all.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps)
            {
                yield return uri;
            }
        }
    }
}

/// <summary>
/// Registrierung, die nachgeholt wird: Beim Setup war der Server nicht erreichbar.
/// Der Dienst versucht es im Hintergrund weiter, bis es klappt.
/// </summary>
public sealed class PendingEnrollment
{
    public List<string> ServerUrls { get; set; } = new();
    public string SpkiPin { get; set; } = string.Empty;
    public string ProtectedEnrollmentToken { get; set; } = string.Empty;
    public string? Proxy { get; set; }
    public string Hostname { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public string? LastError { get; set; }
}
