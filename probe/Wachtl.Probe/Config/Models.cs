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

    /// <summary>Ändert sich einer dieser Werte, wird der Check neu gestartet.</summary>
    [JsonIgnore]
    public string Key => $"{Id}|{Type}|{Target}|{IntervalS}|{TimeoutMs}";
}

public sealed class ProbeConfig
{
    public long ProbeId { get; init; }
    public List<CheckConfig> Checks { get; init; } = new();
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
}

public sealed class HeartbeatResponse
{
    public string ConfigEtag { get; init; } = string.Empty;
    public long ServerTime { get; init; }
}

/// <summary>Dauerhafter Zustand der Probe nach dem Enrollment.</summary>
public sealed class ProbeState
{
    public string ServerUrl { get; set; } = string.Empty;
    public string SpkiPin { get; set; } = string.Empty;
    public long ProbeId { get; set; }
    public string ProtectedToken { get; set; } = string.Empty;
    public string? Proxy { get; set; }
    public string SiteName { get; set; } = string.Empty;
    public DateTimeOffset EnrolledAt { get; set; }
}
