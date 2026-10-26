using System.Text.Json.Serialization;

namespace Wachtl.Probe.Diagnostics;

public enum FindingSeverity
{
    Info = 0,
    Warning = 1,
    Critical = 2,
}

/// <summary>Arten der Client-Hinweise (Wert von <c>kind</c>).</summary>
public static class FindingKinds
{
    public const string CableUnplugged = "cable_unplugged";
    public const string WifiDisconnected = "wifi_disconnected";
    public const string LinkSpeedChanged = "link_speed_changed";
    public const string LinkSpeedLow = "link_speed_low";
    public const string LinkFlapping = "link_flapping";
    public const string DriverError = "driver_error";
    public const string NicReset = "nic_reset";
    public const string Apipa = "apipa";
    public const string NoGateway = "no_gateway";
    public const string NicErrors = "nic_errors";
    public const string AdapterDisabled = "adapter_disabled";
    public const string AdapterRemoved = "adapter_removed";

    public static readonly IReadOnlyList<string> All = new[]
    {
        CableUnplugged, WifiDisconnected, LinkSpeedChanged, LinkSpeedLow, LinkFlapping, DriverError, NicReset, Apipa,
        NoGateway, NicErrors, AdapterDisabled, AdapterRemoved,
    };
}

/// <summary>
/// Ein Client-Hinweis, wie er an POST /api/probe/v1/findings geht (snake_case über ApiClient.JsonOptions).
/// Jede Zustandsänderung erzeugt ein neues Objekt mit derselben <see cref="FindingId"/>; der Server speichert per Upsert.
/// </summary>
public sealed class ClientFinding
{
    public const int MaxTitle = 120;
    public const int MaxText = 500;
    public const int MaxBalloon = 255;
    public const int MaxDetails = 20;

    public string FindingId { get; init; } = string.Empty;
    public string Kind { get; init; } = string.Empty;

    /// <summary>info | warning | critical</summary>
    public string Severity { get; init; } = "warning";

    /// <summary>active | resolved</summary>
    public string State { get; init; } = "active";

    public string Adapter { get; init; } = string.Empty;
    public string AdapterDescription { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public string Solution { get; init; } = string.Empty;

    /// <summary>Kurzfassung für die Sprechblase; nur lokal für das Tray-Symbol, geht nicht an den Server.</summary>
    [JsonIgnore]
    public string Balloon { get; init; } = string.Empty;
    public Dictionary<string, string> Details { get; init; } = new();

    /// <summary>Unix-Sekunden.</summary>
    public long DetectedAt { get; init; }

    /// <summary>Unix-Sekunden, null solange aktiv.</summary>
    public long? ResolvedAt { get; init; }

    [JsonIgnore]
    public bool IsActive => State == "active";

    public static string SeverityName(FindingSeverity severity) => severity switch
    {
        FindingSeverity.Critical => "critical",
        FindingSeverity.Warning => "warning",
        _ => "info",
    };

    public static FindingSeverity ParseSeverity(string? value) => value switch
    {
        "critical" => FindingSeverity.Critical,
        "warning" => FindingSeverity.Warning,
        _ => FindingSeverity.Info,
    };

    public static string Clamp(string? text, int max)
    {
        text = (text ?? string.Empty).Trim();
        return text.Length <= max ? text : text[..(max - 1)].TrimEnd() + "…";
    }

    public static Dictionary<string, string> ClampDetails(IEnumerable<KeyValuePair<string, string>>? details)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (details is null)
        {
            return result;
        }

        foreach (var (key, value) in details)
        {
            if (result.Count >= MaxDetails)
            {
                break;
            }

            result[Clamp(key, 64)] = Clamp(value, 200);
        }

        return result;
    }
}

/// <summary>Body von POST /api/probe/v1/findings.</summary>
public sealed class FindingsUpload
{
    public List<ClientFinding> Findings { get; init; } = new();
}
