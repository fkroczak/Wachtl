using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tray;

/// <summary>Antwort von GET /tray/v1/status (snake_case über ApiClient.JsonOptions).</summary>
public sealed class TrayStatusResponse
{
    public string Role { get; init; } = "probe";
    public string Name { get; init; } = string.Empty;
    public string Site { get; init; } = string.Empty;
    public string ServerUrl { get; init; } = string.Empty;
    public string DashboardUrl { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public bool Enrolled { get; init; }
    public bool Connected { get; init; }
    public long LastContact { get; init; }
    public int PendingReports { get; init; }
}

/// <summary>
/// Schutzregeln und Routen der lokalen Tray-Schnittstelle laut docs/STOERUNGSMELDUNGEN.md –
/// ohne Sockets, damit alles direkt testbar ist.
/// </summary>
public sealed class TrayApi
{
    public const string StatusPath = "/tray/v1/status";
    public const string ReportPath = "/tray/v1/report";
    public const int ReportsPerHour = 30;

    /// <summary>So lange wartet der Tray auf die sofortige Zustellung, danach wird gepuffert.</summary>
    public static readonly TimeSpan ImmediateSendTimeout = TimeSpan.FromSeconds(10);

    private readonly int _port;
    private readonly ProbeStatus _status;
    private readonly PendingReports _pending;
    private readonly IReportSender _sender;
    private readonly RateLimiter _rate;
    private readonly Func<DateTimeOffset> _clock;
    private readonly string _hostname;
    private readonly ILogger? _logger;

    public TrayApi(int port, ProbeStatus status, PendingReports pending, IReportSender sender,
        RateLimiter? rate = null, Func<DateTimeOffset>? clock = null, string? hostname = null, ILogger? logger = null)
    {
        _port = port;
        _status = status;
        _pending = pending;
        _sender = sender;
        _rate = rate ?? new RateLimiter(ReportsPerHour, TimeSpan.FromHours(1));
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _hostname = hostname ?? Environment.MachineName;
        _logger = logger;
    }

    /// <summary>Kopfzeilen-Schutz gegen Browser (CSRF, DNS-Rebinding). Null = erlaubt.</summary>
    public string? CheckAccess(TrayHttpRequest request)
    {
        if (request.Header("X-Wachtl-Tray") != "1")
        {
            return "Kopfzeile X-Wachtl-Tray fehlt.";
        }

        if (!IsAllowedHost(request.Header("Host"), _port))
        {
            return "Unzulässiger Host.";
        }

        if (request.Method == "POST" && !IsJson(request.Header("Content-Type")))
        {
            return "Content-Type muss application/json sein.";
        }

        return null;
    }

    public static bool IsAllowedHost(string? host, int port) =>
        host is not null
        && (string.Equals(host, $"127.0.0.1:{port}", StringComparison.OrdinalIgnoreCase)
            || string.Equals(host, $"localhost:{port}", StringComparison.OrdinalIgnoreCase));

    public static bool IsJson(string? contentType)
    {
        if (contentType is null)
        {
            return false;
        }

        var media = contentType.Split(';')[0].Trim();
        return string.Equals(media, "application/json", StringComparison.OrdinalIgnoreCase);
    }

    public async Task<TrayHttpResponse> HandleAsync(TrayHttpRequest request, CancellationToken ct)
    {
        var denied = CheckAccess(request);
        if (denied is not null)
        {
            return TrayHttpResponse.Error(403, "Zugriff verweigert: " + denied);
        }

        switch (request.Path)
        {
            case StatusPath when request.Method == "GET":
                return Status();
            case ReportPath when request.Method == "POST":
                return await ReportAsync(request.Body, ct).ConfigureAwait(false);
            case StatusPath:
                return MethodNotAllowed("GET");
            case ReportPath:
                return MethodNotAllowed("POST");
            default:
                return TrayHttpResponse.Error(404, "Unbekannte Adresse.");
        }
    }

    private static TrayHttpResponse MethodNotAllowed(string allow)
    {
        var response = TrayHttpResponse.Error(405, "Methode nicht erlaubt.");
        response.Headers["Allow"] = allow;
        return response;
    }

    public TrayStatusResponse BuildStatus()
    {
        var now = _clock();
        return new TrayStatusResponse
        {
            Role = "probe",
            Name = _hostname,
            Site = _status.SiteName,
            ServerUrl = _status.ServerUrl,
            DashboardUrl = string.Empty,
            Version = AppInfo.Version,
            Enrolled = _status.Enrolled,
            Connected = _status.IsConnected(now),
            LastContact = _status.LastContact?.ToUnixTimeSeconds() ?? 0,
            PendingReports = _pending.Count,
        };
    }

    private TrayHttpResponse Status() =>
        new(200, JsonSerializer.Serialize(BuildStatus(), ApiClient.JsonOptions));

    private async Task<TrayHttpResponse> ReportAsync(string body, CancellationToken ct)
    {
        if (!_status.Enrolled)
        {
            return TrayHttpResponse.Error(409, "Dieser PC ist noch nicht beim Wachtl-Server registriert.");
        }

        var report = TrayReportParser.Parse(body, _clock(), _hostname, out var error);
        if (report is null)
        {
            return TrayHttpResponse.Error(400, error ?? "Ungültige Meldung.");
        }

        if (!_rate.TryAcquire(_clock()))
        {
            return TrayHttpResponse.Error(429, "Zu viele Meldungen. Bitte später erneut versuchen oder die IT direkt anrufen.");
        }

        ReportSendResult result;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            timeout.CancelAfter(ImmediateSendTimeout);
            try
            {
                result = await _sender.SendAsync(report, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                result = new ReportSendResult(ReportSendOutcome.Retry, ex.Message);
            }
        }

        switch (result.Outcome)
        {
            case ReportSendOutcome.Delivered:
                _logger?.LogInformation("Störungsmeldung {Id} ({Category}) an den Server übermittelt", report.ReportId, report.Category);
                return Accepted(true);
            case ReportSendOutcome.Rejected:
                _logger?.LogWarning("Server lehnt Störungsmeldung ab: {Error}", result.Error);
                return TrayHttpResponse.Error(400, "Der Server hat die Meldung abgelehnt: " + (result.Error ?? "ungültige Werte"));
            default:
                _pending.Add(report);
                _logger?.LogInformation("Störungsmeldung {Id} ({Category}) gespeichert, wird nachgeliefert ({Reason})",
                    report.ReportId, report.Category, result.Error);
                return Accepted(false);
        }
    }

    private static TrayHttpResponse Accepted(bool delivered) =>
        new(202, delivered ? "{\"ok\":true,\"delivered\":true}" : "{\"ok\":true,\"delivered\":false}");
}
