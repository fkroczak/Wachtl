using System.Net;
using Wachtl.Probe.Config;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tray;

/// <summary>
/// Gemeinsamer Zustand zwischen <see cref="ProbeWorker"/> und der Tray-Schnittstelle:
/// Registrierung, Standort, Server, letzter erfolgreicher Kontakt und der API-Client zum Senden von Meldungen.
/// </summary>
public sealed class ProbeStatus
{
    public static readonly TimeSpan ConnectedWindow = TimeSpan.FromMinutes(2);

    private volatile ProbeState? _state;
    private volatile ApiClient? _api;
    private long _lastContact;

    public void Attach(ProbeState state, ApiClient? api)
    {
        _state = state;
        _api = api;
    }

    /// <summary>Vor dem Freigeben des API-Clients aufrufen, damit keine Meldung mehr darüber läuft.</summary>
    public void Detach() => _api = null;

    public void MarkContact(DateTimeOffset? at = null) =>
        Interlocked.Exchange(ref _lastContact, (at ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds());

    public bool Enrolled => _state is not null;

    public bool CanSend => _api is not null;

    public string SiteName => _state?.SiteName ?? string.Empty;

    public string ServerUrl => _state?.ServerUrl.TrimEnd('/') ?? string.Empty;

    /// <summary>Unix-Sekunden, 0 = noch nie.</summary>
    public long LastContact => Interlocked.Read(ref _lastContact);

    public bool IsConnected(DateTimeOffset now) =>
        LastContact > 0 && now.ToUnixTimeSeconds() - LastContact < (long)ConnectedWindow.TotalSeconds;

    /// <summary>POST api/probe/v1/report über den ApiClient des Workers (Token, Pinning, Proxy).</summary>
    public async Task<ReportSendResult> SendReportAsync(ServerReport report, CancellationToken ct)
    {
        var api = _api;
        if (api is null)
        {
            return new ReportSendResult(ReportSendOutcome.Retry, "Dienst noch nicht mit dem Server verbunden");
        }

        try
        {
            await api.PostResultAsync("report", report, ct).ConfigureAwait(false);
            MarkContact();
            return new ReportSendResult(ReportSendOutcome.Delivered);
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.BadRequest)
        {
            return new ReportSendResult(ReportSendOutcome.Rejected, ex.Detail);
        }
        catch (Exception ex)
        {
            // Netzfehler, Zeitüberschreitung, 401/403/404/5xx, ApiClient schon freigegeben: puffern statt verlieren.
            return new ReportSendResult(ReportSendOutcome.Retry, ex.Message);
        }
    }
}
