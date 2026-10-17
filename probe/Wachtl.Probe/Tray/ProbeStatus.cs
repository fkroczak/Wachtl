using Wachtl.Probe.Config;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tray;

/// <summary>
/// Gemeinsamer Zustand zwischen <see cref="ProbeWorker"/> und der Tray-Schnittstelle:
/// Registrierung, Standort, Server und letzter erfolgreicher Kontakt zum Server.
/// </summary>
public sealed class ProbeStatus
{
    /// <summary>„verbunden“, wenn der letzte Kontakt höchstens so lange her ist.</summary>
    public static readonly TimeSpan ConnectedWindow = TimeSpan.FromMinutes(2);

    private readonly object _lock = new();
    private ProbeState? _state;
    private ApiClient? _api;
    private DateTimeOffset? _lastContact;

    /// <summary>Vom Worker gesetzt, sobald die Probe registriert ist und der API-Client steht.</summary>
    public void Attach(ProbeState state, ApiClient? api)
    {
        lock (_lock)
        {
            _state = state;
            _api = api;
        }
    }

    /// <summary>Vom Worker beim Beenden aufgerufen, bevor der API-Client freigegeben wird.</summary>
    public void Detach()
    {
        lock (_lock)
        {
            _api = null;
        }
    }

    /// <summary>Erfolgreiche Antwort vom Server (Heartbeat, Konfiguration, Messwerte, Meldung).</summary>
    public void MarkContact(DateTimeOffset? at = null)
    {
        lock (_lock)
        {
            _lastContact = at ?? DateTimeOffset.UtcNow;
        }
    }

    public ApiClient? Api
    {
        get
        {
            lock (_lock)
            {
                return _api;
            }
        }
    }

    public bool Enrolled
    {
        get
        {
            lock (_lock)
            {
                return _state is not null;
            }
        }
    }

    public string SiteName
    {
        get
        {
            lock (_lock)
            {
                return _state?.SiteName ?? string.Empty;
            }
        }
    }

    public string ServerUrl
    {
        get
        {
            lock (_lock)
            {
                return _state?.ServerUrl.TrimEnd('/') ?? string.Empty;
            }
        }
    }

    public DateTimeOffset? LastContact
    {
        get
        {
            lock (_lock)
            {
                return _lastContact;
            }
        }
    }

    public bool IsConnected(DateTimeOffset now) =>
        LastContact is { } last && now - last < ConnectedWindow;
}
