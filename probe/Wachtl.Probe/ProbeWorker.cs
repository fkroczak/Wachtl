using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Bandwidth;
using Wachtl.Probe.Buffer;
using Wachtl.Probe.Checks;
using Wachtl.Probe.Config;
using Wachtl.Probe.Diagnostics;
using Wachtl.Probe.Transport;
using Wachtl.Probe.Tray;

namespace Wachtl.Probe;

/// <summary>
/// Hauptschleifen des Dienstes: Konfiguration holen, Checks steuern, Puffer hochladen, Heartbeat senden.
/// Jede Schleife fängt ihre Fehler selbst ab – ein Serverausfall beendet den Dienst nie.
/// </summary>
public sealed class ProbeWorker : BackgroundService
{
    private const int BatchSize = 5000;
    private static readonly TimeSpan MaxBufferAge = TimeSpan.FromDays(7);
    private const long MaxBufferRows = 2_000_000;

    private readonly ILogger<ProbeWorker> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly GatewayResolver _gateway;
    private readonly ProbeStatus _status;
    private readonly ClientDiagnostics _diagnostics;
    private readonly Dictionary<string, IAsyncDisposable> _runners = new();
    private IperfServerHost? _iperfServer;
    private readonly SemaphoreSlim _configChanged = new(0, 1);
    private readonly object _runnerLock = new();
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow;

    private ProbeConfig? _config;
    private ProbeState? _state;
    private ApiClient? _api;
    private SampleBuffer? _buffer;

    public ProbeWorker(ILogger<ProbeWorker> logger, ILoggerFactory loggerFactory, GatewayResolver gateway, ProbeStatus status,
        ClientDiagnostics diagnostics)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
        _gateway = gateway;
        _status = status;
        _diagnostics = diagnostics;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _logger.LogInformation("Wachtl-Probe {Version} startet, Daten in {Dir}", AppInfo.Version, StateStore.DataDir);
        var wait = TimeSpan.FromSeconds(20);
        while ((_state = StateStore.Load()) is null)
        {
            if (StateStore.LoadPending() is { } pending)
            {
                // beim Setup war der Server nicht erreichbar – Registrierung jetzt nachholen
                if (await TryPendingEnrollmentAsync(pending, ct).ConfigureAwait(false))
                {
                    continue;
                }
            }
            else
            {
                _logger.LogError("Probe ist nicht registriert ({Path} fehlt). Bitte das Wachtl-Setup ausführen.", StateStore.StatePath);
            }

            await Task.Delay(wait, ct).ConfigureAwait(false);
            wait = TimeSpan.FromSeconds(Math.Min(600, wait.TotalSeconds * 2));
        }

        string token;
        try
        {
            token = StateStore.UnprotectToken(_state.ProtectedToken);
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Probe-Token kann nicht entschlüsselt werden. Probe neu registrieren.");
            throw;
        }

        _api = new ApiClient(_state.AllServers(), _state.SpkiPin, _state.Proxy, token);
        _api.ServerChanged += uri =>
        {
            _logger.LogWarning("Server über {Uri} erreichbar – andere Adressen antworten nicht", uri);
            SaveServers(uri.ToString(), null);
        };
        _status.Attach(_state, _api);
        _buffer = new SampleBuffer(StateStore.BufferPath, _loggerFactory.CreateLogger<SampleBuffer>());
        _logger.LogInformation("Probe {Id} am Standort {Site}, Server {Server}, Puffer {Count} Werte",
            _state.ProbeId, _state.SiteName, _state.ServerUrl, _buffer.Count());

        if (StateStore.LoadCachedConfig() is { } cached)
        {
            _logger.LogInformation("Starte mit zwischengespeicherter Konfiguration ({Count} Checks)", cached.Checks.Count);
            ApplyConfig(cached);
        }

        try
        {
            await Task.WhenAll(
                _buffer.RunWriterAsync(ct),
                ConfigLoopAsync(ct),
                UploadLoopAsync(ct),
                HeartbeatLoopAsync(ct),
                _diagnostics.RunAsync(ct)).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        finally
        {
            await StopRunnersAsync().ConfigureAwait(false);
            _status.Detach();
            _api.Dispose();
            _logger.LogInformation("Wachtl-Probe beendet");
        }
    }

    // -- Konfiguration -------------------------------------------------------
    private async Task ConfigLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var fresh = await _api!.GetConfigAsync(_config?.Etag, ct).ConfigureAwait(false);
                _status.MarkContact();
                if (fresh is not null)
                {
                    ApplyConfig(fresh);
                    StateStore.SaveCachedConfig(fresh);
                }
            }
            catch (ApiException ex) when (ex.IsAuthError)
            {
                _logger.LogError("Server lehnt das Probe-Token ab ({Message}). Probe deaktiviert oder neu registrieren.", ex.Message);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.LogWarning("Konfiguration nicht abrufbar: {Message}", ex.Message);
            }

            var wait = TimeSpan.FromSeconds(_config is null ? 15 : Math.Max(30, _config.ConfigPollS));
            await _configChanged.WaitAsync(wait, ct).ConfigureAwait(false);
        }
    }

    private static readonly string[] SupportedTypes = { "ping", "path", "iperf", "speedtest" };

    private async Task<bool> TryPendingEnrollmentAsync(PendingEnrollment pending, CancellationToken ct)
    {
        try
        {
            var servers = pending.ServerUrls.Select(u => new Uri(u)).ToList();
            var token = StateStore.UnprotectToken(pending.ProtectedEnrollmentToken);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(30 + 15 * servers.Count));
            var (state, response) = await Enrollment.EnrollAsync(servers, pending.SpkiPin, token, pending.Proxy,
                pending.Hostname, cts.Token).ConfigureAwait(false);
            _logger.LogInformation("Registrierung nachgeholt: Probe {Id} ({Host}) am Standort {Site} über {Server}",
                response.ProbeId, pending.Hostname, response.SiteName, state.ServerUrl);
            return true;
        }
        catch (ApiException ex) when ((int)ex.Status is >= 400 and < 500)
        {
            _logger.LogError("Server lehnt die Registrierung ab: {Message} – bitte ein neues Setup aus dem Web-UI verwenden.", ex.Message);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            _logger.LogWarning("Server noch nicht erreichbar, Registrierung wird weiter versucht: {Message}",
                ex.InnerException?.Message ?? ex.Message);
        }

        return false;
    }

    /// <summary>Bevorzugte Adresse und/oder Adressliste dauerhaft speichern.</summary>
    private void SaveServers(string? preferred, List<string>? all)
    {
        lock (_runnerLock)
        {
            if (_state is null)
            {
                return;
            }

            if (preferred is not null)
            {
                _state.ServerUrl = preferred;
            }

            if (all is not null)
            {
                _state.ServerUrls = all;
            }

            try
            {
                StateStore.Save(_state);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogWarning("Server-Adressen nicht gespeichert: {Message}", ex.Message);
            }
        }
    }

    private void ApplyConfig(ProbeConfig config)
    {
        if (config.ServerUrls.Count > 0 && _state is not null &&
            !config.ServerUrls.SequenceEqual(_state.ServerUrls, StringComparer.OrdinalIgnoreCase))
        {
            // Server hat (weitere) Adressen gemeldet, z. B. eine neue IP: für Ausweichversuche merken
            var urls = config.ServerUrls.Where(u => Uri.TryCreate(u, UriKind.Absolute, out var x) && x.Scheme == Uri.UriSchemeHttps).ToList();
            if (urls.Count > 0)
            {
                _logger.LogInformation("Server-Adressen: {Urls}", string.Join(", ", urls));
                SaveServers(null, urls);
                _api?.UpdateServers(urls.Select(u => new Uri(u)));
            }
        }

        var wanted = config.Checks
            .Where(c => SupportedTypes.Contains(c.Type))
            .GroupBy(c => c.Key)
            .ToDictionary(g => g.Key, g => g.First());
        var unknown = config.Checks.Where(c => !SupportedTypes.Contains(c.Type)).Select(c => c.Type).Distinct().ToList();
        if (unknown.Count > 0)
        {
            _logger.LogWarning("Check-Typen {Types} werden von dieser Probe-Version nicht unterstützt – Probe aktualisieren", string.Join(", ", unknown));
        }

        lock (_runnerLock)
        {
            foreach (var key in _runners.Keys.Where(k => !wanted.ContainsKey(k)).ToList())
            {
                var runner = _runners[key];
                _runners.Remove(key);
                _ = runner.DisposeAsync().AsTask();
            }

            foreach (var (key, check) in wanted)
            {
                if (!_runners.ContainsKey(key))
                {
                    _runners[key] = CreateRunner(check);
                }
            }

            var iperf = config.IperfServer;
            if (_iperfServer is not null && (!iperf.Enabled || _iperfServer.Port != iperf.Port))
            {
                _ = _iperfServer.DisposeAsync().AsTask();
                _iperfServer = null;
            }

            if (iperf.Enabled && _iperfServer is null)
            {
                _iperfServer = new IperfServerHost(iperf.Port, _loggerFactory.CreateLogger<IperfServerHost>());
            }

            _config = config;
        }

        _diagnostics.Configure(config.ClientFindings);

        _logger.LogInformation("Konfiguration {Etag} aktiv: {Count} Checks ({Types}), iperf3-Gegenstelle {Iperf}", config.Etag,
            wanted.Count, string.Join(", ", wanted.Values.GroupBy(c => c.Type).Select(g => $"{g.Count()} {g.Key}")),
            config.IperfServer.Enabled ? $"an Port {config.IperfServer.Port}" : "aus");
    }

    private IAsyncDisposable CreateRunner(CheckConfig check) => check.Type switch
    {
        "path" => new PathRunner(check, _buffer!, _gateway,
            (result, token) => _api!.PostResultAsync("results/path", result, token),
            _loggerFactory.CreateLogger<PathRunner>()),
        "iperf" or "speedtest" => new BandwidthRunner(check, _state?.Proxy,
            (result, token) => _api!.PostResultAsync("results/bandwidth", result, token),
            _loggerFactory.CreateLogger<BandwidthRunner>()),
        _ => new PingRunner(check, _buffer!, _gateway, _loggerFactory.CreateLogger<PingRunner>()),
    };

    private void HandleCommands(IEnumerable<ProbeCommand> commands)
    {
        foreach (var command in commands)
        {
            object? runner;
            lock (_runnerLock)
            {
                runner = _runners.Values.FirstOrDefault(r => r switch
                {
                    PathRunner p => p.Check.Id == command.CheckId,
                    BandwidthRunner b => b.Check.Id == command.CheckId,
                    _ => false,
                });
            }

            switch (command.Type, runner)
            {
                case ("run_check", BandwidthRunner b):
                    _logger.LogInformation("Auftrag vom Server: Check {Id} jetzt messen", command.CheckId);
                    b.RunNow();
                    break;
                case ("retrace", PathRunner p):
                    _logger.LogInformation("Auftrag vom Server: Pfad von Check {Id} neu ermitteln", command.CheckId);
                    p.RequestRetrace();
                    break;
                default:
                    _logger.LogWarning("Auftrag {Type} für Check {Id} kann nicht ausgeführt werden (Check nicht aktiv?)",
                        command.Type, command.CheckId);
                    break;
            }
        }
    }

    private async Task StopRunnersAsync()
    {
        List<IAsyncDisposable> runners;
        lock (_runnerLock)
        {
            runners = _runners.Values.ToList();
            _runners.Clear();
            if (_iperfServer is not null)
            {
                runners.Add(_iperfServer);
                _iperfServer = null;
            }
        }

        foreach (var runner in runners)
        {
            await runner.DisposeAsync().ConfigureAwait(false);
        }
    }

    // -- Upload --------------------------------------------------------------
    private async Task UploadLoopAsync(CancellationToken ct)
    {
        var backoff = TimeSpan.Zero;
        var nextPrune = DateTimeOffset.UtcNow;
        while (!ct.IsCancellationRequested)
        {
            var interval = TimeSpan.FromSeconds(Math.Max(2, _config?.UploadIntervalS ?? 10));
            await Task.Delay(interval + backoff, ct).ConfigureAwait(false);
            try
            {
                var delivered = await UploadPendingAsync(ct).ConfigureAwait(false);
                backoff = delivered ? TimeSpan.Zero : NextBackoff(backoff);
            }
            catch (HttpRequestException ex)
            {
                backoff = NextBackoff(backoff);
                _logger.LogWarning("Server nicht erreichbar, Werte bleiben im Puffer (nächster Versuch in {Seconds} s): {Message}",
                    (interval + backoff).TotalSeconds, ex.InnerException?.Message ?? ex.Message);
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested)
            {
                backoff = NextBackoff(backoff);
                _logger.LogWarning("Zeitüberschreitung beim Hochladen, Werte bleiben im Puffer");
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                backoff = NextBackoff(backoff);
                _logger.LogError(ex, "Fehler beim Hochladen");
            }

            if (DateTimeOffset.UtcNow >= nextPrune)
            {
                _buffer!.Prune(MaxBufferAge, MaxBufferRows);
                nextPrune = DateTimeOffset.UtcNow.AddMinutes(10);
            }
        }
    }

    /// <summary>Lädt den Puffer in Batches hoch. Gibt false zurück, wenn der Server nicht annimmt.</summary>
    private async Task<bool> UploadPendingAsync(CancellationToken ct)
    {
        while (true)
        {
            var batch = _buffer!.Peek(BatchSize);
            if (batch.Count == 0)
            {
                return true;
            }

            var batchId = $"{batch[0].Id}-{batch[^1].Id}";
            var outcome = await _api!.IngestAsync(batchId, batch.Select(b => b.Line), ct).ConfigureAwait(false);
            switch (outcome)
            {
                case IngestOutcome.Delivered:
                    _status.MarkContact();
                    _buffer.DeleteThrough(batch[0].Id, batch[^1].Id);
                    break;
                case IngestOutcome.Unauthorized:
                    _logger.LogError("Server lehnt Messwerte ab (Token ungültig oder Probe deaktiviert)");
                    return false;
                default:
                    _logger.LogWarning("Server nimmt gerade keine Messwerte an, neuer Versuch folgt");
                    return false;
            }

            if (batch.Count < BatchSize)
            {
                return true;
            }
        }
    }

    private static TimeSpan NextBackoff(TimeSpan current) =>
        TimeSpan.FromSeconds(Math.Min(300, Math.Max(5, current.TotalSeconds * 2)));

    // -- Heartbeat -----------------------------------------------------------
    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var response = await _api!.HeartbeatAsync(new HeartbeatRequest
                {
                    Version = AppInfo.Version,
                    Os = AppInfo.OsDescription,
                    Hostname = Environment.MachineName,
                    BufferItems = _buffer!.Count(),
                    UptimeS = (long)(DateTimeOffset.UtcNow - _started).TotalSeconds,
                    Addresses = GatewayResolver.LocalAddresses(),
                }, ct).ConfigureAwait(false);
                _status.MarkContact();
                _diagnostics.RequestFlush();

                if (response.Commands.Count > 0)
                {
                    HandleCommands(response.Commands);
                }

                if (response.ConfigEtag != _config?.Etag && _configChanged.CurrentCount == 0)
                {
                    _configChanged.Release();
                }
            }
            catch (ApiException ex) when (ex.IsAuthError)
            {
                _logger.LogError("Heartbeat abgelehnt: {Message}", ex.Message);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.LogDebug("Heartbeat fehlgeschlagen: {Message}", ex.Message);
            }

            await Task.Delay(TimeSpan.FromSeconds(Math.Max(10, _config?.HeartbeatIntervalS ?? 30)), ct).ConfigureAwait(false);
        }
    }
}
