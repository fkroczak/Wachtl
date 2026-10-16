using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Buffer;
using Wachtl.Probe.Checks;
using Wachtl.Probe.Config;
using Wachtl.Probe.Transport;

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
    private readonly Dictionary<string, PingRunner> _runners = new();
    private readonly SemaphoreSlim _configChanged = new(0, 1);
    private readonly object _runnerLock = new();
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow;

    private ProbeConfig? _config;
    private ProbeState? _state;
    private ApiClient? _api;
    private SampleBuffer? _buffer;

    public ProbeWorker(ILogger<ProbeWorker> logger, ILoggerFactory loggerFactory, GatewayResolver gateway)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
        _gateway = gateway;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _logger.LogInformation("Wachtl-Probe {Version} startet, Daten in {Dir}", AppInfo.Version, StateStore.DataDir);
        while ((_state = StateStore.Load()) is null)
        {
            _logger.LogError("Probe ist nicht registriert ({Path} fehlt). Bitte Install-Wachtl.ps1 ausführen.", StateStore.StatePath);
            await Task.Delay(TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
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

        _api = new ApiClient(new Uri(_state.ServerUrl), _state.SpkiPin, _state.Proxy, token);
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
                HeartbeatLoopAsync(ct)).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        finally
        {
            await StopRunnersAsync().ConfigureAwait(false);
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

    private void ApplyConfig(ProbeConfig config)
    {
        var wanted = config.Checks
            .Where(c => c.Type == "ping")
            .GroupBy(c => c.Key)
            .ToDictionary(g => g.Key, g => g.First());

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
                    _runners[key] = new PingRunner(check, _buffer!, _gateway, _loggerFactory.CreateLogger<PingRunner>());
                }
            }

            _config = config;
        }

        _logger.LogInformation("Konfiguration {Etag} aktiv: {Count} Ping-Checks", config.Etag, wanted.Count);
    }

    private async Task StopRunnersAsync()
    {
        List<PingRunner> runners;
        lock (_runnerLock)
        {
            runners = _runners.Values.ToList();
            _runners.Clear();
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
                }, ct).ConfigureAwait(false);

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
