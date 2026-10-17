using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Config;
using Wachtl.Probe.Tray;

namespace Wachtl.Probe.Diagnostics;

/// <summary>
/// Client-Hinweise: prüft alle 5 s und sofort nach Netzwerkereignissen die Netzwerkkarten dieses PCs,
/// stellt neue und erledigte Hinweise dem Tray bereit (<see cref="Feed"/>) und liefert sie an den Server –
/// gepuffert in findings-pending.json, solange der Server nicht erreichbar ist (gezogenes Kabel).
/// Wird von <see cref="ProbeWorker"/> gestartet und über client_findings in der Konfiguration gesteuert.
/// </summary>
public sealed class ClientDiagnostics
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(30);

    /// <summary>Netzwerkereignisse kommen gebündelt; kurz warten, bis Windows den neuen Zustand meldet (auch „deaktiviert“).</summary>
    private static readonly TimeSpan EventSettle = TimeSpan.FromSeconds(1.5);

    private readonly ILogger _logger;
    private readonly ProbeStatus _status;
    private readonly FindingEvaluator _evaluator = new();
    private readonly AdapterReader _reader;
    private readonly SemaphoreSlim _wake = new(0, 1);
    private readonly SemaphoreSlim _flushSignal = new(0, 1);
    private volatile bool _enabled = true;
    private volatile bool _resetRequested;
    private bool _readFailedLogged;
    private bool _flushFailedLogged;

    public ClientDiagnostics(ProbeStatus status, ILogger<ClientDiagnostics> logger)
        : this(status, logger, new PendingFindings(Path.Combine(StateStore.DataDir, "findings-pending.json"), logger), new FindingFeed())
    {
    }

    internal ClientDiagnostics(ProbeStatus status, ILogger logger, PendingFindings pending, FindingFeed feed)
    {
        _status = status;
        _logger = logger;
        Pending = pending;
        Feed = feed;
        _reader = new AdapterReader(logger);
    }

    /// <summary>Für GET /tray/v1/findings.</summary>
    public FindingFeed Feed { get; }

    public PendingFindings Pending { get; }

    public bool Enabled => _enabled;

    /// <summary>Einstellungen aus der Server-Konfiguration übernehmen (ältere Server: beide an).</summary>
    public void Configure(ClientFindingsConfig? config)
    {
        config ??= new ClientFindingsConfig();
        if (_enabled != config.Enabled)
        {
            _logger.LogInformation("Client-Hinweise (Netzwerkkarte, Kabel, DHCP) {State}", config.Enabled ? "eingeschaltet" : "ausgeschaltet");
            if (!config.Enabled)
            {
                _resetRequested = true;
                Feed.Clear();
            }
        }

        _enabled = config.Enabled;
        Feed.Notify = config.Enabled && config.Notify;
    }

    /// <summary>Gepufferte Hinweise jetzt senden (z. B. nach erfolgreichem Heartbeat).</summary>
    public void RequestFlush() => Signal(_flushSignal);

    public Task RunAsync(CancellationToken ct) => Task.WhenAll(PollLoopAsync(ct), FlushLoopAsync(ct));

    private static void Signal(SemaphoreSlim semaphore)
    {
        try
        {
            if (semaphore.CurrentCount == 0)
            {
                semaphore.Release();
            }
        }
        catch (SemaphoreFullException)
        {
        }
    }

    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        Signal(_wake);
        RequestFlush(); // Verbindung vielleicht wieder da
    }

    private async Task PollLoopAsync(CancellationToken ct)
    {
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged += OnNetworkChanged;
        try
        {
            var afterEvent = false;
            while (!ct.IsCancellationRequested)
            {
                if (_resetRequested)
                {
                    _resetRequested = false;
                    _evaluator.Reset();
                }

                if (_enabled)
                {
                    Poll(afterEvent);
                }

                afterEvent = await _wake.WaitAsync(PollInterval, ct).ConfigureAwait(false);
                if (afterEvent)
                {
                    await Task.Delay(EventSettle, ct).ConfigureAwait(false);
                    _wake.Wait(0);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        finally
        {
            NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
            NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
        }
    }

    private void Poll(bool afterEvent)
    {
        IReadOnlyList<ClientFinding> changes;
        try
        {
            var snapshot = _reader.Read(DateTimeOffset.UtcNow, afterEvent);
            changes = _evaluator.Evaluate(snapshot);
        }
        catch (Exception ex)
        {
            if (!_readFailedLogged)
            {
                _readFailedLogged = true;
                _logger.LogWarning(ex, "Client-Hinweise: Netzwerkkarten konnten nicht geprüft werden");
            }

            return;
        }

        if (changes.Count > 0)
        {
            Publish(changes);
        }
    }

    internal void Publish(IReadOnlyList<ClientFinding> changes)
    {
        foreach (var finding in changes)
        {
            Feed.Publish(finding);
            if (finding.IsActive)
            {
                _logger.Log(finding.Severity == "info" ? LogLevel.Information : LogLevel.Warning,
                    "Client-Hinweis ({Kind}, {Severity}) an „{Adapter}“: {Title} – {Message}",
                    finding.Kind, finding.Severity, finding.Adapter, finding.Title, finding.Message);
            }
            else
            {
                _logger.LogInformation("Client-Hinweis erledigt ({Kind}) an „{Adapter}“: {Title}", finding.Kind, finding.Adapter, finding.Title);
            }
        }

        Pending.Add(changes);
        RequestFlush();
    }

    private async Task FlushLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await _flushSignal.WaitAsync(FlushInterval, ct).ConfigureAwait(false);
                if (!_enabled || Pending.Count == 0 || !_status.CanSend)
                {
                    continue;
                }

                try
                {
                    var before = Pending.Count;
                    var delivered = await Pending.FlushAsync(_status.SendFindingsAsync, ct).ConfigureAwait(false);
                    if (delivered > 0)
                    {
                        _flushFailedLogged = false;
                        _logger.LogInformation("{Count} Client-Hinweis(e) an den Server übermittelt", delivered);
                    }
                    else if (Pending.Count == before && !_flushFailedLogged)
                    {
                        _flushFailedLogged = true;
                        _logger.LogInformation("{Count} Client-Hinweis(e) gespeichert, werden übermittelt, sobald der Server erreichbar ist", before);
                    }
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                {
                    _logger.LogDebug("Client-Hinweise nicht übermittelt: {Message}", ex.Message);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }
}
