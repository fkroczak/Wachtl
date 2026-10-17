using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tray;

public enum ReportSendOutcome
{
    /// <summary>Server hat angenommen (200/201).</summary>
    Delivered,

    /// <summary>Server lehnt die Werte ab (400) – nicht wiederholen.</summary>
    Rejected,

    /// <summary>Server nicht erreichbar oder anderer Fehler – später erneut.</summary>
    Retry,
}

public sealed record ReportSendResult(ReportSendOutcome Outcome, string? Error = null);

public interface IReportSender
{
    Task<ReportSendResult> SendAsync(ServerReport report, CancellationToken ct);
}

/// <summary>Sendet über den ApiClient des Workers (Token, Pinning, Proxy).</summary>
public sealed class ApiReportSender : IReportSender
{
    private readonly ProbeStatus _status;

    public ApiReportSender(ProbeStatus status) => _status = status;

    public async Task<ReportSendResult> SendAsync(ServerReport report, CancellationToken ct)
    {
        var api = _status.Api;
        if (api is null)
        {
            return new ReportSendResult(ReportSendOutcome.Retry, "Dienst noch nicht mit dem Server verbunden");
        }

        try
        {
            await api.PostResultAsync("report", report, ct).ConfigureAwait(false);
            _status.MarkContact();
            return new ReportSendResult(ReportSendOutcome.Delivered);
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.BadRequest)
        {
            return new ReportSendResult(ReportSendOutcome.Rejected, ex.Detail);
        }
        catch (Exception ex)
        {
            // Netzfehler, Zeitüberschreitung, 401/403/404/5xx, ApiClient bereits freigegeben: puffern.
            return new ReportSendResult(ReportSendOutcome.Retry, ex.Message);
        }
    }
}

/// <summary>
/// Noch nicht zugestellte Meldungen in reports-pending.json (höchstens <see cref="MaxEntries"/>, älteste fallen heraus).
/// Dank report_id ist doppeltes Zustellen harmlos.
/// </summary>
public sealed class PendingReports
{
    public const int MaxEntries = 200;

    private readonly string _path;
    private readonly ILogger? _logger;
    private readonly object _lock = new();
    private readonly SemaphoreSlim _flush = new(1, 1);
    private readonly List<ServerReport> _items;

    public PendingReports(string path, ILogger? logger = null)
    {
        _path = path;
        _logger = logger;
        _items = Load();
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _items.Count;
            }
        }
    }

    public IReadOnlyList<ServerReport> Snapshot()
    {
        lock (_lock)
        {
            return _items.ToList();
        }
    }

    public void Add(ServerReport report)
    {
        lock (_lock)
        {
            _items.RemoveAll(r => r.ReportId == report.ReportId);
            _items.Add(report);
            if (_items.Count > MaxEntries)
            {
                var drop = _items.Count - MaxEntries;
                _items.RemoveRange(0, drop);
                _logger?.LogWarning("Zu viele ungesendete Meldungen, {Count} älteste verworfen", drop);
            }

            Save();
        }
    }

    /// <summary>Liefert der Reihe nach nach; bricht beim ersten „später erneut“ ab. Gibt die Zahl der zugestellten zurück.</summary>
    public async Task<int> FlushAsync(IReportSender sender, CancellationToken ct)
    {
        if (!await _flush.WaitAsync(0, ct).ConfigureAwait(false))
        {
            return 0;
        }

        try
        {
            var delivered = 0;
            foreach (var report in Snapshot())
            {
                var result = await sender.SendAsync(report, ct).ConfigureAwait(false);
                if (result.Outcome == ReportSendOutcome.Retry)
                {
                    break;
                }

                if (result.Outcome == ReportSendOutcome.Rejected)
                {
                    _logger?.LogWarning("Server lehnt gepufferte Meldung {Id} ab und sie wird verworfen: {Error}", report.ReportId, result.Error);
                }
                else
                {
                    delivered++;
                }

                Remove(report.ReportId);
            }

            if (delivered > 0)
            {
                _logger?.LogInformation("{Count} gepufferte Störungsmeldung(en) nachgeliefert", delivered);
            }

            return delivered;
        }
        finally
        {
            _flush.Release();
        }
    }

    private void Remove(string reportId)
    {
        lock (_lock)
        {
            if (_items.RemoveAll(r => r.ReportId == reportId) > 0)
            {
                Save();
            }
        }
    }

    private List<ServerReport> Load()
    {
        try
        {
            if (File.Exists(_path))
            {
                var list = JsonSerializer.Deserialize<List<ServerReport>>(File.ReadAllText(_path), ApiClient.JsonOptions) ?? new();
                return list.Where(r => !string.IsNullOrEmpty(r.ReportId)).TakeLast(MaxEntries).ToList();
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            _logger?.LogWarning("{Path} nicht lesbar, ungesendete Meldungen verloren: {Message}", _path, ex.Message);
        }

        return new List<ServerReport>();
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            if (_items.Count == 0)
            {
                File.Delete(_path);
                return;
            }

            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_items, ApiClient.JsonOptionsIndented));
            File.Move(tmp, _path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger?.LogWarning("{Path} nicht schreibbar: {Message}", _path, ex.Message);
        }
    }
}
