using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Transport;
using Wachtl.Probe.Tray;

namespace Wachtl.Probe.Diagnostics;

/// <summary>
/// Noch nicht zugestellte Hinweise in findings-pending.json – je Hinweis nur der neueste Stand,
/// höchstens <see cref="MaxEntries"/> (älteste fallen heraus). Wichtig, weil bei gezogenem Kabel der Server
/// nicht erreichbar ist. Der Server speichert per finding_id, doppeltes Zustellen ist harmlos.
/// </summary>
public sealed class PendingFindings
{
    public const int MaxEntries = 200;
    public const int BatchSize = 50;

    private readonly string _path;
    private readonly ILogger? _logger;
    private readonly object _lock = new();
    private readonly SemaphoreSlim _flush = new(1, 1);
    private readonly List<ClientFinding> _items;

    public PendingFindings(string path, ILogger? logger = null)
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

    public IReadOnlyList<ClientFinding> Snapshot()
    {
        lock (_lock)
        {
            return _items.ToList();
        }
    }

    /// <summary>Neuer Stand ersetzt den alten desselben Hinweises und rückt ans Ende.</summary>
    public void Add(IEnumerable<ClientFinding> findings)
    {
        lock (_lock)
        {
            var changed = false;
            foreach (var finding in findings)
            {
                _items.RemoveAll(f => f.FindingId == finding.FindingId);
                _items.Add(finding);
                changed = true;
            }

            if (_items.Count > MaxEntries)
            {
                var drop = _items.Count - MaxEntries;
                _items.RemoveRange(0, drop);
                _logger?.LogWarning("Zu viele ungesendete Client-Hinweise, {Count} älteste verworfen", drop);
            }

            if (changed)
            {
                Save();
            }
        }
    }

    /// <summary>
    /// Sendet in Paketen zu höchstens 50; bricht beim ersten „später erneut“ ab.
    /// Abgelehnte Pakete (400) werden verworfen. Gibt die Zahl der zugestellten Hinweise zurück.
    /// </summary>
    public async Task<int> FlushAsync(Func<IReadOnlyList<ClientFinding>, CancellationToken, Task<ReportSendResult>> send, CancellationToken ct)
    {
        if (!await _flush.WaitAsync(0, ct).ConfigureAwait(false))
        {
            return 0;
        }

        try
        {
            var delivered = 0;
            var rounds = MaxEntries / BatchSize + 1;
            while (rounds-- > 0)
            {
                var batch = Snapshot().Take(BatchSize).ToList();
                if (batch.Count == 0)
                {
                    break;
                }

                var result = await send(batch, ct).ConfigureAwait(false);
                if (result.Outcome == ReportSendOutcome.Retry)
                {
                    break;
                }

                if (result.Outcome == ReportSendOutcome.Rejected)
                {
                    _logger?.LogWarning("Server lehnt {Count} Client-Hinweise ab, sie werden verworfen: {Error}", batch.Count, result.Error);
                }
                else
                {
                    delivered += batch.Count;
                }

                Remove(batch);
            }

            return delivered;
        }
        finally
        {
            _flush.Release();
        }
    }

    /// <summary>Entfernt genau die gesendeten Stände – ein inzwischen neuerer Stand bleibt stehen.</summary>
    private void Remove(IReadOnlyCollection<ClientFinding> sent)
    {
        lock (_lock)
        {
            var set = new HashSet<ClientFinding>(sent, ReferenceEqualityComparer.Instance);
            if (_items.RemoveAll(set.Contains) > 0)
            {
                Save();
            }
        }
    }

    private List<ClientFinding> Load()
    {
        try
        {
            if (File.Exists(_path))
            {
                var list = JsonSerializer.Deserialize<List<ClientFinding>>(File.ReadAllText(_path), ApiClient.JsonOptions) ?? new();
                return list.Where(f => f is not null && !string.IsNullOrEmpty(f.FindingId)).TakeLast(MaxEntries).ToList();
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            _logger?.LogWarning("{Path} nicht lesbar, ungesendete Client-Hinweise verloren: {Message}", _path, ex.Message);
        }

        return new List<ClientFinding>();
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
