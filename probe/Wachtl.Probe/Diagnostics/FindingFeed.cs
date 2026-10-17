namespace Wachtl.Probe.Diagnostics;

/// <summary>Ein Eintrag von GET /tray/v1/findings (snake_case über ApiClient.JsonOptions).</summary>
public sealed class TrayFindingItem
{
    public long Seq { get; init; }
    public string FindingId { get; init; } = string.Empty;
    public string Kind { get; init; } = string.Empty;
    public string Severity { get; init; } = "warning";
    public string State { get; init; } = "active";
    public string Title { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public string Solution { get; init; } = string.Empty;
    public string Adapter { get; init; } = string.Empty;
    public long DetectedAt { get; init; }
    public long? ResolvedAt { get; init; }
}

/// <summary>Antwort von GET /tray/v1/findings?since=&lt;seq&gt;.</summary>
public sealed class TrayFindingsResponse
{
    public bool Notify { get; init; }

    /// <summary>Höchste vergebene Nummer – ist sie kleiner als der Stand des Tray, wurde der Dienst neu gestartet.</summary>
    public long LatestSeq { get; init; }

    public List<TrayFindingItem> Findings { get; init; } = new();
}

/// <summary>
/// Die letzten <see cref="MaxEntries"/> Hinweise im Speicher, je Hinweis der neueste Stand mit fortlaufender Nummer.
/// Jede Zustandsänderung bekommt eine neue Nummer; die Zählung beginnt bei der Startzeit in Millisekunden,
/// damit ein Tray-Programm nach einem Neustart des Dienstes keine Hinweise verpasst.
/// </summary>
public sealed class FindingFeed
{
    public const int MaxEntries = 50;

    private readonly object _lock = new();
    private readonly Dictionary<string, (long Seq, ClientFinding Finding)> _entries = new(StringComparer.Ordinal);
    private long _seq;

    public FindingFeed(long? startSeq = null)
    {
        _seq = startSeq ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }

    /// <summary>Sprechblasen im Tray erlaubt (client_findings.enabled und .notify).</summary>
    public bool Notify { get; set; } = true;

    public long LatestSeq
    {
        get
        {
            lock (_lock)
            {
                return _seq;
            }
        }
    }

    public long Publish(ClientFinding finding)
    {
        lock (_lock)
        {
            var seq = ++_seq;
            _entries[finding.FindingId] = (seq, finding);
            if (_entries.Count > MaxEntries)
            {
                foreach (var old in _entries.OrderBy(e => e.Value.Seq).Take(_entries.Count - MaxEntries).Select(e => e.Key).ToList())
                {
                    _entries.Remove(old);
                }
            }

            return seq;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
        }
    }

    /// <summary>Alle Einträge mit Nummer größer <paramref name="since"/>, aufsteigend.</summary>
    public TrayFindingsResponse Since(long since)
    {
        lock (_lock)
        {
            return new TrayFindingsResponse
            {
                Notify = Notify,
                LatestSeq = _seq,
                Findings = _entries.Values
                    .Where(e => e.Seq > since)
                    .OrderBy(e => e.Seq)
                    .Select(e => new TrayFindingItem
                    {
                        Seq = e.Seq,
                        FindingId = e.Finding.FindingId,
                        Kind = e.Finding.Kind,
                        Severity = e.Finding.Severity,
                        State = e.Finding.State,
                        Title = e.Finding.Title,
                        Message = e.Finding.Message,
                        Solution = e.Finding.Solution,
                        Adapter = e.Finding.Adapter,
                        DetectedAt = e.Finding.DetectedAt,
                        ResolvedAt = e.Finding.ResolvedAt,
                    })
                    .ToList(),
            };
        }
    }
}
