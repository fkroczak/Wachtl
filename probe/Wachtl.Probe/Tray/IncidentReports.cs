using System.Text.Json;

namespace Wachtl.Probe.Tray;

/// <summary>Meldung, wie sie an POST /api/probe/v1/report geht (snake_case über ApiClient.JsonOptions).</summary>
public sealed class ServerReport
{
    public string ReportId { get; init; } = string.Empty;
    public long OccurredAt { get; init; }
    public string Category { get; init; } = "other";
    public string Duration { get; init; } = "unknown";
    public string Description { get; init; } = string.Empty;
    public string User { get; init; } = string.Empty;
    public string Hostname { get; init; } = string.Empty;
}

/// <summary>Prüft den Körper von POST /tray/v1/report laut docs/STOERUNGSMELDUNGEN.md.</summary>
public static class TrayReportParser
{
    public const int MaxDescription = 1000;
    public const int MaxUser = 128;
    public const int MaxHostname = 255;
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(7);
    public static readonly TimeSpan MaxFuture = TimeSpan.FromMinutes(5);

    public static readonly IReadOnlyList<string> Categories =
        new[] { "no_connection", "slow", "dropouts", "voice_video", "application", "other" };

    public static readonly IReadOnlyList<string> Durations =
        new[] { "unknown", "short", "minutes", "long", "ongoing" };

    /// <summary>Gibt die fertige Server-Meldung zurück oder einen deutschen Fehlertext.</summary>
    public static ServerReport? Parse(string body, DateTimeOffset now, string hostname, out string? error)
    {
        error = null;
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            error = "Die Meldung ist kein gültiges JSON.";
            return null;
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                error = "Die Meldung muss ein JSON-Objekt sein.";
                return null;
            }

            if (!root.TryGetProperty("occurred_at", out var occurredEl) || occurredEl.ValueKind != JsonValueKind.Number
                || !occurredEl.TryGetDouble(out var occurredD) || double.IsNaN(occurredD) || Math.Abs(occurredD) > 1e11)
            {
                error = "Der Zeitpunkt (occurred_at) fehlt oder ist ungültig.";
                return null;
            }

            var occurred = (long)Math.Floor(occurredD);
            var nowS = now.ToUnixTimeSeconds();
            if (occurred < nowS - (long)MaxAge.TotalSeconds || occurred > nowS + (long)MaxFuture.TotalSeconds)
            {
                error = "Der Zeitpunkt muss innerhalb der letzten 7 Tage liegen.";
                return null;
            }

            var category = Text(root, "category");
            if (category is null || !Categories.Contains(category))
            {
                error = "Bitte die Art der Störung auswählen.";
                return null;
            }

            var duration = Text(root, "duration");
            if (string.IsNullOrEmpty(duration))
            {
                duration = "unknown";
            }

            if (!Durations.Contains(duration))
            {
                error = "Unbekannte Dauer.";
                return null;
            }

            if (root.TryGetProperty("description", out var d) && d.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
            {
                error = "Die Beschreibung muss Text sein.";
                return null;
            }

            var description = (Text(root, "description") ?? string.Empty).Trim();
            if (description.Length > MaxDescription)
            {
                error = $"Die Beschreibung darf höchstens {MaxDescription} Zeichen lang sein.";
                return null;
            }

            var user = (Text(root, "user") ?? string.Empty).Trim();
            if (user.Length > MaxUser)
            {
                user = user[..MaxUser];
            }

            return new ServerReport
            {
                ReportId = Guid.NewGuid().ToString(),
                OccurredAt = occurred,
                Category = category,
                Duration = duration,
                Description = description,
                User = user,
                Hostname = hostname.Length > MaxHostname ? hostname[..MaxHostname] : hostname,
            };
        }
    }

    private static string? Text(JsonElement root, string name) =>
        root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;
}

/// <summary>Gleitendes Fenster: höchstens <c>limit</c> Meldungen je <c>window</c> und Schlüssel (z. B. Benutzer).</summary>
public sealed class RateLimiter
{
    private readonly Dictionary<string, Queue<DateTimeOffset>> _hits = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public RateLimiter(int limit, TimeSpan window)
    {
        Limit = limit;
        Window = window;
    }

    public int Limit { get; }

    public TimeSpan Window { get; }

    /// <summary>Zählt einen Treffer und gibt true zurück, solange das Limit für diesen Schlüssel nicht erreicht ist.</summary>
    public bool TryAcquire(DateTimeOffset now, string key = "")
    {
        lock (_lock)
        {
            // abgelaufene Treffer aller Schlüssel entfernen, damit die Tabelle nicht wächst
            foreach (var k in _hits.Keys.ToList())
            {
                var q = _hits[k];
                while (q.Count > 0 && now - q.Peek() >= Window)
                {
                    q.Dequeue();
                }

                if (q.Count == 0)
                {
                    _hits.Remove(k);
                }
            }

            if (!_hits.TryGetValue(key, out var hits))
            {
                hits = _hits[key] = new Queue<DateTimeOffset>();
            }

            if (hits.Count >= Limit)
            {
                return false;
            }

            hits.Enqueue(now);
            return true;
        }
    }
}
