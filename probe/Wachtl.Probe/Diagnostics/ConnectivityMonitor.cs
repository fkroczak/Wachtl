using System.Globalization;
using Wachtl.Probe.Config;

namespace Wachtl.Probe.Diagnostics;

/// <summary>Arten der Hinweise, die die Probe an ihren eigenen Pings erkennt (nur für das Tray-Symbol).</summary>
public static class ConnectivityKinds
{
    public const string GatewayDown = "gateway_down";
    public const string InternetDown = "internet_down";
    public const string TargetDown = "target_down";
    public const string PacketLoss = "packet_loss";
    public const string NetworkChanged = "network_changed";
}

/// <summary>
/// Erkennt an den laufenden Pings dieses PCs, was der Benutzer sofort sehen soll – unabhängig vom Server, auch wenn
/// der PC selbst gerade kein Netz hat:
/// <list type="bullet">
/// <item>Gateway antwortet nicht (kritisch) – das lokale Netz ist weg; Internet und Ziele sind dann Folgen</item>
/// <item>alle Internet-Referenzen antworten nicht (kritisch) – Internetanschluss oder Provider</item>
/// <item>einzelnes Ziel antwortet nicht (Warnung)</item>
/// <item>jeder verlorene Ping (Warnung, einmalig): der erste sofort, weitere derselben Minute zusammengefasst</item>
/// </list>
/// Ausfall = mindestens <see cref="DownAfter"/> ohne Antwort, wie auf dem Server. Kürzere Aussetzer sind Paketverlust.
/// Rein rechnerisch, die Zeit kommt vom Aufrufer – damit testbar.
/// </summary>
public sealed class ConnectivityMonitor
{
    public static readonly TimeSpan DownAfter = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan LossWindow = TimeSpan.FromSeconds(60);

    /// <summary>So lange ohne neuen Ping zählt ein Check nicht mehr (entfernt, Dienst stoppt ihn gerade).</summary>
    public static readonly TimeSpan Stale = TimeSpan.FromSeconds(90);

    /// <summary>
    /// Ein Ausfall muss so lange gleich bleiben, bevor er gemeldet wird: die Pings der Ziele laufen nicht gleichzeitig,
    /// beim Wegfallen und Wiederkommen des Gateways sähe es sonst kurz so aus, als wäre nur das Internet weg.
    /// </summary>
    public static readonly TimeSpan Settle = TimeSpan.FromSeconds(2);

    private readonly object _lock = new();
    private readonly Dictionary<long, Track> _tracks = new();
    private readonly Dictionary<string, ClientFinding> _active = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _pending = new(StringComparer.Ordinal);
    private readonly Action<IReadOnlyList<ClientFinding>> _publish;
    private readonly Func<DateTimeOffset> _clock;

    public ConnectivityMonitor(Action<IReadOnlyList<ClientFinding>> publish, Func<DateTimeOffset>? clock = null)
    {
        _publish = publish;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>false: nichts melden (Einstellung „Ausfälle, Paketverlust und Netzwerkwechsel auf dem PC melden“).</summary>
    public bool Enabled { get; set; } = true;

    private sealed class Track
    {
        public CheckConfig Check = new();
        public DateTimeOffset LastSeen;
        public DateTimeOffset? FailStart;
        public int FailCount;
        public bool Down;
        public DateTimeOffset? WindowStart;
        public int WindowLost;
        public int WindowSent;
    }

    /// <summary>Anzahl Pings ohne Antwort für einen Ausfall (mindestens 2, wie auf dem Server).</summary>
    public static int FailsNeeded(int intervalS) =>
        Math.Max(2, (int)Math.Ceiling(DownAfter.TotalSeconds / Math.Max(1, intervalS)));

    /// <summary>Vom Ping-Check nach jedem Ping aufgerufen.</summary>
    public void RecordPing(CheckConfig check, bool up, DateTimeOffset? at = null)
    {
        if (check.Type != "ping")
        {
            return;
        }

        var now = at ?? _clock();
        var changes = new List<ClientFinding>();
        lock (_lock)
        {
            if (!_tracks.TryGetValue(check.Id, out var t))
            {
                t = new Track();
                _tracks[check.Id] = t;
            }

            t.Check = check;
            t.LastSeen = now;
            if (!up)
            {
                t.FailStart ??= now;
                t.FailCount++;
                if (!t.Down && t.FailCount >= FailsNeeded(check.IntervalS))
                {
                    t.Down = true;
                }
            }
            else
            {
                RollWindow(t, now, changes);
                if (t.FailStart is { } since)
                {
                    if (!t.Down)
                    {
                        Loss(t, t.FailCount, since, now, changes);
                    }

                    t.Down = false;
                    t.FailStart = null;
                    t.FailCount = 0;
                }

                t.WindowSent++;
            }

            Evaluate(now, changes);
        }

        if (Enabled && changes.Count > 0)
        {
            _publish(changes);
        }
    }

    /// <summary>Checks, die es nicht mehr gibt, vergessen (ihre offenen Ausfälle gelten als erledigt).</summary>
    public void KeepChecks(IEnumerable<long> checkIds)
    {
        var keep = checkIds.ToHashSet();
        var changes = new List<ClientFinding>();
        lock (_lock)
        {
            foreach (var id in _tracks.Keys.Where(id => !keep.Contains(id)).ToList())
            {
                _tracks.Remove(id);
            }

            Evaluate(_clock(), changes);
        }

        if (Enabled && changes.Count > 0)
        {
            _publish(changes);
        }
    }

    /// <summary>Aktuell aktive Ausfälle (Schlüssel gateway, internet, check:&lt;id&gt;) – für Tests und Protokoll.</summary>
    public IReadOnlyCollection<string> ActiveKeys
    {
        get
        {
            lock (_lock)
            {
                return _active.Keys.ToList();
            }
        }
    }

    private void Loss(Track t, int lost, DateTimeOffset since, DateTimeOffset now, List<ClientFinding> changes)
    {
        if (t.WindowStart is null)
        {
            // erster Verlust: sofort melden, weitere in dieser Minute sammeln
            t.WindowStart = now;
            t.WindowLost = 0;
            t.WindowSent = 0;
            changes.Add(Event(ConnectivityKinds.PacketLoss, FindingSeverity.Warning, now,
                $"Paketverlust zu {Name(t.Check)}",
                $"{Pings(lost)} zu {Name(t.Check)} ohne Antwort um {Clock(since)}. "
                + "Kurze Aussetzer stören Telefonie, Videokonferenzen und Remote-Sitzungen.",
                "Tritt das öfter auf: Netzwerkkabel bzw. WLAN-Empfang prüfen. Betrifft es mehrere PCs, bitte die IT informieren.",
                $"{Pings(lost)} zu {Name(t.Check)} ohne Antwort ({Clock(since)})."));
            return;
        }

        t.WindowLost += lost;
        t.WindowSent += lost;
    }

    /// <summary>Sammel-Minute vorbei: weitere Verluste darin als ein Hinweis melden, sonst das Fenster schließen.</summary>
    private void RollWindow(Track t, DateTimeOffset now, List<ClientFinding> changes)
    {
        if (t.WindowStart is not { } ws || now - ws < LossWindow)
        {
            return;
        }

        if (t.WindowLost > 0)
        {
            changes.Add(LossSummary(t, now));
            t.WindowStart = now;
        }
        else
        {
            t.WindowStart = null;
        }

        t.WindowLost = 0;
        t.WindowSent = 0;
    }

    private ClientFinding LossSummary(Track t, DateTimeOffset now)
    {
        var pct = t.WindowSent > 0 ? 100.0 * t.WindowLost / t.WindowSent : 0;
        var text = $"Weitere {Pings(t.WindowLost)} zu {Name(t.Check)} ohne Antwort in der letzten Minute "
                   + $"({t.WindowLost} von {t.WindowSent}, {pct.ToString("0.##", CultureInfo.GetCultureInfo("de-DE"))} %).";
        return Event(ConnectivityKinds.PacketLoss, FindingSeverity.Warning, now, $"Weiter Paketverlust zu {Name(t.Check)}", text,
            "Netzwerkkabel bzw. WLAN-Empfang prüfen. Hält der Verlust an, bitte die IT informieren.", text);
    }

    /// <summary>Gewünschte Ausfälle bestimmen und mit den aktiven vergleichen: neue melden, behobene als erledigt.</summary>
    private void Evaluate(DateTimeOffset now, List<ClientFinding> changes)
    {
        var live = _tracks.Values.Where(t => now - t.LastSeen <= Stale).ToList();
        var wanted = new Dictionary<string, (FindingSeverity Severity, DateTimeOffset Since, Func<DateTimeOffset, FindingText> Text)>(StringComparer.Ordinal);
        var gateways = live.Where(t => t.Check.Role == "gateway").ToList();
        var refs = live.Where(t => t.Check.Role == "reference").ToList();
        var gatewayDown = gateways.Where(t => t.Down).ToList();
        if (gatewayDown.Count > 0)
        {
            var since = gatewayDown.Min(t => t.FailStart ?? now);
            wanted["gateway"] = (FindingSeverity.Critical, since, s => new FindingText(
                "Netzwerk unterbrochen – Gateway antwortet nicht",
                $"Seit {Clock(s)} antwortet das Standard-Gateway (Router) nicht. Ohne Gateway gibt es kein Internet und meist keinen Zugriff auf Server.",
                "Netzwerkkabel bzw. WLAN prüfen, Switch und Router auf Strom und Lämpchen prüfen. Betrifft es mehrere PCs, liegt es am Netzwerk – bitte die IT informieren.",
                $"Seit {Clock(s)} keine Antwort vom Gateway (Router).\nLösung: Kabel/WLAN prüfen, Switch und Router auf Strom prüfen."));
        }
        else
        {
            if (refs.Count > 0 && refs.All(t => t.Down))
            {
                var since = refs.Max(t => t.FailStart ?? now);
                var names = string.Join(", ", refs.Select(t => t.Check.Target));
                wanted["internet"] = (FindingSeverity.Critical, since, s => new FindingText(
                    "Internet ausgefallen",
                    $"Seit {Clock(s)} antwortet keines der Internet-Ziele ({names}). Das lokale Netz ist erreichbar – Internetanschluss, Router oder Provider gestört.",
                    "Router bzw. Modem prüfen (Lämpchen, ggf. neu starten). Hält es an, den Provider informieren. Wachtl zeichnet die Störung für den Bericht auf.",
                    $"Seit {Clock(s)} kein Internet (keine Antwort von {names}).\nLösung: Router/Modem prüfen, ggf. Provider informieren."));
            }
            else
            {
                foreach (var t in refs.Where(t => t.Down))
                {
                    AddTarget(wanted, t, now);
                }
            }

            foreach (var t in live.Where(t => t.Down && t.Check.Role == "target"))
            {
                AddTarget(wanted, t, now);
            }
        }

        foreach (var key in _pending.Keys.Where(k => !wanted.ContainsKey(k)).ToList())
        {
            _pending.Remove(key);
        }

        foreach (var (key, w) in wanted)
        {
            if (_active.ContainsKey(key))
            {
                continue;
            }

            if (!_pending.TryGetValue(key, out var first))
            {
                _pending[key] = now;
                continue;
            }

            if (now - first < Settle)
            {
                continue;
            }

            _pending.Remove(key);

            var text = w.Text(w.Since);
            var finding = new ClientFinding
            {
                FindingId = Guid.NewGuid().ToString("N"),
                Kind = key == "gateway" ? ConnectivityKinds.GatewayDown : key == "internet" ? ConnectivityKinds.InternetDown : ConnectivityKinds.TargetDown,
                Severity = ClientFinding.SeverityName(w.Severity),
                State = "active",
                Title = ClientFinding.Clamp(text.Title, ClientFinding.MaxTitle),
                Message = ClientFinding.Clamp(text.Message, ClientFinding.MaxText),
                Solution = ClientFinding.Clamp(text.Solution, ClientFinding.MaxText),
                Balloon = ClientFinding.Clamp(text.Balloon, ClientFinding.MaxBalloon),
                DetectedAt = w.Since.ToUnixTimeSeconds(),
            };
            _active[key] = finding;
            changes.Add(finding);
        }

        foreach (var key in _active.Keys.Where(k => !wanted.ContainsKey(k)).ToList())
        {
            var old = _active[key];
            _active.Remove(key);
            var downtime = now - DateTimeOffset.FromUnixTimeSeconds(old.DetectedAt);
            // noch gestört, aber jetzt Teil einer größeren Störung (Gateway weg): still aus der Liste nehmen
            var stillDown = key == "internet"
                ? refs.Count > 0 && refs.All(t => t.Down)
                : key.StartsWith("check:", StringComparison.Ordinal)
                  && live.Any(t => t.Down && "check:" + t.Check.Id.ToString(CultureInfo.InvariantCulture) == key);
            var (title, message) = key switch
            {
                "gateway" => ("Netzwerk wieder da", $"Das Gateway antwortet wieder. Unterbrechung: {FindingTexts.Duration(downtime)}."),
                "internet" => ("Internet wieder erreichbar", $"Die Internet-Ziele antworten wieder. Ausfall: {FindingTexts.Duration(downtime)}."),
                _ => ("Wieder erreichbar: " + old.Title.Replace(" nicht erreichbar", string.Empty, StringComparison.Ordinal),
                    $"Antwortet wieder. Ausfall: {FindingTexts.Duration(downtime)}."),
            };
            changes.Add(new ClientFinding
            {
                FindingId = old.FindingId,
                Kind = old.Kind,
                Severity = old.Severity,
                State = "resolved",
                Title = ClientFinding.Clamp(title, ClientFinding.MaxTitle),
                Message = ClientFinding.Clamp(message, ClientFinding.MaxText),
                Balloon = ClientFinding.Clamp(message, ClientFinding.MaxBalloon),
                DetectedAt = old.DetectedAt,
                ResolvedAt = now.ToUnixTimeSeconds(),
                Quiet = stillDown,
            });
        }
    }

    private static void AddTarget(Dictionary<string, (FindingSeverity, DateTimeOffset, Func<DateTimeOffset, FindingText>)> wanted, Track t, DateTimeOffset now)
    {
        var name = Name(t.Check);
        wanted["check:" + t.Check.Id.ToString(CultureInfo.InvariantCulture)] = (FindingSeverity.Warning, t.FailStart ?? now, s => new FindingText(
            $"{name} nicht erreichbar",
            $"Seit {Clock(s)} antwortet {name} nicht. Andere Ziele sind erreichbar.",
            "Ist das Ziel ein Server oder Dienst in Ihrem Netz, bitte die IT informieren.",
            $"Seit {Clock(s)} keine Antwort von {name}."));
    }

    private static ClientFinding Event(string kind, FindingSeverity severity, DateTimeOffset now, string title, string message,
        string solution, string balloon) => new()
    {
        FindingId = Guid.NewGuid().ToString("N"),
        Kind = kind,
        Severity = ClientFinding.SeverityName(severity),
        State = "active",
        Event = true,
        Title = ClientFinding.Clamp(title, ClientFinding.MaxTitle),
        Message = ClientFinding.Clamp(message, ClientFinding.MaxText),
        Solution = ClientFinding.Clamp(solution, ClientFinding.MaxText),
        Balloon = ClientFinding.Clamp(balloon, ClientFinding.MaxBalloon),
        DetectedAt = now.ToUnixTimeSeconds(),
    };

    internal static string Name(CheckConfig check) =>
        string.Equals(check.Target, "gateway", StringComparison.OrdinalIgnoreCase) ? "Gateway" : check.Target;

    private static string Pings(int n) => n == 1 ? "1 Ping" : n.ToString(CultureInfo.InvariantCulture) + " Pings";

    private static string Clock(DateTimeOffset at) => at.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);
}

/// <summary>
/// Meldet, wenn sich das Netzwerk dieses PCs ändert: andere Verbindung (LAN ↔ WLAN), neue IP-Adresse, Gateway weg
/// oder dazu. Ein neuer Zustand muss zwei Abfragen lang bestehen; „gar kein Netz“ melden andere Hinweise.
/// </summary>
public sealed class NetworkChangeDetector
{
    private string? _reported;
    private string? _candidate;
    private int _seen;
    private string _reportedText = string.Empty;

    /// <summary>Kennung und Beschreibung der aktiven Verbindungen (echte Karten mit IPv4 und Gateway).</summary>
    public static (string Key, string Text) Describe(AdapterSnapshot snapshot)
    {
        var active = snapshot.Adapters
            .Where(a => a.IsPhysical && a.Status == LinkStatus.Up && a.HasRoutableIpv4 && a.HasGateway)
            .OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var key = string.Join("|", active.Select(a => $"{a.Id}={string.Join(",", a.Ipv4.OrderBy(i => i, StringComparer.Ordinal))}"));
        var text = string.Join(", ", active.Select(a =>
            $"{(a.IsWifi ? "WLAN" : "LAN")} „{a.Name}“ ({string.Join(", ", a.Ipv4.Where(i => !AdapterClassifier.IsApipa(i)))})"));
        return (key, text);
    }

    /// <summary>Nächste Momentaufnahme; liefert einen Hinweis, wenn sich das Netzwerk geändert hat.</summary>
    public ClientFinding? Check(AdapterSnapshot snapshot)
    {
        var (key, text) = Describe(snapshot);
        if (_reported is null)
        {
            if (key.Length > 0)
            {
                _reported = key;
                _reportedText = text;
            }

            return null;
        }

        if (key.Length == 0 || key == _reported)
        {
            _candidate = null;
            _seen = 0;
            return null;
        }

        if (key != _candidate)
        {
            _candidate = key;
            _seen = 1;
            return null;
        }

        if (++_seen < 2)
        {
            return null;
        }

        var before = _reportedText;
        _reported = key;
        _reportedText = text;
        _candidate = null;
        _seen = 0;
        var message = $"Netzwerk geändert: jetzt {text}" + (before.Length > 0 ? $", vorher {before}." : ".");
        return new ClientFinding
        {
            FindingId = Guid.NewGuid().ToString("N"),
            Kind = ConnectivityKinds.NetworkChanged,
            Severity = "info",
            State = "active",
            Event = true,
            Title = "Netzwerkverbindung gewechselt",
            Message = ClientFinding.Clamp(message, ClientFinding.MaxText),
            Solution = "Nichts zu tun, wenn Sie das Netzwerk bewusst gewechselt haben (z. B. Notebook vom Dock genommen). Sonst: Kabel und WLAN prüfen.",
            Balloon = ClientFinding.Clamp(message, ClientFinding.MaxBalloon),
            DetectedAt = snapshot.At.ToUnixTimeSeconds(),
        };
    }
}
