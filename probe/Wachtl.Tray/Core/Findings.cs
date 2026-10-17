using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace Wachtl.Tray.Core
{
    /// <summary>Ein Client-Hinweis aus GET /tray/v1/findings.</summary>
    [DataContract]
    public sealed class TrayFinding
    {
        [DataMember(Name = "seq")] public long Seq { get; set; }
        [DataMember(Name = "finding_id")] public string? FindingId { get; set; }
        [DataMember(Name = "kind")] public string? Kind { get; set; }
        [DataMember(Name = "severity")] public string? Severity { get; set; }
        [DataMember(Name = "state")] public string? State { get; set; }
        [DataMember(Name = "title")] public string? Title { get; set; }
        [DataMember(Name = "message")] public string? Message { get; set; }
        [DataMember(Name = "solution")] public string? Solution { get; set; }
        [DataMember(Name = "balloon")] public string? Balloon { get; set; }
        [DataMember(Name = "adapter")] public string? Adapter { get; set; }
        [DataMember(Name = "detected_at")] public long DetectedAt { get; set; }
        [DataMember(Name = "resolved_at")] public long? ResolvedAt { get; set; }

        public bool IsActive => State == "active";

        /// <summary>0 = info, 1 = warning, 2 = critical.</summary>
        public int Rank => Severity == "critical" ? 2 : Severity == "warning" ? 1 : 0;

        public string Id => FindingId ?? string.Empty;
    }

    /// <summary>Antwort von GET /tray/v1/findings?since=&lt;seq&gt;.</summary>
    [DataContract]
    public sealed class TrayFindingsResponse
    {
        [DataMember(Name = "notify")] public bool Notify { get; set; }
        [DataMember(Name = "latest_seq")] public long LatestSeq { get; set; }
        [DataMember(Name = "start_seq")] public long StartSeq { get; set; }
        [DataMember(Name = "findings")] public List<TrayFinding>? Findings { get; set; }
    }

    public enum FindingsPollStatus
    {
        Ok,

        /// <summary>Dienst antwortet nicht – beim nächsten Mal wieder versuchen.</summary>
        ServiceDown,

        /// <summary>404: Dienst kennt die Schnittstelle nicht (Server-Probe, ältere Version) – bis zum Neustart nicht mehr fragen.</summary>
        NotSupported,

        Failed,
    }

    public sealed class FindingsPoll
    {
        public FindingsPoll(FindingsPollStatus status, TrayFindingsResponse? response = null)
        {
            Status = status;
            Response = response;
        }

        public FindingsPollStatus Status { get; }

        public TrayFindingsResponse? Response { get; }

        public static FindingsPoll Interpret(int status, string body)
        {
            if (status == 404)
            {
                return new FindingsPoll(FindingsPollStatus.NotSupported);
            }

            var response = status == 200 ? Json.Read<TrayFindingsResponse>(body) : null;
            return response != null ? new FindingsPoll(FindingsPollStatus.Ok, response) : new FindingsPoll(FindingsPollStatus.Failed);
        }
    }

    public enum BalloonIcon
    {
        Info,
        Warning,
        Error,
    }

    /// <summary>Eine Sprechblase am Tray-Symbol; <see cref="Items"/> für das Detailfenster beim Klick.</summary>
    public sealed class Balloon
    {
        public Balloon(string title, string text, BalloonIcon icon, IList<TrayFinding> items)
        {
            Title = title;
            Text = text;
            Icon = icon;
            Items = items;
        }

        public string Title { get; }

        public string Text { get; }

        public BalloonIcon Icon { get; }

        public IList<TrayFinding> Items { get; }
    }

    /// <summary>
    /// Entscheidet, welche Client-Hinweise als Sprechblase erscheinen: Stand (seq) merken, nur Warnungen und
    /// kritische Hinweise zeigen, „erledigt“ nur für vorher gezeigte, höchstens eine Sprechblase je 15 s,
    /// mehr als 3 wartende zu einer zusammenfassen. Ohne WinForms, damit testbar.
    /// </summary>
    public sealed class FindingNotifier
    {
        public const int MaxBalloonTitle = 63;
        public const int MaxBalloonText = 255;
        public const int CombineAbove = 3;
        public const string Caption = "Wachtl – Netzwerk-Hinweise";
        public const string NoFindings = "Zurzeit gibt es keine Netzwerk-Hinweise für diesen PC.";

        public static readonly TimeSpan MinInterval = TimeSpan.FromSeconds(15);

        /// <summary>Beim Start des Tray noch gezeigt: aktive Hinweise, die höchstens so alt sind.</summary>
        public static readonly TimeSpan RecentWindow = TimeSpan.FromMinutes(10);

        private readonly Dictionary<string, TrayFinding> _active = new Dictionary<string, TrayFinding>(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _shown = new Dictionary<string, int>(StringComparer.Ordinal);
        private readonly List<TrayFinding> _queue = new List<TrayFinding>();
        private long? _cursor;
        private DateTime? _lastBalloon;

        /// <summary>Wert für ?since= der nächsten Abfrage.</summary>
        public long Cursor => _cursor ?? 0;

        public bool HasQueued => _queue.Count > 0;

        public int QueuedCount => _queue.Count;

        /// <summary>Aktive Hinweise, schwerste und neueste zuerst.</summary>
        public IList<TrayFinding> Active =>
            _active.Values.OrderByDescending(f => f.Rank).ThenByDescending(f => f.DetectedAt).ToList();

        public void Accept(TrayFindingsResponse response, DateTime utcNow)
        {
            if (_cursor.HasValue && response.LatestSeq < _cursor.Value)
            {
                // Dienst neu gestartet: Nummern beginnen neu – beim nächsten Mal alles holen
                _cursor = null;
                return;
            }

            // Dienst neu gestartet (neue Zählung beginnt über unserem Stand): bisher aktive Hinweise sind hinfällig,
            // der neue Dienst kennt sie nicht und meldet sie nie als erledigt
            var first = !_cursor.HasValue || response.StartSeq > _cursor.Value;
            if (first)
            {
                _active.Clear();
            }

            var nowS = new DateTimeOffset(DateTime.SpecifyKind(utcNow, DateTimeKind.Utc)).ToUnixTimeSeconds();
            var max = _cursor ?? 0;
            foreach (var f in (response.Findings ?? new List<TrayFinding>()).Where(f => !string.IsNullOrEmpty(f.FindingId)).OrderBy(f => f.Seq))
            {
                max = Math.Max(max, f.Seq);
                if (f.IsActive)
                {
                    _active[f.Id] = f;
                }
                else
                {
                    _active.Remove(f.Id);
                }

                if (!response.Notify)
                {
                    continue;
                }

                if (first)
                {
                    if (f.IsActive && f.Rank >= 1 && nowS - f.DetectedAt <= (long)RecentWindow.TotalSeconds)
                    {
                        Enqueue(f);
                    }
                }
                else
                {
                    Consider(f);
                }
            }

            if (!response.Notify)
            {
                _queue.Clear();
            }

            _cursor = Math.Max(max, response.LatestSeq);
        }

        private void Consider(TrayFinding f)
        {
            int shownRank;
            var shown = _shown.TryGetValue(f.Id, out shownRank);
            if (f.IsActive)
            {
                if (f.Rank >= 1 && (!shown || f.Rank > shownRank))
                {
                    Enqueue(f);
                }
            }
            else
            {
                _queue.RemoveAll(q => q.Id == f.Id); // noch nicht gezeigt und schon erledigt: gar nicht erst zeigen
                if (shown)
                {
                    _queue.Add(f);
                }
            }
        }

        private void Enqueue(TrayFinding f)
        {
            _queue.RemoveAll(q => q.Id == f.Id);
            _queue.Add(f);
        }

        /// <summary>Nächste Sprechblase oder null (nichts wartet oder die letzte ist keine 15 s her).</summary>
        public Balloon? Next(DateTime utcNow)
        {
            if (_queue.Count == 0 || (_lastBalloon.HasValue && utcNow - _lastBalloon.Value < MinInterval))
            {
                return null;
            }

            List<TrayFinding> items;
            if (_queue.Count > CombineAbove)
            {
                items = _queue.ToList();
                _queue.Clear();
            }
            else
            {
                items = new List<TrayFinding> { _queue[0] };
                _queue.RemoveAt(0);
            }

            foreach (var f in items)
            {
                if (f.IsActive)
                {
                    _shown[f.Id] = f.Rank;
                }
                else
                {
                    _shown.Remove(f.Id);
                }
            }

            _lastBalloon = utcNow;
            return items.Count == 1 ? Single(items[0]) : Combined(items);
        }

        private static Balloon Single(TrayFinding f)
        {
            var icon = !f.IsActive ? BalloonIcon.Info : f.Rank >= 2 ? BalloonIcon.Error : BalloonIcon.Warning;
            var title = Truncate(NonEmpty(f.Title, "Netzwerk-Hinweis"), MaxBalloonTitle);
            return new Balloon(title, BalloonText(f), icon, new List<TrayFinding> { f });
        }

        private static Balloon Combined(List<TrayFinding> items)
        {
            var active = items.Where(f => f.IsActive).ToList();
            var icon = active.Any(f => f.Rank >= 2) ? BalloonIcon.Error : active.Any(f => f.Rank >= 1) ? BalloonIcon.Warning : BalloonIcon.Info;
            var title = items.Count.ToString(CultureInfo.InvariantCulture) + " Netzwerk-Hinweise – Klicken für Details";
            var text = string.Join("\n", items.Select(f => "• " + NonEmpty(f.Title, "Netzwerk-Hinweis")));
            return new Balloon(Truncate(title, MaxBalloonTitle), Truncate(text, MaxBalloonText), icon, items);
        }

        /// <summary>Text der Sprechblase: Meldung und Lösung, höchstens 255 Zeichen (Grenze von Windows).</summary>
        public static string BalloonText(TrayFinding f)
        {
            if (f.IsActive && !string.IsNullOrWhiteSpace(f.Balloon))
            {
                return Truncate(f.Balloon!.Trim(), MaxBalloonText); // Kurzfassung der Probe (ab 0.8.1)
            }

            var text = NonEmpty(f.Message, NonEmpty(f.Title, "Netzwerk-Hinweis"));
            if (f.IsActive && !string.IsNullOrWhiteSpace(f.Solution))
            {
                text += "\nLösung: " + f.Solution!.Trim();
            }

            return Truncate(text, MaxBalloonText);
        }

        /// <summary>Vollständiger Text für das Detailfenster (Klick auf die Sprechblase, Menü „Netzwerk-Hinweise …“).</summary>
        public static string DetailText(IEnumerable<TrayFinding> findings)
        {
            var sb = new StringBuilder();
            foreach (var f in findings)
            {
                if (sb.Length > 0)
                {
                    sb.Append("\n\n");
                }

                sb.Append(NonEmpty(f.Title, "Netzwerk-Hinweis"));
                var when = DateTimeOffset.FromUnixTimeSeconds(f.IsActive || !f.ResolvedAt.HasValue ? f.DetectedAt : f.ResolvedAt.Value)
                    .ToLocalTime().ToString("dd.MM.yyyy HH:mm", CultureInfo.InvariantCulture);
                sb.Append(" (").Append(f.IsActive ? "seit " : "erledigt ").Append(when).Append(')');
                if (!string.IsNullOrWhiteSpace(f.Message))
                {
                    sb.Append('\n').Append(f.Message!.Trim());
                }

                if (f.IsActive && !string.IsNullOrWhiteSpace(f.Solution))
                {
                    sb.Append("\n\nLösung: ").Append(f.Solution!.Trim());
                }
            }

            return sb.Length == 0 ? NoFindings : sb.ToString();
        }

        /// <summary>Text für das Menü „Netzwerk-Hinweise …“.</summary>
        public string ActiveSummary() => DetailText(Active);

        public static string Truncate(string text, int max) =>
            text.Length <= max ? text : text.Substring(0, max - 1).TrimEnd() + "…";

        private static string NonEmpty(string? text, string fallback) =>
            string.IsNullOrWhiteSpace(text) ? fallback : text!.Trim();
    }
}
