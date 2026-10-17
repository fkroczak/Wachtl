using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Wachtl.Tray.Core
{
    /// <summary>Ein Eintrag einer Auswahlliste: Wert für die Schnittstelle und deutscher Anzeigetext.</summary>
    public sealed class Choice
    {
        public Choice(string value, string label)
        {
            Value = value;
            Label = label;
        }

        public string Value { get; }

        public string Label { get; }

        public override string ToString() => Label;
    }

    /// <summary>Kategorien und Dauern laut docs/STOERUNGSMELDUNGEN.md.</summary>
    public static class ReportCatalog
    {
        public static readonly IList<Choice> Categories = new[]
        {
            new Choice("no_connection", "Keine Verbindung / Internet weg"),
            new Choice("slow", "Langsam / lange Ladezeiten"),
            new Choice("dropouts", "Aussetzer / Verbindungsabbrüche"),
            new Choice("voice_video", "Telefonie oder Video gestört"),
            new Choice("application", "Bestimmte Anwendung oder Website betroffen"),
            new Choice("other", "Sonstiges"),
        };

        public static readonly IList<Choice> Durations = new[]
        {
            new Choice("unknown", "Unbekannt"),
            new Choice("short", "Kurz (unter 1 Minute)"),
            new Choice("minutes", "Einige Minuten (1–15 Minuten)"),
            new Choice("long", "Länger (über 15 Minuten)"),
            new Choice("ongoing", "Dauert noch an"),
        };

        public const string DefaultDuration = "unknown";

        public static bool IsCategory(string? value) => Find(Categories, value) != null;

        public static bool IsDuration(string? value) => Find(Durations, value) != null;

        public static Choice? Find(IList<Choice> list, string? value)
        {
            foreach (var c in list)
            {
                if (c.Value == value)
                {
                    return c;
                }
            }

            return null;
        }
    }

    /// <summary>Eingaben aus dem Meldefenster.</summary>
    public sealed class ReportInput
    {
        /// <summary>true = „Jetzt“, sonst gilt <see cref="LocalTime"/>.</summary>
        public bool Now { get; set; } = true;

        /// <summary>Gewählte Uhrzeit in Ortszeit (DateTimePicker).</summary>
        public DateTime LocalTime { get; set; }

        public string? Category { get; set; }

        public string Duration { get; set; } = ReportCatalog.DefaultDuration;

        public string? Description { get; set; }

        public string User { get; set; } = string.Empty;
    }

    /// <summary>Prüfung, Zeitumrechnung und JSON-Aufbau einer Meldung – ohne WinForms.</summary>
    public static class ReportBuilder
    {
        public const int MaxDescription = 1000;
        public const int MaxUser = 128;
        public static readonly TimeSpan MaxAge = TimeSpan.FromDays(7);

        /// <summary>Erlaubter Vorlauf der gewählten Uhrzeit (Uhrenabweichung), wie beim Server.</summary>
        public static readonly TimeSpan MaxFuture = TimeSpan.FromMinutes(5);

        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>Ortszeit (oder UTC) in Unix-Sekunden UTC.</summary>
        public static long ToUnixSeconds(DateTime time)
        {
            var utc = time.Kind == DateTimeKind.Utc ? time : DateTime.SpecifyKind(time, DateTimeKind.Local).ToUniversalTime();
            return (long)Math.Floor((utc - Epoch).TotalSeconds);
        }

        public static DateTime FromUnixSecondsLocal(long seconds) => Epoch.AddSeconds(seconds).ToLocalTime();

        /// <summary>„DOMÄNE\Benutzer“ (ohne Domäne nur der Benutzer), höchstens 128 Zeichen.</summary>
        public static string FormatUser(string? domain, string? user)
        {
            var name = string.IsNullOrEmpty(domain) ? user ?? string.Empty : domain + "\\" + user;
            return name.Length > MaxUser ? name.Substring(0, MaxUser) : name;
        }

        /// <summary>Zeitpunkt der Meldung in Unix-Sekunden; bei „Jetzt“ der Zeitpunkt des Absendens.</summary>
        public static long OccurredAt(ReportInput input, DateTime utcNow) =>
            input.Now ? ToUnixSeconds(DateTime.SpecifyKind(utcNow, DateTimeKind.Utc)) : ToUnixSeconds(input.LocalTime);

        /// <summary>Deutscher Fehlertext oder null, wenn alles passt.</summary>
        public static string? Validate(ReportInput input, DateTime utcNow)
        {
            if (!ReportCatalog.IsCategory(input.Category))
            {
                return "Bitte wählen Sie aus, was passiert ist.";
            }

            if (!ReportCatalog.IsDuration(input.Duration))
            {
                return "Bitte wählen Sie aus, wie lange das Problem gedauert hat.";
            }

            if ((input.Description ?? string.Empty).Trim().Length > MaxDescription)
            {
                return "Die Beschreibung darf höchstens " + MaxDescription + " Zeichen lang sein.";
            }

            if (!input.Now)
            {
                var occurred = ToUnixSeconds(input.LocalTime);
                var now = ToUnixSeconds(DateTime.SpecifyKind(utcNow, DateTimeKind.Utc));
                if (occurred > now + (long)MaxFuture.TotalSeconds)
                {
                    return "Der Zeitpunkt liegt in der Zukunft.";
                }

                if (occurred < now - (long)MaxAge.TotalSeconds)
                {
                    return "Der Zeitpunkt darf höchstens 7 Tage zurückliegen.";
                }
            }

            return null;
        }

        /// <summary>Körper für POST /tray/v1/report.</summary>
        public static string ToJson(ReportInput input, DateTime utcNow)
        {
            var description = (input.Description ?? string.Empty).Trim();
            var user = input.User ?? string.Empty;
            var sb = new StringBuilder();
            sb.Append("{\"occurred_at\":").Append(OccurredAt(input, utcNow).ToString(CultureInfo.InvariantCulture));
            sb.Append(",\"category\":").Append(TrayJson.Quote(input.Category));
            sb.Append(",\"duration\":").Append(TrayJson.Quote(input.Duration));
            sb.Append(",\"description\":").Append(TrayJson.Quote(description));
            sb.Append(",\"user\":").Append(TrayJson.Quote(user.Length > MaxUser ? user.Substring(0, MaxUser) : user));
            sb.Append('}');
            return sb.ToString();
        }
    }
}
