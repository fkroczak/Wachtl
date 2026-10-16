using System.Globalization;

namespace Wachtl.Probe.Bandwidth;

/// <summary>
/// Zeitplan für Bandbreitenmessungen (Ortszeit der Probe):
/// alle <c>scheduleMin</c> Minuten ab Mitternacht plus Versatz, nur im Zeitfenster und an den gewählten Wochentagen.
/// Intervalle über einen Tag zählen ab Montag 00:00.
/// </summary>
public static class Schedule
{
    public static DateTime? NextRun(DateTime afterLocal, int scheduleMin, int offsetMin, string windowStart, string windowEnd,
        string weekdays)
    {
        if (scheduleMin <= 0)
        {
            return null;
        }

        var start = ParseTimeOfDay(windowStart) ?? 0;
        var end = ParseTimeOfDay(windowEnd) ?? 1439;
        var days = string.IsNullOrWhiteSpace(weekdays) ? "1234567" : weekdays;
        var weekly = scheduleMin > 1440;
        var periodMinutes = weekly ? 10080 : 1440;
        var period = weekly ? TimeSpan.FromDays(7) : TimeSpan.FromDays(1);
        var first = afterLocal.Date;
        if (weekly)
        {
            first = first.AddDays(-(((int)first.DayOfWeek + 6) % 7));   // Montag
        }

        var offset = ((offsetMin % scheduleMin) + scheduleMin) % scheduleMin;
        for (var p = 0; p < 15; p++)
        {
            var periodStart = first + period * p;
            for (var m = offset; m < periodMinutes; m += scheduleMin)
            {
                var t = periodStart.AddMinutes(m);
                if (t <= afterLocal || !Allowed(t, start, end, days))
                {
                    continue;
                }

                return t;
            }
        }

        return null;
    }

    internal static bool Allowed(DateTime t, int startMin, int endMin, string weekdays)
    {
        var isoDay = ((int)t.DayOfWeek + 6) % 7 + 1;   // 1 = Montag … 7 = Sonntag
        if (!weekdays.Contains((char)('0' + isoDay)))
        {
            return false;
        }

        var tod = t.Hour * 60 + t.Minute;
        return startMin <= endMin ? tod >= startMin && tod <= endMin : tod >= startMin || tod <= endMin;
    }

    internal static int? ParseTimeOfDay(string? value) =>
        TimeOnly.TryParseExact(value ?? string.Empty, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var t)
            ? t.Hour * 60 + t.Minute
            : null;
}
