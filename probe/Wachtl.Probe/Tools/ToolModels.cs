using System.Globalization;
using System.Text.Json;

namespace Wachtl.Probe.Tools;

/// <summary>Einzeltest aus dem Web-UI (docs/WERKZEUGE.md), abgeholt über GET tools/next.</summary>
public sealed class ToolJob
{
    public long Id { get; init; }
    public string Tool { get; init; } = string.Empty;
    public JsonElement Args { get; init; }
}

public sealed class ToolNextResponse
{
    public ToolJob? Job { get; init; }
}

/// <summary>Fortschritt bzw. Ergebnis für POST tools/{id} – dasselbe Format wie die Server-Probe (serverprobe/tools.py).</summary>
public sealed class ToolUpdate
{
    public double? Progress { get; init; }
    public string? Step { get; init; }
    public List<string> Lines { get; init; } = new();
    public bool Done { get; init; }
    public bool Ok { get; init; }
    public ToolResult? Result { get; init; }
    public string? Error { get; init; }
}

public sealed class ToolResult
{
    public string? Headline { get; set; }
    /// <summary>ok | warn | bad</summary>
    public string? Verdict { get; set; }
    /// <summary>Zeilen [Bezeichnung, Wert, Klasse (good|warn|bad|leer)].</summary>
    public List<string[]> Summary { get; } = new();
    public ToolStats? Stats { get; set; }
    public ToolTable? Table { get; set; }

    public ToolResult Add(string label, string value, string cls = "")
    {
        Summary.Add(new[] { label, value, cls });
        return this;
    }
}

public sealed class ToolStats
{
    public int Sent { get; init; }
    public int Received { get; init; }
    public double Loss { get; init; }
    public double? Min { get; init; }
    public double? Avg { get; init; }
    public double? Max { get; init; }
    public double? Mdev { get; init; }
}

public sealed class ToolTable
{
    public string Title { get; init; } = string.Empty;
    public List<string> Head { get; init; } = new();
    public List<List<string>> Rows { get; } = new();
    public List<string> Classes { get; } = new();
}

/// <summary>Werte aus den Argumenten lesen; der Server hat sie schon geprüft (services/tools.py).</summary>
public static class ToolArgs
{
    public static string Str(this JsonElement a, string name, string fallback = "") =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? fallback
            : fallback;

    public static int Int(this JsonElement a, string name, int fallback, int lo, int hi)
    {
        if (a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
            && v.TryGetDouble(out var d))
        {
            return (int)Math.Clamp(Math.Round(d), lo, hi);
        }

        return fallback;
    }

    public static double Num(this JsonElement a, string name, double fallback, double lo, double hi) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
            ? Math.Clamp(v.GetDouble(), lo, hi)
            : fallback;

    public static bool Flag(this JsonElement a, string name, bool fallback = false) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v)
            ? v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => fallback }
            : fallback;

    public static List<int> Ints(this JsonElement a, string name)
    {
        var list = new List<int>();
        if (a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in v.EnumerateArray())
            {
                if (x.ValueKind == JsonValueKind.Number && x.TryGetInt32(out var i) && i is > 0 and < 65536)
                {
                    list.Add(i);
                }
            }
        }

        return list;
    }

    /// <summary>Millisekunden wie im Web-UI: unter 10 mit zwei, sonst mit einer Nachkommastelle, Komma als Trenner.</summary>
    public static string Ms(double? v) => v is null
        ? "–"
        : v.Value.ToString(v.Value < 10 ? "0.00" : "0.0", CultureInfo.InvariantCulture).Replace('.', ',');
}
