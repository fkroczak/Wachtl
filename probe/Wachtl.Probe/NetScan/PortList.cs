using System.Globalization;

namespace Wachtl.Probe.NetScan;

/// <summary>Portliste des Portscans: Komma-getrennt, Bereiche „8000-8010“ erlaubt, höchstens 1024 Ports.</summary>
public static class PortList
{
    public const string Default = "21,22,23,25,53,80,110,135,139,143,443,445,515,554,631,993,995,1883,3306,3389,5060,5432,5900,8006,8080,8443,9100";
    public const int MaxPorts = 1024;

    /// <summary>Ports aufsteigend und ohne Doppelte; leer = Standardliste. null und <paramref name="error"/> bei Fehlern.</summary>
    public static List<int>? Parse(string? spec, out string? error)
    {
        error = null;
        var text = string.IsNullOrWhiteSpace(spec) ? Default : spec;
        var ports = new SortedSet<int>();
        foreach (var raw in text.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var dash = raw.IndexOf('-');
            int from, to;
            if (dash < 0)
            {
                if (!TryPort(raw, out from))
                {
                    error = $"Ungültiger Port „{raw}“ (1–65535)";
                    return null;
                }

                to = from;
            }
            else if (!TryPort(raw[..dash], out from) || !TryPort(raw[(dash + 1)..], out to) || from > to)
            {
                error = $"Ungültiger Portbereich „{raw}“";
                return null;
            }

            if (to - from + 1 > MaxPorts)
            {
                error = $"Zu viele Ports (höchstens {MaxPorts})";
                return null;
            }

            for (var p = from; p <= to; p++)
            {
                ports.Add(p);
            }

            if (ports.Count > MaxPorts)
            {
                error = $"Zu viele Ports (höchstens {MaxPorts})";
                return null;
            }
        }

        return ports.ToList();
    }

    private static bool TryPort(string text, out int port) =>
        int.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
}
