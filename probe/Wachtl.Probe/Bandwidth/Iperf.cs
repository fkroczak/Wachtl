using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Wachtl.Probe.Config;

namespace Wachtl.Probe.Bandwidth;

public sealed record IperfOptions(
    string Host,
    int Port,
    string Protocol,
    int DurationS,
    int OmitS,
    int Streams,
    double UdpMbps,
    int WindowKb,
    int TimeoutS);

/// <summary>Startet iperf3.exe (beigelegt im Probe-Setup) und wertet die JSON-Ausgabe aus.</summary>
public static class Iperf
{
    public static string? FindExecutable()
    {
        foreach (var candidate in new[]
                 {
                     Path.Combine(AppContext.BaseDirectory, "iperf3", "iperf3.exe"),
                     Path.Combine(AppContext.BaseDirectory, "iperf3.exe"),
                 })
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    public static IReadOnlyList<string> ClientArguments(IperfOptions o, bool reverse)
    {
        var args = new List<string>
        {
            "-c", o.Host, "-p", o.Port.ToString(CultureInfo.InvariantCulture), "-J",
            "-t", o.DurationS.ToString(CultureInfo.InvariantCulture),
            "-P", Math.Clamp(o.Streams, 1, 32).ToString(CultureInfo.InvariantCulture),
            "--connect-timeout", "5000",
        };
        if (o.OmitS > 0)
        {
            args.AddRange(new[] { "-O", o.OmitS.ToString(CultureInfo.InvariantCulture) });
        }

        if (o.Protocol == "udp")
        {
            args.AddRange(new[] { "-u", "-b", o.UdpMbps.ToString("0.###", CultureInfo.InvariantCulture) + "M" });
        }
        else if (o.WindowKb > 0)
        {
            args.AddRange(new[] { "-w", o.WindowKb.ToString(CultureInfo.InvariantCulture) + "K" });
        }

        if (reverse)
        {
            args.Add("-R");
        }

        return args;
    }

    /// <summary>Eine Messung in eine Richtung. „down“ = Gegenstelle sendet (-R), „up“ = Probe sendet.</summary>
    public static async Task<BandwidthMeasurement> RunAsync(IperfOptions o, string direction, CancellationToken ct)
    {
        var result = new BandwidthMeasurement { Direction = direction, Protocol = o.Protocol, Peer = $"{o.Host}:{o.Port}" };
        var exe = FindExecutable();
        if (exe is null)
        {
            result.Error = "iperf3.exe nicht gefunden – Probe-Setup ab Version 0.3 installieren";
            return result;
        }

        // Ein iperf3-Server nimmt immer nur einen Test an: bei „busy“ später erneut versuchen.
        for (var attempt = 0; ; attempt++)
        {
            var (exitCode, stdout, stderr) = await ExecuteAsync(exe, ClientArguments(o, direction == "down"),
                TimeSpan.FromSeconds(Math.Max(o.TimeoutS, o.DurationS + 15)), ct).ConfigureAwait(false);
            Parse(stdout, result);
            if (result.Error is null && exitCode != 0 && result.Mbps is null)
            {
                result.Error = string.IsNullOrWhiteSpace(stderr) ? $"iperf3 beendet mit Code {exitCode}" : stderr.Trim();
            }

            if (result.Error is not null && result.Error.Contains("busy", StringComparison.OrdinalIgnoreCase) && attempt < 3)
            {
                result.Error = null;
                await Task.Delay(TimeSpan.FromSeconds(20 + Random.Shared.Next(0, 30)), ct).ConfigureAwait(false);
                continue;
            }

            return result;
        }
    }

    /// <summary>Wertet die JSON-Ausgabe von <c>iperf3 -J</c> aus (TCP und UDP).</summary>
    public static void Parse(string json, BandwidthMeasurement result)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            result.Error ??= "keine Ausgabe von iperf3";
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out var err) && err.ValueKind == JsonValueKind.String)
            {
                result.Error = err.GetString();
                return;
            }

            if (!root.TryGetProperty("end", out var end))
            {
                result.Error = "iperf3-Ergebnis unvollständig";
                return;
            }

            JsonElement sum;
            if (result.Protocol == "udp")
            {
                sum = end.TryGetProperty("sum_received", out var sr) && sr.TryGetProperty("bits_per_second", out _)
                    ? sr
                    : end.GetProperty("sum");
                var stats = end.TryGetProperty("sum", out var s) ? s : sum;
                result.JitterMs = Number(stats, "jitter_ms");
                result.LossPct = Number(stats, "lost_percent");
            }
            else
            {
                sum = end.GetProperty("sum_received");
                if (end.TryGetProperty("sum_sent", out var sent) && Number(sent, "retransmits") is double r)
                {
                    result.Retransmits = (long)r;
                }
            }

            if (Number(sum, "bits_per_second") is double bps)
            {
                result.Mbps = Math.Round(bps / 1_000_000, 2);
            }

            result.DurationS = Number(sum, "seconds") is double sec ? Math.Round(sec, 1) : null;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            result.Error = "iperf3-Ausgabe nicht lesbar: " + ex.Message;
        }
    }

    private static double? Number(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
            ? v.GetDouble()
            : null;

    internal static async Task<(int ExitCode, string Stdout, string Stderr)> ExecuteAsync(
        string exe, IEnumerable<string> args, TimeSpan timeout, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(exe)!,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("iperf3 konnte nicht gestartet werden");
        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            if (ct.IsCancellationRequested)
            {
                throw;
            }

            return (-1, string.Empty, $"Abbruch nach {timeout.TotalSeconds:0} s – Gegenstelle antwortet nicht");
        }

        return (process.ExitCode, await stdoutTask.ConfigureAwait(false), await stderrTask.ConfigureAwait(false));
    }
}
