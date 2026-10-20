using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Diagnostics;

/// <summary>
/// <c>wachtl-probe.exe diagnose</c>: dieselben Client-Hinweise wie der Probe-Dienst, aber ohne Dienst und ohne Server –
/// für den Wachtl-Server unter Windows. Die Server-Probe (Python) startet den Befehl, liest je Zustandsänderung eine
/// JSON-Zeile von stdout (Felder wie POST /api/probe/v1/findings, dazu <c>balloon</c>) und leitet sie an Tray und Server weiter.
/// Endet, sobald stdin geschlossen wird (Server-Probe beendet). Protokoll auf stderr.
/// </summary>
public static class DiagnoseCommand
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan EventSettle = TimeSpan.FromSeconds(1.5);

    public static async Task<int> RunAsync(TextReader stdin, TextWriter stdout)
    {
        using var loggerFactory = LoggerFactory.Create(b => b
            .SetMinimumLevel(LogLevel.Information)
            .AddSimpleConsole(o => o.TimestampFormat = "HH:mm:ss ")
            .AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace));
        var logger = loggerFactory.CreateLogger("wachtl.diagnose");
        using var cts = new CancellationTokenSource();

        // stdin zu: die Server-Probe läuft nicht mehr
        _ = Task.Run(() =>
        {
            try
            {
                while (stdin.ReadLine() is not null)
                {
                }
            }
            catch (IOException)
            {
            }

            cts.Cancel();
        });

        var wake = new SemaphoreSlim(0, 1);
        void OnChanged(object? s, EventArgs e)
        {
            try
            {
                if (wake.CurrentCount == 0)
                {
                    wake.Release();
                }
            }
            catch (SemaphoreFullException)
            {
            }
        }

        NetworkChange.NetworkAddressChanged += OnChanged;
        NetworkChange.NetworkAvailabilityChanged += OnChanged;
        var reader = new AdapterReader(logger);
        var evaluator = new FindingEvaluator();
        logger.LogInformation("Client-Hinweise für diesen Server gestartet");
        try
        {
            var afterEvent = false;
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    foreach (var finding in evaluator.Evaluate(reader.Read(DateTimeOffset.UtcNow, afterEvent)))
                    {
                        await stdout.WriteLineAsync(ToLine(finding)).ConfigureAwait(false);
                    }

                    await stdout.FlushAsync().ConfigureAwait(false);
                }
                catch (IOException)
                {
                    return 0; // stdout zu: die Server-Probe läuft nicht mehr
                }
                catch (Exception ex)
                {
                    logger.LogWarning("Netzwerkkarten konnten nicht geprüft werden: {Message}", ex.Message);
                }

                afterEvent = await wake.WaitAsync(PollInterval, cts.Token).ConfigureAwait(false);
                if (afterEvent)
                {
                    await Task.Delay(EventSettle, cts.Token).ConfigureAwait(false);
                    wake.Wait(0);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            NetworkChange.NetworkAddressChanged -= OnChanged;
            NetworkChange.NetworkAvailabilityChanged -= OnChanged;
        }

        return 0;
    }

    /// <summary>Eine Zeile JSON, snake_case wie die Probe-API, mit der Kurzfassung für die Sprechblase.</summary>
    public static string ToLine(ClientFinding finding)
    {
        var node = JsonSerializer.SerializeToNode(finding, ApiClient.JsonOptions)!.AsObject();
        node["balloon"] = finding.Balloon;
        return node.ToJsonString();
    }
}
