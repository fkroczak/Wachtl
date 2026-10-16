using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Logging;

namespace Wachtl.Probe.Bandwidth;

/// <summary>Betreibt iperf3 als Server, wenn die Probe im Web-UI als Gegenstelle eingerichtet ist.</summary>
public sealed class IperfServerHost : IAsyncDisposable
{
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _task;

    public IperfServerHost(int port, ILogger logger)
    {
        Port = port;
        _logger = logger;
        _task = Task.Run(() => RunAsync(_cts.Token));
    }

    public int Port { get; }

    private async Task RunAsync(CancellationToken ct)
    {
        var exe = Iperf.FindExecutable();
        if (exe is null)
        {
            _logger.LogError("iperf3-Gegenstelle soll laufen, aber iperf3.exe fehlt – Probe-Setup ab Version 0.3 installieren");
            return;
        }

        var backoff = TimeSpan.FromSeconds(2);
        while (!ct.IsCancellationRequested)
        {
            var started = DateTime.UtcNow;
            try
            {
                var psi = new ProcessStartInfo(exe)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = Path.GetDirectoryName(exe)!,
                };
                psi.ArgumentList.Add("-s");
                psi.ArgumentList.Add("-p");
                psi.ArgumentList.Add(Port.ToString(CultureInfo.InvariantCulture));
                using var process = Process.Start(psi) ?? throw new InvalidOperationException("Start fehlgeschlagen");
                _logger.LogInformation("iperf3-Gegenstelle läuft auf Port {Port} (PID {Pid})", Port, process.Id);
                process.OutputDataReceived += (_, e) =>
                {
                    if (e.Data is { Length: > 0 } line && line.Contains("Accepted connection", StringComparison.Ordinal))
                    {
                        _logger.LogInformation("iperf3-Gegenstelle: {Line}", line.Trim());
                    }
                };
                process.ErrorDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrWhiteSpace(e.Data))
                    {
                        _logger.LogWarning("iperf3-Gegenstelle: {Line}", e.Data.Trim());
                    }
                };
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                try
                {
                    await process.WaitForExitAsync(ct).ConfigureAwait(false);
                    _logger.LogWarning("iperf3-Gegenstelle beendet (Code {Code}), Neustart folgt", process.ExitCode);
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

                    return;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError("iperf3-Gegenstelle konnte nicht gestartet werden: {Message}", ex.Message);
            }

            backoff = DateTime.UtcNow - started > TimeSpan.FromMinutes(1)
                ? TimeSpan.FromSeconds(2)
                : TimeSpan.FromSeconds(Math.Min(300, backoff.TotalSeconds * 2));
            try
            {
                await Task.Delay(backoff, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        await _task.ConfigureAwait(false);
        _cts.Dispose();
        _logger.LogInformation("iperf3-Gegenstelle gestoppt");
    }
}
