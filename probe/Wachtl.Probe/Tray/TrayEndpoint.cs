using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Config;

namespace Wachtl.Probe.Tray;

/// <summary>
/// Lokale Schnittstelle für wachtl-tray.exe: lauscht ausschließlich auf 127.0.0.1:&lt;port&gt; (TcpListener, kein http.sys)
/// und liefert gepufferte Störungsmeldungen regelmäßig nach. Ein belegter Port beendet den Dienst nicht.
/// </summary>
public sealed class TrayEndpoint : BackgroundService
{
    public const int DefaultPort = 47251;
    private const int MaxConcurrent = 8;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(60);

    private readonly ILogger _logger;
    private readonly ProbeStatus _status;
    private readonly PendingReports _pending;
    private readonly TrayApi _api;
    private readonly SemaphoreSlim _slots = new(MaxConcurrent, MaxConcurrent);

    public TrayEndpoint(ProbeStatus status, ILogger<TrayEndpoint> logger)
        : this(ResolvePort(), status, new PendingReports(Path.Combine(StateStore.DataDir, "reports-pending.json"), logger),
            logger)
    {
    }

    internal TrayEndpoint(int port, ProbeStatus status, PendingReports pending, ILogger logger)
    {
        Port = port;
        _status = status;
        _pending = pending;
        _logger = logger;
        _api = new TrayApi(port, status, pending, status.SendReportAsync, logger: logger);
    }

    public int Port { get; }

    /// <summary>WACHTL_TRAY_PORT (1–65535) oder 47251 – identisch im Tray-Programm.</summary>
    public static int ResolvePort(string? value = null)
    {
        value ??= Environment.GetEnvironmentVariable("WACHTL_TRAY_PORT");
        return int.TryParse(value?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port is > 0 and < 65536
            ? port
            : DefaultPort;
    }

    protected override Task ExecuteAsync(CancellationToken ct) =>
        Task.WhenAll(ListenAsync(ct), FlushLoopAsync(ct));

    private async Task ListenAsync(CancellationToken ct)
    {
        var listener = new TcpListener(IPAddress.Loopback, Port);
        try
        {
            // Verhindert, dass sich ein anderer Prozess per SO_REUSEADDR auf denselben Port setzt.
            if (OperatingSystem.IsWindows())
            {
                listener.ExclusiveAddressUse = true;
            }

            listener.Start();
        }
        catch (SocketException ex)
        {
            _logger.LogWarning("Tray-Schnittstelle 127.0.0.1:{Port} nicht verfügbar ({Message}) – „Problem melden“ funktioniert nicht, Messungen laufen weiter",
                Port, ex.Message);
            return;
        }

        _logger.LogInformation("Tray-Schnittstelle lauscht auf 127.0.0.1:{Port}", Port);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException ex)
                {
                    _logger.LogDebug("Tray-Verbindung nicht angenommen: {Message}", ex.Message);
                    continue;
                }

                if (!await _slots.WaitAsync(0, ct).ConfigureAwait(false))
                {
                    client.Dispose();
                    continue;
                }

                _ = HandleClientAsync(client, ct);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using (client)
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                timeout.CancelAfter(RequestTimeout + TrayApi.ImmediateSendTimeout);
                var stream = client.GetStream();
                TrayHttpResponse response;
                try
                {
                    using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
                    readTimeout.CancelAfter(RequestTimeout);
                    var request = await TrayHttp.ReadAsync(stream, readTimeout.Token).ConfigureAwait(false);
                    response = await _api.HandleAsync(request, timeout.Token).ConfigureAwait(false);
                }
                catch (TrayHttpException ex)
                {
                    response = TrayHttpResponse.Error(ex.Status, ex.Message);
                }

                await stream.WriteAsync(TrayHttp.Format(response), timeout.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            _logger.LogDebug("Tray-Verbindung abgebrochen: {Message}", ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Fehler in der Tray-Schnittstelle");
        }
        finally
        {
            _slots.Release();
        }
    }

    private async Task FlushLoopAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
            while (!ct.IsCancellationRequested)
            {
                if (_pending.Count > 0 && _status.CanSend)
                {
                    try
                    {
                        await _pending.FlushAsync(_status.SendReportAsync, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (!ct.IsCancellationRequested)
                    {
                        _logger.LogWarning("Nachliefern der Störungsmeldungen fehlgeschlagen: {Message}", ex.Message);
                    }
                }

                await Task.Delay(FlushInterval, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }
}
