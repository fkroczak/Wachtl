using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Wachtl.Probe.NetScan;

/// <summary>Auswertung einer HTTP-Antwort: Statuscode, <c>Server</c>-Header, Seitentitel.</summary>
public readonly record struct HttpInfo(int? Status, string? Server, string? Title);

/// <summary>
/// Diensterkennung je offenem Port (höchstens 2 s): Banner lesen, auf HTTP-Ports <c>HEAD /</c> und <c>GET /</c>,
/// auf TLS-Ports TLS-Handshake ohne Zertifikatsprüfung (nur zur Erkennung, es werden keine Daten vertraut).
/// </summary>
public static class ServiceProbe
{
    public const int MaxText = 200;
    public const int MaxBody = 16 * 1024;
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan BannerWait = TimeSpan.FromSeconds(1);

    /// <summary>Auf HTTP-Ports spricht der Server nie zuerst – kurz warten, damit Zeit für HEAD/GET bleibt.</summary>
    private static readonly TimeSpan HttpBannerWait = TimeSpan.FromMilliseconds(300);

    /// <summary>Typische HTTP-Ports (631 und 9100 bewusst nicht: Drucker reagieren darauf mit Ausdrucken o. Ä.).</summary>
    public static readonly HashSet<int> HttpPorts = new() { 80, 81, 443, 591, 5000, 8000, 8001, 8006, 8008, 8080, 8081, 8443, 8888, 9443 };

    /// <summary>Ports, auf denen direkt TLS gesprochen wird.</summary>
    public static readonly HashSet<int> TlsPorts = new() { 443, 8443, 8006, 9443 };

    private static readonly Regex TitleRegex = new(@"<title[^>]*>(.*?)(?:</title|$)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);

    private static readonly Regex Whitespace = new(@"\s+", RegexOptions.CultureInvariant);

    /// <summary>Text säubern: Steuerzeichen entfernen, Leerraum zusammenfassen, auf 200 Zeichen kürzen; leer = null.</summary>
    public static string? CleanText(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        var sb = new StringBuilder(Math.Min(text.Length, 1024));
        foreach (var c in text)
        {
            if (c is '\r' or '\n' or '\t')
            {
                sb.Append(' ');
            }
            else if (!char.IsControl(c) && c != '�')
            {
                sb.Append(c);
            }

            if (sb.Length > 4 * MaxText)
            {
                break;
            }
        }

        var clean = Whitespace.Replace(sb.ToString(), " ").Trim();
        if (clean.Length > MaxText)
        {
            var cut = char.IsHighSurrogate(clean[MaxText - 1]) ? MaxText - 1 : MaxText;
            clean = clean[..cut].TrimEnd();
        }

        return clean.Length == 0 ? null : clean;
    }

    /// <summary>Bytes als Text (UTF-8, ungültige Bytes fallen beim Säubern weg).</summary>
    public static string? CleanBytes(ReadOnlySpan<byte> data) => CleanText(Encoding.UTF8.GetString(data));

    /// <summary>Sieht wie TLS aus: Handshake (0x16) oder Alert (0x15), Version 3.x.</summary>
    public static bool LooksLikeTls(ReadOnlySpan<byte> data) =>
        data.Length >= 1 && data[0] is 0x16 or 0x15 && (data.Length < 2 || data[1] == 0x03);

    /// <summary>HTTP-Antwort auswerten. Kein „HTTP/“ am Anfang = alles null.</summary>
    public static HttpInfo ParseHttp(ReadOnlySpan<byte> data)
    {
        var text = Encoding.UTF8.GetString(data);
        if (!text.StartsWith("HTTP/", StringComparison.Ordinal))
        {
            return default;
        }

        var end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var sepLength = 4;
        if (end < 0)
        {
            end = text.IndexOf("\n\n", StringComparison.Ordinal);
            sepLength = 2;
        }

        var headers = end >= 0 ? text[..end] : text;
        var body = end >= 0 ? text[(end + sepLength)..] : string.Empty;
        var lines = headers.Split('\n');

        int? status = null;
        var statusParts = lines[0].Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (statusParts.Length >= 2 && int.TryParse(statusParts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var code) &&
            code is >= 100 and <= 999)
        {
            status = code;
        }

        string? server = null;
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':');
            if (colon > 0 && line[..colon].Trim().Equals("Server", StringComparison.OrdinalIgnoreCase))
            {
                server = CleanText(line[(colon + 1)..]);
                break;
            }
        }

        return new HttpInfo(status, server, ExtractTitle(body));
    }

    /// <summary>Inhalt von &lt;title&gt; mit aufgelösten HTML-Entities, gekürzt auf 200 Zeichen.</summary>
    public static string? ExtractTitle(string html)
    {
        var m = TitleRegex.Match(html);
        return m.Success ? CleanText(WebUtility.HtmlDecode(m.Groups[1].Value)) : null;
    }

    /// <summary>
    /// Dienst hinter einem offenen Port erkennen. <paramref name="client"/> ist die Verbindung des Portscans (für das Banner);
    /// HTTP/TLS laufen über neue Verbindungen. Höchstens 2 s, Teilergebnisse bleiben erhalten.
    /// </summary>
    internal static async Task<NetScanPort> DetectAsync(TcpClient client, IPAddress address, int port, TimeSpan connectTimeout,
        CancellationToken ct, bool? isHttp = null)
    {
        var info = new NetScanPort { Port = port };
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(Budget);
        try
        {
            await DetectCoreAsync(info, client, address, port, isHttp ?? HttpPorts.Contains(port), connectTimeout, budget.Token)
                .ConfigureAwait(false);
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            // Erkennung ist nur ein Zusatz: Zeitüberschreitung, Abbruch durch das Gerät, TLS-Fehler … – Port bleibt offen
        }

        return info;
    }

    private static async Task DetectCoreAsync(NetScanPort info, TcpClient client, IPAddress address, int port, bool http,
        TimeSpan connectTimeout, CancellationToken ct)
    {
        if (TlsPorts.Contains(port))
        {
            await HttpAsync(info, address, port, true, connectTimeout, ct).ConfigureAwait(false);
            return;
        }

        var banner = await ReadSomeAsync(client.GetStream(), 1024, http ? HttpBannerWait : BannerWait, ct).ConfigureAwait(false);
        if (banner.Length > 0)
        {
            if (LooksLikeTls(banner))
            {
                info.Tls = true;
                return;
            }

            var h = ParseHttp(banner);
            if (h.Status is not null)
            {
                Apply(info, h);
                return;
            }

            info.Banner = CleanBytes(banner);
            return;
        }

        if (http)
        {
            await HttpAsync(info, address, port, false, connectTimeout, ct).ConfigureAwait(false);
        }
    }

    /// <summary><c>HEAD /</c>, bei HTTP-Antwort zusätzlich <c>GET /</c> für den Titel. Antwortet der Port mit TLS: über TLS wiederholen.</summary>
    private static async Task HttpAsync(NetScanPort info, IPAddress address, int port, bool tls, TimeSpan connectTimeout,
        CancellationToken ct)
    {
        var head = await ExchangeAsync(info, address, port, tls, Request("HEAD", address, port, tls), 4096, connectTimeout, ct)
            .ConfigureAwait(false);
        if (head is null || head.Length == 0)
        {
            return;
        }

        if (!tls && LooksLikeTls(head))
        {
            await HttpAsync(info, address, port, true, connectTimeout, ct).ConfigureAwait(false);
            return;
        }

        var h = ParseHttp(head);
        if (h.Status is null)
        {
            info.Banner ??= CleanBytes(head);
            return;
        }

        Apply(info, h);
        var get = await ExchangeAsync(info, address, port, tls, Request("GET", address, port, tls), MaxBody, connectTimeout, ct)
            .ConfigureAwait(false);
        if (get is { Length: > 0 })
        {
            var g = ParseHttp(get);
            info.HttpTitle = g.Title;
            info.HttpServer ??= g.Server;
            if (info.HttpStatus is 405 or 501 && g.Status is not null)
            {
                info.HttpStatus = g.Status;   // HEAD nicht unterstützt
            }
        }
    }

    private static void Apply(NetScanPort info, HttpInfo h)
    {
        info.HttpStatus = h.Status;
        info.HttpServer = h.Server;
        info.HttpTitle ??= h.Title;
    }

    private static string Request(string method, IPAddress address, int port, bool tls)
    {
        var host = port == (tls ? 443 : 80) ? address.ToString() : $"{address}:{port}";
        return $"{method} / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Wachtl-Probe/{AppInfo.Version}\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    }

    /// <summary>Neue Verbindung (optional TLS), Anfrage senden, Antwort bis Verbindungsende bzw. <paramref name="max"/> Bytes lesen.</summary>
    private static async Task<byte[]?> ExchangeAsync(NetScanPort info, IPAddress address, int port, bool tls, string request, int max,
        TimeSpan connectTimeout, CancellationToken ct)
    {
        var (client, _) = await NetScanner.ConnectAsync(address, port, connectTimeout, ct).ConfigureAwait(false);
        if (client is null)
        {
            return null;
        }

        using (client)
        {
            Stream stream = client.GetStream();
            SslStream? ssl = null;
            try
            {
                if (tls)
                {
                    ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = address.ToString(),
                        // nur Erkennung: Geräte im LAN haben fast immer selbstsignierte Zertifikate
                        RemoteCertificateValidationCallback = static (_, _, _, _) => true,
                    }, ct).ConfigureAwait(false);
                    info.Tls = true;
                    info.TlsSubject ??= CleanText(ssl.RemoteCertificate?.Subject);
                    stream = ssl;
                }

                var bytes = Encoding.ASCII.GetBytes(request);
                await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                return await ReadAllAsync(stream, max, ct).ConfigureAwait(false);
            }
            finally
            {
                ssl?.Dispose();
            }
        }
    }

    /// <summary>Bis Verbindungsende oder <paramref name="max"/> Bytes lesen; bei Abbruch nach ersten Daten das Gelesene.</summary>
    private static async Task<byte[]> ReadAllAsync(Stream stream, int max, CancellationToken ct)
    {
        var buffer = new byte[max];
        var total = 0;
        try
        {
            while (total < max)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(total, max - total), ct).ConfigureAwait(false);
                if (n == 0)
                {
                    break;
                }

                total += n;
            }
        }
        catch (Exception ex) when (total > 0 && ex is OperationCanceledException or IOException)
        {
        }

        return buffer[..total];
    }

    /// <summary>Höchstens <paramref name="wait"/> auf Daten warten (Banner). Nichts gekommen = leeres Array.</summary>
    private static async Task<byte[]> ReadSomeAsync(Stream stream, int max, TimeSpan wait, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(wait);
        var buffer = new byte[max];
        try
        {
            var n = await stream.ReadAsync(buffer.AsMemory(), timeout.Token).ConfigureAwait(false);
            return buffer[..n];
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return Array.Empty<byte>();
        }
        catch (IOException)
        {
            return Array.Empty<byte>();
        }
    }
}
