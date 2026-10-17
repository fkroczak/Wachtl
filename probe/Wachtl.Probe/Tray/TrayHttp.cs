using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Wachtl.Probe.Tray;

/// <summary>Eine HTTP-Anfrage des Tray-Programms (eine Anfrage je Verbindung).</summary>
public sealed class TrayHttpRequest
{
    public string Method { get; init; } = string.Empty;

    /// <summary>Pfad ohne Query-String.</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Query-String ohne „?“ (leer, wenn keiner).</summary>
    public string Query { get; init; } = string.Empty;

    public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public string Body { get; init; } = string.Empty;

    public string? Header(string name) => Headers.TryGetValue(name, out var value) ? value : null;

    /// <summary>Wert eines Query-Parameters (ohne URL-Dekodierung – die Tray-API nutzt nur Zahlen) oder null.</summary>
    public string? QueryValue(string name)
    {
        foreach (var pair in Query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            var key = eq < 0 ? pair : pair[..eq];
            if (string.Equals(key, name, StringComparison.Ordinal))
            {
                return eq < 0 ? string.Empty : pair[(eq + 1)..];
            }
        }

        return null;
    }
}

public sealed class TrayHttpResponse
{
    public TrayHttpResponse(int status, string json)
    {
        Status = status;
        Json = json;
    }

    public int Status { get; }

    public string Json { get; }

    public static TrayHttpResponse Error(int status, string message) =>
        new(status, JsonSerializer.Serialize(new Dictionary<string, string> { ["error"] = message }));
}

/// <summary>Fehler beim Lesen der Anfrage, wird direkt mit diesem Status beantwortet.</summary>
public sealed class TrayHttpException : Exception
{
    public TrayHttpException(int status, string message)
        : base(message)
    {
        Status = status;
    }

    public int Status { get; }
}

/// <summary>
/// Minimaler HTTP/1.1-Parser für die lokale Tray-Schnittstelle. Bewusst ohne http.sys/HttpListener:
/// keine URL-ACL, kein Konflikt mit anderen Diensten, volle Kontrolle über Limits.
/// </summary>
public static class TrayHttp
{
    public const int MaxHeaderBytes = 8 * 1024;
    public const int MaxBodyBytes = 16 * 1024;

    private static readonly byte[] HeaderEnd = "\r\n\r\n"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static async Task<TrayHttpRequest> ReadAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[MaxHeaderBytes + MaxBodyBytes];
        var filled = 0;
        int headerEnd;
        while ((headerEnd = IndexOf(buffer, filled, HeaderEnd)) < 0)
        {
            if (filled >= MaxHeaderBytes)
            {
                throw new TrayHttpException(431, "Kopfzeilen zu groß.");
            }

            var read = await stream.ReadAsync(buffer.AsMemory(filled, MaxHeaderBytes - filled), ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw new TrayHttpException(400, "Unvollständige Anfrage.");
            }

            filled += read;
        }

        var head = Encoding.ASCII.GetString(buffer, 0, headerEnd);
        var (method, path, query, headers) = ParseHead(head);
        var length = ContentLength(headers);

        var bodyStart = headerEnd + HeaderEnd.Length;
        var have = filled - bodyStart;
        if (have > length)
        {
            throw new TrayHttpException(400, "Körper länger als Content-Length.");
        }

        var body = new byte[length];
        Array.Copy(buffer, bodyStart, body, 0, have);
        while (have < length)
        {
            var read = await stream.ReadAsync(body.AsMemory(have, length - have), ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw new TrayHttpException(400, "Unvollständiger Körper.");
            }

            have += read;
        }

        string text;
        try
        {
            text = StrictUtf8.GetString(body);
        }
        catch (DecoderFallbackException)
        {
            throw new TrayHttpException(400, "Körper ist kein gültiges UTF-8.");
        }

        return new TrayHttpRequest { Method = method, Path = path, Query = query, Headers = headers, Body = text };
    }

    /// <summary>Zerlegt Anfragezeile und Kopfzeilen (ohne die abschließende Leerzeile).</summary>
    public static (string Method, string Path, string Query, Dictionary<string, string> Headers) ParseHead(string head)
    {
        var lines = head.Split("\r\n");
        var parts = lines[0].Split(' ');
        if (parts.Length != 3 || parts[0].Length == 0 || !parts[1].StartsWith('/') || !parts[2].StartsWith("HTTP/1.", StringComparison.Ordinal))
        {
            throw new TrayHttpException(400, "Ungültige Anfragezeile.");
        }

        var path = parts[1];
        var query = string.Empty;
        var mark = path.IndexOf('?');
        if (mark >= 0)
        {
            query = path[(mark + 1)..];
            path = path[..mark];
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0 || line[0] is ' ' or '\t')
            {
                throw new TrayHttpException(400, "Ungültige Kopfzeile.");
            }

            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (headers.ContainsKey(name))
            {
                // Doppelte Host-/Content-Length-/Schutz-Kopfzeilen sind ein typisches Schmuggel-Muster.
                throw new TrayHttpException(400, $"Kopfzeile {name} doppelt.");
            }

            headers[name] = value;
        }

        return (parts[0], path, query, headers);
    }

    private static int ContentLength(Dictionary<string, string> headers)
    {
        if (headers.ContainsKey("Transfer-Encoding"))
        {
            throw new TrayHttpException(400, "Transfer-Encoding wird nicht unterstützt.");
        }

        if (!headers.TryGetValue("Content-Length", out var value))
        {
            return 0;
        }

        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var length))
        {
            throw new TrayHttpException(400, "Ungültige Content-Length.");
        }

        if (length > MaxBodyBytes)
        {
            throw new TrayHttpException(413, "Anfrage zu groß (höchstens 16 KB).");
        }

        return (int)length;
    }

    private static int IndexOf(byte[] buffer, int count, byte[] pattern) => buffer.AsSpan(0, count).IndexOf(pattern);

    public static byte[] Format(TrayHttpResponse response)
    {
        var body = Encoding.UTF8.GetBytes(response.Json);
        var reason = Reason(response.Status);
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"HTTP/1.1 {response.Status} {reason}\r\n");
        sb.Append("Content-Type: application/json; charset=utf-8\r\n");
        sb.Append(CultureInfo.InvariantCulture, $"Content-Length: {body.Length}\r\n");
        sb.Append("Cache-Control: no-store\r\n");
        sb.Append("X-Content-Type-Options: nosniff\r\n");
        sb.Append("Connection: close\r\n\r\n");
        var head = Encoding.ASCII.GetBytes(sb.ToString());
        var result = new byte[head.Length + body.Length];
        head.CopyTo(result, 0);
        body.CopyTo(result, head.Length);
        return result;
    }

    private static string Reason(int status) => status switch
    {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
}
