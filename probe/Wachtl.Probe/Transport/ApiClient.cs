using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Wachtl.Probe.Config;

namespace Wachtl.Probe.Transport;

public enum IngestOutcome
{
    Delivered,
    Retry,
    Unauthorized,
}

public sealed class ApiException : Exception
{
    public ApiException(HttpStatusCode status, string message)
        : base($"HTTP {(int)status}: {message}")
    {
        Status = status;
        Detail = message;
    }

    public HttpStatusCode Status { get; }

    /// <summary>Fehlertext des Servers ohne Statuscode-Präfix.</summary>
    public string Detail { get; }

    public bool IsAuthError => Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden;
}

/// <summary>HTTPS-Client für die Probe-API mit Zertifikats-Pinning und optionalem Proxy.</summary>
public sealed class ApiClient : IDisposable
{
    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public static readonly JsonSerializerOptions JsonOptionsIndented = new(JsonOptions) { WriteIndented = true };

    private const string Prefix = "api/probe/v1/";
    private readonly HttpClient _http;
    private readonly string? _spkiPin;
    private readonly string? _token;
    private readonly object _serverLock = new();
    private Uri[] _servers;
    private int _current;

    public ApiClient(Uri serverUrl, string? spkiPin, string? proxyUrl, string? token = null)
        : this(new[] { serverUrl }, spkiPin, proxyUrl, token)
    {
    }

    /// <summary>
    /// Mehrere Adressen desselben Servers (Name, weitere Namen, IP-Adressen): ist eine nicht erreichbar –
    /// etwa weil der Name am Standort nicht auflösbar ist –, nimmt der Client die nächste.
    /// Der Pin prüft den Schlüssel, nicht den Namen: jede Adresse ist gleich sicher.
    /// </summary>
    public ApiClient(IEnumerable<Uri> servers, string? spkiPin, string? proxyUrl, string? token = null)
    {
        _servers = Normalize(servers);
        if (_servers.Length == 0)
        {
            throw new ArgumentException("Keine Server-Adresse angegeben");
        }

        _spkiPin = string.IsNullOrWhiteSpace(spkiPin) ? null : spkiPin.Trim();
        _token = token;
        var handler = new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = TimeSpan.FromSeconds(10),
            AutomaticDecompression = DecompressionMethods.GZip,
            SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = ValidateCertificate },
        };
        if (!string.IsNullOrWhiteSpace(proxyUrl))
        {
            handler.Proxy = new WebProxy(proxyUrl);
            handler.UseProxy = true;
        }

        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"wachtl-probe/{AppInfo.Version}");
    }

    /// <summary>Adresse, über die zuletzt erfolgreich verbunden wurde.</summary>
    public Uri CurrentServer
    {
        get
        {
            lock (_serverLock)
            {
                return _servers[_current];
            }
        }
    }

    public IReadOnlyList<Uri> Servers
    {
        get
        {
            lock (_serverLock)
            {
                return _servers.ToArray();
            }
        }
    }

    /// <summary>Wird ausgelöst, wenn der Client auf eine andere Adresse wechselt.</summary>
    public event Action<Uri>? ServerChanged;

    /// <summary>Neue Adressliste vom Server übernehmen; die funktionierende Adresse bleibt vorn.</summary>
    public void UpdateServers(IEnumerable<Uri> servers)
    {
        var list = Normalize(servers);
        if (list.Length == 0)
        {
            return;
        }

        lock (_serverLock)
        {
            var current = _servers[_current];
            var merged = new[] { current }.Concat(list).Distinct().ToArray();
            _servers = merged;
            _current = 0;
        }
    }

    internal static Uri[] Normalize(IEnumerable<Uri> servers) =>
        servers.Where(u => u is not null && u.IsAbsoluteUri)
            .Select(u => new Uri(u.GetLeftPart(UriPartial.Authority) + "/"))
            .Distinct()
            .ToArray();

    /// <summary>
    /// Anfrage senden; bei Verbindungsfehlern (Name nicht auflösbar, Host nicht erreichbar, Zeitüberschreitung)
    /// nacheinander die übrigen Adressen versuchen.
    /// </summary>
    private async Task<HttpResponseMessage> SendAsync(Func<HttpRequestMessage> build, CancellationToken ct)
    {
        Uri[] servers;
        int start;
        lock (_serverLock)
        {
            servers = _servers;
            start = _current;
        }

        Exception? last = null;
        for (var i = 0; i < servers.Length; i++)
        {
            var index = (start + i) % servers.Length;
            using var request = build();
            request.RequestUri = new Uri(servers[index], request.RequestUri!.OriginalString);
            try
            {
                var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
                if (i > 0)
                {
                    lock (_serverLock)
                    {
                        if (ReferenceEquals(_servers, servers))
                        {
                            _current = index;
                        }
                    }

                    ServerChanged?.Invoke(servers[index]);
                }

                return response;
            }
            catch (HttpRequestException ex) when (servers.Length > 1)
            {
                last = ex;
            }
            catch (TaskCanceledException ex) when (servers.Length > 1 && !ct.IsCancellationRequested)
            {
                last = ex;
            }
        }

        System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(last!).Throw();
        throw last!;
    }

    private bool ValidateCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (_spkiPin is null)
        {
            return errors == SslPolicyErrors.None;
        }

        if (certificate is null)
        {
            return false;
        }

        // Bei selbstsignierten Zertifikaten zählt allein der gepinnte Schlüssel.
        using var cert = new X509Certificate2(certificate);
        return SpkiPin.Matches(cert, _spkiPin);
    }

    private HttpRequestMessage Request(HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, new Uri(Prefix + path, UriKind.Relative));
        if (_token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        }

        return request;
    }

    private static async Task<ApiException> ErrorAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var message = body;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("error", out var err))
            {
                message = err.GetString() ?? body;
            }
        }
        catch (JsonException)
        {
        }

        return new ApiException(response.StatusCode, message.Length > 300 ? message[..300] : message);
    }

    public async Task<EnrollResponse> EnrollAsync(EnrollRequest enroll, CancellationToken ct)
    {
        using var response = await SendAsync(() =>
        {
            var request = Request(HttpMethod.Post, "enroll");
            request.Content = JsonContent.Create(enroll, options: JsonOptions);
            return request;
        }, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorAsync(response, ct).ConfigureAwait(false);
        }

        return await response.Content.ReadFromJsonAsync<EnrollResponse>(JsonOptions, ct).ConfigureAwait(false)
               ?? throw new ApiException(response.StatusCode, "leere Antwort");
    }

    /// <summary>Holt die Konfiguration; null bedeutet „unverändert“ (HTTP 304).</summary>
    public async Task<ProbeConfig?> GetConfigAsync(string? etag, CancellationToken ct)
    {
        using var response = await SendAsync(() =>
        {
            var request = Request(HttpMethod.Get, "config");
            if (!string.IsNullOrEmpty(etag))
            {
                request.Headers.TryAddWithoutValidation("If-None-Match", $"\"{etag}\"");
            }
            return request;
        }, ct).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            return null;
        }

        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorAsync(response, ct).ConfigureAwait(false);
        }

        return await response.Content.ReadFromJsonAsync<ProbeConfig>(JsonOptions, ct).ConfigureAwait(false);
    }

    public async Task<IngestOutcome> IngestAsync(string batchId, IEnumerable<string> lines, CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        await using (var gzip = new GZipStream(buffer, CompressionLevel.Fastest, leaveOpen: true))
        await using (var writer = new StreamWriter(gzip, new UTF8Encoding(false)))
        {
            foreach (var line in lines)
            {
                await writer.WriteAsync(line).ConfigureAwait(false);
                await writer.WriteAsync('\n').ConfigureAwait(false);
            }
        }

        using var response = await SendAsync(() =>
        {
            var request = Request(HttpMethod.Post, "ingest");
            request.Headers.Add("X-Batch-Id", batchId);
            request.Content = new ByteArrayContent(buffer.ToArray());
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain") { CharSet = "utf-8" };
            request.Content.Headers.ContentEncoding.Add("gzip");
            return request;
        }, ct).ConfigureAwait(false);
        return response.StatusCode switch
        {
            HttpStatusCode.NoContent or HttpStatusCode.OK => IngestOutcome.Delivered,
            // 422: alle Zeilen abgelehnt (z. B. Check inzwischen gelöscht) – nicht endlos wiederholen
            HttpStatusCode.UnprocessableEntity => IngestOutcome.Delivered,
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => IngestOutcome.Unauthorized,
            _ => IngestOutcome.Retry,
        };
    }

    public async Task<HeartbeatResponse> HeartbeatAsync(HeartbeatRequest heartbeat, CancellationToken ct)
    {
        using var response = await SendAsync(() =>
        {
            var request = Request(HttpMethod.Post, "heartbeat");
            request.Content = JsonContent.Create(heartbeat, options: JsonOptions);
            return request;
        }, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorAsync(response, ct).ConfigureAwait(false);
        }

        return await response.Content.ReadFromJsonAsync<HeartbeatResponse>(JsonOptions, ct).ConfigureAwait(false)
               ?? new HeartbeatResponse();
    }

    /// <summary>Probe am Server abmelden (Deinstallation): das Token wird dort sofort ungültig.</summary>
    public async Task DeregisterAsync(CancellationToken ct)
    {
        using var response = await SendAsync(() =>
        {
            var request = Request(HttpMethod.Post, "deregister");
            request.Content = new StringContent("{}", Encoding.UTF8, "application/json");
            return request;
        }, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorAsync(response, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Ergebnisse (Pfad, Bandbreite) als JSON senden.</summary>
    public async Task PostResultAsync<T>(string path, T payload, CancellationToken ct)
    {
        using var response = await SendAsync(() =>
        {
            var request = Request(HttpMethod.Post, path);
            request.Content = JsonContent.Create(payload, options: JsonOptions);
            return request;
        }, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorAsync(response, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Werkzeuge: nächsten Einzeltest holen (null = keiner wartet).</summary>
    public async Task<Tools.ToolJob?> GetToolJobAsync(CancellationToken ct)
    {
        using var response = await SendAsync(() => Request(HttpMethod.Get, "tools/next"), ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorAsync(response, ct).ConfigureAwait(false);
        }

        var body = await response.Content.ReadFromJsonAsync<Tools.ToolNextResponse>(JsonOptions, ct).ConfigureAwait(false);
        return body?.Job;
    }

    public void Dispose() => _http.Dispose();
}
