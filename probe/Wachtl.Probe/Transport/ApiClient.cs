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
    }

    public HttpStatusCode Status { get; }

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

    public ApiClient(Uri serverUrl, string? spkiPin, string? proxyUrl, string? token = null)
    {
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

        var baseUrl = serverUrl.ToString().TrimEnd('/') + "/";
        _http = new HttpClient(handler) { BaseAddress = new Uri(baseUrl), Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"wachtl-probe/{AppInfo.Version}");
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
        var request = new HttpRequestMessage(method, Prefix + path);
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
        using var request = Request(HttpMethod.Post, "enroll");
        request.Content = JsonContent.Create(enroll, options: JsonOptions);
        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
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
        using var request = Request(HttpMethod.Get, "config");
        if (!string.IsNullOrEmpty(etag))
        {
            request.Headers.TryAddWithoutValidation("If-None-Match", $"\"{etag}\"");
        }

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
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

        using var request = Request(HttpMethod.Post, "ingest");
        request.Headers.Add("X-Batch-Id", batchId);
        request.Content = new ByteArrayContent(buffer.ToArray());
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain") { CharSet = "utf-8" };
        request.Content.Headers.ContentEncoding.Add("gzip");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
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
        using var request = Request(HttpMethod.Post, "heartbeat");
        request.Content = JsonContent.Create(heartbeat, options: JsonOptions);
        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorAsync(response, ct).ConfigureAwait(false);
        }

        return await response.Content.ReadFromJsonAsync<HeartbeatResponse>(JsonOptions, ct).ConfigureAwait(false)
               ?? new HeartbeatResponse();
    }

    public void Dispose() => _http.Dispose();
}
