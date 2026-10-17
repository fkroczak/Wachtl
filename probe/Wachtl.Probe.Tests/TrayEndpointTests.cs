using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Wachtl.Probe.Config;
using Wachtl.Probe.Diagnostics;
using Wachtl.Probe.Tray;
using Wachtl.Tray.Core;

namespace Wachtl.Probe.Tests;

public sealed class TrayEndpointTests : IDisposable
{
    private const int Port = 47251;
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_792_230_000);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "wachtl-tray-" + Guid.NewGuid().ToString("N"));
    private readonly ProbeStatus _status = new();
    private readonly List<ServerReport> _sent = new();
    private ReportSendOutcome _outcome = ReportSendOutcome.Delivered;

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    private string PendingPath => Path.Combine(_dir, "reports-pending.json");

    private Task<ReportSendResult> FakeSend(ServerReport report, CancellationToken ct)
    {
        _sent.Add(report);
        return Task.FromResult(new ReportSendResult(_outcome, _outcome == ReportSendOutcome.Rejected ? "occurred_at ungültig" : null));
    }

    private readonly FindingFeed _feed = new(startSeq: 1000);

    private TrayApi Api(PendingReports? pending = null, RateLimiter? rate = null) =>
        new(Port, _status, pending ?? new PendingReports(PendingPath), FakeSend, rate, () => Now, "PC-TEST", findings: _feed);

    private static TrayHttpRequest Request(string method, string path, string body = "", string host = "127.0.0.1:47251",
        string? tray = "1", string contentType = "application/json", string query = "")
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Host"] = host, ["Content-Type"] = contentType };
        if (tray is not null)
        {
            headers["X-Wachtl-Tray"] = tray;
        }

        return new TrayHttpRequest { Method = method, Path = path, Query = query, Headers = headers, Body = body };
    }

    private static string ReportBody(long occurred, string category = "slow", string? extra = null) =>
        $"{{\"occurred_at\":{occurred},\"category\":\"{category}\",\"duration\":\"minutes\",\"description\":\"Teams ruckelt\",\"user\":\"KUNDE\\\\mm\"{extra}}}";

    private void Enroll() => _status.Attach(new ProbeState { ServerUrl = "https://wachtl.kunde.local/", SiteName = "Zentrale" }, null);

    // -- HTTP-Parser --------------------------------------------------------

    [Fact]
    public async Task ReadsRequestWithBodyAndStripsQuery()
    {
        var raw = "POST /tray/v1/report?x=1 HTTP/1.1\r\nHost: 127.0.0.1:47251\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        var request = await TrayHttp.ReadAsync(new MemoryStream(Encoding.UTF8.GetBytes(raw)), CancellationToken.None);
        Assert.Equal("POST", request.Method);
        Assert.Equal("/tray/v1/report", request.Path);
        Assert.Equal("127.0.0.1:47251", request.Header("host"));
        Assert.Equal("{\"a\":1}", request.Body);
        Assert.Equal("x=1", request.Query);
        Assert.Equal("1", request.QueryValue("x"));
        Assert.Null(request.QueryValue("since"));
    }

    [Theory]
    [InlineData("GET / HTTP/1.1\r\nContent-Length: 16385\r\n\r\n", 413)]
    [InlineData("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 400)]
    [InlineData("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 400)]
    [InlineData("GET /\r\n\r\n", 400)]
    [InlineData("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab", 400)]
    public async Task RejectsBadRequests(string raw, int status)
    {
        var ex = await Assert.ThrowsAsync<TrayHttpException>(() =>
            TrayHttp.ReadAsync(new MemoryStream(Encoding.ASCII.GetBytes(raw)), CancellationToken.None));
        Assert.Equal(status, ex.Status);
    }

    [Fact]
    public async Task RejectsOversizedHeaders()
    {
        var raw = "GET / HTTP/1.1\r\nX-Pad: " + new string('a', TrayHttp.MaxHeaderBytes) + "\r\n\r\n";
        var ex = await Assert.ThrowsAsync<TrayHttpException>(() =>
            TrayHttp.ReadAsync(new MemoryStream(Encoding.ASCII.GetBytes(raw)), CancellationToken.None));
        Assert.Equal(431, ex.Status);
    }

    // -- Schutzregeln -------------------------------------------------------

    [Theory]
    [InlineData("GET", "127.0.0.1:47251", "1", "application/json", 200)]
    [InlineData("GET", "localhost:47251", "1", "", 200)]
    [InlineData("GET", "127.0.0.1:47251", null, "", 403)]
    [InlineData("GET", "127.0.0.1:47251", "true", "", 403)]
    [InlineData("GET", "evil.example:47251", "1", "", 403)]
    [InlineData("GET", "127.0.0.1:8080", "1", "", 403)]
    [InlineData("GET", "127.0.0.1", "1", "", 403)]
    [InlineData("POST", "127.0.0.1:47251", "1", "text/plain", 403)]
    [InlineData("POST", "127.0.0.1:47251", "1", "application/x-www-form-urlencoded", 403)]
    public async Task GuardsHeaders(string method, string host, string? tray, string contentType, int expected)
    {
        Enroll();
        var path = method == "GET" ? TrayApi.StatusPath : TrayApi.ReportPath;
        var response = await Api().HandleAsync(Request(method, path, ReportBody(Now.ToUnixTimeSeconds()), host, tray, contentType), default);
        Assert.Equal(expected, response.Status == 202 ? 200 : response.Status);
    }

    [Fact]
    public async Task RoutesUnknownPathAndMethod()
    {
        Assert.Equal(404, (await Api().HandleAsync(Request("GET", "/tray/v1/nix"), default)).Status);
        Assert.Equal(405, (await Api().HandleAsync(Request("POST", TrayApi.StatusPath, "{}"), default)).Status);
        Assert.Equal(405, (await Api().HandleAsync(Request("GET", TrayApi.ReportPath), default)).Status);
    }

    [Fact]
    public async Task StatusMatchesContract()
    {
        Enroll();
        _status.MarkContact(Now.AddSeconds(-30));
        var response = await Api().HandleAsync(Request("GET", TrayApi.StatusPath), default);
        using var doc = JsonDocument.Parse(response.Json);
        var root = doc.RootElement;
        Assert.Equal("probe", root.GetProperty("role").GetString());
        Assert.Equal("PC-TEST", root.GetProperty("name").GetString());
        Assert.Equal("Zentrale", root.GetProperty("site").GetString());
        Assert.Equal("https://wachtl.kunde.local", root.GetProperty("server_url").GetString());
        Assert.Equal("", root.GetProperty("dashboard_url").GetString());
        Assert.True(root.GetProperty("enrolled").GetBoolean());
        Assert.True(root.GetProperty("connected").GetBoolean());
        Assert.Equal(Now.ToUnixTimeSeconds() - 30, root.GetProperty("last_contact").GetInt64());
        Assert.Equal(0, root.GetProperty("pending_reports").GetInt32());
        Assert.True(root.TryGetProperty("version", out _));
    }

    [Fact]
    public void ConnectedOnlyWithinTwoMinutes()
    {
        Assert.False(_status.IsConnected(Now));
        _status.MarkContact(Now.AddMinutes(-3));
        Assert.False(_status.IsConnected(Now));
        _status.MarkContact(Now.AddSeconds(-119));
        Assert.True(_status.IsConnected(Now));
    }

    // -- Meldungen ----------------------------------------------------------

    [Fact]
    public async Task ReportNotEnrolledIs409()
    {
        var response = await Api().HandleAsync(Request("POST", TrayApi.ReportPath, ReportBody(Now.ToUnixTimeSeconds())), default);
        Assert.Equal(409, response.Status);
    }

    [Fact]
    public async Task DeliveredReportGetsIdAndHostname()
    {
        Enroll();
        var response = await Api().HandleAsync(Request("POST", TrayApi.ReportPath, ReportBody(Now.ToUnixTimeSeconds() - 600)), default);
        Assert.Equal(202, response.Status);
        Assert.Equal("{\"ok\":true,\"delivered\":true}", response.Json);
        var sent = Assert.Single(_sent);
        Assert.True(Guid.TryParse(sent.ReportId, out _));
        Assert.Equal("PC-TEST", sent.Hostname);
        Assert.Equal("KUNDE\\mm", sent.User);
        Assert.Equal(Now.ToUnixTimeSeconds() - 600, sent.OccurredAt);
        Assert.Equal("minutes", sent.Duration);
    }

    [Fact]
    public async Task UnreachableServerQueuesReport()
    {
        Enroll();
        _outcome = ReportSendOutcome.Retry;
        var pending = new PendingReports(PendingPath);
        var response = await Api(pending).HandleAsync(Request("POST", TrayApi.ReportPath, ReportBody(Now.ToUnixTimeSeconds())), default);
        Assert.Equal("{\"ok\":true,\"delivered\":false}", response.Json);
        Assert.Equal(1, pending.Count);
        Assert.Equal(1, new PendingReports(PendingPath).Count);
    }

    [Fact]
    public async Task ServerRejectionIs400AndNotQueued()
    {
        Enroll();
        _outcome = ReportSendOutcome.Rejected;
        var pending = new PendingReports(PendingPath);
        var response = await Api(pending).HandleAsync(Request("POST", TrayApi.ReportPath, ReportBody(Now.ToUnixTimeSeconds())), default);
        Assert.Equal(400, response.Status);
        Assert.Contains("occurred_at ungültig", JsonDocument.Parse(response.Json).RootElement.GetProperty("error").GetString());
        Assert.Equal(0, pending.Count);
    }

    [Fact]
    public async Task RateLimitIs429After30PerHour()
    {
        Enroll();
        var api = Api();
        for (var i = 0; i < TrayApi.ReportsPerHour; i++)
        {
            Assert.Equal(202, (await api.HandleAsync(Request("POST", TrayApi.ReportPath, ReportBody(Now.ToUnixTimeSeconds())), default)).Status);
        }

        Assert.Equal(429, (await api.HandleAsync(Request("POST", TrayApi.ReportPath, ReportBody(Now.ToUnixTimeSeconds())), default)).Status);
    }

    [Fact]
    public void RateLimiterCountsPerKey()
    {
        var rate = new RateLimiter(1, TimeSpan.FromHours(1));
        Assert.True(rate.TryAcquire(Now, "KUNDE\\a"));
        Assert.False(rate.TryAcquire(Now, "kunde\\A"));
        Assert.True(rate.TryAcquire(Now, "KUNDE\\b"));
    }

    [Fact]
    public void RateLimiterWindowSlides()
    {
        var rate = new RateLimiter(2, TimeSpan.FromHours(1));
        Assert.True(rate.TryAcquire(Now));
        Assert.True(rate.TryAcquire(Now.AddMinutes(10)));
        Assert.False(rate.TryAcquire(Now.AddMinutes(59)));
        Assert.True(rate.TryAcquire(Now.AddMinutes(60)));
        Assert.False(rate.TryAcquire(Now.AddMinutes(61)));
    }

    [Theory]
    [InlineData("nicht json")]
    [InlineData("[]")]
    [InlineData("{\"category\":\"slow\"}")]
    [InlineData("{\"occurred_at\":\"1792230000\",\"category\":\"slow\"}")]
    [InlineData("{\"occurred_at\":1792230000,\"category\":\"kaputt\"}")]
    [InlineData("{\"occurred_at\":1792230000,\"category\":\"slow\",\"duration\":\"ewig\"}")]
    [InlineData("{\"occurred_at\":1792230000,\"category\":\"slow\",\"description\":42}")]
    [InlineData("{\"occurred_at\":1791620000,\"category\":\"slow\"}")] // älter als 7 Tage
    [InlineData("{\"occurred_at\":1792230400,\"category\":\"slow\"}")] // mehr als 5 min in der Zukunft
    public void ParserRejectsInvalidReports(string body)
    {
        Assert.Null(TrayReportParser.Parse(body, Now, "PC", out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void ParserLimitsTexts()
    {
        var tooLong = $"{{\"occurred_at\":1792230000,\"category\":\"other\",\"description\":\"{new string('x', 1001)}\"}}";
        Assert.Null(TrayReportParser.Parse(tooLong, Now, "PC", out _));

        var longUser = $"{{\"occurred_at\":1792230000,\"category\":\"other\",\"user\":\"{new string('u', 200)}\"}}";
        var report = TrayReportParser.Parse(longUser, Now, "PC", out _)!;
        Assert.Equal(128, report.User.Length);
        Assert.Equal("unknown", report.Duration);
        Assert.Equal("", report.Description);
    }

    // -- Client-Hinweise ----------------------------------------------------

    private static ClientFinding Finding(string id, string state = "active") => new()
    {
        FindingId = id, Kind = FindingKinds.CableUnplugged, Severity = "critical", State = state, Adapter = "Ethernet",
        AdapterDescription = "Intel", Title = "Netzwerkkabel getrennt", Message = "m", Solution = "s", DetectedAt = 1_792_229_990,
        ResolvedAt = state == "resolved" ? 1_792_230_000 : null, Details = new() { ["x"] = "y" },
    };

    [Fact]
    public async Task FindingsMatchContract()
    {
        _feed.Publish(Finding("a"));
        _feed.Publish(Finding("b"));
        _feed.Publish(Finding("a", "resolved"));

        var response = await Api().HandleAsync(Request("GET", TrayApi.FindingsPath, query: "since=0"), default);
        Assert.Equal(200, response.Status);
        using var doc = JsonDocument.Parse(response.Json);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("notify").GetBoolean());
        Assert.Equal(1003, root.GetProperty("latest_seq").GetInt64());
        var items = root.GetProperty("findings").EnumerateArray().ToList();
        Assert.Equal(new long[] { 1002, 1003 }, items.Select(i => i.GetProperty("seq").GetInt64()));
        var a = items[1];
        Assert.Equal("a", a.GetProperty("finding_id").GetString());
        Assert.Equal("resolved", a.GetProperty("state").GetString());
        Assert.Equal(1_792_230_000, a.GetProperty("resolved_at").GetInt64());
        Assert.Equal(JsonValueKind.Null, items[0].GetProperty("resolved_at").ValueKind);
        foreach (var name in new[] { "seq", "finding_id", "kind", "severity", "state", "title", "message", "solution", "adapter", "detected_at", "resolved_at" })
        {
            Assert.True(a.TryGetProperty(name, out _), name);
        }

        var since = await Api().HandleAsync(Request("GET", TrayApi.FindingsPath, query: "since=1002"), default);
        Assert.Single(JsonDocument.Parse(since.Json).RootElement.GetProperty("findings").EnumerateArray());
        var all = await Api().HandleAsync(Request("GET", TrayApi.FindingsPath), default);
        Assert.Equal(2, JsonDocument.Parse(all.Json).RootElement.GetProperty("findings").GetArrayLength());
    }

    [Theory]
    [InlineData("since=abc", 400)]
    [InlineData("since=-1", 400)]
    [InlineData("since=5&x=1", 200)]
    public async Task FindingsValidateSince(string query, int expected)
    {
        Assert.Equal(expected, (await Api().HandleAsync(Request("GET", TrayApi.FindingsPath, query: query), default)).Status);
    }

    [Fact]
    public async Task FindingsAreGuardedLikeTheRest()
    {
        Assert.Equal(403, (await Api().HandleAsync(Request("GET", TrayApi.FindingsPath, tray: null), default)).Status);
        Assert.Equal(403, (await Api().HandleAsync(Request("GET", TrayApi.FindingsPath, host: "evil.example:47251"), default)).Status);
        Assert.Equal(405, (await Api().HandleAsync(Request("POST", TrayApi.FindingsPath, "{}"), default)).Status);
    }

    [Fact]
    public async Task ConfigSwitchesNotifyAndMonitor()
    {
        var diagnostics = new ClientDiagnostics(_status, NullLogger.Instance, new PendingFindings(Path.Combine(_dir, "f.json")), _feed);
        diagnostics.Publish(new[] { Finding("a") });
        Assert.Equal(1, diagnostics.Pending.Count);

        diagnostics.Configure(new ClientFindingsConfig { Enabled = true, Notify = false });
        var response = await Api().HandleAsync(Request("GET", TrayApi.FindingsPath), default);
        Assert.False(JsonDocument.Parse(response.Json).RootElement.GetProperty("notify").GetBoolean());
        Assert.True(diagnostics.Enabled);

        diagnostics.Configure(new ClientFindingsConfig { Enabled = false, Notify = true });
        Assert.False(diagnostics.Enabled);
        Assert.False(_feed.Notify);
        Assert.Empty(_feed.Since(0).Findings);

        diagnostics.Configure(null); // älterer Server ohne client_findings
        Assert.True(diagnostics.Enabled);
        Assert.True(_feed.Notify);
    }

    // -- Puffer -------------------------------------------------------------

    private static ServerReport Report(int i) => new() { ReportId = $"id-{i}", OccurredAt = i, Category = "slow" };

    [Fact]
    public void PendingKeepsNewest200AndPersists()
    {
        var pending = new PendingReports(PendingPath);
        for (var i = 0; i < 205; i++)
        {
            pending.Add(Report(i));
        }

        var reloaded = new PendingReports(PendingPath).Snapshot();
        Assert.Equal(PendingReports.MaxEntries, reloaded.Count);
        Assert.Equal("id-5", reloaded[0].ReportId);
        Assert.Equal("id-204", reloaded[^1].ReportId);
        Assert.Contains("\"report_id\"", File.ReadAllText(PendingPath));
    }

    [Fact]
    public async Task FlushStopsAtFirstRetryAndDropsRejected()
    {
        var pending = new PendingReports(PendingPath);
        for (var i = 0; i < 4; i++)
        {
            pending.Add(Report(i));
        }

        var outcomes = new Queue<ReportSendOutcome>(new[] { ReportSendOutcome.Delivered, ReportSendOutcome.Rejected, ReportSendOutcome.Retry });
        var delivered = await pending.FlushAsync((r, ct) => Task.FromResult(new ReportSendResult(outcomes.Dequeue())), default);

        Assert.Equal(1, delivered);
        Assert.Equal(new[] { "id-2", "id-3" }, pending.Snapshot().Select(r => r.ReportId));

        delivered = await pending.FlushAsync((r, ct) => Task.FromResult(new ReportSendResult(ReportSendOutcome.Delivered)), default);
        Assert.Equal(2, delivered);
        Assert.Equal(0, pending.Count);
        Assert.False(File.Exists(PendingPath));
    }

    [Fact]
    public void ResolvesPort()
    {
        Assert.Equal(47251, TrayEndpoint.ResolvePort(""));
        Assert.Equal(47251, TrayEndpoint.ResolvePort("70000"));
        Assert.Equal(48000, TrayEndpoint.ResolvePort(" 48000 "));
        Assert.Equal(TrayEndpoint.ResolvePort("123"), TrayClient.ResolvePort("123"));
        Assert.Equal(TrayEndpoint.ResolvePort("abc"), TrayClient.ResolvePort("abc"));
    }

    // -- Ende zu Ende: wachtl-tray-Client gegen den echten Endpunkt ----------

    [Fact]
    public async Task TrayClientTalksToEndpoint()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        var client = new TrayClient(port);
        Assert.Null(client.GetStatus()); // Dienst läuft noch nicht

        var endpoint = new TrayEndpoint(port, _status, new PendingReports(PendingPath), NullLogger.Instance);
        await endpoint.StartAsync(default);
        try
        {
            var status = client.GetStatus();
            Assert.NotNull(status);
            Assert.False(status!.Enrolled);
            Assert.Equal(TrayConnection.NotEnrolled, status.Connection);

            var json = ReportBuilder.ToJson(new ReportInput { Category = "slow", User = "KUNDE\\mm" }, DateTime.UtcNow);
            var notEnrolled = client.SendReport(json);
            Assert.Equal(ReportOutcome.Failed, notEnrolled.Outcome);
            Assert.Contains("nicht beim Wachtl-Server registriert", notEnrolled.Message);

            // Registriert, aber ohne ApiClient: Meldung wird gepuffert.
            Enroll();
            var queued = client.SendReport(json);
            Assert.Equal(ReportOutcome.Queued, queued.Outcome);
            Assert.Equal(1, client.GetStatus()!.PendingReports);
            Assert.Equal("Zentrale", client.GetStatus()!.Site);

            // Client-Hinweise über die echte Schnittstelle (ohne Hinweis-Quelle: leer, notify an)
            var poll = client.GetFindings(0);
            Assert.Equal(FindingsPollStatus.Ok, poll.Status);
            Assert.Empty(poll.Response!.Findings!);
        }
        finally
        {
            await endpoint.StopAsync(default);
        }
    }
}
