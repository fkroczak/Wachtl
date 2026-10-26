using System.Text.Json;
using Wachtl.Tray.Core;

namespace Wachtl.Probe.Tests;

public class TrayCoreTests
{
    private static readonly DateTime UtcNow = new(2026, 10, 17, 10, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void JsonForNowUsesSendTimeAndEscapes()
    {
        var input = new ReportInput { Category = "voice_video", Duration = "ongoing", Description = "  „Teams“ \"ruckelt\"\n ", User = "KUNDE\\mm" };
        using var doc = JsonDocument.Parse(ReportBuilder.ToJson(input, UtcNow));
        var root = doc.RootElement;
        Assert.Equal(new DateTimeOffset(UtcNow).ToUnixTimeSeconds(), root.GetProperty("occurred_at").GetInt64());
        Assert.Equal("voice_video", root.GetProperty("category").GetString());
        Assert.Equal("ongoing", root.GetProperty("duration").GetString());
        Assert.Equal("„Teams“ \"ruckelt\"", root.GetProperty("description").GetString());
        Assert.Equal("KUNDE\\mm", root.GetProperty("user").GetString());
    }

    [Fact]
    public void ChosenLocalTimeBecomesUtcSeconds()
    {
        var local = UtcNow.ToLocalTime().AddMinutes(-30);
        var input = new ReportInput { Now = false, LocalTime = DateTime.SpecifyKind(local, DateTimeKind.Unspecified), Category = "slow" };
        Assert.Equal(new DateTimeOffset(UtcNow).ToUnixTimeSeconds() - 1800, ReportBuilder.OccurredAt(input, UtcNow));
    }

    [Fact]
    public void ValidatesInput()
    {
        Assert.NotNull(ReportBuilder.Validate(new ReportInput(), UtcNow)); // keine Kategorie
        Assert.NotNull(ReportBuilder.Validate(new ReportInput { Category = "slow", Duration = "x" }, UtcNow));
        Assert.NotNull(ReportBuilder.Validate(new ReportInput { Category = "slow", Description = new string('x', 1001) }, UtcNow));
        Assert.NotNull(ReportBuilder.Validate(new ReportInput { Category = "slow", Now = false, LocalTime = UtcNow.AddDays(-8) }, UtcNow));
        Assert.NotNull(ReportBuilder.Validate(new ReportInput { Category = "slow", Now = false, LocalTime = UtcNow.AddMinutes(10) }, UtcNow));
        Assert.Null(ReportBuilder.Validate(new ReportInput { Category = "slow", Now = false, LocalTime = UtcNow.AddDays(-6) }, UtcNow));
        Assert.Null(ReportBuilder.Validate(new ReportInput { Category = "other" }, UtcNow));
    }

    [Fact]
    public void CatalogMatchesServiceLists()
    {
        Assert.Equal(Tray.TrayReportParser.Categories, ReportCatalog.Categories.Select(c => c.Value));
        Assert.Equal(Tray.TrayReportParser.Durations, ReportCatalog.Durations.Select(c => c.Value));
        Assert.Equal("unknown", ReportCatalog.DefaultDuration);
    }

    [Fact]
    public void FormatsUser()
    {
        Assert.Equal("KUNDE\\mm", ReportBuilder.FormatUser("KUNDE", "mm"));
        Assert.Equal("mm", ReportBuilder.FormatUser("", "mm"));
        Assert.Equal(128, ReportBuilder.FormatUser("D", new string('u', 200)).Length);
    }

    [Theory]
    [InlineData(202, "{\"ok\":true,\"delivered\":true}", ReportOutcome.Delivered)]
    [InlineData(202, "{\"ok\":true,\"delivered\":false}", ReportOutcome.Queued)]
    [InlineData(202, "kaputt", ReportOutcome.Failed)]
    [InlineData(400, "{\"error\":\"Bitte die Art der Störung auswählen.\"}", ReportOutcome.Failed)]
    [InlineData(409, "{\"error\":\"x\"}", ReportOutcome.Failed)]
    [InlineData(429, "", ReportOutcome.Failed)]
    public void InterpretsReportResponse(int status, string body, ReportOutcome expected)
    {
        var result = TrayClient.Interpret(status, body);
        Assert.Equal(expected, result.Outcome);
        Assert.False(string.IsNullOrEmpty(result.Message));
        if (status == 400)
        {
            Assert.Contains("Bitte die Art der Störung auswählen.", result.Message);
        }
    }

    [Fact]
    public void ParsesStatus()
    {
        var status = Json.Read<TrayStatus>(
            "{\"role\":\"server\",\"name\":\"SRV\",\"site\":\"Zentrale\",\"server_url\":\"https://w\",\"dashboard_url\":\"https://w\"," +
            "\"version\":\"1.0.0\",\"enrolled\":true,\"connected\":false,\"last_contact\":1792230000,\"pending_reports\":2,\"neu\":1}")!;
        Assert.True(status.IsServer);
        Assert.Equal("https://w", status.DashboardUrl);
        Assert.Equal(1792230000, status.LastContact);
        Assert.Equal(2, status.PendingReports);
        Assert.Equal(TrayConnection.Disconnected, status.Connection);
        Assert.Null(Json.Read<TrayStatus>("<html>"));
    }

    [Fact]
    public void TooltipFitsNotifyIconLimit()
    {
        foreach (TrayConnection state in Enum.GetValues(typeof(TrayConnection)))
        {
            var text = TrayTexts.Tooltip(state);
            Assert.StartsWith("Wachtl – Netzwerk-Monitoring", text);
            Assert.True(text.Length <= 63, text);
        }
    }

    // -- Netzwerk-Hinweise --------------------------------------------------

    private static readonly long NowS = new DateTimeOffset(UtcNow).ToUnixTimeSeconds();

    private static TrayFinding F(long seq, string id, string severity = "critical", string state = "active", long? detected = null,
        string title = "Netzwerkkabel getrennt") => new()
    {
        Seq = seq, FindingId = id, Kind = "cable_unplugged", Severity = severity, State = state, Title = title,
        Message = "Die Netzwerkkarte „Ethernet“ hat keine Verbindung mehr.", Solution = "Kabel prüfen.",
        Adapter = "Ethernet", DetectedAt = detected ?? NowS - 5, ResolvedAt = state == "resolved" ? NowS : null,
    };

    private static TrayFindingsResponse R(long latest, params TrayFinding[] findings) =>
        new() { Notify = true, LatestSeq = latest, Findings = findings.ToList() };

    [Fact]
    public void ParsesFindingsResponse()
    {
        var json = "{\"notify\":true,\"latest_seq\":12,\"findings\":[{\"seq\":12,\"finding_id\":\"a\",\"kind\":\"apipa\",\"severity\":\"critical\"," +
                   "\"state\":\"active\",\"title\":\"Keine IP-Adresse\",\"message\":\"m\",\"solution\":\"s\",\"adapter\":\"Ethernet\"," +
                   "\"detected_at\":1792230000,\"resolved_at\":null,\"neu\":1}]}";
        var poll = FindingsPoll.Interpret(200, json);
        Assert.Equal(FindingsPollStatus.Ok, poll.Status);
        var f = Assert.Single(poll.Response!.Findings!);
        Assert.Equal(12, f.Seq);
        Assert.Null(f.ResolvedAt);
        Assert.True(f.IsActive);
        Assert.Equal(2, f.Rank);
        Assert.Equal(FindingsPollStatus.NotSupported, FindingsPoll.Interpret(404, "{\"error\":\"Not Found\"}").Status);
        Assert.Equal(FindingsPollStatus.Failed, FindingsPoll.Interpret(200, "<html>").Status);
        Assert.Equal(FindingsPollStatus.Failed, FindingsPoll.Interpret(403, "{}").Status);
    }

    [Fact]
    public void FirstPollSetsCursorAndShowsOnlyRecentActiveWarnings()
    {
        var n = new FindingNotifier();
        n.Accept(R(20,
            F(10, "old", detected: NowS - 3600),
            F(11, "info", severity: "info"),
            F(12, "done", state: "resolved"),
            F(13, "fresh", severity: "warning", detected: NowS - 300)), UtcNow);
        Assert.Equal(20, n.Cursor);
        var b = n.Next(UtcNow)!;
        Assert.Equal("fresh", Assert.Single(b.Items).FindingId);
        Assert.Equal(BalloonIcon.Warning, b.Icon);
        Assert.False(n.HasQueued);
        Assert.Equal(3, n.Active.Count); // old, info, fresh – fürs Menü
    }

    [Fact]
    public void ShowsNewFindingAndResolutionOfShownOnly()
    {
        var n = new FindingNotifier();
        n.Accept(R(5), UtcNow);
        n.Accept(R(7, F(6, "a"), F(7, "b", severity: "info")), UtcNow);
        var b = n.Next(UtcNow)!;
        Assert.Equal(BalloonIcon.Error, b.Icon);
        Assert.Equal("Netzwerkkabel getrennt", b.Title);
        Assert.Equal("Die Netzwerkkarte „Ethernet“ hat keine Verbindung mehr.\nLösung: Kabel prüfen.", b.Text);
        var info = n.Next(UtcNow.AddSeconds(30))!; // auch Info erscheint – nichts wird verschwiegen
        Assert.Equal(BalloonIcon.Info, info.Icon);
        Assert.Equal("b", Assert.Single(info.Items).FindingId);

        n.Accept(R(9, F(8, "a", state: "resolved", title: "Netzwerkkabel wieder verbunden"), F(9, "b", state: "resolved")), UtcNow);
        var resolved = n.Next(UtcNow.AddSeconds(60))!;
        Assert.Equal(BalloonIcon.Info, resolved.Icon);
        Assert.Equal("Netzwerkkabel wieder verbunden", resolved.Title);
        Assert.DoesNotContain("Lösung", resolved.Text);
        Assert.Equal(1, n.QueuedCount); // b wurde gezeigt, also auch seine Erledigung
        Assert.Empty(n.Active);
    }

    [Fact]
    public void ResolvedBeforeShownIsNotShownEvenForInfo()
    {
        var n = new FindingNotifier();
        n.Accept(R(1), UtcNow);
        n.Accept(R(3, F(2, "a", severity: "info"), F(3, "a", severity: "info", state: "resolved")), UtcNow);
        Assert.False(n.HasQueued);
    }

    [Fact]
    public void EventsAreShownOnceAndNeverListedAsActive()
    {
        var n = new FindingNotifier();
        n.Accept(R(1), UtcNow);
        var loss = F(2, "loss", severity: "warning", title: "Paketverlust zu 8.8.8.8");
        loss.Event = true;
        loss.Balloon = "1 Ping zu 8.8.8.8 ohne Antwort (10:00:01).";
        var change = F(3, "net", severity: "info", title: "Netzwerkverbindung gewechselt");
        change.Event = true;
        n.Accept(R(3, loss, change), UtcNow);
        Assert.Empty(n.Active);
        Assert.Equal(-1, n.WorstActiveRank);
        var b = n.Next(UtcNow)!;
        Assert.Equal(BalloonIcon.Warning, b.Icon);
        Assert.Equal("1 Ping zu 8.8.8.8 ohne Antwort (10:00:01).", b.Text);
        Assert.Contains("(um ", FindingNotifier.DetailText(b.Items));
        Assert.Equal(BalloonIcon.Info, n.Next(UtcNow.AddSeconds(15))!.Icon);
        Assert.False(n.HasQueued);
    }

    [Fact]
    public void EventsBeforeTrayStartAreNotReplayed()
    {
        var n = new FindingNotifier();
        var loss = F(2, "loss", severity: "warning", detected: NowS - 5);
        loss.Event = true;
        n.Accept(R(2, loss), UtcNow);
        Assert.False(n.HasQueued);
    }

    [Fact]
    public void QuietFindingsAreListedButNotShown()
    {
        var n = new FindingNotifier();
        n.Accept(R(1), UtcNow);
        var quiet = F(2, "a");
        quiet.Quiet = true;
        n.Accept(R(2, quiet), UtcNow);
        Assert.False(n.HasQueued);
        Assert.Single(n.Active);
        Assert.Equal(2, n.WorstActiveRank);
    }

    [Fact]
    public void ParsesEventAndQuietFlags()
    {
        var json = "{\"notify\":true,\"latest_seq\":3,\"findings\":[{\"seq\":3,\"finding_id\":\"x\",\"severity\":\"warning\"," +
                   "\"state\":\"active\",\"title\":\"t\",\"detected_at\":1792230000,\"event\":true,\"quiet\":true}]}";
        var f = Assert.Single(FindingsPoll.Interpret(200, json).Response!.Findings!);
        Assert.True(f.Event);
        Assert.True(f.Quiet);
    }

    [Fact]
    public void TestBalloonIsAWarning()
    {
        var b = FindingNotifier.TestBalloon();
        Assert.Equal(BalloonIcon.Warning, b.Icon);
        Assert.True(b.Text.Length <= FindingNotifier.MaxBalloonText);
    }

    [Fact]
    public void ResolvedBeforeShownIsNotShown()
    {
        var n = new FindingNotifier();
        n.Accept(R(1), UtcNow);
        n.Accept(R(2, F(2, "a")), UtcNow);
        n.Accept(R(3, F(3, "a", state: "resolved")), UtcNow);
        Assert.False(n.HasQueued);
    }

    [Fact]
    public void AtMostOneBalloonPer15SecondsAndCombinesMoreThanThree()
    {
        var n = new FindingNotifier();
        n.Accept(R(1), UtcNow);
        n.Accept(R(3, F(2, "a"), F(3, "b")), UtcNow);
        Assert.NotNull(n.Next(UtcNow));
        Assert.Null(n.Next(UtcNow.AddSeconds(10)));
        Assert.NotNull(n.Next(UtcNow.AddSeconds(15)));

        n.Accept(R(7, F(4, "c", severity: "warning"), F(5, "d"), F(6, "e", severity: "warning"), F(7, "f", severity: "warning")), UtcNow);
        var combined = n.Next(UtcNow.AddSeconds(30))!;
        Assert.Equal(4, combined.Items.Count);
        Assert.Equal("4 Netzwerk-Hinweise – Klicken für Details", combined.Title);
        Assert.Equal(BalloonIcon.Error, combined.Icon);
        Assert.False(n.HasQueued);
        Assert.Contains("seit", FindingNotifier.DetailText(combined.Items));
    }

    [Fact]
    public void HigherSeverityIsShownAgain()
    {
        var n = new FindingNotifier();
        n.Accept(R(1), UtcNow);
        n.Accept(R(2, F(2, "a", severity: "warning")), UtcNow);
        Assert.NotNull(n.Next(UtcNow));
        n.Accept(R(3, F(3, "a", severity: "warning")), UtcNow);
        Assert.False(n.HasQueued);
        n.Accept(R(4, F(4, "a", severity: "critical")), UtcNow);
        Assert.Equal(BalloonIcon.Error, n.Next(UtcNow.AddMinutes(1))!.Icon);
    }

    [Fact]
    public void NotifyOffShowsNothingButKeepsList()
    {
        var n = new FindingNotifier();
        n.Accept(R(1), UtcNow);
        var r = R(2, F(2, "a"));
        r.Notify = false;
        n.Accept(r, UtcNow);
        Assert.False(n.HasQueued);
        Assert.Single(n.Active);
        Assert.Contains("Netzwerkkabel getrennt", n.ActiveSummary());
    }

    [Fact]
    public void ServiceRestartResetsCursor()
    {
        var n = new FindingNotifier();
        n.Accept(R(100), UtcNow);
        n.Accept(R(5), UtcNow);
        Assert.Equal(0, n.Cursor);
        n.Accept(R(6, F(6, "neu", detected: NowS - 60)), UtcNow);
        Assert.Equal(6, n.Cursor);
        Assert.True(n.HasQueued); // wie ein erster Abruf: frische aktive Hinweise zeigen
    }

    [Fact]
    public void ServiceRestartDropsStaleActiveFindings()
    {
        var n = new FindingNotifier();
        n.Accept(R(1_000), UtcNow);
        n.Accept(R(1_001, F(1_001, "alt", detected: NowS - 3600)), UtcNow);
        Assert.Single(n.Active);
        // neuer Dienst: Zählung beginnt über dem Stand des Tray, kennt „alt“ nicht mehr
        var restarted = R(5_000);
        restarted.StartSeq = 5_000;
        n.Accept(restarted, UtcNow);
        Assert.Empty(n.Active);
        Assert.Equal(5_000, n.Cursor);
    }

    [Fact]
    public void BalloonTextsFitWindowsLimits()
    {
        var f = F(1, "a", title: new string('T', 100));
        f.Message = new string('m', 400);
        f.Solution = new string('s', 400);
        var n = new FindingNotifier();
        n.Accept(R(0), UtcNow);
        n.Accept(R(1, f), UtcNow);
        var b = n.Next(UtcNow)!;
        Assert.True(b.Title.Length <= 63);
        Assert.True(b.Text.Length <= 255);
        Assert.EndsWith("…", b.Text);
        Assert.Equal(FindingNotifier.NoFindings, new FindingNotifier().ActiveSummary());
    }

    [Fact]
    public void BalloonUsesShortTextOfProbe()
    {
        var f = F(1, "a");
        f.Message = new string('m', 300);
        f.Solution = "lange Lösung";
        f.Balloon = "Kabel nicht verbunden.\nLösung: Stecker fest einstecken.";
        Assert.Equal(f.Balloon, FindingNotifier.BalloonText(f));
        // Ältere Probe ohne Kurzfassung: wie bisher Meldung + Lösung
        f.Balloon = null;
        Assert.StartsWith("mmm", FindingNotifier.BalloonText(f));
        // Entwarnung zeigt die Meldung, nicht die Kurzfassung
        var resolved = F(2, "b");
        resolved.State = "resolved";
        resolved.Message = "Wieder verbunden.";
        resolved.Balloon = "Kurz";
        Assert.Equal("Wieder verbunden.", FindingNotifier.BalloonText(resolved));
    }
}
