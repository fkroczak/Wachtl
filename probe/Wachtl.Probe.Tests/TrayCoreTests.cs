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
            "\"version\":\"0.5.0\",\"enrolled\":true,\"connected\":false,\"last_contact\":1792230000,\"pending_reports\":2,\"neu\":1}")!;
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
}
