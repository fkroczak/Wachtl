using System.Text.Json;
using Wachtl.Probe.Config;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tests;

public class ConfigJsonTests
{
    [Fact]
    public void ParsesServerConfig()
    {
        const string json = """
            {"probe_id": 4, "etag": "abc123", "upload_interval_s": 10, "heartbeat_interval_s": 30, "config_poll_s": 300,
             "checks": [{"id": 1, "type": "ping", "target": "gateway", "role": "gateway", "interval_s": 1, "timeout_ms": 1000, "params": {}},
                        {"id": 2, "type": "ping", "target": "8.8.8.8", "role": "reference", "interval_s": 5, "timeout_ms": 800, "params": {}}]}
            """;
        var config = JsonSerializer.Deserialize<ProbeConfig>(json, ApiClient.JsonOptions)!;
        Assert.Equal(4, config.ProbeId);
        Assert.Equal("abc123", config.Etag);
        Assert.Equal(2, config.Checks.Count);
        Assert.Equal("2|ping|8.8.8.8|5|800", config.Checks[1].Key);
    }

    [Fact]
    public void SerializesHeartbeatInSnakeCase()
    {
        var json = JsonSerializer.Serialize(new HeartbeatRequest { BufferItems = 5, UptimeS = 9 }, ApiClient.JsonOptions);
        Assert.Contains("\"buffer_items\":5", json);
        Assert.Contains("\"uptime_s\":9", json);
    }
}
