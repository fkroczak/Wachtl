using System.Globalization;
using Wachtl.Probe.Metrics;

namespace Wachtl.Probe.Tests;

public class MetricLineTests
{
    [Fact]
    public void FormatsWithCheckIdAndMillisecondTimestamp()
    {
        var line = MetricLine.Format(MetricLine.PingRtt, 3, 12.34567, 1_700_000_000_000);
        Assert.Equal("wachtl_ping_rtt_ms{check_id=\"3\"} 12.346 1700000000000", line);
    }

    [Fact]
    public void UsesInvariantCultureEvenOnGermanSystems()
    {
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("de-DE");
            Assert.EndsWith(" 0.5 1", MetricLine.Format(MetricLine.PingUp, 1, 0.5, 1));
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }
}
