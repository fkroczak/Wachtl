using Wachtl.Probe.Checks;

namespace Wachtl.Probe.Tests;

public class JitterCalculatorTests
{
    [Fact]
    public void AveragesAbsoluteDifferencesAndSkipsLosses()
    {
        var jitter = new JitterCalculator();
        jitter.Add(10);
        jitter.Add(12);   // +2
        jitter.Add(11);   // +1
        jitter.Add(null); // Verlust
        jitter.Add(15);   // +4
        Assert.Equal(7.0 / 3, jitter.TakeAndReset()!.Value, 6);
    }

    [Fact]
    public void ReturnsNullWithoutPairsAndResets()
    {
        var jitter = new JitterCalculator();
        Assert.Null(jitter.TakeAndReset());
        jitter.Add(5);
        Assert.Null(jitter.TakeAndReset());
        jitter.Add(7);
        Assert.Equal(2.0, jitter.TakeAndReset());
        Assert.Null(jitter.TakeAndReset());
    }
}
