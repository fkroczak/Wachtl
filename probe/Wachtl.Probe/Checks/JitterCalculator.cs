namespace Wachtl.Probe.Checks;

/// <summary>
/// Jitter als mittlere absolute Differenz aufeinanderfolgender Antwortzeiten
/// (Interarrival-Jitter-Idee aus RFC 3550, ohne Glättung). Verluste werden übersprungen.
/// </summary>
public sealed class JitterCalculator
{
    private double? _last;
    private double _sum;
    private int _count;

    public void Add(double? rttMs)
    {
        if (rttMs is not double rtt)
        {
            return;
        }

        if (_last is double last)
        {
            _sum += Math.Abs(rtt - last);
            _count++;
        }

        _last = rtt;
    }

    /// <summary>Mittelwert seit dem letzten Aufruf; null, wenn zu wenige Werte vorlagen.</summary>
    public double? TakeAndReset()
    {
        if (_count == 0)
        {
            return null;
        }

        var result = _sum / _count;
        _sum = 0;
        _count = 0;
        return result;
    }
}
