namespace Wachtl.Probe.Checks;

/// <summary>Ziel für Messwert-Zeilen (in der Praxis der lokale Puffer).</summary>
public interface ISampleSink
{
    void Add(string line);
}
