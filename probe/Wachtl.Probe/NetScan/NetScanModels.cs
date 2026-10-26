namespace Wachtl.Probe.NetScan;

/// <summary>Ein offener TCP-Port mit erkanntem Dienst (Banner, TLS, HTTP-Antwort).</summary>
public sealed class NetScanPort
{
    public int Port { get; init; }
    public string? Banner { get; set; }
    public bool Tls { get; set; }
    public int? HttpStatus { get; set; }
    public string? HttpServer { get; set; }
    public string? HttpTitle { get; set; }
    public string? TlsSubject { get; set; }
}

/// <summary>Ein gefundenes Gerät.</summary>
public sealed class NetScanHost
{
    public string Ip { get; init; } = string.Empty;
    public string? Mac { get; set; }
    public string? Hostname { get; set; }
    public double? RttMs { get; set; }

    /// <summary>Wie das Gerät gefunden wurde: „icmp“, „arp“, „tcp“.</summary>
    public List<string> Via { get; set; } = new();

    /// <summary>true = die scannende Probe selbst.</summary>
    public bool Self { get; set; }

    public List<NetScanPort> Ports { get; set; } = new();
}

/// <summary>Ergebnis eines Netzwerkscans für <c>POST results/netscan</c> (docs/NETZWERKSCAN.md).</summary>
public sealed class NetScanResult
{
    public long CheckId { get; set; }
    public long Ts { get; set; }
    public string Trigger { get; set; } = "schedule";
    public double DurationS { get; set; }
    public List<string> Subnets { get; set; } = new();

    /// <summary>Text, wenn der Scan nicht laufen konnte (dann ohne Hosts).</summary>
    public string? Error { get; set; }

    public List<NetScanHost> Hosts { get; set; } = new();
}

/// <summary>Einstellungen eines Scans aus den Check-Parametern.</summary>
public sealed record NetScanOptions(string Target, IReadOnlyList<int> Ports, bool PortScan, int TimeoutMs, int Parallel, int MaxHosts);
