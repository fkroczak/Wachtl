using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Wachtl.Probe.Checks;

namespace Wachtl.Probe.Tools;

/// <summary>
/// Werkzeuge der Windows-Probe (docs/WERKZEUGE.md): Ping, MTU, Traceroute, DNS, Port, HTTP(S), Zertifikat.
/// Gleiche Argumente, gleiches Ergebnisformat und gleiche Texte wie die Server-Probe (server/wachtl/serverprobe/tools.py),
/// damit das Web-UI beide gleich anzeigt.
/// </summary>
public sealed class ToolRunner
{
    private static readonly Dictionary<IPStatus, string> Errors = new()
    {
        [IPStatus.TimedOut] = "Zeitüberschreitung",
        [IPStatus.DestinationHostUnreachable] = "Host nicht erreichbar",
        [IPStatus.DestinationNetworkUnreachable] = "Netz nicht erreichbar",
        [IPStatus.DestinationUnreachable] = "Ziel nicht erreichbar",
        [IPStatus.PacketTooBig] = "Paket zu groß (Fragmentierung nötig)",
        [IPStatus.TtlExpired] = "TTL abgelaufen",
    };

    private static readonly (int Mtu, string Text)[] MtuHints =
    {
        (9000, "Jumbo-Frames"), (1500, "Ethernet ohne Tunnel – volle Größe"), (1492, "PPPoE (DSL)"), (1480, "6in4-Tunnel"),
        (1476, "GRE-Tunnel"), (1420, "WireGuard"), (1400, "IPsec oder anderer VPN-Tunnel"),
    };

    private static readonly Dictionary<int, string> PortNames = new()
    {
        [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP", [53] = "DNS", [80] = "HTTP", [110] = "POP3", [135] = "RPC",
        [139] = "NetBIOS", [143] = "IMAP", [161] = "SNMP", [389] = "LDAP", [443] = "HTTPS", [445] = "SMB", [465] = "SMTPS",
        [587] = "Submission", [636] = "LDAPS", [993] = "IMAPS", [995] = "POP3S", [1194] = "OpenVPN", [1433] = "MS SQL",
        [1723] = "PPTP", [3306] = "MySQL", [3389] = "RDP", [4433] = "HTTPS alt", [4443] = "HTTPS alt", [4444] = "Sophos Admin",
        [5060] = "SIP", [5061] = "SIP-TLS", [5432] = "PostgreSQL", [5900] = "VNC", [8080] = "HTTP alt",
        [8291] = "MikroTik Winbox", [8443] = "HTTPS alt", [10443] = "FortiGate SSL-VPN",
    };

    private readonly Func<ToolUpdate, Task> _send;
    private readonly List<string> _lines = new();
    private readonly Stopwatch _sinceSend = Stopwatch.StartNew();
    private double? _progress;
    private string? _step;

    public ToolRunner(Func<ToolUpdate, Task> send) => _send = send;

    public async Task RunAsync(ToolJob job, CancellationToken ct)
    {
        (bool Ok, ToolResult Result, string? Error) outcome;
        try
        {
            outcome = job.Tool switch
            {
                "ping" => await PingAsync(job, ct).ConfigureAwait(false),
                "mtu" => await MtuAsync(job, ct).ConfigureAwait(false),
                "trace" => await TraceAsync(job, ct).ConfigureAwait(false),
                "dns" => await DnsAsync(job, ct).ConfigureAwait(false),
                "port" => await PortAsync(job, ct).ConfigureAwait(false),
                "http" => await HttpAsync(job, ct).ConfigureAwait(false),
                "tls" => await TlsAsync(job, ct).ConfigureAwait(false),
                _ => (false, new ToolResult(), $"Werkzeug {job.Tool} wird von dieser Probe nicht unterstützt."),
            };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            outcome = (false, new ToolResult(), $"{ex.GetType().Name}: {ex.Message}");
        }

        await _send(new ToolUpdate
        {
            Done = true, Ok = outcome.Ok, Result = outcome.Result, Error = outcome.Error, Lines = TakeLines(),
        }).ConfigureAwait(false);
    }

    private List<string> TakeLines()
    {
        var lines = new List<string>(_lines);
        _lines.Clear();
        return lines;
    }

    private async Task Report(double? progress = null, string? step = null, string? line = null)
    {
        if (progress is not null)
        {
            _progress = progress;
        }

        if (step is not null)
        {
            _step = step;
        }

        if (line is not null)
        {
            _lines.Add(line);
        }

        if (_sinceSend.Elapsed < TimeSpan.FromMilliseconds(500))
        {
            return;
        }

        _sinceSend.Restart();
        try
        {
            await _send(new ToolUpdate { Progress = _progress, Step = _step, Lines = TakeLines() }).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Fortschritt ist nur Anzeige; das Ergebnis zählt
        }
    }

    private static string Err(IPStatus status, string error) =>
        Errors.TryGetValue(status, out var text) ? text : string.IsNullOrEmpty(error) ? "keine Antwort" : error;

    private static string TargetText(string host, IPAddress ip) => host == ip.ToString() ? host : $"{host} ({ip})";

    private static async Task<(IPAddress? Ip, string Error)> ResolveAsync(string host, CancellationToken ct)
    {
        if (IPAddress.TryParse(host, out var ip))
        {
            return ip.AddressFamily == AddressFamily.InterNetworkV6
                ? (null, "IPv6 wird von den ICMP-Werkzeugen noch nicht unterstützt.")
                : (ip, string.Empty);
        }

        try
        {
            var all = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, ct).ConfigureAwait(false);
            return all.Length == 0 ? (null, "DNS liefert keine IPv4-Adresse") : (all[0], string.Empty);
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            return (null, "DNS-Auflösung fehlgeschlagen: " + ex.Message);
        }
    }

    private static async Task<PingResult> PingOnceAsync(IPAddress ip, int size, int ttl, bool df, int timeoutMs, CancellationToken ct)
    {
        using var ping = new Ping();
        return await PingHelper.SendAsync(ping, ip, TimeSpan.FromMilliseconds(timeoutMs), new byte[size],
            new PingOptions(ttl, df), ct).ConfigureAwait(false);
    }

    // -- Ping ----------------------------------------------------------------------------
    private async Task<(bool, ToolResult, string?)> PingAsync(ToolJob job, CancellationToken ct)
    {
        var a = job.Args;
        var host = a.Str("host");
        var (ip, error) = await ResolveAsync(host, ct).ConfigureAwait(false);
        if (ip is null)
        {
            return (false, new ToolResult(), error);
        }

        int count = a.Int("count", 10, 1, 100), size = a.Int("size", 32, 0, 8972);
        var interval = a.Num("interval", 1, 0.2, 5);
        var df = a.Flag("df");
        var rtts = new List<double>();
        var tooBig = false;
        await Report(line: $"Ping {TargetText(host, ip)} mit {size} Byte Nutzdaten{(df ? " (nicht fragmentieren)" : "")}:").ConfigureAwait(false);
        for (var i = 1; i <= count; i++)
        {
            var sw = Stopwatch.StartNew();
            var r = await PingOnceAsync(ip, size, 128, df, 2000, ct).ConfigureAwait(false);
            string line;
            if (r.Success)
            {
                rtts.Add(r.RttMs);
                line = $"Antwort von {r.From ?? ip}: Bytes={size} Zeit={ToolArgs.Ms(r.RttMs)} ms TTL={r.Ttl?.ToString() ?? "–"}";
            }
            else
            {
                tooBig |= r.Status == IPStatus.PacketTooBig;
                line = $"Paket {i}: {Err(r.Status, r.Error)}";
            }

            await Report((double)i / count, $"Paket {i} von {count}: {(r.Success ? ToolArgs.Ms(r.RttMs) + " ms" : Err(r.Status, r.Error))}", line)
                .ConfigureAwait(false);
            if (i < count)
            {
                var rest = TimeSpan.FromSeconds(interval) - sw.Elapsed;
                if (rest > TimeSpan.Zero)
                {
                    await Task.Delay(rest, ct).ConfigureAwait(false);
                }
            }
        }

        var got = rtts.Count;
        var loss = Math.Round((count - got) * 100.0 / count, 1);
        double? avg = got > 0 ? Math.Round(rtts.Average(), 2) : null;
        var result = new ToolResult
        {
            Headline = loss == 0 ? "Alle Pakete beantwortet" : got == 0 ? "Keine Antwort" : $"{count - got} von {count} Paketen ohne Antwort",
            Verdict = loss == 0 ? "ok" : loss >= 50 ? "bad" : "warn",
            Stats = new ToolStats
            {
                Sent = count, Received = got, Loss = loss, Min = got > 0 ? rtts.Min() : null, Avg = avg, Max = got > 0 ? rtts.Max() : null,
                Mdev = got > 1 ? Math.Round(Math.Sqrt(rtts.Average(x => (x - avg!.Value) * (x - avg.Value))), 2) : got == 1 ? 0 : null,
            },
        };
        result.Add("Ziel", TargetText(host, ip))
            .Add("Pakete", $"{count} × {size} Byte Nutzdaten ({size + 28} Byte IP-Paket){(df ? ", nicht fragmentieren" : "")}");
        if (tooBig)
        {
            result.Add("Hinweis", "Paket zu groß für den Weg – Größe verkleinern oder DF ausschalten; die passende Größe zeigt der MTU-Test.", "warn");
        }

        return (true, result, null);
    }

    // -- MTU -----------------------------------------------------------------------------
    private async Task<(bool, ToolResult, string?)> MtuAsync(ToolJob job, CancellationToken ct)
    {
        var a = job.Args;
        var host = a.Str("host");
        var (ip, error) = await ResolveAsync(host, ct).ConfigureAwait(false);
        if (ip is null)
        {
            return (false, new ToolResult(), error);
        }

        int lo = a.Int("min", 576, 68, 9000), hi = a.Int("max", 1500, 68, 9000), tries = a.Int("tries", 2, 1, 5);
        var steps = Math.Max(1, (int)Math.Ceiling(Math.Log2(Math.Max(2, hi - lo)))) + 2;
        var done = 0;

        async Task<(bool Fits, IPStatus Why)> Fits(int mtu)
        {
            done++;
            var last = IPStatus.Unknown;
            for (var t = 0; t < tries; t++)
            {
                var r = await PingOnceAsync(ip, mtu - 28, 128, true, 1500, ct).ConfigureAwait(false);
                if (r.Success)
                {
                    await Report(Math.Min(0.95, (double)done / steps), $"{mtu} Byte: passt", $"{mtu} Byte: Antwort nach {ToolArgs.Ms(r.RttMs)} ms")
                        .ConfigureAwait(false);
                    return (true, IPStatus.Success);
                }

                last = r.Status;
            }

            await Report(Math.Min(0.95, (double)done / steps), $"{mtu} Byte: {Err(last, "")}", $"{mtu} Byte: {Err(last, "")}").ConfigureAwait(false);
            return (false, last);
        }

        var result = new ToolResult().Add("Ziel", TargetText(host, ip));
        var (okLo, why) = await Fits(lo).ConfigureAwait(false);
        if (!okLo)
        {
            return (false, result, $"Schon {lo} Byte kommen nicht durch ({Err(why, "")}) – Ziel antwortet nicht auf Ping oder ICMP ist gefiltert.");
        }

        var (okHi, whyHi) = await Fits(hi).ConfigureAwait(false);
        int best;
        var blackhole = false;
        if (okHi)
        {
            best = hi;
        }
        else
        {
            int good = lo, bad = hi;
            while (bad - good > 1)
            {
                var mid = (good + bad) / 2;
                if ((await Fits(mid).ConfigureAwait(false)).Fits)
                {
                    good = mid;
                }
                else
                {
                    bad = mid;
                }
            }

            best = good;
            blackhole = whyHi == IPStatus.TimedOut;
        }

        var hint = MtuHints.FirstOrDefault(h => best >= h.Mtu).Text ?? "kleiner als üblich – Tunnel oder Fehlkonfiguration auf dem Weg";
        result.Headline = $"Pfad-MTU {best} Byte";
        result.Verdict = best >= 1500 || okHi ? "ok" : "warn";
        result.Add("Pfad-MTU", $"{best} Byte{(okHi ? " oder mehr" : "")}", best >= 1500 ? "good" : "warn")
            .Add("Einordnung", hint).Add("TCP-MSS dazu", $"{best - 40} Byte");
        if (blackhole)
        {
            result.Add("Hinweis", "Zu große Pakete verschwinden ohne Fehlermeldung (keine ICMP-Meldung „Fragmentierung nötig“) – " +
                                  "möglicher PMTU-Blackhole: große Downloads oder VPN können hängen.", "warn");
        }

        return (true, result, null);
    }

    // -- Traceroute ----------------------------------------------------------------------
    private async Task<(bool, ToolResult, string?)> TraceAsync(ToolJob job, CancellationToken ct)
    {
        var a = job.Args;
        var host = a.Str("host");
        var (ip, error) = await ResolveAsync(host, ct).ConfigureAwait(false);
        if (ip is null)
        {
            return (false, new ToolResult(), error);
        }

        int count = a.Int("count", 3, 1, 10), maxHops = a.Int("max_hops", 30, 1, 40);
        var names = a.Flag("names", true);
        var table = new ToolTable { Title = "Weg", Head = new() { "Hop", "Router", "Verlust", "min ms", "Mittel ms", "max ms" } };
        var reached = false;
        await Report(line: $"Traceroute zu {TargetText(host, ip)}, höchstens {maxHops} Hops, {count} Pakete je Hop").ConfigureAwait(false);
        for (var ttl = 1; ttl <= maxHops; ttl++)
        {
            var rtts = new List<double>();
            IPAddress? source = null;
            for (var i = 0; i < count; i++)
            {
                var r = await PingOnceAsync(ip, 32, ttl, false, 1500, ct).ConfigureAwait(false);
                if (r.Success || r.Status == IPStatus.TtlExpired)
                {
                    source ??= r.From;
                    rtts.Add(r.RttMs);
                    reached |= r.Success;
                }
            }

            var loss = (int)Math.Round((count - rtts.Count) * 100.0 / count);
            var name = source is not null && names ? await PtrAsync(source, ct).ConfigureAwait(false) : null;
            var addr = source is null ? "*" : name is null ? source.ToString() : $"{name} ({source})";
            table.Rows.Add(new List<string>
            {
                ttl.ToString(), addr, $"{loss} %",
                rtts.Count > 0 ? ToolArgs.Ms(rtts.Min()) : "–", rtts.Count > 0 ? ToolArgs.Ms(rtts.Average()) : "–",
                rtts.Count > 0 ? ToolArgs.Ms(rtts.Max()) : "–",
            });
            table.Classes.Add(rtts.Count == 0 || loss == 0 ? string.Empty : "warn");
            var detail = rtts.Count > 0 ? string.Join(" ", rtts.Select(x => ToolArgs.Ms(x) + " ms")) : "keine Antwort";
            await Report(reached ? 1.0 : (double)ttl / maxHops, $"Hop {ttl}: {addr}", $"{ttl,3}  {addr,-45} {loss,3} %  {detail}")
                .ConfigureAwait(false);
            if (reached)
            {
                break;
            }
        }

        var hops = table.Rows.Count;
        var hopWord = hops == 1 ? "Hop" : "Hops";
        var result = new ToolResult
        {
            Headline = $"{(reached ? "Ziel erreicht" : "Ziel nicht erreicht")} – {hops} {hopWord}",
            Verdict = reached ? "ok" : "bad",
            Table = table,
        };
        result.Add("Ziel", TargetText(host, ip))
            .Add("Ziel erreicht", reached ? $"ja, nach {hops} {hopWord}" : $"nein – nach {hops} {hopWord} abgebrochen", reached ? "good" : "bad");
        var silent = table.Rows.Where(r => r[1] == "*").Select(r => r[0]).ToList();
        if (silent.Count > 0 && reached)
        {
            result.Add("Ohne Antwort", $"Hop {string.Join(", ", silent)} – viele Router beantworten Traceroute nicht, das ist meist " +
                                       "unbedenklich, solange das Ziel antwortet.");
        }

        return (true, result, null);
    }

    private static async Task<string?> PtrAsync(IPAddress ip, CancellationToken ct)
    {
        try
        {
            var lookup = Dns.GetHostEntryAsync(ip);
            var done = await Task.WhenAny(lookup, Task.Delay(1500, ct)).ConfigureAwait(false);
            return done == lookup && lookup.Result.HostName != ip.ToString() ? lookup.Result.HostName : null;
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            return null;
        }
    }

    // -- DNS -----------------------------------------------------------------------------
    private async Task<(bool, ToolResult, string?)> DnsAsync(ToolJob job, CancellationToken ct)
    {
        var a = job.Args;
        var name = a.Str("name");
        var type = a.Str("type", "A");
        if (!DnsClient.Types.TryGetValue(type, out var qtype))
        {
            return (false, new ToolResult(), "Unbekannter DNS-Typ.");
        }

        var servers = IPAddress.TryParse(a.Str("server"), out var own) ? new List<IPAddress> { own } : DnsClient.SystemResolvers().Take(3).ToList();
        if (servers.Count == 0)
        {
            return (false, new ToolResult(), "Kein DNS-Server gefunden – bitte einen DNS-Server angeben.");
        }

        var result = new ToolResult().Add("Name", name).Add("Typ", type);
        DnsAnswer? first = null;
        ToolTable? table = null;
        for (var i = 0; i < servers.Count; i++)
        {
            var server = servers[i];
            await Report((double)i / servers.Count, $"Frage {server} …").ConfigureAwait(false);
            var sw = Stopwatch.StartNew();
            DnsAnswer res;
            try
            {
                res = await DnsClient.AskAsync(server, name, qtype, TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or FormatException or IOException
                                           && !ct.IsCancellationRequested)
            {
                var msg = ex is OperationCanceledException ? "keine Antwort (Zeitüberschreitung)" : ex.Message;
                result.Add($"Server {server}", msg, "bad");
                await Report(line: $"{server}: {msg}").ConfigureAwait(false);
                continue;
            }

            var answers = res.Records.Where(r => r.Section == "answer").ToList();
            var cls = res.Rcode == "NOERROR" && answers.Count > 0 ? "good" : res.Rcode == "NOERROR" ? "warn" : "bad";
            result.Add($"Server {server}", $"{res.Rcode} · {answers.Count} Einträge · {ToolArgs.Ms(sw.Elapsed.TotalMilliseconds)} ms" +
                                           (res.Authoritative ? " · autoritativ" : "") + (res.Tcp ? " · über TCP" : ""), cls);
            await Report(line: $"{server}: {res.Rcode}, {answers.Count} Einträge in {ToolArgs.Ms(sw.Elapsed.TotalMilliseconds)} ms")
                .ConfigureAwait(false);
            if (first is null)
            {
                first = res;
                table = new ToolTable { Title = "Einträge", Head = new() { "Name", "Typ", "TTL", "Wert" } };
                foreach (var r in answers)
                {
                    table.Rows.Add(new List<string> { r.Name, r.Type, r.Ttl.ToString(), r.Data });
                    await Report(line: $"  {r.Name} {r.Ttl} {r.Type} {r.Data}").ConfigureAwait(false);
                }
            }
        }

        if (first is null)
        {
            return (false, result, "Kein DNS-Server hat geantwortet.");
        }

        var n = table!.Rows.Count;
        result.Verdict = first.Rcode == "NOERROR" && n > 0 ? "ok" : first.Rcode == "NOERROR" ? "warn" : "bad";
        result.Headline = n > 0 ? $"{n} {(n == 1 ? "Eintrag" : "Einträge")}"
            : first.Rcode == "NXDOMAIN" ? "Name existiert nicht (NXDOMAIN)"
            : first.Rcode == "NOERROR" ? $"Keine {type}-Einträge" : $"Fehler: {first.Rcode}";
        if (n > 0)
        {
            result.Table = table;
        }

        return (true, result, null);
    }

    // -- Port ----------------------------------------------------------------------------
    private async Task<(bool, ToolResult, string?)> PortAsync(ToolJob job, CancellationToken ct)
    {
        var a = job.Args;
        var host = a.Str("host");
        IPAddress ip;
        if (!IPAddress.TryParse(host, out ip!))
        {
            try
            {
                ip = (await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, ct).ConfigureAwait(false)).First();
            }
            catch (Exception ex) when (ex is SocketException or InvalidOperationException or ArgumentException)
            {
                return (false, new ToolResult(), "DNS-Auflösung fehlgeschlagen: " + ex.Message);
            }
        }

        var ports = a.Ints("ports");
        var timeout = TimeSpan.FromSeconds(a.Int("timeout", 3, 1, 10));
        var table = new ToolTable { Title = "Ports", Head = new() { "Port", "Dienst", "Zustand", "Antwort", "Details" } };
        var open = 0;
        for (var i = 0; i < ports.Count; i++)
        {
            var port = ports[i];
            var (state, ms, detail) = await CheckPortAsync(ip, port, timeout, ct).ConfigureAwait(false);
            open += state == "offen" ? 1 : 0;
            table.Rows.Add(new List<string> { port.ToString(), PortNames.GetValueOrDefault(port, ""), state, ms is null ? "–" : ToolArgs.Ms(ms) + " ms", detail });
            table.Classes.Add(state == "offen" ? string.Empty : state == "geschlossen" ? "warn" : "bad");
            await Report((double)(i + 1) / ports.Count, $"Port {port}: {state}", $"{port,5}/tcp  {state}  {detail}").ConfigureAwait(false);
        }

        var total = ports.Count;
        var result = new ToolResult
        {
            Headline = $"{open} von {total} {(total == 1 ? "Port" : "Ports")} offen",
            Verdict = open == total ? "ok" : open > 0 ? "warn" : "bad",
            Table = table,
        };
        result.Add("Ziel", TargetText(host, ip));
        return (true, result, null);
    }

    private static async Task<(string State, double? Ms, string Detail)> CheckPortAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
    {
        using var client = new TcpClient(ip.AddressFamily);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var sw = Stopwatch.StartNew();
        try
        {
            await client.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
            return ("offen", sw.Elapsed.TotalMilliseconds, string.Empty);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return ("geschlossen", sw.Elapsed.TotalMilliseconds, "abgewiesen (RST)");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return ("gefiltert", null, "keine Antwort – Firewall verwirft");
        }
        catch (SocketException ex)
        {
            return ("Fehler", null, ex.Message);
        }
    }

    // -- HTTP(S) und Zertifikat ------------------------------------------------------------
    private sealed record TlsConnection(Stream Stream, TcpClient Client, IPAddress Ip, double DnsMs, double ConnectMs, double? TlsMs,
        X509Certificate2? Certificate, SslPolicyErrors Errors, string Protocol) : IDisposable
    {
        public void Dispose()
        {
            Stream.Dispose();
            Client.Dispose();
            Certificate?.Dispose();
        }
    }

    private static async Task<TlsConnection> ConnectAsync(string host, int port, bool tls, string? sni, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(10));
        var sw = Stopwatch.StartNew();
        var ip = IPAddress.TryParse(host, out var parsed) ? parsed
            : (await Dns.GetHostAddressesAsync(host, cts.Token).ConfigureAwait(false)).First();
        var dnsMs = sw.Elapsed.TotalMilliseconds;
        var client = new TcpClient(ip.AddressFamily);
        try
        {
            await client.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
            var connectMs = sw.Elapsed.TotalMilliseconds - dnsMs;
            if (!tls)
            {
                return new TlsConnection(client.GetStream(), client, ip, dnsMs, connectMs, null, null, SslPolicyErrors.None, string.Empty);
            }

            var errors = SslPolicyErrors.None;
            X509Certificate2? cert = null;
            var ssl = new SslStream(client.GetStream(), false, (_, c, _, e) =>
            {
                errors = e;
                cert = c is null ? null : new X509Certificate2(c);
                return true;   // geprüft wird im Ergebnis, nicht beim Verbinden
            });
            var t0 = sw.Elapsed.TotalMilliseconds;
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = sni ?? host }, cts.Token)
                .ConfigureAwait(false);
            return new TlsConnection(ssl, client, ip, dnsMs, connectMs, sw.Elapsed.TotalMilliseconds - t0, cert, errors,
                $"{ProtocolName(ssl.SslProtocol)} · {ssl.NegotiatedCipherSuite}");
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

#pragma warning disable SYSLIB0039 // alte Protokolle nur zum Benennen
    private static string ProtocolName(SslProtocols p) => p switch
    {
        SslProtocols.Tls13 => "TLSv1.3",
        SslProtocols.Tls12 => "TLSv1.2",
        SslProtocols.Tls11 => "TLSv1.1",
        SslProtocols.Tls => "TLSv1",
        _ => p.ToString(),
    };
#pragma warning restore SYSLIB0039

    private static string VerifyText(SslPolicyErrors e) => e switch
    {
        SslPolicyErrors.None => "in Ordnung",
        SslPolicyErrors.RemoteCertificateNameMismatch => "FEHLER: Name passt nicht zum Zertifikat",
        SslPolicyErrors.RemoteCertificateChainErrors => "FEHLER: Aussteller nicht vertrauenswürdig oder Kette unvollständig",
        _ => $"FEHLER: {e}",
    };

    private static void AddCert(ToolResult result, X509Certificate2 cert, SslPolicyErrors errors, bool withTrust = true)
    {
        var san = cert.Extensions.FirstOrDefault(x => x.Oid?.Value == "2.5.29.17")?.Format(false) ?? string.Empty;
        var names = string.Join(", ", san.Split(new[] { ',', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => x.Replace("DNS Name=", string.Empty).Replace("DNS-Name=", string.Empty)).Take(8));
        var days = (int)Math.Floor((cert.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays);
        result.Add("Zertifikat für", string.IsNullOrEmpty(names) ? cert.Subject : names)
            .Add("Aussteller", cert.Issuer)
            .Add("Gültig bis", $"{cert.NotAfter:dd.MM.yyyy} ({(days < 0 ? "ABGELAUFEN" : $"noch {days} Tage")})",
                days < 0 ? "bad" : days < 21 ? "warn" : "good");
        if (withTrust)
        {
            result.Add("Vertrauen", VerifyText(errors), errors == SslPolicyErrors.None ? "good" : "bad");
        }
    }

    private async Task<(bool, ToolResult, string?)> TlsAsync(ToolJob job, CancellationToken ct)
    {
        var a = job.Args;
        var host = a.Str("host");
        var port = a.Int("port", 443, 1, 65535);
        var sni = a.Str("sni");
        await Report(0.2, $"Verbinde mit {host}:{port} …").ConfigureAwait(false);
        TlsConnection conn;
        try
        {
            conn = await ConnectAsync(host, port, true, string.IsNullOrEmpty(sni) ? null : sni, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException
                                       && !ct.IsCancellationRequested)
        {
            return (false, new ToolResult(), "Keine TLS-Verbindung: " + ex.Message);
        }

        using (conn)
        {
            if (conn.Certificate is null)
            {
                return (false, new ToolResult(), "Der Dienst hat kein Zertifikat gesendet.");
            }

            var result = new ToolResult().Add("Ziel", $"{host}:{port}" + (conn.Ip.ToString() != host ? $" ({conn.Ip})" : ""));
            AddCert(result, conn.Certificate, conn.Errors);
            var days = (conn.Certificate.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays;
            result.Add("Protokoll", conn.Protocol, conn.Protocol.StartsWith("TLSv1 ", StringComparison.Ordinal) || conn.Protocol.StartsWith("TLSv1.1", StringComparison.Ordinal) ? "warn" : "")
                .Add("Handshake", $"{ToolArgs.Ms(conn.TlsMs)} ms");
            var bad = conn.Errors != SslPolicyErrors.None || days < 0;
            result.Headline = bad ? "Zertifikat mit Problem" : "Zertifikat in Ordnung";
            result.Verdict = bad ? "bad" : days < 21 ? "warn" : "ok";
            return (true, result, null);
        }
    }

    private static readonly Dictionary<int, string> HttpText = new()
    {
        [200] = "OK", [204] = "Kein Inhalt", [301] = "Dauerhaft verschoben", [302] = "Vorübergehend verschoben", [303] = "Siehe andere Adresse",
        [304] = "Nicht geändert", [307] = "Vorübergehend umgeleitet", [308] = "Dauerhaft umgeleitet", [400] = "Ungültige Anfrage",
        [401] = "Anmeldung erforderlich", [403] = "Zugriff verweigert", [404] = "Nicht gefunden",
        [405] = "Methode nicht erlaubt (GET statt HEAD versuchen)", [429] = "Zu viele Anfragen", [500] = "Interner Serverfehler",
        [502] = "Fehlerhaftes Gateway", [503] = "Dienst nicht verfügbar", [504] = "Gateway-Zeitüberschreitung",
    };

    private async Task<(bool, ToolResult, string?)> HttpAsync(ToolJob job, CancellationToken ct)
    {
        var a = job.Args;
        var url = new Uri(a.Str("url"));
        var https = url.Scheme == Uri.UriSchemeHttps;
        var method = a.Str("method", "HEAD") == "GET" ? "GET" : "HEAD";
        var insecure = a.Flag("insecure");
        var fail = new ToolResult().Add("Adresse", url.ToString());
        await Report(0.1, $"Verbinde mit {url.Host}:{url.Port} …").ConfigureAwait(false);
        var total = Stopwatch.StartNew();
        TlsConnection conn;
        try
        {
            conn = await ConnectAsync(url.Host, url.Port, https, null, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException
                                       or InvalidOperationException && !ct.IsCancellationRequested)
        {
            return (false, fail, "Keine Verbindung: " + ex.Message);
        }

        using (conn)
        {
            if (https && conn.Errors != SslPolicyErrors.None && !insecure)
            {
                return (false, fail, $"Zertifikat abgelehnt: {VerifyText(conn.Errors)} – zum Testen „Zertifikatsfehler ignorieren“ wählen.");
            }

            await Report(0.5, "Warte auf Antwort …").ConfigureAwait(false);
            var hostHeader = url.IsDefaultPort ? url.Host : $"{url.Host}:{url.Port}";
            var request = $"{method} {url.PathAndQuery} HTTP/1.1\r\nHost: {hostHeader}\r\nUser-Agent: Wachtl-Werkzeug\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            var send = Stopwatch.StartNew();
            await conn.Stream.WriteAsync(Encoding.ASCII.GetBytes(request), ct).ConfigureAwait(false);
            var buf = new MemoryStream();
            var chunk = new byte[16384];
            double? ttfb = null;
            int headerEnd;
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(15));
            while ((headerEnd = IndexOfHeaderEnd(buf)) < 0 && buf.Length < 65536)
            {
                var n = await conn.Stream.ReadAsync(chunk, cts.Token).ConfigureAwait(false);
                if (n == 0)
                {
                    break;
                }

                ttfb ??= send.Elapsed.TotalMilliseconds;
                buf.Write(chunk, 0, n);
            }

            long body = headerEnd >= 0 ? buf.Length - headerEnd - 4 : 0;
            if (method == "GET")
            {
                while (body < 5_000_000)
                {
                    var n = await conn.Stream.ReadAsync(chunk, cts.Token).ConfigureAwait(false);
                    if (n == 0)
                    {
                        break;
                    }

                    body += n;
                }
            }

            var head = Encoding.Latin1.GetString(buf.GetBuffer(), 0, headerEnd >= 0 ? headerEnd : (int)buf.Length).Split("\r\n");
            var m = System.Text.RegularExpressions.Regex.Match(head.Length > 0 ? head[0] : string.Empty, @"HTTP/([\d.]+)\s+(\d{3})");
            if (!m.Success)
            {
                return (false, fail, "Keine gültige HTTP-Antwort erhalten.");
            }

            var code = int.Parse(m.Groups[2].Value);
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in head.Skip(1))
            {
                var k = line.IndexOf(':');
                if (k > 0)
                {
                    headers.TryAdd(line[..k].Trim(), line[(k + 1)..].Trim());
                }
            }

            foreach (var line in head)
            {
                await Report(line: line).ConfigureAwait(false);
            }

            var text = HttpText.GetValueOrDefault(code, string.Empty);
            var cls = code < 300 ? "good" : code < 400 ? "" : code < 500 ? "warn" : "bad";
            var result = new ToolResult
            {
                Headline = $"HTTP {code} {text}".Trim(),
                Verdict = code < 400 ? "ok" : code < 500 ? "warn" : "bad",
            };
            result.Add("Adresse", url.ToString()).Add("Status", $"HTTP {code} {text} (HTTP/{m.Groups[1].Value})", cls)
                .Add("Server-IP", conn.Ip.ToString())
                .Add("Zeiten", $"DNS {ToolArgs.Ms(conn.DnsMs)} ms · Verbindung {ToolArgs.Ms(conn.ConnectMs)} ms" +
                               (conn.TlsMs is null ? "" : $" · TLS {ToolArgs.Ms(conn.TlsMs)} ms") +
                               $" · erstes Byte {ToolArgs.Ms(ttfb)} ms · gesamt {ToolArgs.Ms(total.Elapsed.TotalMilliseconds)} ms");
            if (headers.TryGetValue("location", out var loc))
            {
                result.Add("Weiterleitung", loc, "warn");
            }

            if (headers.TryGetValue("server", out var server))
            {
                result.Add("Server", server);
            }

            if (headers.TryGetValue("content-type", out var ctype))
            {
                result.Add("Inhalt", ctype + (method == "GET" ? $" · {body} Byte" : ""));
            }

            if (conn.Certificate is not null)
            {
                AddCert(result, conn.Certificate, conn.Errors, insecure);
            }

            return (true, result, null);
        }
    }

    private static int IndexOfHeaderEnd(MemoryStream ms)
    {
        var b = ms.GetBuffer();
        for (var i = 0; i + 3 < ms.Length; i++)
        {
            if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n')
            {
                return i;
            }
        }

        return -1;
    }
}
