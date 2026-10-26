using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Wachtl.Probe.Buffer;
using Wachtl.Probe.Config;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe;

/// <summary>
/// Befehle für den Setup-Assistenten und die Diagnose.
/// Exit-Codes: 0 ok, 2 Aufruf falsch, 3 Pin passt nicht, 4 Server nicht erreichbar, 5 Server lehnt ab, 6 nicht registriert,
/// 7 Server nicht erreichbar, Registrierung wird vom Dienst nachgeholt (enroll --defer-offline 1).
/// Mit <c>--out datei.ini</c> schreiben enroll/check/configure ihr Ergebnis als INI (UTF-16) für den Assistenten.
/// </summary>
public static class Cli
{
    public const int ExitOk = 0, ExitUsage = 2, ExitPinMismatch = 3, ExitUnreachable = 4, ExitRejected = 5, ExitNotEnrolled = 6,
        ExitDeferred = 7;

    private static readonly string[] Commands = { "enroll", "check", "configure", "show-pin", "status", "deregister", "trust", "--version", "help", "--help" };

    public static bool IsCommand(string[] args) => args.Length > 0 && Commands.Contains(args[0]);

    public static async Task<int> RunAsync(string[] args)
    {
        Dictionary<string, string> options;
        try
        {
            options = ParseOptions(args[1..]);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine("Fehler: " + ex.Message);
            Help();
            return ExitUsage;
        }

        var result = new CliResult(options.TryGetValue("out", out var outFile) ? outFile : null);
        try
        {
            var code = args[0] switch
            {
                "enroll" => await EnrollAsync(options, result),
                "check" => await CheckAsync(options, result),
                "configure" => Configure(options, result),
                "show-pin" => await ShowPinAsync(options),
                "status" => Status(),
                "deregister" => await DeregisterAsync(result),
                "trust" => await TrustAsync(options, result),
                "--version" => PrintVersion(),
                _ => Help(),
            };
            result.Write(code);
            return code;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine("Fehler: " + ex.Message);
            result.Set("error", ex.Message);
            result.Write(ExitUsage);
            return ExitUsage;
        }        catch (UnauthorizedAccessException)
        {
            const string message = "Keine Berechtigung – bitte als Administrator ausführen.";
            Console.Error.WriteLine("Fehler: " + message);
            result.Set("error", message);
            result.Write(1);
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Fehler: " + ex.Message);
            result.Set("error", ex.Message);
            result.Write(1);
            return 1;
        }
    }

    internal static Dictionary<string, string> ParseOptions(string[] args)
    {
        var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Length)
            {
                throw new ArgumentException($"Unerwartetes Argument: {args[i]}");
            }

            options[args[i][2..]] = args[++i];
        }

        return options;
    }

    private static string Required(Dictionary<string, string> options, string key) =>
        options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : throw new ArgumentException($"--{key} fehlt");

    private static string? Optional(Dictionary<string, string> options, string key) =>
        options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;

    internal static Uri ParseServer(string value) => Enrollment.ParseServers(value)[0];

    // -- deregister ----------------------------------------------------------------------
    /// <summary>
    /// Bei der Deinstallation: Probe am Server abmelden (Token wird dort sofort ungültig) und das
    /// lokal gespeicherte Token löschen. Ist der Server nicht erreichbar, wird das Token trotzdem gelöscht
    /// (Exit-Code 4) – die Probe sollte dann im Dashboard gelöscht werden.
    /// </summary>
    private static async Task<int> DeregisterAsync(CliResult result)
    {
        var state = StateStore.Load();
        if (state is null)
        {
            Console.WriteLine("Probe ist nicht registriert – nichts abzumelden.");
            result.Set("deregistered", "0");
            DeleteState();
            return ExitNotEnrolled;
        }

        var code = ExitOk;
        try
        {
            var token = StateStore.UnprotectToken(state.ProtectedToken);
            using var api = new ApiClient(state.AllServers(), state.SpkiPin, state.Proxy, token);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await api.DeregisterAsync(cts.Token);
            Console.WriteLine($"Probe {state.ProbeId} bei {state.ServerUrl} abgemeldet – ihr Token ist ab sofort ungültig.");
            result.Set("deregistered", "1");
        }
        catch (ApiException ex) when (ex.IsAuthError)
        {
            Console.WriteLine("Der Server kennt das Token nicht mehr (Probe bereits gelöscht oder deaktiviert).");
            result.Set("deregistered", "1");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or ApiException
                                       or System.Security.Cryptography.CryptographicException or FormatException)
        {
            Console.Error.WriteLine($"Abmeldung am Server nicht möglich: {ex.Message}. Bitte die Probe im Dashboard löschen.");
            result.Set("deregistered", "0");
            result.Set("error", ex.Message);
            code = ExitUnreachable;
        }

        DeleteState();
        return code;
    }

    private static void DeleteState()
    {
        StateStore.DeletePending();
        foreach (var path in new[] { StateStore.StatePath, StateStore.StatePath + ".tmp", StateStore.ConfigCachePath,
                                     StateStore.ConfigCachePath + ".tmp" })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    // -- trust: Server-Zertifikat als Stammzertifikat ablegen (Setup, als Administrator) ------------
    /// <summary>
    /// Holt das Zertifikat vom Server – nur wenn es zum Pin passt – und legt es unter „Vertrauenswürdige
    /// Stammzertifizierungsstellen“ ab. Server, Pin und Proxy kommen aus dem Zustand der Probe (oder der
    /// nachzuholenden Registrierung) bzw. aus --server/--pin/--proxy. Mit --remove 1: wieder entfernen.
    /// </summary>
    private static async Task<int> TrustAsync(Dictionary<string, string> options, CliResult result)
    {
        if (Optional(options, "remove") is "1" or "true")
        {
            var removed = RootTrust.RemoveAll();
            result.Set("removed", removed.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Console.WriteLine(removed > 0 ? "Wachtl-Zertifikat aus den Stammzertifizierungsstellen entfernt." : "Kein Wachtl-Zertifikat abgelegt.");
            return ExitOk;
        }

        IReadOnlyList<Uri> servers;
        string pin;
        string? proxy;
        if (Optional(options, "server") is { } serverArg)
        {
            servers = Enrollment.ParseServers(serverArg);
            pin = Required(options, "pin");
            proxy = Optional(options, "proxy");
        }
        else if (StateStore.Load() is { } state)
        {
            servers = state.AllServers().ToList();
            pin = state.SpkiPin;
            proxy = state.Proxy;
        }
        else if (StateStore.LoadPending() is { } pending)
        {
            servers = Enrollment.ParseServers(string.Join(",", pending.ServerUrls));
            pin = pending.SpkiPin;
            proxy = pending.Proxy;
        }
        else
        {
            Console.Error.WriteLine("Probe ist nicht registriert – --server und --pin angeben.");
            return ExitNotEnrolled;
        }

        if (string.IsNullOrWhiteSpace(pin) || servers.Count == 0)
        {
            Console.Error.WriteLine("Server oder Pin fehlen.");
            return ExitNotEnrolled;
        }

        CliResult? lastResult = null;
        var lastCode = ExitUnreachable;
        foreach (var server in servers)
        {
            var attempt = new CliResult(null);
            var (code, cert, ca) = await FetchPinnedCertificateAsync(server, pin, proxy, attempt);
            if (cert is null)
            {
                lastResult = attempt;
                lastCode = code;
                continue;
            }

            using (cert)
            using (ca)
            {
                var root = RootTrust.SelectRoot(cert, ca);
                var outcome = root is null ? RootTrust.Outcome.NotSelfSigned : RootTrust.Install(root);
                var shown = root ?? cert;
                result.Set("trusted", outcome == RootTrust.Outcome.NotSelfSigned ? "0" : "1");
                result.Set("outcome", outcome.ToString());
                result.Set("thumbprint", shown.Thumbprint);
                Console.WriteLine(outcome switch
                {
                    RootTrust.Outcome.Added => $"Zertifikat {shown.Subject} unter „Vertrauenswürdige Stammzertifizierungsstellen“ abgelegt.",
                    RootTrust.Outcome.AlreadyTrusted => "Zertifikat ist bereits als vertrauenswürdig hinterlegt.",
                    _ => "Der Server nutzt ein Zertifikat einer Zertifizierungsstelle – nichts abzulegen.",
                });
                return ExitOk;
            }
        }

        if (lastResult is not null)
        {
            result.CopyFrom(lastResult);
        }

        result.Set("trusted", "0");
        Console.Error.WriteLine("Zertifikat nicht abgelegt: " + (lastResult?.Get("error") ?? "Server nicht erreichbar"));
        return lastCode;
    }

    /// <summary>
    /// Zertifikat des Servers holen (nur wenn sein Schlüssel zum Pin passt) und über dieselbe gepinnte Verbindung
    /// die Wachtl-CA von /zertifikat/wachtl.crt. Ältere Server ohne diese Seite: CA ist null.
    /// </summary>
    private static async Task<(int Code, X509Certificate2? Certificate, X509Certificate2? Ca)> FetchPinnedCertificateAsync(
        Uri server, string pin, string? proxy, CliResult result)
    {
        X509Certificate2? pinned = null;
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(10),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, cert, _, _) =>
                {
                    if (cert is null)
                    {
                        return false;
                    }

                    var c = new X509Certificate2(cert);
                    if (!SpkiPin.Matches(c, pin))
                    {
                        c.Dispose();
                        return false;
                    }

                    pinned?.Dispose();
                    pinned = c;
                    return true;
                },
            },
        };
        if (proxy is not null)
        {
            handler.Proxy = new WebProxy(proxy);
            handler.UseProxy = true;
        }

        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
        try
        {
            using (await http.GetAsync(new Uri(server, "healthz")))
            {
            }

            X509Certificate2? ca = null;
            using var response = await http.GetAsync(new Uri(server, "zertifikat/wachtl.crt"));
            if (response.IsSuccessStatusCode)
            {
                try
                {
                    ca = new X509Certificate2(await response.Content.ReadAsByteArrayAsync());
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    ca = null;
                }
            }

            return (ExitOk, pinned, ca);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            pinned?.Dispose();
            return (Fail(ex, result), null, null);
        }
    }

    // -- enroll ------------------------------------------------------------------------
    private static async Task<int> EnrollAsync(Dictionary<string, string> options, CliResult result)
    {
        var servers = Enrollment.ParseServers(Required(options, "server"));
        var pin = Required(options, "pin");
        var token = Required(options, "token");
        var proxy = Optional(options, "proxy");
        var hostname = Optional(options, "hostname") ?? Environment.MachineName;
        var defer = Optional(options, "defer-offline") is "1" or "true";

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30 + 15 * servers.Count));
            var (state, response) = await Enrollment.EnrollAsync(servers, pin, token, proxy, hostname, cts.Token);
            result.Set("probe_id", response.ProbeId.ToString());
            result.Set("site", response.SiteName);
            result.Set("hostname", hostname);
            result.Set("server", state.ServerUrl);
            Console.WriteLine($"Registriert: Probe {response.ProbeId} ({hostname}) am Standort {response.SiteName} über {state.ServerUrl}");
            return ExitOk;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or ApiException)
        {
            var code = Fail(ex, result);
            if (code == ExitUnreachable && defer)
            {
                // Server gerade nicht erreichbar (Standort offline, VPN aus …): der Dienst holt die Registrierung nach
                Enrollment.Defer(servers, pin, token, proxy, hostname, ex.InnerException?.Message ?? ex.Message);
                result.Set("deferred", "1");
                result.Set("hostname", hostname);
                Console.WriteLine("Server nicht erreichbar – die Registrierung wird automatisch nachgeholt, sobald er erreichbar ist.");
                return ExitDeferred;
            }

            return code;
        }
    }

    // -- check: Server erreichbar? Pin richtig? Verbraucht keinen Token ---------------------------
    private static async Task<int> CheckAsync(Dictionary<string, string> options, CliResult result)
    {
        List<Uri> servers;
        string? pin, proxy;
        if (options.ContainsKey("use-state"))
        {
            var state = StateStore.Load();
            if (state is null)
            {
                result.Set("error", "Diese Probe ist noch nicht registriert.");
                return ExitNotEnrolled;
            }

            servers = state.AllServers().ToList();
            pin = state.SpkiPin;
            proxy = options.ContainsKey("proxy") ? Optional(options, "proxy") : state.Proxy;
        }
        else
        {
            servers = Enrollment.ParseServers(Required(options, "server"));
            pin = Optional(options, "pin");
            proxy = Optional(options, "proxy");
        }

        // jede Adresse probieren: die erste, die antwortet, zählt; sonst der aussagekräftigste Fehler
        var best = int.MaxValue;
        CliResult? bestResult = null;
        foreach (var server in servers)
        {
            var attempt = new CliResult(null);
            var code = await CheckOneAsync(server, pin, proxy, attempt);
            if (code == ExitOk)
            {
                result.CopyFrom(attempt);
                return ExitOk;
            }

            var rank = code switch { ExitPinMismatch => 0, ExitRejected => 1, _ => 2 };
            if (rank < best)
            {
                best = rank;
                bestResult = attempt;
                bestResult.Set("code_detail", code.ToString());
            }
        }

        result.CopyFrom(bestResult!);
        if (servers.Count > 1)
        {
            result.Set("error", "Keine der Adressen funktioniert (" + string.Join(", ", servers.Select(s => s.Authority)) + "). " +
                                (bestResult!.Get("error") ?? string.Empty));
        }

        return int.Parse(bestResult!.Get("code_detail") ?? "4");
    }

    private static async Task<int> CheckOneAsync(Uri server, string? pin, string? proxy, CliResult result)
    {
        string? seenPin = null;
        string? subject = null;
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(10),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, cert, _, _) =>
                {
                    if (cert is null)
                    {
                        return false;
                    }

                    using var c = new X509Certificate2(cert);
                    seenPin = SpkiPin.Compute(c);
                    subject = c.Subject;
                    return pin is null || SpkiPin.Matches(c, pin);
                },
            },
        };
        if (proxy is not null)
        {
            handler.Proxy = new WebProxy(proxy);
            handler.UseProxy = true;
        }

        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
        result.Set("server", server.ToString());
        try
        {
            using var response = await http.GetAsync(new Uri(server, "healthz"));
            result.Set("pin", seenPin ?? string.Empty);
            result.Set("subject", subject ?? string.Empty);
            if (!response.IsSuccessStatusCode)
            {
                result.Set("error", $"Der Server antwortet mit HTTP {(int)response.StatusCode} – ist das wirklich der Wachtl-Server?");
                return ExitRejected;
            }

            var body = await response.Content.ReadAsStringAsync();
            if (!body.Contains("\"status\"", StringComparison.Ordinal))
            {
                result.Set("error", "Unter dieser Adresse antwortet kein Wachtl-Server.");
                return ExitRejected;
            }

            Console.WriteLine($"Server erreichbar, Pin: {seenPin}");
            return ExitOk;
        }
        catch (HttpRequestException ex) when (seenPin is not null && pin is not null && ex.InnerException is AuthenticationException)
        {
            result.Set("pin", seenPin);
            result.Set("error", $"Der Server meldet den Pin {seenPin}, eingegeben wurde {pin}. " +
                                "Pin prüfen (setup-info.txt auf dem Server) oder Proxy mit TLS-Prüfung ausnehmen.");
            return ExitPinMismatch;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return Fail(ex, result);
        }
    }

    // -- configure: nur Proxy ändern ------------------------------------------------------------
    private static int Configure(Dictionary<string, string> options, CliResult result)
    {
        var state = StateStore.Load();
        if (state is null)
        {
            result.Set("error", "Diese Probe ist noch nicht registriert.");
            return ExitNotEnrolled;
        }

        if (options.TryGetValue("proxy", out var proxy))
        {
            state.Proxy = string.IsNullOrWhiteSpace(proxy) || proxy.Equals("none", StringComparison.OrdinalIgnoreCase)
                ? null
                : proxy.Trim();
        }

        StateStore.Save(state);
        Console.WriteLine($"Proxy: {state.Proxy ?? "keiner"}");
        return ExitOk;
    }

    private static int Fail(Exception ex, CliResult result)
    {
        switch (ex)
        {
            case HttpRequestException { InnerException: AuthenticationException }:
                result.Set("error", "Das Server-Zertifikat passt nicht zum angegebenen Pin.");
                Console.Error.WriteLine("Fehler: Das Server-Zertifikat passt nicht zum angegebenen Pin.");
                return ExitPinMismatch;
            case ApiException api:
                result.Set("error", "Der Server lehnt ab: " + api.Message);
                Console.Error.WriteLine("Fehler: Server lehnt ab: " + api.Message);
                return ExitRejected;
            default:
                var message = ex is TaskCanceledException
                    ? "Zeitüberschreitung – Server oder Proxy antwortet nicht."
                    : "Server nicht erreichbar: " + (ex.InnerException?.Message ?? ex.Message);
                result.Set("error", message);
                Console.Error.WriteLine("Fehler: " + message);
                return ExitUnreachable;
        }
    }

    // -- show-pin / status / help ----------------------------------------------------------
    private static async Task<int> ShowPinAsync(Dictionary<string, string> options)
    {
        var server = ParseServer(Required(options, "server"));
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.Host, server.Port);
        X509Certificate2? cert = null;
        await using var ssl = new SslStream(tcp.GetStream(), false, (_, c, _, _) =>
        {
            if (c is not null)
            {
                cert = new X509Certificate2(c);
            }

            return true; // nur anzeigen, keine Daten übertragen
        });
        await ssl.AuthenticateAsClientAsync(server.Host);
        if (cert is null)
        {
            Console.Error.WriteLine("Kein Zertifikat erhalten.");
            return ExitUnreachable;
        }

        Console.WriteLine($"Zertifikat: {cert.Subject}, gültig bis {cert.NotAfter:dd.MM.yyyy}");
        Console.WriteLine($"SPKI-Pin:   {SpkiPin.Compute(cert)}");
        Console.WriteLine("Vergleiche den Pin mit setup-info.txt auf dem Server.");
        return ExitOk;
    }

    private static int Status()
    {
        if (Directory.Exists(StateStore.DataDir))
        {
            // ohne Adminrechte ist der Datenordner gesperrt – nicht fälschlich "nicht registriert" melden
            _ = Directory.GetFiles(StateStore.DataDir);
        }

        var state = StateStore.Load();
        if (state is null)
        {
            Console.WriteLine("Nicht registriert.");
            return ExitNotEnrolled;
        }

        Console.WriteLine($"Server:        {state.ServerUrl}");
        Console.WriteLine($"Probe-ID:      {state.ProbeId}");
        Console.WriteLine($"Standort:      {state.SiteName}");
        Console.WriteLine($"Registriert:   {state.EnrolledAt.LocalDateTime:dd.MM.yyyy HH:mm}");
        Console.WriteLine($"Proxy:         {state.Proxy ?? "keiner"}");
        if (StateStore.LoadCachedConfig() is { } config)
        {
            Console.WriteLine($"Checks:        {config.Checks.Count} (Konfiguration {config.Etag})");
            foreach (var c in config.Checks)
            {
                Console.WriteLine($"  - {c.Type} {c.Target} alle {c.IntervalS} s");
            }
        }

        if (File.Exists(StateStore.BufferPath))
        {
            var buffer = new SampleBuffer(StateStore.BufferPath, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
            Console.WriteLine($"Puffer:        {buffer.Count()} nicht gesendete Werte");
        }

        return ExitOk;
    }

    private static int PrintVersion()
    {
        Console.WriteLine(AppInfo.Version);
        return ExitOk;
    }

    private static int Help()
    {
        Console.WriteLine("""
            Wachtl-Probe

              wachtl-probe.exe                    als Dienst starten (oder im Vordergrund testen)
              wachtl-probe.exe check --server https://wachtl.firma.local[,https://10.0.0.5] [--pin <Pin>] [--proxy http://proxy:3128]
              wachtl-probe.exe enroll --server https://wachtl.firma.local[,https://10.0.0.5] --token <Token> --pin <SPKI-Pin>
                               [--proxy …] [--hostname NAME] [--defer-offline 1]
              wachtl-probe.exe configure --proxy http://proxy:3128 | none
              wachtl-probe.exe show-pin --server https://wachtl.firma.local
              wachtl-probe.exe status
              wachtl-probe.exe deregister         am Server abmelden und Token löschen (Deinstallation)
              wachtl-probe.exe trust [--remove 1] Server-Zertifikat als Stammzertifikat ablegen/entfernen (als Administrator)
              wachtl-probe.exe --version

            Optional bei check/enroll/configure: --out ergebnis.ini (für den Setup-Assistenten)
            """);
        return ExitOk;
    }
}

/// <summary>Ergebnisdatei im INI-Format (UTF-16 mit BOM), lesbar mit GetIniString im Setup.</summary>
internal sealed class CliResult
{
    private readonly string? _path;
    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);

    public CliResult(string? path) => _path = path;

    public void Set(string key, string value) =>
        _values[key] = value.Replace("\r", string.Empty, StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);

    public string? Get(string key) => _values.TryGetValue(key, out var value) ? value : null;

    public void CopyFrom(CliResult other)
    {
        foreach (var (key, value) in other._values)
        {
            if (key != "code_detail")
            {
                _values[key] = value;
            }
        }
    }

    public void Write(int exitCode)
    {
        if (string.IsNullOrEmpty(_path))
        {
            return;
        }

        var sb = new StringBuilder("[result]\r\n");
        sb.Append("ok=").Append(exitCode == 0 ? "1" : "0").Append("\r\n");
        sb.Append("code=").Append(exitCode).Append("\r\n");
        foreach (var (key, value) in _values)
        {
            sb.Append(key).Append('=').Append(value).Append("\r\n");
        }

        File.WriteAllText(_path, sb.ToString(), new UnicodeEncoding(bigEndian: false, byteOrderMark: true));
    }
}
