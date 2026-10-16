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
/// Befehle für Setup-Assistent, Install-Wachtl.ps1 und Diagnose.
/// Exit-Codes: 0 ok, 2 Aufruf falsch, 3 Pin passt nicht, 4 Server nicht erreichbar, 5 Server lehnt ab, 6 nicht registriert.
/// Mit <c>--out datei.ini</c> schreiben enroll/check/configure ihr Ergebnis als INI (UTF-16) für den Assistenten.
/// </summary>
public static class Cli
{
    public const int ExitOk = 0, ExitUsage = 2, ExitPinMismatch = 3, ExitUnreachable = 4, ExitRejected = 5, ExitNotEnrolled = 6;

    private static readonly string[] Commands = { "enroll", "check", "configure", "show-pin", "status", "--version", "help", "--help" };

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

    internal static Uri ParseServer(string value)
    {
        var text = value.Trim();
        if (!text.Contains("://", StringComparison.Ordinal))
        {
            text = "https://" + text;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Die Server-Adresse muss mit https:// beginnen, z. B. https://wachtl.kunde.local");
        }

        return new Uri(uri.GetLeftPart(UriPartial.Authority) + "/");
    }

    // -- enroll ------------------------------------------------------------------------
    private static async Task<int> EnrollAsync(Dictionary<string, string> options, CliResult result)
    {
        var server = ParseServer(Required(options, "server"));
        var pin = Required(options, "pin");
        var proxy = Optional(options, "proxy");
        var hostname = Optional(options, "hostname") ?? Environment.MachineName;

        using var api = new ApiClient(server, pin, proxy);
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var response = await api.EnrollAsync(new EnrollRequest
            {
                EnrollmentToken = Required(options, "token"),
                Hostname = hostname,
                Os = AppInfo.OsDescription,
                Version = AppInfo.Version,
            }, cts.Token);

            StateStore.Save(new ProbeState
            {
                ServerUrl = server.ToString(),
                SpkiPin = pin,
                ProbeId = response.ProbeId,
                ProtectedToken = StateStore.ProtectToken(response.Token),
                Proxy = proxy,
                SiteName = response.SiteName,
                EnrolledAt = DateTimeOffset.UtcNow,
            });
            result.Set("probe_id", response.ProbeId.ToString());
            result.Set("site", response.SiteName);
            result.Set("hostname", hostname);
            Console.WriteLine($"Registriert: Probe {response.ProbeId} ({hostname}) am Standort {response.SiteName}");
            return ExitOk;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or ApiException)
        {
            return Fail(ex, result);
        }
    }

    // -- check: Server erreichbar? Pin richtig? Verbraucht keinen Token ---------------------------
    private static async Task<int> CheckAsync(Dictionary<string, string> options, CliResult result)
    {
        Uri server;
        string? pin, proxy;
        if (options.ContainsKey("use-state"))
        {
            var state = StateStore.Load();
            if (state is null)
            {
                result.Set("error", "Diese Probe ist noch nicht registriert.");
                return ExitNotEnrolled;
            }

            server = new Uri(state.ServerUrl);
            pin = state.SpkiPin;
            proxy = options.ContainsKey("proxy") ? Optional(options, "proxy") : state.Proxy;
        }
        else
        {
            server = ParseServer(Required(options, "server"));
            pin = Optional(options, "pin");
            proxy = Optional(options, "proxy");
        }

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
              wachtl-probe.exe check --server https://wachtl.firma.local [--pin <Pin>] [--proxy http://proxy:3128]
              wachtl-probe.exe enroll --server https://wachtl.firma.local --token <Token> --pin <SPKI-Pin> [--proxy …] [--hostname NAME]
              wachtl-probe.exe configure --proxy http://proxy:3128 | none
              wachtl-probe.exe show-pin --server https://wachtl.firma.local
              wachtl-probe.exe status
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
