using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;

#pragma warning disable SYSLIB0014 // HttpWebRequest: in .NET Framework 4.6.2 ohne Zusatz-DLL verfügbar

namespace Wachtl.Tray.Core
{
    /// <summary>Verbindungszustand, wie ihn das Tray-Symbol anzeigt.</summary>
    public enum TrayConnection
    {
        Unknown,
        ServiceDown,
        NotEnrolled,
        Disconnected,
        Connected,
    }

    /// <summary>Antwort von GET /tray/v1/status.</summary>
    public sealed class TrayStatus
    {
        public string Role { get; set; } = "probe";
        public string Name { get; set; } = string.Empty;
        public string Site { get; set; } = string.Empty;
        public string ServerUrl { get; set; } = string.Empty;
        public string DashboardUrl { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public bool Enrolled { get; set; }
        public bool Connected { get; set; }
        public long LastContact { get; set; }
        public int PendingReports { get; set; }

        public bool IsServer => Role == "server";

        public TrayConnection Connection =>
            !Enrolled ? TrayConnection.NotEnrolled : Connected ? TrayConnection.Connected : TrayConnection.Disconnected;

        public static TrayStatus? FromJson(string json)
        {
            var o = TrayJson.TryParseObject(json);
            if (o == null)
            {
                return null;
            }

            return new TrayStatus
            {
                Role = TrayJson.GetString(o, "role", "probe"),
                Name = TrayJson.GetString(o, "name"),
                Site = TrayJson.GetString(o, "site"),
                ServerUrl = TrayJson.GetString(o, "server_url"),
                DashboardUrl = TrayJson.GetString(o, "dashboard_url"),
                Version = TrayJson.GetString(o, "version"),
                Enrolled = TrayJson.GetBool(o, "enrolled"),
                Connected = TrayJson.GetBool(o, "connected"),
                LastContact = TrayJson.GetLong(o, "last_contact"),
                PendingReports = (int)TrayJson.GetLong(o, "pending_reports"),
            };
        }
    }

    public enum ReportOutcome
    {
        /// <summary>sofort an den Server zugestellt</summary>
        Delivered,

        /// <summary>vom Dienst gespeichert, wird nachgeliefert</summary>
        Queued,

        /// <summary>abgelehnt oder Dienst nicht erreichbar – Fenster bleibt offen</summary>
        Failed,
    }

    public sealed class ReportResult
    {
        public ReportResult(ReportOutcome outcome, string message)
        {
            Outcome = outcome;
            Message = message;
        }

        public ReportOutcome Outcome { get; }

        public string Message { get; }
    }

    /// <summary>Texte für Tooltip, Über-Fenster und Rückmeldungen.</summary>
    public static class TrayTexts
    {
        public const string Title = "Wachtl – Netzwerk-Monitoring";
        public const string Delivered = "Danke – Ihre Meldung wurde an die IT übermittelt.";
        public const string Queued = "Danke – Ihre Meldung wurde gespeichert und wird übermittelt, sobald der Server erreichbar ist.";
        public const string ServiceDown =
            "Der Wachtl-Dienst auf diesem PC ist nicht erreichbar. Die Meldung wurde nicht gesendet.\n\nBitte versuchen Sie es später erneut oder wenden Sie sich direkt an die IT.";

        public static string Connection(TrayConnection state)
        {
            switch (state)
            {
                case TrayConnection.Connected: return "verbunden";
                case TrayConnection.Disconnected: return "keine Verbindung zum Server";
                case TrayConnection.NotEnrolled: return "nicht beim Server registriert";
                case TrayConnection.ServiceDown: return "Wachtl-Dienst läuft nicht";
                default: return "Zustand wird abgefragt …";
            }
        }

        /// <summary>Tooltip des Symbols; NotifyIcon.Text erlaubt in .NET Framework höchstens 63 Zeichen.</summary>
        public static string Tooltip(TrayConnection state)
        {
            var text = Title + "\n" + Connection(state);
            return text.Length > 63 ? text.Substring(0, 63) : text;
        }

        public static string ForStatusCode(int status, string? serverMessage)
        {
            var detail = string.IsNullOrWhiteSpace(serverMessage) ? null : serverMessage!.Trim();
            switch (status)
            {
                case 400: return "Die Meldung wurde nicht angenommen: " + (detail ?? "ungültige Angaben.");
                case 403: return "Der Wachtl-Dienst hat die Anfrage abgelehnt (Zugriff verweigert).";
                case 409: return "Dieser PC ist noch nicht beim Wachtl-Server registriert. Bitte wenden Sie sich direkt an die IT.";
                case 413: return "Die Meldung ist zu lang.";
                case 429: return "Es wurden in der letzten Stunde zu viele Meldungen gesendet. Bitte wenden Sie sich direkt an die IT.";
                default:
                    return "Die Meldung konnte nicht gesendet werden (Fehler " + status.ToString(CultureInfo.InvariantCulture) + ")"
                           + (detail != null ? ": " + detail : ".");
            }
        }
    }

    /// <summary>HTTP-Client für die lokale Schnittstelle des Wachtl-Dienstes (nur 127.0.0.1).</summary>
    public sealed class TrayClient
    {
        public const int DefaultPort = 47251;

        public TrayClient(int port)
        {
            Port = port;
        }

        public int Port { get; }

        public int StatusTimeoutMs { get; set; } = 5000;

        /// <summary>Der Dienst wartet bis zu 10 s auf den Server und puffert dann – etwas Reserve.</summary>
        public int ReportTimeoutMs { get; set; } = 25000;

        /// <summary>WACHTL_TRAY_PORT (1–65535) oder 47251 – identisch im Dienst.</summary>
        public static int ResolvePort(string? value)
        {
            int port;
            return int.TryParse((value ?? string.Empty).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port)
                   && port > 0 && port < 65536
                ? port
                : DefaultPort;
        }

        public static TrayClient FromEnvironment() =>
            new TrayClient(ResolvePort(Environment.GetEnvironmentVariable("WACHTL_TRAY_PORT")));

        /// <summary>Status oder null, wenn der Dienst nicht antwortet.</summary>
        public TrayStatus? GetStatus()
        {
            var response = Send("GET", "/tray/v1/status", null, StatusTimeoutMs);
            return response != null && response.Status == 200 ? TrayStatus.FromJson(response.Body) : null;
        }

        public ReportResult SendReport(string json)
        {
            var response = Send("POST", "/tray/v1/report", json, ReportTimeoutMs);
            if (response == null)
            {
                return new ReportResult(ReportOutcome.Failed, TrayTexts.ServiceDown);
            }

            return Interpret(response.Status, response.Body);
        }

        /// <summary>Wertet die Antwort von POST /tray/v1/report aus.</summary>
        public static ReportResult Interpret(int status, string body)
        {
            var o = TrayJson.TryParseObject(body);
            if (status == 202 || status == 200)
            {
                if (o != null && TrayJson.GetBool(o, "ok"))
                {
                    return TrayJson.GetBool(o, "delivered")
                        ? new ReportResult(ReportOutcome.Delivered, TrayTexts.Delivered)
                        : new ReportResult(ReportOutcome.Queued, TrayTexts.Queued);
                }

                return new ReportResult(ReportOutcome.Failed, "Unerwartete Antwort des Wachtl-Dienstes.");
            }

            return new ReportResult(ReportOutcome.Failed, TrayTexts.ForStatusCode(status, o != null ? TrayJson.GetString(o, "error") : null));
        }

        private sealed class RawResponse
        {
            public int Status;
            public string Body = string.Empty;
        }

        private RawResponse? Send(string method, string path, string? body, int timeoutMs)
        {
            try
            {
                var request = (HttpWebRequest)WebRequest.Create("http://127.0.0.1:" + Port.ToString(CultureInfo.InvariantCulture) + path);
                request.Method = method;
                request.Proxy = null;
                request.KeepAlive = false;
                request.AllowAutoRedirect = false;
                request.Timeout = timeoutMs;
                request.ReadWriteTimeout = timeoutMs;
                request.Accept = "application/json";
                request.UserAgent = "wachtl-tray";
                request.Headers["X-Wachtl-Tray"] = "1";
                if (body != null)
                {
                    var bytes = new UTF8Encoding(false).GetBytes(body);
                    request.ContentType = "application/json; charset=utf-8";
                    request.ContentLength = bytes.Length;
                    using (var stream = request.GetRequestStream())
                    {
                        stream.Write(bytes, 0, bytes.Length);
                    }
                }

                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    return Read(response);
                }
            }
            catch (WebException ex) when (ex.Response is HttpWebResponse error)
            {
                using (error)
                {
                    return Read(error);
                }
            }
            catch (WebException)
            {
                return null; // Verbindung abgelehnt, Zeitüberschreitung: Dienst läuft nicht
            }
            catch (IOException)
            {
                return null;
            }
        }

        private static RawResponse Read(HttpWebResponse response)
        {
            using (var stream = response.GetResponseStream())
            using (var reader = new StreamReader(stream ?? Stream.Null, Encoding.UTF8))
            {
                return new RawResponse { Status = (int)response.StatusCode, Body = reader.ReadToEnd() };
            }
        }
    }
}
