using System.Globalization;

namespace Wachtl.Probe.Diagnostics;

/// <summary>Texte eines Hinweises. <c>Balloon</c> ist die Kurzfassung für die Sprechblase (Windows: höchstens 255 Zeichen).</summary>
public sealed record FindingText(string Title, string Message, string Solution = "", string Balloon = "");

/// <summary>Deutsche Texte der Client-Hinweise: kurz, für Anwender verständlich, mit Lösungsvorschlag.</summary>
public static class FindingTexts
{
    private const string DuplexAuto =
        "„Geschwindigkeit und Duplex“ an Netzwerkkarte und Switch auf „Automatisch“ stellen.";

    private const string PowerSaving =
        "Im Geräte-Manager bei der Netzwerkkarte unter „Energieverwaltung“ den Haken bei „Computer kann das Gerät ausschalten, um Energie zu sparen“ entfernen.";

    public static FindingText CableUnplugged(AdapterState a, string? fallback) => new(
        "Netzwerkkabel getrennt",
        $"Die Netzwerkkarte „{a.Name}“ hat keine Verbindung mehr: Das Netzwerkkabel ist ausgesteckt oder die Gegenstelle (Netzwerkdose, Switch) antwortet nicht."
        + (fallback is null ? string.Empty : $" Die Verbindung läuft vorerst über „{fallback}“ weiter."),
        "Prüfen Sie, ob das Netzwerkkabel am PC und an der Netzwerkdose bzw. am Switch fest eingesteckt ist (der Stecker muss einrasten). "
        + "Leuchtet an der Buchse keine Lampe, Kabel oder Netzwerkdose tauschen.",
        $"Das Netzwerkkabel von „{a.Name}“ ist nicht verbunden.\n"
        + "Lösung: Stecker am PC und an der Netzwerkdose fest einstecken. Leuchtet keine Lampe, Kabel tauschen.");

    public static FindingText CableReconnected(string name, TimeSpan downtime) => new(
        "Netzwerkkabel wieder verbunden",
        $"Die Netzwerkkarte „{name}“ ist wieder verbunden (Unterbrechung {Duration(downtime)}).");

    public static FindingText WifiDisconnected(AdapterState a, string? fallback) => new(
        "WLAN-Verbindung getrennt",
        $"Der WLAN-Adapter „{a.Name}“ hat die Verbindung zum Funknetz verloren."
        + (fallback is null ? string.Empty : $" Die Verbindung läuft vorerst über „{fallback}“ weiter."),
        "Prüfen Sie, ob WLAN eingeschaltet und der Flugmodus aus ist. Gehen Sie näher an den Access Point "
        + "oder verbinden Sie sich über die Netzwerkliste neu mit dem Funknetz.",
        $"WLAN „{a.Name}“ hat keine Verbindung.\n"
        + "Lösung: WLAN einschalten, Flugmodus aus, näher zum Access Point gehen.");

    public static FindingText WifiReconnected(string name, TimeSpan downtime) => new(
        "WLAN wieder verbunden",
        $"Der WLAN-Adapter „{name}“ ist wieder verbunden (Unterbrechung {Duration(downtime)}).");

    public static FindingText SpeedChanged(AdapterState a, long oldBps, long newBps) => new(
        $"Netzwerk langsamer: {Speed(oldBps)} → {Speed(newBps)}",
        $"Die Netzwerkkarte „{a.Name}“ arbeitet nur noch mit {Speed(newBps)} statt {Speed(oldBps)}. "
        + "Datenübertragungen, Backups und Updates werden dadurch deutlich langsamer.",
        "Netzwerkkabel prüfen oder tauschen (mindestens Cat 5e, ohne Knicke, Stecker fest). Anderen Switch-Port bzw. andere Netzwerkdose testen. "
        + DuplexAuto + " Energiesparen der Netzwerkkarte abschalten (z. B. „Energy Efficient Ethernet“).",
        $"„{a.Name}“ läuft nur noch mit {Speed(newBps)} statt {Speed(oldBps)}.\n"
        + "Lösung: Netzwerkkabel tauschen (mind. Cat 5e) oder andere Netzwerkdose bzw. anderen Switch-Port testen.");

    public static FindingText SpeedRestored(string name, long bps) => new(
        "Netzwerkgeschwindigkeit wieder normal",
        $"Die Netzwerkkarte „{name}“ arbeitet wieder mit {Speed(bps)}.");

    public static FindingText SpeedLow(AdapterState a, long bps) => new(
        $"Langsame Netzwerkverbindung: nur {Speed(bps)}",
        $"Die Netzwerkkarte „{a.Name}“ ist nur mit {Speed(bps)} verbunden, üblich ist 1 Gbit/s. "
        + "Große Dateien, Backups und Updates dauern dadurch ein Vielfaches länger.",
        "Netzwerkkabel prüfen oder tauschen (mindestens Cat 5e – bei 100 Mbit/s sind oft nicht alle Adern verbunden). "
        + "Anderen Switch-Port bzw. andere Netzwerkdose testen. " + DuplexAuto,
        $"„{a.Name}“ ist nur mit {Speed(bps)} verbunden, üblich ist 1 Gbit/s.\n"
        + "Lösung: Netzwerkkabel tauschen (mind. Cat 5e) oder andere Netzwerkdose testen.");

    public static FindingText Flapping(AdapterState a, int count) => new(
        "Netzwerkverbindung bricht wiederholt ab",
        $"Die Netzwerkkarte „{a.Name}“ hat die Verbindung in den letzten 10 Minuten {count}-mal verloren und wieder aufgebaut. "
        + "Jede Unterbrechung stört laufende Anrufe, Downloads und Anmeldungen.",
        "Netzwerkkabel und Switch-Port bzw. Netzwerkdose tauschen. " + PowerSaving + " Treiber der Netzwerkkarte aktualisieren.",
        $"„{a.Name}“ hat die Verbindung in 10 Minuten {count}-mal verloren.\n"
        + "Lösung: Kabel und Netzwerkdose tauschen, Energiesparen der Netzwerkkarte abschalten.");

    public static FindingText FlappingResolved(string name) => new(
        "Netzwerkverbindung wieder stabil",
        $"Die Netzwerkkarte „{name}“ ist seit 10 Minuten ohne Unterbrechung verbunden.");

    public static FindingText DriverError(AdapterState a, int code) => new(
        "Problem mit der Netzwerkkarte oder ihrem Treiber",
        $"Der Geräte-Manager meldet für „{Device(a)}“ den Fehlercode {code.ToString(CultureInfo.InvariantCulture)}: {DriverCode(code)}.",
        code switch
        {
            28 => "Treiber der Netzwerkkarte installieren (Website des PC- oder Kartenherstellers bzw. Windows Update), danach PC neu starten.",
            14 => "PC neu starten.",
            43 => "PC ganz herunterfahren und wieder einschalten (nicht nur neu starten). Treiber der Netzwerkkarte aktualisieren. "
                  + "Bleibt der Fehler, die IT informieren – die Netzwerkkarte kann defekt sein.",
            _ => "Treiber der Netzwerkkarte neu installieren oder aktualisieren (Website des Herstellers bzw. Windows Update) und den PC neu starten. "
                 + "Bleibt der Fehler, die IT informieren – die Netzwerkkarte kann defekt sein.",
        },
        $"Die Netzwerkkarte meldet Fehler {code.ToString(CultureInfo.InvariantCulture)}: {DriverCode(code)}.\nLösung: "
        + code switch
        {
            28 => "Treiber installieren, danach den PC neu starten.",
            14 => "PC neu starten.",
            43 => "PC ganz herunterfahren und wieder einschalten, Treiber aktualisieren.",
            _ => "Treiber neu installieren und den PC neu starten. Hilft das nicht, die IT informieren.",
        });

    public static FindingText DriverOk(string device) => new(
        "Netzwerkkarte funktioniert wieder",
        $"Der Geräte-Manager meldet für „{device}“ keinen Fehler mehr.");

    public static FindingText NicReset(string? adapter, int count) => new(
        "Treiber setzt die Netzwerkkarte wiederholt zurück",
        $"Windows hat die Netzwerkkarte{(string.IsNullOrEmpty(adapter) ? string.Empty : $" „{adapter}“")} in den letzten 15 Minuten "
        + $"{count}-mal zurückgesetzt (Ereignis NDIS 10400). Dabei bricht die Verbindung jedes Mal kurz ab.",
        "Treiber der Netzwerkkarte aktualisieren (Website des Herstellers). " + PowerSaving
        + " In den erweiterten Eigenschaften „Energy Efficient Ethernet“ bzw. „Green Ethernet“ ausschalten.",
        $"Windows hat die Netzwerkkarte in 15 Minuten {count}-mal zurückgesetzt, die Verbindung bricht dabei ab.\n"
        + "Lösung: Treiber aktualisieren, Energiesparen der Netzwerkkarte abschalten.");

    public static FindingText NicResetResolved() => new(
        "Netzwerkkarte läuft wieder stabil",
        "Seit 15 Minuten hat Windows die Netzwerkkarte nicht mehr zurückgesetzt.");

    public static FindingText Apipa(AdapterState a) => new(
        "Keine IP-Adresse vom DHCP-Server",
        $"Die Netzwerkkarte „{a.Name}“ hat keine IP-Adresse vom DHCP-Server erhalten und nutzt die Notadresse {a.Ipv4.FirstOrDefault()}. "
        + "Netzwerk und Internet sind so nicht erreichbar.",
        "Netzwerkkabel und Switch-Port bzw. Netzwerkdose prüfen (richtiges Netz bzw. VLAN?). Prüfen, ob der DHCP-Server läuft und freie Adressen hat. "
        + "Danach in der Eingabeaufforderung „ipconfig /renew“ ausführen oder das Kabel kurz aus- und wieder einstecken.",
        $"„{a.Name}“ hat keine IP-Adresse vom DHCP-Server, das Netzwerk ist nicht erreichbar.\n"
        + "Lösung: Kabel kurz aus- und wieder einstecken. Hilft das nicht, die IT informieren.");

    public static FindingText ApipaResolved(string name, string? ip) => new(
        "IP-Adresse wieder erhalten",
        $"Die Netzwerkkarte „{name}“ hat wieder eine gültige IP-Adresse{(string.IsNullOrEmpty(ip) ? string.Empty : $" ({ip})")}.");

    public static FindingText NoGateway(AdapterState a) => new(
        "Kein Standard-Gateway",
        $"Die Netzwerkkarte „{a.Name}“ hat eine IP-Adresse ({a.Ipv4.FirstOrDefault(ip => !AdapterClassifier.IsApipa(ip))}), aber kein Standard-Gateway. "
        + "Andere Netze und das Internet sind dadurch nicht erreichbar.",
        "Bei fester IP-Adresse das Standard-Gateway in den IPv4-Einstellungen der Netzwerkkarte eintragen. "
        + "Bei DHCP prüfen, ob der DHCP-Server die Option „Router“ (Option 3) verteilt, danach „ipconfig /renew“ ausführen.",
        $"„{a.Name}“ hat kein Standard-Gateway, Internet und andere Netze sind nicht erreichbar.\n"
        + "Lösung: Die IT informieren – das Gateway fehlt in den IP-Einstellungen bzw. im DHCP.");

    public static FindingText GatewayResolved() => new(
        "Standard-Gateway wieder vorhanden",
        "Der PC hat wieder ein Standard-Gateway, andere Netze und das Internet sind erreichbar.");

    public static FindingText NicErrors(AdapterState a, long errors, double percent) => new(
        "Viele fehlerhafte Datenpakete",
        $"Die Netzwerkkarte „{a.Name}“ hat in der letzten Minute {errors.ToString(CultureInfo.InvariantCulture)} fehlerhafte oder verworfene Pakete gezählt "
        + $"({percent.ToString("0.0", CultureInfo.InvariantCulture).Replace('.', ',')} %). Das führt zu Aussetzern und langsamen Übertragungen.",
        "Netzwerkkabel und Switch-Port bzw. Netzwerkdose tauschen. " + DuplexAuto + " Treiber der Netzwerkkarte aktualisieren.",
        $"„{a.Name}“ zählt viele fehlerhafte Pakete ({percent.ToString("0.0", CultureInfo.InvariantCulture).Replace('.', ',')} %), das führt zu Aussetzern.\n"
        + "Lösung: Kabel und Netzwerkdose tauschen, Treiber aktualisieren.");

    public static FindingText NicErrorsResolved(string name) => new(
        "Datenpakete wieder fehlerfrei",
        $"Die Netzwerkkarte „{name}“ zählt keine auffälligen Paketfehler mehr.");

    public static FindingText AdapterDisabled(AdapterState a, string? fallback) => new(
        a.IsWifi ? "WLAN ausgeschaltet" : "Netzwerkkarte ausgeschaltet",
        $"Die Netzwerkkarte „{a.Name}“ wurde in Windows deaktiviert."
        + (fallback is null ? " Ohne sie hat der PC keine Netzwerkverbindung." : $" Die Verbindung läuft vorerst über „{fallback}“ weiter."),
        $"Windows-Einstellungen › Netzwerk und Internet › Erweiterte Netzwerkeinstellungen öffnen und bei „{a.Name}“ auf „Aktivieren“ klicken "
        + "(oder Systemsteuerung › Netzwerkverbindungen, Rechtsklick auf die Karte › Aktivieren). Fehlen dafür die Rechte, die IT informieren.",
        $"Die Netzwerkkarte „{a.Name}“ ist ausgeschaltet"
        + (fallback is null ? ", das Netzwerk ist nicht erreichbar.\n" : ".\n")
        + "Lösung: Einstellungen › Netzwerk und Internet › Erweiterte Netzwerkeinstellungen › „Aktivieren“.");

    public static FindingText AdapterEnabled(string name, TimeSpan downtime) => new(
        "Netzwerkkarte wieder eingeschaltet",
        $"Die Netzwerkkarte „{name}“ ist wieder eingeschaltet (war {Duration(downtime)} aus).");

    public static FindingText AdapterGone(string name) => new(
        "Netzwerkkarte deaktiviert oder entfernt",
        $"Die Netzwerkkarte „{name}“ wurde deaktiviert oder entfernt, der Hinweis ist damit erledigt.");

    /// <summary>Text zu Geräte-Manager-Fehlercodes (ConfigManagerErrorCode).</summary>
    public static string DriverCode(int code) => code switch
    {
        1 => "Das Gerät ist nicht richtig konfiguriert",
        3 => "Der Treiber ist beschädigt oder es fehlt Arbeitsspeicher",
        10 => "Das Gerät kann nicht gestartet werden",
        12 => "Für das Gerät sind nicht genügend Ressourcen frei",
        14 => "Das Gerät funktioniert erst nach einem Neustart",
        18 => "Der Treiber muss neu installiert werden",
        19 => "Die Konfiguration in der Registrierung ist beschädigt",
        21 => "Das Gerät wird gerade entfernt",
        28 => "Für das Gerät ist kein Treiber installiert",
        29 => "Das Gerät ist in der Firmware (BIOS/UEFI) deaktiviert",
        31 => "Das Gerät funktioniert nicht richtig, Windows kann den Treiber nicht laden",
        32 => "Der Treiberdienst ist deaktiviert",
        37 => "Der Treiber konnte nicht initialisiert werden",
        38 or 39 or 41 => "Windows kann den Treiber nicht laden",
        43 => "Das Gerät hat ein Problem gemeldet und wurde angehalten",
        48 => "Der Treiber wurde wegen eines Kompatibilitätsproblems blockiert",
        52 => "Die digitale Signatur des Treibers kann nicht überprüft werden",
        _ => "Das Gerät funktioniert nicht richtig",
    };

    /// <summary>„1 Gbit/s“, „2,5 Gbit/s“, „100 Mbit/s“.</summary>
    public static string Speed(long bps)
    {
        if (bps >= 1_000_000_000)
        {
            return Number(bps / 1e9) + " Gbit/s";
        }

        if (bps >= 1_000_000)
        {
            return Number(bps / 1e6) + " Mbit/s";
        }

        return Number(bps / 1e3) + " kbit/s";
    }

    public static string Mbps(long bps) => (bps / 1_000_000).ToString(CultureInfo.InvariantCulture);

    private static string Number(double value) =>
        Math.Abs(value - Math.Round(value)) < 0.05
            ? Math.Round(value).ToString(CultureInfo.InvariantCulture)
            : value.ToString("0.#", CultureInfo.InvariantCulture).Replace('.', ',');

    /// <summary>„45 s“, „3 Min.“, „1 Std. 5 Min.“</summary>
    public static string Duration(TimeSpan span)
    {
        var s = (long)Math.Max(0, Math.Round(span.TotalSeconds));
        if (s < 60)
        {
            return $"{s} s";
        }

        if (s < 3600)
        {
            var m = s / 60;
            var rest = s % 60;
            return rest == 0 || m >= 10 ? $"{m} Min." : $"{m} Min. {rest} s";
        }

        var h = s / 3600;
        var min = s % 3600 / 60;
        return min == 0 ? $"{h} Std." : $"{h} Std. {min} Min.";
    }

    private static string Device(AdapterState a) => string.IsNullOrEmpty(a.Description) ? a.Name : a.Description;
}
