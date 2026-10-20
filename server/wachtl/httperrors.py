"""Deutung von HTTP-Statuscodes in Messfehlern („HTTP 429 von speed.cloudflare.com“).

Die Probes melden nur den nackten Code; hier wird daraus ein kurzer Hinweis, was er
für einen Speedtest bedeutet und was man tun kann.
"""
from __future__ import annotations

import re

HINTS = {
    400: "Anfrage abgelehnt – URL oder Parameter prüfen",
    401: "Anmeldung verlangt – die URL ist nicht öffentlich",
    403: "Zugriff verweigert – oft blockiert der Anbieter die Anfrage (Bot-Schutz, Firewall/Proxy, Geo-Sperre)",
    404: "Adresse nicht gefunden – Download-/Upload-URL prüfen",
    405: "Methode nicht erlaubt – die URL nimmt z. B. keine Uploads an",
    407: "Proxy verlangt Anmeldung – Proxy-Einstellungen des Probe-Rechners prüfen",
    408: "Zeitüberschreitung beim Server – Leitung überlastet oder zu langsam",
    413: "Upload zu groß für den Server",
    429: "Zu viele Anfragen – der Anbieter drosselt (Rate-Limit). Seltener messen, weniger parallele "
         "Streams nutzen oder einen eigenen Speedtest-Server (z. B. iperf3) verwenden; mehrere Probes "
         "hinter derselben öffentlichen IP zählen zusammen",
    500: "Fehler beim Anbieter – meist vorübergehend",
    502: "Gateway-Fehler – Proxy oder Anbieter gestört, meist vorübergehend",
    503: "Dienst nicht verfügbar – Anbieter überlastet oder in Wartung, meist vorübergehend",
    504: "Gateway-Zeitüberschreitung – Proxy oder Anbieter antwortet nicht rechtzeitig",
}

_CODE = re.compile(r"\bHTTP (\d{3})\b")


def hint(error: str | None) -> str:
    """Hinweis zum ersten HTTP-Code im Fehlertext, sonst ''."""
    m = _CODE.search(error or "")
    if not m:
        return ""
    code = int(m.group(1))
    if code in HINTS:
        return HINTS[code]
    if 400 <= code < 500:
        return "Anfrage vom Server abgelehnt (Client-Fehler)"
    if 500 <= code < 600:
        return "Fehler beim Anbieter – meist vorübergehend"
    return ""


def explain(error: str | None) -> str:
    """Fehlertext mit angehängtem Hinweis: „HTTP 429 von x – Zu viele Anfragen …“."""
    h = hint(error)
    return f"{error} – {h}" if h else (error or "")
