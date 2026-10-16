"""Check-Typen und ihre Einstellungen.

Jede Einstellung ist hier genau einmal beschrieben. Daraus entstehen das Formular im
Web-UI, die Prüfung der Eingaben und die Werte, die an die Probe gehen. Neue Optionen
werden nur hier ergänzt.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
HOSTPORT_RE = re.compile(r"^\[?[A-Za-z0-9.:-]{1,253}\]?$")
URL_RE = re.compile(r"^https?://[^\s\"'<>]{3,500}$")


@dataclass(frozen=True)
class Field:
    key: str
    label: str
    kind: str                       # int | float | bool | choice | text | time | url | host
    default: object
    min: float | None = None
    max: float | None = None
    choices: tuple[tuple[str, str], ...] = ()
    help: str = ""
    unit: str = ""
    show_if: tuple[str, tuple[str, ...]] | None = None   # (feld, erlaubte Werte)
    group: str = "Messung"
    required: bool = False


@dataclass(frozen=True)
class CheckType:
    key: str
    label: str
    description: str
    target_label: str
    target_help: str
    uses_role: bool
    fields: tuple[Field, ...] = field(default_factory=tuple)

    def defaults(self) -> dict:
        return {f.key: f.default for f in self.fields}


DIRECTIONS = (("down", "Download (Gegenstelle → Probe)"), ("up", "Upload (Probe → Gegenstelle)"),
              ("both", "Beide Richtungen nacheinander"))
SCHEDULE_FIELDS = (
    Field("schedule_min", "Automatisch messen alle", "int", 60, 0, 10080, unit="min",
          help="0 = nur auf Knopfdruck „Jetzt messen“.", group="Zeitplan"),
    Field("offset_min", "Versatz", "int", -1, -1, 10079, unit="min",
          help="-1 = automatisch je Probe verteilt, damit nicht alle Probes gleichzeitig messen.", group="Zeitplan"),
    Field("window_start", "Nur zwischen", "time", "00:00", help="Ortszeit der Probe", group="Zeitplan"),
    Field("window_end", "und", "time", "23:59", group="Zeitplan"),
    Field("weekdays", "An Wochentagen", "text", "1234567",
          help="Ziffern 1 = Montag … 7 = Sonntag, z. B. 12345 für Werktage.", group="Zeitplan"),
)
THRESHOLD_FIELDS = (
    Field("min_down_mbps", "Alarm, wenn Download unter", "float", 0, 0, 100000, unit="Mbit/s",
          help="0 = kein Alarm", group="Schwellwerte"),
    Field("min_up_mbps", "Alarm, wenn Upload unter", "float", 0, 0, 100000, unit="Mbit/s",
          help="0 = kein Alarm", group="Schwellwerte"),
)

TYPES: dict[str, CheckType] = {
    "ping": CheckType(
        "ping", "Ping (Dauerping)",
        "Erreichbarkeit, Latenz, Paketverlust und Jitter zu einem Ziel.",
        "Ziel", "IP-Adresse, Hostname oder gateway (Default-Gateway der Probe)", True,
        (
            Field("size_bytes", "Paketgröße", "int", 32, 0, 1472, unit="Byte", help="Nutzdaten je ICMP-Paket"),
            Field("ttl", "TTL", "int", 128, 1, 255),
            Field("jitter_window_s", "Jitter berechnen über", "int", 60, 10, 3600, unit="s"),
        ),
    ),
    "path": CheckType(
        "path", "Pfad (Traceroute + Hop-Pings)",
        "Ermittelt alle Router bis zum Ziel und pingt jeden Hop dauerhaft. So sieht man, ab welchem Hop "
        "Verluste oder Verzögerungen beginnen.",
        "Ziel", "z. B. 1.1.1.1 – IP-Adresse oder Hostname im Internet", False,
        (
            Field("max_hops", "Maximale Hops", "int", 20, 1, 64),
            Field("hop_size_bytes", "Paketgröße", "int", 32, 0, 1472, unit="Byte"),
            Field("trace_interval_min", "Pfad neu ermitteln alle", "int", 10, 1, 1440, unit="min"),
            Field("retrace_on_loss", "Pfad sofort neu ermitteln bei Verlust am Ziel", "bool", True),
            Field("trace_timeout_ms", "Timeout je Traceroute-Hop", "int", 1000, 100, 5000, unit="ms"),
            Field("probes_per_hop", "Versuche je Hop beim Traceroute", "int", 2, 1, 5),
            Field("ping_hops", "Hops", "choice", "all",
                  choices=(("all", "alle Hops dauerhaft pingen"), ("first", "nur die ersten N Hops"),
                           ("none", "nur Traceroute, keine Dauerpings"))),
            Field("first_n", "N", "int", 5, 1, 64, show_if=("ping_hops", ("first",))),
            Field("skip_private", "Private Hops (LAN) überspringen", "bool", False,
                  help="z. B. wenn das LAN bereits mit eigenen Checks überwacht wird."),
        ),
    ),
    "iperf": CheckType(
        "iperf", "Bandbreite intern (iperf3)",
        "Durchsatz zwischen Probe und Wachtl-Server, zwischen zwei Probes oder zu einem eigenen iperf3-Server.",
        "Gegenstelle", "", False,
        (
            Field("peer", "Gegenstelle", "choice", "server",
                  choices=(("server", "Wachtl-Server"), ("probe", "andere Probe"), ("host", "eigener iperf3-Server")),
                  group="Gegenstelle"),
            Field("peer_probe_id", "Probe", "int", 0, 0, None, show_if=("peer", ("probe",)), group="Gegenstelle"),
            Field("host", "Host", "host", "", show_if=("peer", ("host",)), group="Gegenstelle"),
            Field("port", "Port", "int", 5201, 1, 65535, show_if=("peer", ("host",)), group="Gegenstelle",
                  help="Wachtl-Server und Probes nutzen ihren eingestellten iperf3-Port."),
            Field("protocol", "Protokoll", "choice", "tcp", choices=(("tcp", "TCP"), ("udp", "UDP"))),
            Field("direction", "Richtung", "choice", "both", choices=DIRECTIONS),
            Field("duration_s", "Testdauer", "int", 10, 1, 120, unit="s"),
            Field("omit_s", "Anlaufzeit ignorieren", "int", 1, 0, 30, unit="s", help="TCP-Slow-Start nicht mitmessen"),
            Field("streams", "Parallele Streams", "int", 1, 1, 32),
            Field("udp_mbps", "UDP-Sendeleistung", "float", 100, 0.1, 10000, unit="Mbit/s",
                  show_if=("protocol", ("udp",))),
            Field("window_kb", "TCP-Fenster", "int", 0, 0, 65536, unit="KB", help="0 = Betriebssystem-Standard",
                  show_if=("protocol", ("tcp",))),
            Field("timeout_s", "Abbruch nach", "int", 60, 10, 600, unit="s", help="falls die Gegenstelle hängt"),
        ) + SCHEDULE_FIELDS + THRESHOLD_FIELDS,
    ),
    "speedtest": CheckType(
        "speedtest", "Bandbreite WAN (Internet)",
        "Durchsatz ins Internet – per HTTP-Download/-Upload oder zu einem iperf3-Server im Internet.",
        "Gegenstelle", "", False,
        (
            Field("method", "Verfahren", "choice", "http",
                  choices=(("http", "HTTP (Download/Upload von URLs)"), ("iperf", "iperf3-Server im Internet")),
                  group="Gegenstelle"),
            Field("down_url", "Download-URL", "url", "https://speed.cloudflare.com/__down?bytes=25000000",
                  show_if=("method", ("http",)), group="Gegenstelle",
                  help="Wird wiederholt geladen, bis die Testdauer erreicht ist."),
            Field("up_url", "Upload-URL", "url", "https://speed.cloudflare.com/__up",
                  show_if=("method", ("http",)), group="Gegenstelle", help="Leer = kein Upload-Test"),
            Field("latency_url", "Latenz-URL", "url", "https://speed.cloudflare.com/__down?bytes=0",
                  show_if=("method", ("http",)), group="Gegenstelle", help="Leer = keine Latenzmessung"),
            Field("use_proxy", "Proxy der Probe verwenden", "bool", False, show_if=("method", ("http",)),
                  group="Gegenstelle"),
            Field("host", "iperf3-Host", "host", "", show_if=("method", ("iperf",)), group="Gegenstelle"),
            Field("port", "Port", "int", 5201, 1, 65535, show_if=("method", ("iperf",)), group="Gegenstelle"),
            Field("protocol", "Protokoll", "choice", "tcp", choices=(("tcp", "TCP"), ("udp", "UDP")),
                  show_if=("method", ("iperf",))),
            Field("udp_mbps", "UDP-Sendeleistung", "float", 100, 0.1, 10000, unit="Mbit/s",
                  show_if=("protocol", ("udp",))),
            Field("direction", "Richtung", "choice", "both", choices=DIRECTIONS),
            Field("duration_s", "Testdauer je Richtung", "int", 10, 2, 120, unit="s"),
            Field("streams", "Parallele Verbindungen", "int", 4, 1, 32),
            Field("timeout_s", "Abbruch nach", "int", 90, 10, 600, unit="s"),
        ) + SCHEDULE_FIELDS + THRESHOLD_FIELDS,
    ),
}

ROLE_DEFAULT = {"ping": "target", "path": "target", "iperf": "target", "speedtest": "reference"}
SCHEDULED_TYPES = ("iperf", "speedtest")


def _visible(f: Field, values: dict) -> bool:
    if not f.show_if:
        return True
    other, allowed = f.show_if
    return str(values.get(other)) in allowed


def parse_params(type_key: str, form: dict, *, probe_ids: set[int] | None = None) -> tuple[dict, list[str]]:
    """Formularwerte prüfen. Gibt (params, Fehler) zurück; unsichtbare Felder behalten ihren Standard."""
    ct = TYPES[type_key]
    values: dict = {}
    errors: list[str] = []
    # zuerst Auswahlfelder, damit show_if ausgewertet werden kann
    ordered = sorted(ct.fields, key=lambda f: 0 if f.kind == "choice" else 1)
    for f in ordered:
        raw = form.get(f.key)
        if f.kind == "bool":
            values[f.key] = raw in ("on", "true", "1", True)
            continue
        if not _visible(f, values):
            values[f.key] = f.default
            continue
        raw = "" if raw is None else str(raw).strip()
        try:
            values[f.key] = _convert(f, raw)
        except ValueError as exc:
            errors.append(f"{f.label}: {exc}")
            values[f.key] = f.default

    if type_key == "iperf":
        if values["peer"] == "host" and not values["host"]:
            errors.append("Host der Gegenstelle fehlt.")
        if values["peer"] == "probe" and probe_ids is not None and values["peer_probe_id"] not in probe_ids:
            errors.append("Bitte eine Probe als Gegenstelle auswählen.")
    if type_key == "speedtest":
        if values["method"] == "iperf" and not values["host"]:
            errors.append("iperf3-Host fehlt.")
        if values["method"] == "http" and not values["down_url"] and not values["up_url"]:
            errors.append("Mindestens eine Download- oder Upload-URL angeben.")
    if type_key in SCHEDULED_TYPES:
        if not values["weekdays"] or set(values["weekdays"]) - set("1234567"):
            errors.append("Wochentage: nur Ziffern 1 bis 7.")
        else:
            values["weekdays"] = "".join(sorted(set(values["weekdays"])))
        if values["offset_min"] >= max(values["schedule_min"], 1) and values["schedule_min"]:
            errors.append("Versatz muss kleiner als das Messintervall sein.")
        if values["duration_s"] * (2 if values["direction"] == "both" else 1) + 10 > values["timeout_s"]:
            errors.append("„Abbruch nach“ ist kürzer als die Testdauer.")
    return values, errors


def _convert(f: Field, raw: str):
    if f.kind in ("int", "float"):
        if raw == "":
            if f.required:
                raise ValueError("fehlt")
            return f.default
        try:
            v = int(raw) if f.kind == "int" else float(raw.replace(",", "."))
        except ValueError:
            raise ValueError("keine Zahl") from None
        if f.min is not None and v < f.min:
            raise ValueError(f"mindestens {f.min:g}")
        if f.max is not None and v > f.max:
            raise ValueError(f"höchstens {f.max:g}")
        return v
    if f.kind == "choice":
        allowed = [k for k, _ in f.choices]
        if raw not in allowed:
            raise ValueError("ungültige Auswahl")
        return raw
    if f.kind == "time":
        if not TIME_RE.match(raw):
            raise ValueError("Format HH:MM")
        return raw
    if f.kind == "url":
        if raw and not URL_RE.match(raw):
            raise ValueError("keine gültige http(s)-URL")
        return raw
    if f.kind == "host":
        if raw and not valid_host(raw):
            raise ValueError("keine gültige Adresse")
        return raw
    if len(raw) > 200:
        raise ValueError("zu lang")
    return raw


def valid_host(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    from .repo import HOSTNAME_RE

    return bool(HOSTNAME_RE.match(value))


def merged(type_key: str, params: dict | None) -> dict:
    """Gespeicherte Parameter mit Standardwerten ergänzen (für ältere Checks ohne neue Felder)."""
    out = TYPES[type_key].defaults() if type_key in TYPES else {}
    out.update(params or {})
    return out


def summary(check: dict, params: dict, probe_names: dict[int, str] | None = None) -> str:
    """Kurzbeschreibung für Tabellen."""
    t = check["type"]
    p = merged(t, params)
    if t == "ping":
        return f"alle {check['interval_s']} s"
    if t == "path":
        hops = {"all": "alle Hops", "first": f"erste {p['first_n']} Hops", "none": "nur Traceroute"}[p["ping_hops"]]
        return f"{hops} alle {check['interval_s']} s, Pfad alle {p['trace_interval_min']} min"
    direction = {"down": "↓", "up": "↑", "both": "↓↑"}[p["direction"]]
    when = f"alle {p['schedule_min']} min" if p["schedule_min"] else "nur manuell"
    proto = p.get("protocol", "tcp").upper() if t == "iperf" or p.get("method") == "iperf" else "HTTP"
    return f"{proto} {direction} {p['duration_s']} s, {p['streams']}×, {when}"


def target_for(type_key: str, params: dict, probe_names: dict[int, str] | None = None) -> str:
    """Anzeigename der Gegenstelle für iperf-/Speedtest-Checks (Spalte ``target``)."""
    if type_key == "iperf":
        if params["peer"] == "server":
            return "wachtl-server"
        if params["peer"] == "probe":
            name = (probe_names or {}).get(params["peer_probe_id"], str(params["peer_probe_id"]))
            return f"probe:{name}"
        return f"{params['host']}:{params['port']}"
    if type_key == "speedtest":
        if params["method"] == "iperf":
            return f"{params['host']}:{params['port']}"
        from urllib.parse import urlparse

        return urlparse(params["down_url"] or params["up_url"]).hostname or "internet"
    raise ValueError(type_key)
