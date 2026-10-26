"""Werkzeuge (docs/WERKZEUGE.md): Einzeltests wie in Hop7 – Ping, MTU, Traceroute, DNS, Port, HTTP(S), Zertifikat.

Ein Test läuft auf einer Probe: auf dem Wachtl-Server (Server-Probe) oder auf einem PC beim Kunden. Das Web-UI legt
einen Auftrag an (``tool_jobs``), die Probe holt ihn über das Probe-API ab, meldet Fortschritt (Balken, Schritt,
Zeilen) und am Ende das Ergebnis. Je Probe läuft immer nur ein Test, weitere warten in der Reihe.

Angenommen werden nur die Werkzeuge aus TOOLS mit geprüften Werten – nie Befehle oder freie Parameter.
"""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse

from .. import repo
from ..db import ex, ins, q, q1

HOSTNAME_RE = re.compile(r"^(?=.{1,253}\.?$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?"
                         r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)*\.?$")
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA")
QUEUED_TTL_S = 300          # so lange wartet ein Auftrag auf die Probe
STALE_S = 120               # so lange darf eine laufende Probe schweigen
KEEP_S = 30 * 86400         # Verlauf

# Name, Beschriftung des Zielfelds, Platzhalter, Erklärung
TOOLS = {
    "ping": ("Ping", "Ziel (Host oder IP)", "z. B. 8.8.8.8 oder vpn.kunde.de",
             "Latenz und Verlust mit eigener Anzahl, Paketgröße und Intervall. Mit „Nicht fragmentieren“ prüfbar, "
             "ob eine Paketgröße durchkommt."),
    "mtu": ("MTU", "Ziel (Host oder IP)", "z. B. 8.8.8.8 oder vpn.kunde.de",
            "Sucht die größte Paketgröße ohne Fragmentierung (Pfad-MTU) und erkennt gefilterte ICMP-Meldungen."),
    "trace": ("Traceroute", "Ziel (Host oder IP)", "z. B. 8.8.8.8 oder vpn.kunde.de",
              "Weg zum Ziel Hop für Hop mit Verlust und Laufzeit je Router (wie mtr bzw. pathping)."),
    "dns": ("DNS", "Name oder IP (für PTR)", "z. B. www.kunde.de oder _dmarc.kunde.de",
            "Fragt DNS-Einträge ab – beim Resolver der Probe oder einem eigenen DNS-Server."),
    "port": ("Port", "Ziel (Host oder IP)", "z. B. 192.168.1.10",
             "Prüft TCP-Ports: offen, geschlossen (abgewiesen) oder gefiltert (keine Antwort, Firewall)."),
    "http": ("HTTP(S)", "Adresse (URL)", "z. B. https://portal.kunde.de/",
             "Statuscode, Zeiten (DNS, Verbindung, TLS, erstes Byte), Weiterleitung und Zertifikat."),
    "tls": ("Zertifikat", "Ziel (Host oder IP)", "z. B. mail.kunde.de",
            "Zertifikat eines TLS-Dienstes: Namen, Aussteller, Ablauf, Protokoll."),
    "ipinfo": ("IP-Info", "IP oder Host", "z. B. 203.0.113.10",
               "Rückwärtsname, Netz, Anbieter, Kontakte, Land und Herkunfts-AS – direkt bei der zuständigen Registry "
               "(RDAP, ersatzweise WHOIS), ohne Dienst eines Dritten. Läuft immer auf dem Wachtl-Server."),
}
SERVER_ONLY = {"ipinfo"}       # nur die Server-Probe kann das (Registry-Abfragen, Zwischenspeicher)


class ToolError(ValueError):
    pass


# -- Prüfung der Eingaben ------------------------------------------------------------------
def _host(v: str | None, what: str = "Ziel") -> str:
    v = (v or "").strip()
    if not v:
        raise ToolError(f"{what} fehlt.")
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if not HOSTNAME_RE.match(v):
        raise ToolError(f"{what}: kein gültiger Hostname und keine IP-Adresse.")
    return v.rstrip(".").lower()


def _num(form: dict, key: str, default, lo, hi, cast=int, label: str = ""):
    raw = str(form.get(key) if form.get(key) is not None else "").strip().replace(",", ".")
    if raw == "":
        return default
    try:
        v = cast(float(raw)) if cast is int else cast(raw)
    except ValueError:
        raise ToolError(f"{label or key}: keine Zahl.") from None
    if not lo <= v <= hi:
        raise ToolError(f"{label or key}: erlaubt sind {lo:g} bis {hi:g}.")
    return v


def _flag(form: dict, key: str, default: bool = False) -> bool:
    v = form.get(key)
    if v is None:
        return default
    return v is True or str(v).lower() in ("1", "true", "on", "ja")


def clean(tool: str, form: dict) -> tuple[str, dict]:
    """Eingaben eines Werkzeugs prüfen. Gibt (Ziel für die Anzeige, Argumente) zurück oder wirft ToolError."""
    if tool not in TOOLS:
        raise ToolError("Unbekanntes Werkzeug.")
    if tool == "ping":
        host = _host(form.get("host"))
        return host, {"host": host, "count": _num(form, "count", 10, 1, 100, label="Anzahl"),
                      "size": _num(form, "size", 32, 0, 8972, label="Nutzdaten"),
                      "interval": _num(form, "interval", 1.0, 0.2, 5, float, "Intervall"),
                      "df": _flag(form, "df")}
    if tool == "mtu":
        host = _host(form.get("host"))
        lo = _num(form, "min", 576, 68, 9000, label="MTU von")
        hi = _num(form, "max", 1500, 68, 9000, label="MTU bis")
        if lo >= hi:
            raise ToolError("MTU von muss kleiner sein als MTU bis.")
        return host, {"host": host, "min": lo, "max": hi, "tries": _num(form, "tries", 2, 1, 5, label="Pings je Größe")}
    if tool == "trace":
        host = _host(form.get("host"))
        return host, {"host": host, "max_hops": _num(form, "max_hops", 30, 1, 40, label="Höchstens Hops"),
                      "count": _num(form, "count", 3, 1, 10, label="Pakete je Hop"), "names": _flag(form, "names", True)}
    if tool == "dns":
        rtype = str(form.get("type") or "A").upper()
        if rtype not in DNS_TYPES:
            raise ToolError("Unbekannter DNS-Typ.")
        name = (form.get("name") or form.get("host") or "").strip()
        try:
            ip = ipaddress.ip_address(name)
            name, rtype = ip.reverse_pointer, "PTR"
        except ValueError:
            name = _host(name, "Name")
        server = (form.get("server") or "").strip()
        if server:
            try:
                server = str(ipaddress.ip_address(server))
            except ValueError:
                raise ToolError("DNS-Server: bitte als IP-Adresse angeben.") from None
        return name, {"name": name, "type": rtype, "server": server}
    if tool == "port":
        host = _host(form.get("host"))
        raw = str(form.get("ports") or "443").replace(";", ",").replace(" ", ",")
        ports = []
        for part in filter(None, raw.split(",")):
            try:
                p = int(part)
            except ValueError:
                raise ToolError(f"Port „{part}“ ist keine Zahl.") from None
            if not 1 <= p <= 65535:
                raise ToolError(f"Port {p}: erlaubt sind 1 bis 65535.")
            if p not in ports:
                ports.append(p)
        if not ports or len(ports) > 10:
            raise ToolError("Bitte 1 bis 10 Ports angeben.")
        return host, {"host": host, "ports": ports, "timeout": _num(form, "timeout", 3, 1, 10, label="Wartezeit")}
    if tool == "http":
        url = (form.get("url") or form.get("host") or "").strip()
        if url and "://" not in url:
            url = "https://" + url
        u = urlparse(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ToolError("Adresse: bitte als http:// oder https://-Adresse angeben.")
        _host(u.hostname, "Adresse")
        try:
            u.port
        except ValueError:
            raise ToolError("Adresse: ungültiger Port.") from None
        method = "GET" if str(form.get("method") or "").upper() == "GET" else "HEAD"
        return url[:500], {"url": url[:500], "method": method, "insecure": _flag(form, "insecure")}
    if tool == "ipinfo":
        host = _host(form.get("host"), "IP oder Host")
        return host, {"host": host}
    # tls
    host = _host(form.get("host"))
    sni = (form.get("sni") or "").strip()
    if sni:
        sni = _host(sni, "Servername")
    return f"{host}:{_num(form, 'port', 443, 1, 65535, label='Port')}", {
        "host": host, "port": _num(form, "port", 443, 1, 65535, label="Port"), "sni": sni}


def estimate(tool: str, args: dict) -> float:
    """Ungefähre Dauer in Sekunden – der Balken kommt auch ohne Zwischenstände voran."""
    if tool == "ping":
        return args["count"] * args["interval"] + 2
    if tool == "mtu":
        return (max(1, (args["max"] - args["min"]).bit_length()) + 2) * args["tries"] * 0.6 + 2
    if tool == "trace":
        return args["max_hops"] * args["count"] * 0.4 + (5 if args.get("names") else 0)
    if tool == "port":
        return len(args["ports"]) * min(args["timeout"], 2)
    if tool == "ipinfo":
        return 8
    return 4


# -- Aufträge ------------------------------------------------------------------------------
def create(probe_id: int, tool: str, target: str, args: dict, username: str) -> int:
    ts = repo.now()
    return ins("INSERT INTO tool_jobs (probe_id, tool, target, args, status, created_by, created_at, updated_at) "
               "VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)", (probe_id, tool, target, json.dumps(args), username, ts, ts))


def expire(ts: int | None = None) -> None:
    """Aufträge, die nie abgeholt wurden oder deren Probe verstummt ist, als Fehler abschließen."""
    ts = ts or repo.now()
    ex("UPDATE tool_jobs SET status = 'error', finished_at = ?, error = ? WHERE status = 'queued' AND created_at < ?",
       (ts, "Die Probe hat den Auftrag nicht abgeholt – ist sie online?", ts - QUEUED_TTL_S))
    ex("UPDATE tool_jobs SET status = 'error', finished_at = ?, error = ? WHERE status = 'running' AND updated_at < ?",
       (ts, "Die Probe meldet sich nicht mehr – Test abgebrochen.", ts - STALE_S))


def prune(ts: int | None = None) -> None:
    ex("DELETE FROM tool_jobs WHERE created_at < ?", ((ts or repo.now()) - KEEP_S,))


def pending(probe_id: int) -> int:
    row = q1("SELECT COUNT(*) AS n FROM tool_jobs WHERE probe_id = ? AND status = 'queued'", (probe_id,))
    return int(row["n"] or 0)


def take(probe_id: int) -> dict | None:
    """Nächsten Auftrag einer Probe abholen – nur wenn gerade keiner läuft."""
    expire()
    if q1("SELECT id FROM tool_jobs WHERE probe_id = ? AND status = 'running'", (probe_id,)):
        return None
    job = q1("SELECT * FROM tool_jobs WHERE probe_id = ? AND status = 'queued' ORDER BY id LIMIT 1", (probe_id,))
    if not job:
        return None
    ts = repo.now()
    ex("UPDATE tool_jobs SET status = 'running', started_at = ?, updated_at = ?, progress = 0 WHERE id = ? "
       "AND status = 'queued'", (ts, ts, job["id"]))
    return {"id": job["id"], "tool": job["tool"], "args": json.loads(job["args"])}


def _clip(v, limit: int) -> str | None:
    return None if v is None else str(v)[:limit]


def clean_result(raw) -> dict:
    """Ergebnis einer Probe auf das bekannte Format beschränken (Anzeige ohne HTML)."""
    if not isinstance(raw, dict):
        return {}
    out: dict = {}
    summary = []
    for row in (raw.get("summary") or [])[:40]:
        if isinstance(row, (list, tuple)) and len(row) >= 2:
            cls = str(row[2]) if len(row) > 2 and row[2] in ("good", "warn", "bad") else ""
            summary.append([_clip(row[0], 80), _clip(row[1], 400), cls])
    out["summary"] = summary
    stats = raw.get("stats")
    if isinstance(stats, dict):
        out["stats"] = {str(k)[:20]: v for k, v in list(stats.items())[:12] if isinstance(v, (int, float, type(None)))}
    table = raw.get("table")
    if isinstance(table, dict) and isinstance(table.get("head"), list) and isinstance(table.get("rows"), list):
        out["table"] = {"title": _clip(table.get("title"), 80) or "",
                        "head": [_clip(h, 40) for h in table["head"][:10]],
                        "rows": [[_clip(c, 200) if c is not None else "" for c in r[:10]]
                                 for r in table["rows"][:64] if isinstance(r, list)],
                        "classes": [str(c) if c in ("good", "warn", "bad") else ""
                                    for c in (table.get("classes") or [])[:64]]}
    if raw.get("verdict") in ("ok", "warn", "bad"):
        out["verdict"] = raw["verdict"]
    if raw.get("headline"):
        out["headline"] = _clip(raw["headline"], 200)
    return out


def update(job_id: int, probe_id: int, data: dict) -> bool:
    """Fortschritt bzw. Ergebnis der Probe übernehmen. False, wenn der Auftrag nicht (mehr) ihr gehört."""
    job = q1("SELECT * FROM tool_jobs WHERE id = ? AND probe_id = ?", (job_id, probe_id))
    if not job or job["status"] not in ("running", "queued"):
        return False
    ts = repo.now()
    lines = data.get("lines")
    output = job["output"] or ""
    if isinstance(lines, list):
        add = "\n".join(str(x)[:300] for x in lines[:200])
        output = (output + ("\n" if output and add else "") + add)[-20000:]
    progress = data.get("progress")
    try:
        progress = max(0.0, min(1.0, float(progress))) if progress is not None else job["progress"]
    except (TypeError, ValueError):
        progress = job["progress"]
    if data.get("done"):
        ok = bool(data.get("ok"))
        ex("UPDATE tool_jobs SET status = ?, progress = 1, step = NULL, output = ?, result = ?, error = ?, "
           "updated_at = ?, finished_at = ? WHERE id = ?",
           ("ok" if ok else "error", output, json.dumps(clean_result(data.get("result"))),
            None if ok else _clip(data.get("error") or "Test fehlgeschlagen", 500), ts, ts, job_id))
    else:
        ex("UPDATE tool_jobs SET status = 'running', progress = ?, step = ?, output = ?, updated_at = ?, "
           "started_at = COALESCE(started_at, ?) WHERE id = ?",
           (progress, _clip(data.get("step"), 200), output, ts, ts, job_id))
    return True


def view(job: dict) -> dict:
    """Auftrag für das Web-UI."""
    args = json.loads(job["args"] or "{}")
    ahead = 0
    if job["status"] == "queued":
        row = q1("SELECT COUNT(*) AS n FROM tool_jobs WHERE probe_id = ? AND status IN ('queued', 'running') AND id < ?",
                 (job["probe_id"], job["id"]))
        ahead = int(row["n"] or 0)
    return {
        "id": job["id"], "tool": job["tool"], "label": TOOLS[job["tool"]][0], "target": job["target"], "args": args,
        "status": job["status"], "progress": job["progress"], "step": job["step"], "output": job["output"] or "",
        "result": json.loads(job["result"]) if job["result"] else None, "error": job["error"],
        "created_at": job["created_at"], "started": job["started_at"], "finished": job["finished_at"],
        "now": repo.now(), "eta": estimate(job["tool"], args), "ahead": ahead, "probe_id": job["probe_id"],
    }


def recent(limit: int = 20) -> list[dict]:
    expire()
    return q("SELECT j.*, p.hostname FROM tool_jobs j JOIN probes p ON p.id = j.probe_id ORDER BY j.id DESC LIMIT ?",
             (limit,))
