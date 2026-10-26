"""TP-Link Easy Smart (TL-SG105E/108E/105PE/108PE/1016PE …) über die Weboberfläche lesen.

Diese Switches können kein SNMP und kein LLDP. Ihre Weboberfläche (HTTP) liefert die Daten aber als
JavaScript-Variablen in den Seiten – das hier liest sie und baut daraus dieselbe Momentaufnahme wie
snmpcollect.collect(), damit Baum, Frontansicht und Befunde unverändert funktionieren.

Gelesen wird nur (Anmelden, vier Seiten abrufen, Abmelden). Seiten und Variablen wie in der Firmware
der Easy-Smart-Reihe ab etwa 2017:

  logon.cgi             logonInfo = new Array(0, …)   0 = angemeldet, 1 = Benutzer/Passwort falsch …
  SystemInfoRpm.htm     info_ds = {descriStr:[…], macStr:[…], ipStr:[…], gatewayStr:[…], firmwareStr:[…], hardwareStr:[…]}
  PortSettingRpm.htm    max_port_num, all_info = {state:[…], spd_cfg:[…], spd_act:[…], fc_cfg:[…], fc_act:[…]}
  PortStatisticsRpm.htm all_info = {state:[…], link_status:[…], pkts:[TxGut, TxFehler, RxGut, RxFehler, …]}
  PoeConfigRpm.htm      poe_port_num, portConfig = {state, power, powerstatus …}, globalConfig = {…}  (nur PoE-Modelle)
"""
from __future__ import annotations

import logging
import re
import time

import requests

log = logging.getLogger(__name__)

TIMEOUT = 5.0
MAX_PORTS = 64
# spd_act / link_status → (Mbit/s, Duplex); 0 = kein Link, 1 = automatisch (nur Einstellung)
SPEEDS = {2: (10, "half"), 3: (10, "full"), 4: (100, "half"), 5: (100, "full"), 6: (1000, "full"),
          7: (10000, "full")}
LOGON_ERRORS = {
    "1": "Benutzer oder Passwort falsch.",
    "2": "Dieser Benutzer darf sich nicht anmelden.",
    "3": "Zu viele angemeldete Benutzer – Weboberfläche des Switches in anderen Browsern abmelden.",
    "4": "Zu viele angemeldete Benutzer – Weboberfläche des Switches in anderen Browsern abmelden.",
    "5": "Sitzung abgelaufen.",
}


class EasySmartError(Exception):
    """Switch nicht erreichbar, Anmeldung abgelehnt oder unerwartete Antwort."""


# -- JavaScript-Werte aus den Seiten ---------------------------------------------------
_VAR_RE = re.compile(r"\bvar\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*")


class _Parser:
    """Kleiner Leser für die JS-Literale der Easy-Smart-Seiten: Zahlen, Texte, [..], new Array(..), {key: ..}."""

    def __init__(self, text: str, pos: int):
        self.t, self.i = text, pos

    def ws(self) -> None:
        while self.i < len(self.t) and self.t[self.i] in " \t\r\n":
            self.i += 1

    def value(self, depth: int = 0):
        if depth > 8:
            raise ValueError("zu tief verschachtelt")
        self.ws()
        if self.i >= len(self.t):
            raise ValueError("Ende")
        c = self.t[self.i]
        if c in "\"'":
            end = self.t.find(c, self.i + 1)
            if end < 0:
                raise ValueError("Text ohne Ende")
            s = self.t[self.i + 1:end]
            self.i = end + 1
            return s
        if c == "[":
            return self.seq("[", "]", depth)
        if c == "{":
            return self.obj(depth)
        if self.t.startswith("new", self.i):
            m = re.compile(r"new\s+Array\s*\(").match(self.t, self.i)
            if m:
                self.i = m.end() - 1
                return self.seq("(", ")", depth)
        m = re.compile(r"-?(0x[0-9A-Fa-f]+|\d+(\.\d+)?)").match(self.t, self.i)
        if m:
            self.i = m.end()
            raw = m.group(0)
            return int(raw, 16) if "x" in raw.lower() else (float(raw) if "." in raw else int(raw))
        m = re.compile(r"[A-Za-z_][A-Za-z0-9_]*").match(self.t, self.i)
        if m:
            self.i = m.end()
            return {"true": True, "false": False, "null": None}.get(m.group(0), m.group(0))
        raise ValueError(f"unerwartetes Zeichen {c!r}")

    def seq(self, open_: str, close: str, depth: int) -> list:
        self.i += 1
        out = []
        while True:
            self.ws()
            if self.i < len(self.t) and self.t[self.i] == close:
                self.i += 1
                return out
            out.append(self.value(depth + 1))
            self.ws()
            if self.i < len(self.t) and self.t[self.i] == ",":
                self.i += 1
            elif self.i < len(self.t) and self.t[self.i] == close:
                continue
            else:
                raise ValueError("Liste ohne Ende")

    def obj(self, depth: int) -> dict:
        self.i += 1
        out = {}
        while True:
            self.ws()
            if self.i < len(self.t) and self.t[self.i] == "}":
                self.i += 1
                return out
            key = self.value(depth + 1)
            self.ws()
            if self.i >= len(self.t) or self.t[self.i] != ":":
                raise ValueError("Doppelpunkt fehlt")
            self.i += 1
            out[str(key)] = self.value(depth + 1)
            self.ws()
            if self.i < len(self.t) and self.t[self.i] == ",":
                self.i += 1


def page_vars(page: str) -> dict:
    """Alle ``var name = …;`` einer Seite als Python-Werte; unlesbare Werte werden übersprungen."""
    out: dict = {}
    for m in _VAR_RE.finditer(page or ""):
        try:
            out[m.group(1)] = _Parser(page, m.end()).value()
        except (ValueError, IndexError):
            continue
    return out


# -- Weboberfläche -------------------------------------------------------------------
class Session:
    """Angemeldete Sitzung an der Weboberfläche. Als Kontextmanager: meldet sich am Ende wieder ab."""

    def __init__(self, host: str, user: str, password: str, port: int = 80, timeout: float = TIMEOUT):
        self.base = f"http://{host}:{port}" if port != 80 else f"http://{host}"
        self.user, self.password, self.timeout = user, password, timeout
        self.http = requests.Session()
        self.http.trust_env = False            # nie über einen Proxy: der Switch steht im lokalen Netz

    def __enter__(self) -> "Session":
        self.login()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _req(self, method: str, path: str, **kw) -> str:
        try:
            r = self.http.request(method, f"{self.base}/{path}", timeout=self.timeout, allow_redirects=True, **kw)
        except requests.Timeout as exc:
            raise EasySmartError(f"Keine Antwort von {self.base} (Zeitüberschreitung)") from exc
        except requests.RequestException as exc:
            raise EasySmartError(f"Weboberfläche {self.base} nicht erreichbar: {type(exc).__name__}") from exc
        if r.status_code != 200:
            raise EasySmartError(f"{path}: Antwort {r.status_code}")
        return r.content[:2_000_000].decode("utf-8", errors="replace")

    def login(self) -> None:
        page = self._req("POST", "logon.cgi", data={"username": self.user, "password": self.password,
                                                    "cpassword": "", "logon": "Login"})
        info = page_vars(page).get("logonInfo")
        code = str(info[0]) if isinstance(info, list) and info else None
        if code == "0":
            return
        if code is None:
            raise EasySmartError("Keine Anmeldeseite eines TP-Link Easy Smart Switches – Adresse prüfen.")
        raise EasySmartError(f"Anmeldung abgelehnt: {LOGON_ERRORS.get(code, f'Fehler {code}')}")

    def vars(self, path: str) -> dict:
        v = page_vars(self._req("GET", path))
        if "logonInfo" in v:
            raise EasySmartError("Der Switch hat die Anmeldung beendet (Sitzung abgelaufen).")
        return v

    def close(self) -> None:
        try:
            self.http.get(f"{self.base}/Logout.htm", timeout=2)
        except requests.RequestException:
            pass
        self.http.close()


def _first(d: dict, key: str) -> str | None:
    v = d.get(key)
    if isinstance(v, list):
        v = v[0] if v else None
    return str(v).strip() if v not in (None, "") else None


def _num_list(v, n: int) -> list[int | None]:
    v = v if isinstance(v, list) else []
    return [(x if isinstance(x, int) and not isinstance(x, bool) else None) for x in (v + [None] * n)[:n]]


def _mac(text: str | None) -> str | None:
    if not text:
        return None
    m = text.strip().upper().replace("-", ":")
    return m if re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", m) else None


def collect(sess: Session) -> dict:
    """Momentaufnahme im Format von snmpcollect.collect() (ohne MAC-Tabelle und Nachbarn – kann der Switch nicht)."""
    started = time.monotonic()
    info = sess.vars("SystemInfoRpm.htm").get("info_ds")
    if not isinstance(info, dict):
        raise EasySmartError("Systeminformationen fehlen – kein TP-Link Easy Smart Switch?")
    model, firmware = _first(info, "hardwareStr"), _first(info, "firmwareStr")
    settings = sess.vars("PortSettingRpm.htm")
    count = settings.get("max_port_num")
    allp = settings.get("all_info") if isinstance(settings.get("all_info"), dict) else {}
    if not isinstance(count, int) or not 1 <= count <= MAX_PORTS:
        count = len(allp.get("spd_act") or []) or 0
    count = min(count, MAX_PORTS)
    state, spd_act = _num_list(allp.get("state"), count), _num_list(allp.get("spd_act"), count)
    try:
        stats = sess.vars("PortStatisticsRpm.htm").get("all_info")
    except EasySmartError as exc:
        log.debug("%s: keine Port-Statistik: %s", sess.base, exc)
        stats = None
    stats = stats if isinstance(stats, dict) else {}
    pkts = _num_list(stats.get("pkts"), count * 4)
    link = _num_list(stats.get("link_status"), count)
    interfaces = []
    for n in range(1, count + 1):
        act = spd_act[n - 1] if spd_act[n - 1] is not None else link[n - 1]
        mbps, duplex = SPEEDS.get(act or 0, (None, None))
        interfaces.append({
            "index": n, "name": f"Port {n}", "descr": f"Port {n}", "alias": None, "type": 6, "speed_mbps": mbps,
            "mac": None, "admin_up": state[n - 1] != 0, "oper_up": mbps is not None,
            "in_errors": pkts[(n - 1) * 4 + 3], "out_errors": pkts[(n - 1) * 4 + 1], "fcs_errors": None,
            "duplex": duplex,
        })
    poe = None
    try:
        pv = sess.vars("PoeConfigRpm.htm")
    except EasySmartError:
        pv = {}
    pc, gc = pv.get("portConfig"), pv.get("globalConfig")
    if isinstance(pc, dict) and isinstance(pv.get("poe_port_num"), int) and pv["poe_port_num"] > 0:
        status = _num_list(pc.get("powerstatus"), min(pv["poe_port_num"], count))
        gc = gc if isinstance(gc, dict) else {}
        limit, used = gc.get("system_power_limit"), gc.get("system_power_consumption")
        poe = {"power_w": round(limit / 10) if isinstance(limit, (int, float)) else None,
               "used_w": round(used / 10) if isinstance(used, (int, float)) else None,
               "ports": [n for n, s in enumerate(status, 1) if s == 2]}
    ip = _first(info, "ipStr")
    return {
        "system": {"name": _first(info, "descriStr"), "object_id": None, "uptime_s": None, "contact": None,
                   "location": None, "descr": " · ".join(x for x in (f"TP-Link {model}" if model else "TP-Link Easy Smart",
                                                                     f"Firmware {firmware}" if firmware else None) if x)},
        "interfaces": interfaces, "fdb": [], "lldp": [], "cdp": [], "pvid": {}, "poe": poe, "bridge_ports": {},
        "ips": [ip] if ip else [], "arp": [], "gateway": _first(info, "gatewayStr"),
        "base_mac": _mac(_first(info, "macStr")), "lldp_chassis": None,
        "duration_s": round(time.monotonic() - started, 2),
    }


def poll(host: str, creds: dict, port: int = 80, timeout: float = TIMEOUT) -> dict:
    """Anmelden, lesen, abmelden."""
    with Session(host, creds.get("user") or "", creds.get("password") or "", port=port, timeout=timeout) as sess:
        return collect(sess)
