"""Gateways automatisch erkennen (docs/TOPOLOGIE.md#gateway-automatisch-erkennen).

Jede Probe meldet ihr Default-Gateway samt MAC (Heartbeat). Wachtl bestimmt daraus je Standort das Gateway und
erkennt Hersteller und Modell – ohne Anmeldung am Gerät – aus:

- MAC-Präfix (gateway_oui.py, switch_oui.py): AVM, Ubiquiti, Sophos, Fortinet, Juniper, LANCOM, MikroTik …
- Weboberfläche aus Netzwerkscan und Server-Probe: Seitentitel, Server-Kennung, Zertifikat (z. B. „FRITZ!Box“,
  „UniFi OS“, „Sophos“, CN=FGT60F…)
- UPnP/TR-064 der Server-Probe (FRITZ!Box, Speedport, Vodafone Station melden Hersteller und Modell)
- LLDP/CDP der eingetragenen Switches (Router-Nachbar mit Systembeschreibung)
- Rückwärtsname (fritz.box, unifi.localdomain …)

Das Ergebnis ist die Wurzel des Topologie-Baums: Internet → Gateway → Switches → Geräte.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter

from .. import gateway_oui, switch_oui
from ..db import ex, ins, q, q1

# (Muster, Hersteller, Produkt, Modell-Muster) – Reihenfolge zählt: Spezielles vor Allgemeinem
FINGERPRINTS: list[tuple[re.Pattern, str, str, re.Pattern | None]] = [
    (re.compile(r"FRITZ!\s?Box|fritz\.box|AVM", re.I), "AVM", "FRITZ!Box",
     re.compile(r"FRITZ!\s?Box\s+(\d{4}\w*(?:\s(?:AX|Cable|LTE|5G|Fiber|LTE|SL))?)", re.I)),
    (re.compile(r"Zyxel|ZyWALL|USG\s?FLEX|\bATP\s?\d{3}", re.I), "Zyxel", "Firewall",
     re.compile(r"(USG\s?FLEX\s?\d+\w*|ATP\s?\d{3}\w*|ZyWALL\s?\w+)", re.I)),
    (re.compile(r"UniFi|Dream\s?(Machine|Router|Wall)|\bUDM\b|\bUDM[- ]|\bUDR\b|\bUXG\b|\bUCG\b|\bUSG\b|Cloud Gateway|"
                r"Ubiquiti|EdgeRouter|EdgeOS", re.I), "Ubiquiti", "UniFi Gateway",
     re.compile(r"(UDM[- ]?(?:Pro(?:[- ]Max)?|SE)?|UDR\d*|UXG[- ]?\w*|UCG[- ]?\w*|USG[- ]?(?:Pro[- ]?4|3P)?|"
                r"Dream Machine(?: Pro| SE)?|Cloud Gateway(?: Ultra| Max)?|EdgeRouter[\w -]*)", re.I)),
    (re.compile(r"Sophos|Cyberoam|\bXGS?\s?\d{2,4}|UTM\s?Manager|WebAdmin|SFOS", re.I), "Sophos", "Firewall",
     re.compile(r"\b(XGS?\s?\d{2,4}w?|SG\s?\d{3}w?)(?![0-9])", re.I)),
    (re.compile(r"Forti(Gate|net|OS|Wifi)|\bFGT[\w-]*|\bFG\d{2,4}\w", re.I), "Fortinet", "FortiGate",
     re.compile(r"\bF(?:GT|G)[-_]?(\d{2,4}[A-Z]?)(?=[A-Z]{2}\d|[\W_]|$)", re.I)),
    (re.compile(r"Session Smart|\b128T\b|128 Technology|\bSSR\s?\d{3,4}\b|\bSSR\b|Conductor", re.I), "Juniper",
     "SSR (Session Smart Router)", re.compile(r"\b(SSR\s?\d{3,4}\w*)", re.I)),
    (re.compile(r"\bJunos\b|\bSRX\s?\d+", re.I), "Juniper", "SRX", re.compile(r"\b(SRX\s?\d+\w*)", re.I)),
    (re.compile(r"pfSense|Netgate", re.I), "Netgate", "pfSense", None),
    (re.compile(r"OPNsense", re.I), "Deciso", "OPNsense", None),
    (re.compile(r"LANCOM|LCOS", re.I), "LANCOM", "Router", re.compile(r"LANCOM\s+([\w+-]*\d[\w+-]*)", re.I)),
    (re.compile(r"RouterOS|MikroTik|Winbox", re.I), "MikroTik", "RouterOS",
     re.compile(r"\b((?:RB|CCR|CRS|hEX|hAP|L009)[\w+-]*)", re.I)),
    (re.compile(r"Meraki", re.I), "Cisco Meraki", "MX", re.compile(r"\b(MX\d{2,3}\w*|Z\d\w*)\b")),
    (re.compile(r"Sonic(Wall|OS)", re.I), "SonicWall", "Firewall", re.compile(r"\b(TZ\s?\d{3}\w*|NSa?\s?\d{3,4})\b", re.I)),
    (re.compile(r"WatchGuard|Fireware|Firebox", re.I), "WatchGuard", "Firebox",
     re.compile(r"\b((?:T|M)\d{2,4}\w*)\b")),
    (re.compile(r"DrayTek|Vigor", re.I), "DrayTek", "Vigor", re.compile(r"Vigor\s?(\d{4}\w*)", re.I)),
    (re.compile(r"Securepoint", re.I), "Securepoint", "UTM", None),
    (re.compile(r"Speedport", re.I), "Telekom", "Speedport", re.compile(r"(Speedport\s+[\w ]*?\d\w*)", re.I)),
    (re.compile(r"Vodafone|Connect\s?Box|EasyBox", re.I), "Vodafone", "Router",
     re.compile(r"(Vodafone Station|Connect\s?Box|EasyBox\s?\d*)", re.I)),
    (re.compile(r"o2\s?HomeBox|HomeBox", re.I), "o2", "HomeBox", None),
    (re.compile(r"Palo\s?Alto|GlobalProtect|PAN-OS", re.I), "Palo Alto", "Firewall",
     re.compile(r"\b(PA-\d{3,4}\w*)", re.I)),
    (re.compile(r"Check\s?Point|Gaia", re.I), "Check Point", "Gateway", None),
    (re.compile(r"Barracuda|CloudGen", re.I), "Barracuda", "CloudGen Firewall", None),
    (re.compile(r"bintec|be\.IP|elmeg", re.I), "bintec elmeg", "Router", None),
    (re.compile(r"Teltonika|\bRUT[XM]?\d+", re.I), "Teltonika", "Router", re.compile(r"\b(RUT[XM]?\d+\w*)", re.I)),
    (re.compile(r"Stormshield", re.I), "Stormshield", "SNS", None),
    (re.compile(r"Untangle|Arista Edge", re.I), "Untangle", "NG Firewall", None),
    (re.compile(r"Kerio Control", re.I), "GFI", "Kerio Control", None),
    (re.compile(r"Peplink|Pepwave", re.I), "Peplink", "Balance", None),
    (re.compile(r"Viprinet", re.I), "Viprinet", "Router", None),
    (re.compile(r"Cisco IOS|\bISR\s?\d{3,4}|Catalyst 8\d{3}|Cisco", re.I), "Cisco", "Router",
     re.compile(r"\b(ISR\s?\d{3,4}\w*|C\d{3,4}\w*)\b", re.I)),
]
# Provider-Router ohne eigenen Webtitel: Hersteller der MAC → Bezeichnung
ISP_VENDORS = {"Sagemcom": "Provider-Router (Sagemcom)", "Arcadyan": "Provider-Router (Arcadyan, z. B. Speedport)",
               "Technicolor": "Provider-Router (Technicolor)", "Compal": "Kabelrouter (Compal, z. B. Connect Box)"}
PRODUCT_NAMES = {"AVM": "FRITZ!Box", "Ubiquiti": "UniFi Gateway", "Sophos": "Sophos Firewall", "Fortinet": "FortiGate",
                 "LANCOM": "LANCOM Router", "MikroTik": "MikroTik Router", "Cisco Meraki": "Meraki MX",
                 "SonicWall": "SonicWall", "WatchGuard": "WatchGuard Firebox", "DrayTek": "DrayTek Vigor",
                 "Palo Alto": "Palo Alto Firewall", "Check Point": "Check Point Gateway", "Barracuda": "Barracuda Firewall",
                 "Juniper": "Juniper Router", "Zyxel": "Zyxel Firewall", "Teltonika": "Teltonika Router",
                 "Peplink": "Peplink Router", "Stormshield": "Stormshield Firewall", "Viprinet": "Viprinet Router",
                 "bintec elmeg": "bintec Router", "Securepoint": "Securepoint UTM", "Netgate": "pfSense",
                 "Deciso": "OPNsense"}
SOURCE_LABELS = {"probe": "Default-Gateway der Probes", "switch": "Switch (SNMP)", "oui": "Hersteller der MAC-Adresse",
                 "web": "Weboberfläche", "tls": "Zertifikat", "upnp": "UPnP/TR-064", "lldp": "LLDP/CDP der Switches",
                 "name": "Gerätename"}
BRANDS = {"AVM": "", "Fortinet": "", "Ubiquiti": "UniFi", "Telekom": "", "DrayTek": "", "Cisco Meraki": "Meraki",
          "Netgate": "", "Deciso": ""}
WEB_PORTS = (443, 4444, 8443, 10443, 4443, 80, 8080)     # Reihenfolge = Vorzug für „Weboberfläche öffnen“


def _mac(v) -> str | None:
    from .topology import _mac as norm

    return norm(v)


def _ip(v) -> str | None:
    try:
        return str(ipaddress.IPv4Address(str(v).strip()))
    except (ValueError, AttributeError):
        return None


def fingerprint(texts: list[str]) -> dict | None:
    """Hersteller, Produkt und Modell aus Texten (Titel, Server, Zertifikat, UPnP, LLDP, Name)."""
    blob = " · ".join(t for t in texts if t)
    if not blob:
        return None
    for pattern, vendor, product, _model_re in FINGERPRINTS:
        if pattern.search(blob):
            model = fingerprint_model(vendor, texts)
            return {"vendor": vendor, "product": product, "model": model}
    return None


def fingerprint_model(vendor: str, texts: list[str]) -> str | None:
    for _pattern, v, _product, model_re in FINGERPRINTS:
        if v == vendor and model_re is not None:
            for t in texts:
                m = t and model_re.search(t)
                if m:
                    model = re.sub(r"\s+", " ", m.group(1)).strip()
                    if vendor == "Fortinet":
                        return f"FortiGate {model.upper()}"
                    return model.upper() if vendor == "Ubiquiti" and model[:1].lower() == "u" else model
    return None


def identify(ip: str, mac: str | None, services: list[dict], upnp: dict | None = None,
             lldp: list[dict] | None = None, hostname: str | None = None) -> dict:
    """Ein Gateway bewerten (rein, ohne Datenbank – testbar)."""
    sources: list[str] = []
    oui = gateway_oui.vendor(mac) or switch_oui.vendor(mac)
    if oui:
        sources.append("oui")
    web_texts = [x for s in services for x in (s.get("http_title"), s.get("http_server"), s.get("banner")) if x]
    tls_texts = [s["tls_subject"] for s in services if s.get("tls_subject")]
    upnp = upnp or {}
    upnp_texts = [str(upnp[k]) for k in ("manufacturer", "modelName", "modelNumber", "friendlyName", "modelDescription")
                  if upnp.get(k)]
    lldp_texts = [x for e in lldp or [] for x in (e.get("sys_descr"), e.get("platform"), e.get("sys_name")) if x]
    found = None
    groups = (("upnp", upnp_texts), ("web", web_texts), ("tls", tls_texts), ("lldp", lldp_texts),
              ("name", [hostname] if hostname else []))
    for kind, texts in groups:
        hit = fingerprint(texts)
        if hit:
            sources.append(kind)
            if found is None:
                found = {**hit, "source": kind}
    if found and not found.get("model"):
        # Modell steht oft woanders als der Hersteller (Titel „Sophos“, Zertifikat CN=XGS2100…)
        found["model"] = fingerprint_model(found["vendor"], [t for _k, texts in groups for t in texts])
    vendor = (found or {}).get("vendor") or oui
    product = (found or {}).get("product")
    model = (found or {}).get("model")
    if not model and upnp.get("modelName") and vendor in ("AVM", "Telekom", "Vodafone", "o2"):
        model = str(upnp["modelName"])
    if vendor == "AVM" and model and not model.upper().startswith("FRITZ"):
        model = f"FRITZ!Box {model}"
    if found:
        confidence = 95 if oui and oui.split()[0] == vendor.split()[0] else 90 if found["source"] in ("upnp", "lldp") else 80
    else:
        confidence = 40 if oui else 0
    label = gateway_label(vendor, product, model, bool(found))
    web = None
    by_port = {s.get("port"): s for s in services}
    for port in WEB_PORTS:
        s = by_port.get(port)
        if s and (s.get("http_status") or s.get("tls") or s.get("http_title") or s.get("service") in ("http", "https")):
            tls = bool(s.get("tls")) or port in (443, 4444, 8443, 10443, 4443) and s.get("service") != "http"
            scheme = "https" if tls else "http"
            suffix = "" if (scheme, port) in (("https", 443), ("http", 80)) else f":{port}"
            web = f"{scheme}://{ip}{suffix}/"
            break
    return {"ip": ip, "mac": mac, "vendor": vendor, "product": product, "model": model, "label": label,
            "confidence": confidence, "sources": sources, "web": web or f"https://{ip}/",
            "upnp": {k: upnp[k] for k in ("manufacturer", "modelName", "friendlyName", "softwareVersion") if upnp.get(k)}}


# -- Daten des Standorts -------------------------------------------------------------------
def site_gateway_ip(site_id: int) -> tuple[str | None, str | None, int]:
    """Häufigstes Default-Gateway der aktiven Probes (mit MAC) – und wie viele Probes es melden."""
    rows = q("SELECT gateway, gateway_mac FROM probes WHERE site_id = ? AND status = 'active' AND gateway IS NOT NULL",
             (site_id,))
    if not rows:
        return None, None, 0
    count = Counter(r["gateway"] for r in rows)
    ip, n = count.most_common(1)[0]
    mac = next((r["gateway_mac"] for r in rows if r["gateway"] == ip and r["gateway_mac"]), None)
    return ip, mac, n


def for_site(site_id: int, switch_gateway: str | None = None, lldp: list[dict] | None = None) -> dict | None:
    """Gateway des Standorts mit Erkennung – oder None, wenn keine Probe und kein Switch ein Gateway kennt."""
    ip, mac, n_probes = site_gateway_ip(site_id)
    sources_extra = ["probe"] if ip else []
    if not ip and switch_gateway:
        ip, sources_extra = switch_gateway, ["switch"]
    if not ip:
        return None
    dev = q1("SELECT * FROM net_devices WHERE site_id = ? AND ip = ? ORDER BY last_seen DESC LIMIT 1", (site_id, ip))
    if dev and not mac:
        mac = dev["mac"]
    services = [dict(s) for s in q("SELECT * FROM net_services WHERE device_id = ?", (dev["id"],))] if dev else []
    info = q1("SELECT * FROM net_gateway_info WHERE site_id = ? AND ip = ?", (site_id, ip))
    upnp = None
    if info:
        data = json.loads(info["data"] or "{}")
        known = {s.get("port") for s in services}
        services += [s for s in data.get("services") or [] if s.get("port") not in known]
        upnp = data.get("upnp")
        mac = mac or info["mac"]
    mine = [e for e in lldp or [] if e.get("mgmt_ip") == ip or (mac and _mac(e.get("chassis_id")) == mac)]
    gw = identify(ip, mac, services, upnp, mine, dev["hostname"] if dev else None)
    gw["sources"] = sources_extra + gw["sources"]
    gw["probes"] = n_probes
    gw["device_id"] = dev["id"] if dev else None
    gw["note"] = dev["note"] if dev else None
    gw["seen"] = info["ts"] if info else (dev["last_seen"] if dev else None)
    gw["sources_text"] = ", ".join(SOURCE_LABELS.get(s, s) for s in dict.fromkeys(gw["sources"]))
    if gw["note"]:
        gw["label"] = gw["note"]
    elif not gw["vendor"] and dev and dev["hostname"]:
        gw["label"] = dev["hostname"]        # nichts erkannt: Name aus dem Netzwerkscan
    return gw


def store_info(site_id: int, data: dict, ts: int) -> bool:
    """Ergebnis der Server-Probe (results/gateway) übernehmen."""
    from .topology import _text

    ip = _ip(data.get("ip"))
    if not ip:
        return False
    services = []
    for s in (data.get("services") or [])[:12]:
        if isinstance(s, dict) and isinstance(s.get("port"), int):
            services.append({"port": s["port"], "tls": bool(s.get("tls")), "http_status": s.get("http_status")
                             if isinstance(s.get("http_status"), int) else None,
                             **{k: _text(s.get(k), 200) for k in ("http_title", "http_server", "tls_subject", "banner")}})
    upnp = {}
    if isinstance(data.get("upnp"), dict):
        upnp = {k: _text(data["upnp"].get(k), 120) for k in ("manufacturer", "modelName", "modelNumber", "friendlyName",
                                                              "modelDescription", "softwareVersion")
                if data["upnp"].get(k)}
    payload = json.dumps({"services": services, "upnp": upnp})
    mac = _mac(data.get("mac"))
    if q1("SELECT id FROM net_gateway_info WHERE site_id = ? AND ip = ?", (site_id, ip)):
        ex("UPDATE net_gateway_info SET mac = COALESCE(?, mac), data = ?, ts = ? WHERE site_id = ? AND ip = ?",
           (mac, payload, ts, site_id, ip))
    else:
        ins("INSERT INTO net_gateway_info (site_id, ip, mac, data, ts) VALUES (?, ?, ?, ?, ?)",
            (site_id, ip, mac, payload, ts))
    return True


def clean_probe_gateway(raw_ip, raw_mac) -> tuple[str | None, str | None]:
    """Gateway aus dem Heartbeat: nur private IPv4-Adressen, MAC normalisiert."""
    ip = _ip(raw_ip)
    if ip and not ipaddress.IPv4Address(ip).is_private:
        ip = None
    return ip, _mac(raw_mac) if ip else None


def gateway_label(vendor: str | None, product: str | None, model: str | None, sure: bool = True) -> str:
    """Anzeigename: „FRITZ!Box 7590“, „FortiGate 60F“, „UniFi UDM-Pro“, „Sophos XGS 2100“, „Juniper SSR …“."""
    brand = BRANDS.get(vendor or "", vendor or "")
    if model:
        if not brand or model.lower().startswith(brand.lower()[:5]):
            return model
        return f"{brand} {model}"
    if vendor in ISP_VENDORS and not sure:
        return ISP_VENDORS[vendor]
    if vendor == "Juniper" and product:
        return f"Juniper {product}"
    if vendor:
        return PRODUCT_NAMES.get(vendor) or f"{vendor} {product or 'Gateway'}"
    return "Gateway"


def summary(site_id: int) -> dict | None:
    """Kurzinfo für Kacheln (Topologie- und Netzwerk-Übersicht)."""
    try:
        return for_site(site_id)
    except Exception:  # noqa: BLE001 – Kachel ohne Gateway ist kein Fehler
        return None

