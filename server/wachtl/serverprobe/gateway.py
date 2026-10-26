"""Gateway der Server-Probe erkennen (docs/TOPOLOGIE.md#gateway-automatisch-erkennen).

Alle 30 Minuten, ohne Anmeldung am Gerät: Weboberflächen auf den üblichen Ports (Titel, Server-Kennung, Zertifikat),
TR-064 der FRITZ!Box (Port 49000) und UPnP-Gerätebeschreibung (SSDP). Ausgewertet wird auf dem Server
(services/gateways.py); hier wird nur gesammelt.
"""
from __future__ import annotations

import logging
import re
import socket
import threading
import time
import urllib.request
from typing import Callable
from urllib.parse import urlparse
from xml.etree import ElementTree

from . import net

log = logging.getLogger("wachtl.serverprobe")
PORTS = (80, 443, 4443, 4444, 8080, 8443, 10443)
INTERVAL_S = 1800
UPNP_FIELDS = ("manufacturer", "modelName", "modelNumber", "friendlyName", "modelDescription", "softwareVersion")


def parse_device_xml(text: str) -> dict:
    """UPnP/TR-064-Gerätebeschreibung: Hersteller, Modell, Name (erstes <device>)."""
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return {}
    out: dict = {}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag in UPNP_FIELDS and tag not in out and (el.text or "").strip():
            out[tag] = el.text.strip()[:120]
    return out


def _fetch(url: str, timeout: float = 3.0, limit: int = 65536) -> str | None:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Wachtl"}), timeout=timeout) as r:
            return r.read(limit).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 – kein UPnP ist kein Fehler
        return None


def ssdp_location(gateway: str, timeout: float = 2.0) -> str | None:
    """UPnP-Rundruf (SSDP M-SEARCH): LOCATION der Gerätebeschreibung, wenn das Gateway antwortet."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n"
           "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.sendto(msg, ("239.255.255.250", 1900))
            s.sendto(msg, (gateway, 1900))
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                try:
                    data, addr = s.recvfrom(2048)
                except socket.timeout:
                    continue
                if addr[0] != gateway:
                    continue
                m = re.search(rb"^location:\s*(\S+)", data, re.I | re.M)
                if m:
                    loc = m.group(1).decode("ascii", "replace")
                    return loc if urlparse(loc).hostname == gateway else None
    except OSError:
        return None
    return None


def collect(gateway: str, scan_port: Callable | None = None, fetch: Callable = _fetch,
            ssdp: Callable = ssdp_location, arp: Callable | None = None) -> dict:
    """Alles sammeln, was das Gateway ohne Anmeldung verrät."""
    from . import netscan

    scan_port = scan_port or netscan.scan_port
    services = []
    for port in PORTS:
        try:
            r = scan_port(gateway, port, 1.5)
        except Exception:  # noqa: BLE001
            r = None
        if r:
            services.append({k: r.get(k) for k in ("port", "tls", "http_status", "http_server", "http_title",
                                                     "tls_subject", "banner")})
    upnp: dict = {}
    for url in (f"http://{gateway}:49000/tr64desc.xml", f"http://{gateway}:49000/igddesc.xml"):
        text = fetch(url)
        if text:
            upnp = parse_device_xml(text)
            if upnp:
                break
    if not upnp:
        loc = ssdp(gateway)
        text = fetch(loc) if loc else None
        upnp = parse_device_xml(text) if text else {}
    mac = None
    try:
        mac = (arp or netscan.arp_table)().get(gateway)
    except Exception:  # noqa: BLE001
        pass
    return {"ip": gateway, "mac": mac, "services": services, "upnp": upnp, "ts": int(time.time())}


def loop(api_getter: Callable, stop: threading.Event) -> None:
    stop.wait(60)                       # erst messen, dann erkennen
    while not stop.is_set():
        api = api_getter()
        gw = net.gateway()
        if api is not None and gw:
            try:
                data = collect(gw)
                api.result("gateway", data)
                log.info("Gateway %s: %d Dienste, UPnP %s", gw, len(data["services"]),
                         data["upnp"].get("modelName") or "–")
            except Exception as exc:  # noqa: BLE001 – nächster Versuch beim nächsten Durchlauf
                log.debug("Gateway-Erkennung fehlgeschlagen: %s", exc)
        stop.wait(INTERVAL_S)
