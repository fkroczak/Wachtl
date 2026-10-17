"""Default-Gateway und lokale Adressen des Servers (wie GatewayResolver.cs der Windows-Probe)."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import threading
import time

_lock = threading.Lock()
_cache: tuple[float, str | None] = (0.0, None)


def parse_proc_route(text: str) -> str | None:
    """/proc/net/route: Zeile mit Ziel 00000000 und gesetztem Gateway (Hex, Little Endian)."""
    best: tuple[int, str] | None = None
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8 or parts[1] != "00000000":
            continue
        flags = int(parts[3], 16)
        if not flags & 0x2:            # RTF_GATEWAY
            continue
        gw = socket.inet_ntoa(int(parts[2], 16).to_bytes(4, "little"))
        metric = int(parts[6])
        if best is None or metric < best[0]:
            best = (metric, gw)
    return best[1] if best else None


_ROUTE_PRINT = re.compile(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\d+)", re.M)


def parse_route_print(text: str) -> str | None:
    """Ausgabe von ``route print -4 0.0.0.0`` (Windows): Gateway mit der kleinsten Metrik."""
    routes = sorted((int(m.group(2)), m.group(1)) for m in _ROUTE_PRINT.finditer(text))
    return routes[0][1] if routes else None


def _resolve_gateway() -> str | None:
    try:
        if os.name == "nt":
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True, text=True,
                                 errors="replace", timeout=10).stdout
            return parse_route_print(out)
        with open("/proc/net/route", encoding="ascii") as f:
            return parse_proc_route(f.read())
    except (OSError, subprocess.SubprocessError):
        return None


def gateway() -> str | None:
    """IPv4-Default-Gateway, 30 s zwischengespeichert."""
    global _cache
    with _lock:
        if time.monotonic() < _cache[0]:
            return _cache[1]
        gw = _resolve_gateway()
        _cache = (time.monotonic() + 30, gw)
        return gw


def local_addresses() -> list[str]:
    """Lokale IPv4-Adressen; die Adresse der Default-Route zuerst."""
    out: list[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))     # baut keine Verbindung auf, wählt nur die Quelladresse
            out.append(s.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            out.append(info[4][0])
    except OSError:
        pass
    result = []
    for a in out:
        ip = ipaddress.ip_address(a)
        if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified) and a not in result:
            result.append(a)
    return result[:8]
