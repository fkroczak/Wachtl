"""Lokale IP-Adressen des Servers – damit Probes ihn auch ohne funktionierende Namensauflösung erreichen."""
from __future__ import annotations

import ipaddress
import socket


def local_ipv4() -> list[str]:
    """IPv4-Adressen dieses Rechners, ohne Loopback und Link-Local; die Adresse der Standardroute zuerst."""
    found: list[str] = []

    def add(value: str) -> None:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return
        if ip.version == 4 and not (ip.is_loopback or ip.is_link_local or ip.is_unspecified) and value not in found:
            found.append(value)

    # Adresse der Standardroute: UDP-"Verbindung" sendet kein Paket, wählt aber die Quelladresse
    for probe in ("192.0.2.1", "10.255.255.255"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((probe, 9))
                add(s.getsockname()[0])
        except OSError:
            pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add(info[4][0])
    except OSError:
        pass
    return found


def with_local_ips(names: list[str]) -> list[str]:
    """Namensliste um die lokalen IPv4-Adressen ergänzen (Reihenfolge der Namen bleibt)."""
    result = list(names)
    for ip in local_ipv4():
        if ip not in result:
            result.append(ip)
    return result
