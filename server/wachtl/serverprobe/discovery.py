"""Switches im eigenen Netz per Rundruf finden (docs/TOPOLOGIE.md#switches-automatisch-finden).

Viele günstige Switches ohne SNMP melden sich auf einen Rundruf ihres Herstellers – ganz ohne Anmeldung:

- TP-Link Easy Smart (TL-SG105E/108E/105PE/108PE …): UDP 29808, Antwort als Broadcast an UDP 29809.
  Pakete mit festem Schlüssel verschleiert (RC4-Strom, wie im „Easy Smart Configuration Utility“).
- Netgear ProSAFE Plus (GS105E/GS108E/GS305E …, Protokoll NSDP): UDP 63322 (ältere) bzw. 63324 (neuere Firmware),
  Antwort an 63321 bzw. 63323.

Die Antworten nennen Modell, Name, MAC, IP und Firmware. Rundrufe bleiben im eigenen Netzsegment – die
Server-Probe findet so nur Switches in ihrem Netz; Switches anderer Standorte findet der Netzwerkscan.
"""
from __future__ import annotations

import ipaddress
import logging
import random
import select
import socket
import struct
import threading
import time
import uuid
from typing import Callable

log = logging.getLogger("wachtl.serverprobe")
INTERVAL_S = 900
LISTEN_S = 3.0

# -- TP-Link Easy Smart ---------------------------------------------------------------
ES_SEND, ES_RECV = 29808, 29809
ES_KEY = bytes([
    191, 155, 227, 202, 99, 162, 79, 104, 49, 18, 190, 164, 30, 76, 189, 131, 23, 52, 86, 106, 207, 125, 126, 169,
    196, 28, 172, 58, 188, 132, 160, 3, 36, 120, 144, 168, 12, 231, 116, 44, 41, 97, 108, 213, 42, 198, 32, 148,
    218, 107, 247, 112, 204, 14, 66, 68, 91, 224, 206, 235, 33, 130, 203, 178, 1, 134, 199, 78, 249, 123, 7, 145,
    73, 208, 209, 100, 74, 115, 72, 118, 8, 22, 243, 147, 64, 96, 5, 87, 60, 113, 233, 152, 31, 219, 143, 174,
    232, 153, 245, 158, 254, 70, 170, 75, 77, 215, 211, 59, 71, 133, 214, 157, 151, 6, 46, 81, 94, 136, 166, 210,
    4, 43, 241, 29, 223, 176, 67, 63, 186, 137, 129, 40, 248, 255, 55, 15, 62, 183, 222, 105, 236, 197, 127, 54,
    179, 194, 229, 185, 37, 90, 237, 184, 25, 156, 173, 26, 187, 220, 2, 225, 0, 240, 50, 251, 212, 253, 167, 17,
    193, 205, 177, 21, 181, 246, 82, 226, 38, 101, 163, 182, 242, 92, 20, 11, 95, 13, 230, 16, 121, 124, 109, 195,
    117, 39, 98, 239, 84, 56, 139, 161, 47, 201, 51, 135, 250, 10, 19, 150, 45, 111, 27, 24, 142, 80, 85, 83, 234,
    138, 216, 57, 93, 65, 154, 141, 122, 34, 140, 128, 238, 88, 89, 9, 146, 171, 149, 53, 102, 61, 114, 69, 217,
    175, 103, 228, 35, 180, 252, 200, 192, 165, 159, 221, 244, 110, 119, 48])
ES_HEADER = struct.Struct("!BB6s6shihhhhi")     # Version, Opcode, Switch-MAC, Host-MAC, Folge, Fehler, Länge, …
ES_END = b"\xff\xff\x00\x00"


def es_crypt(data: bytes) -> bytes:
    """Ver- und Entschlüsseln (symmetrisch): RC4-Schlüsselstrom mit fester Startbelegung."""
    s = bytearray(ES_KEY)
    out = bytearray(data)
    j = 0
    for k in range(len(out)):
        i = (k + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out[k] ^= s[(s[i] + s[j]) & 255]
    return bytes(out)


def es_request(host_mac: bytes, seq: int) -> bytes:
    """Rundruf „Wer ist da?“ (Opcode 0, ohne Nutzdaten)."""
    header = ES_HEADER.pack(1, 0, b"\x00" * 6, host_mac, seq % 1000, 0, ES_HEADER.size + len(ES_END), 0, 0, 0, 0)
    return es_crypt(header + ES_END)


def _ip4(raw: bytes) -> str | None:
    return str(ipaddress.IPv4Address(raw)) if len(raw) == 4 and raw != b"\x00" * 4 else None


def _txt(raw: bytes) -> str | None:
    t = raw.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
    return "".join(ch for ch in t if ch.isprintable())[:80] or None


def _macs(raw: bytes) -> str | None:
    return ":".join(f"{b:02X}" for b in raw) if len(raw) == 6 and any(raw) else None


def es_parse(packet: bytes) -> dict | None:
    """Antwort eines Easy-Smart-Switches → Gerät; fremde oder kaputte Pakete → None."""
    data = es_crypt(packet)
    if len(data) < ES_HEADER.size + len(ES_END) or not data.endswith(ES_END) or data[0] != 1:
        return None
    payload = data[ES_HEADER.size:-len(ES_END)]
    tlv: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(payload):
        kind, length = struct.unpack_from("!HH", payload, pos)
        if length > len(payload) - pos - 4:
            return None
        tlv.setdefault(kind, payload[pos + 4:pos + 4 + length])
        pos += 4 + length
    mac = _macs(tlv.get(3, b""))
    if not mac:
        return None
    ports = tlv.get(10, b"")
    return {"proto": "easysmart", "vendor": "TP-Link", "mac": mac, "ip": _ip4(tlv.get(4, b"")),
            "model": _txt(tlv.get(1, b"")), "name": _txt(tlv.get(2, b"")), "firmware": _txt(tlv.get(7, b"")),
            "hardware": _txt(tlv.get(8, b"")), "ports": int.from_bytes(ports, "big") if 0 < len(ports) <= 2 else None}


# -- Netgear NSDP ---------------------------------------------------------------------
NSDP_PORTS = ((63321, 63322), (63323, 63324))           # (eigener Port, Port des Switches)
NSDP_HEADER = struct.Struct("!BBH4s6s6s2sH4s4s")        # Version, Opcode, Ergebnis, -, Host-MAC, Geräte-MAC, -, Folge, "NSDP", -
NSDP_END = b"\xff\xff\x00\x00"
NSDP_ASK = (0x0001, 0x0003, 0x0004, 0x0006, 0x000D)     # Modell, Name, MAC, IP, Firmware


def nsdp_request(host_mac: bytes, seq: int) -> bytes:
    body = b"".join(struct.pack("!HH", t, 0) for t in NSDP_ASK)
    return NSDP_HEADER.pack(1, 1, 0, b"\x00" * 4, host_mac, b"\x00" * 6, b"\x00" * 2, seq & 0xFFFF, b"NSDP",
                            b"\x00" * 4) + body + NSDP_END


def nsdp_parse(packet: bytes) -> dict | None:
    if len(packet) < NSDP_HEADER.size + 4 or packet[24:28] != b"NSDP" or packet[1] != 2:
        return None
    tlv: dict[int, bytes] = {}
    pos = NSDP_HEADER.size
    while pos + 4 <= len(packet):
        kind, length = struct.unpack_from("!HH", packet, pos)
        if kind == 0xFFFF:
            break
        tlv.setdefault(kind, packet[pos + 4:pos + 4 + length])
        pos += 4 + length
    mac = _macs(tlv.get(0x0004, b"")) or _macs(packet[14:20])
    if not mac:
        return None
    return {"proto": "nsdp", "vendor": "Netgear", "mac": mac, "ip": _ip4(tlv.get(0x0006, b"")),
            "model": _txt(tlv.get(0x0001, b"")), "name": _txt(tlv.get(0x0003, b"")),
            "firmware": _txt(tlv.get(0x000D, b"")), "hardware": None, "ports": None}


# -- Senden und Empfangen ---------------------------------------------------------------
def broadcast_addresses(interfaces: list[tuple[str, int]]) -> list[str]:
    """255.255.255.255 und die gerichteten Broadcasts der eigenen Netze (manche Router lassen nur diese durch)."""
    out = ["255.255.255.255"]
    for ip, prefix in interfaces:
        try:
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except ValueError:
            continue
        if net.version == 4 and 16 <= prefix <= 30 and not net.is_loopback and str(net.broadcast_address) not in out:
            out.append(str(net.broadcast_address))
    return out


def _socket(port: int) -> socket.socket | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.bind(("", port))
    except OSError as exc:
        log.debug("UDP %s nicht nutzbar: %s", port, exc)
        s.close()
        return None
    return s


def discover(interfaces: list[tuple[str, int]] | None = None, listen_s: float = LISTEN_S,
             targets: list[str] | None = None) -> list[dict]:
    """Rundruf senden, Antworten sammeln; je MAC ein Gerät."""
    if interfaces is None:
        from .netscan import local_interfaces

        interfaces = local_interfaces()
    targets = targets or broadcast_addresses(interfaces)
    host_mac = uuid.getnode().to_bytes(6, "big")
    seq = random.randint(1, 999)
    plan = [(ES_RECV, ES_SEND, es_request(host_mac, seq), es_parse)]
    plan += [(mine, theirs, nsdp_request(host_mac, seq), nsdp_parse) for mine, theirs in NSDP_PORTS]
    socks: dict[socket.socket, Callable] = {}
    try:
        for mine, theirs, packet, parser in plan:
            s = _socket(mine)
            if s is None:
                continue
            socks[s] = parser
            for addr in targets:
                try:
                    s.sendto(packet, (addr, theirs))
                except OSError as exc:
                    log.debug("Rundruf an %s:%s fehlgeschlagen: %s", addr, theirs, exc)
        found: dict[str, dict] = {}
        deadline = time.monotonic() + listen_s
        while socks and (left := deadline - time.monotonic()) > 0:
            ready, _w, _x = select.select(list(socks), [], [], left)
            for s in ready:
                try:
                    data, _addr = s.recvfrom(2048)
                except OSError:
                    continue
                dev = socks[s](data)
                if dev and dev["mac"] not in found:
                    found[dev["mac"]] = dev
        return list(found.values())
    finally:
        for s in socks:
            s.close()


def loop(api_getter: Callable, stop: threading.Event, finder: Callable[[], list[dict]] = discover) -> None:
    """Alle 15 Minuten suchen und das Ergebnis melden (auch leer: so weiß der Server, dass gesucht wurde)."""
    stop.wait(20)
    while not stop.is_set():
        api = api_getter()
        if api is not None:
            try:
                devices = finder()
                api.result("discovery", {"ts": int(time.time()), "devices": devices})
                if devices:
                    log.info("Rundruf: %d Switches gefunden", len(devices))
            except Exception as exc:  # noqa: BLE001 – Suche ist Zusatz, darf die Probe nie beenden
                log.debug("Rundruf nicht möglich: %s", exc)
        stop.wait(INTERVAL_S)
