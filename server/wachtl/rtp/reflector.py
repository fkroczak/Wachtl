"""RTP-Reflektor: Gegenstelle für Sprachtests (Wachtl-Server; Probes bringen RtpReflector.cs mit).

Antwortet nur auf Wachtl-RTP-Pakete, in gleicher Größe und mit Ratenbegrenzung je Absender – ein offener
UDP-Port soll nicht als Verstärker für fremden Verkehr taugen.
"""
from __future__ import annotations

import logging
import socket
import threading
import time

from . import parse, reflect

log = logging.getLogger("wachtl.rtp")

PER_SOURCE_PPS = 2000       # z. B. 20 Probes hinter einer NAT-Adresse mit 10-ms-Paketen
TOTAL_PPS = 20000
SESSION_IDLE_S = 120
MAX_SESSIONS = 50000


class Bucket:
    def __init__(self, rate: float, now: float):
        self.rate, self.tokens, self.at = rate, rate, now

    def take(self, now: float) -> bool:
        self.tokens = min(self.rate, self.tokens + (now - self.at) * self.rate)
        self.at = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


class Reflector:
    """Zustand des Reflektors ohne Socket – testbar mit ``handle``."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.sessions: dict[tuple, list] = {}       # (Adresse, Port, SSRC) -> [Zähler, zuletzt gesehen]
        self.sources: dict[str, Bucket] = {}
        self.total = Bucket(TOTAL_PPS, clock())
        self.next_cleanup = clock() + 10
        self.dropped = 0

    def handle(self, data: bytes, addr: tuple) -> bytes | None:
        now = self.clock()
        packet = parse(data)
        if packet is None:
            return None
        bucket = self.sources.get(addr[0])
        if bucket is None:
            bucket = self.sources[addr[0]] = Bucket(PER_SOURCE_PPS, now)
        if not (bucket.take(now) and self.total.take(now)):
            self.dropped += 1
            return None
        key = (addr[0], addr[1], packet.ssrc)
        session = self.sessions.get(key)
        if session is None:
            if len(self.sessions) >= MAX_SESSIONS:
                self.dropped += 1
                return None
            session = self.sessions[key] = [0, now]
        if not packet.query:
            session[0] += 1
        session[1] = now
        if now >= self.next_cleanup:
            self.cleanup(now)
        return reflect(data, int(now * 1_000_000), session[0])

    def cleanup(self, now: float) -> None:
        self.next_cleanup = now + 10
        for key in [k for k, s in self.sessions.items() if now - s[1] > SESSION_IDLE_S]:
            del self.sessions[key]
        for ip in [ip for ip, b in self.sources.items() if now - b.at > SESSION_IDLE_S]:
            del self.sources[ip]


def bind(port: int, host: str = "") -> socket.socket:
    """IPv6-Socket, der auch IPv4 annimmt; ohne IPv6 nur IPv4."""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind((host or "::", port))
    except OSError:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host or "0.0.0.0", port))
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 46 << 2)    # Antworten als Sprache (EF) markieren
    except OSError:
        pass
    return sock


def serve(port: int, stop: threading.Event | None = None, host: str = "") -> None:
    stop = stop or threading.Event()
    sock = bind(port, host)
    sock.settimeout(1.0)
    reflector = Reflector()
    log.info("RTP-Reflektor lauscht auf UDP-Port %s", port)
    with sock:
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError as exc:      # Windows meldet ICMP „Port unreachable“ früherer Antworten als Fehler
                log.debug("Empfang: %s", exc)
                continue
            reply = reflector.handle(data, addr)
            if reply is not None:
                try:
                    sock.sendto(reply, addr)
                except OSError as exc:
                    log.debug("Antwort an %s nicht gesendet: %s", addr[0], exc)
    log.info("RTP-Reflektor beendet")
