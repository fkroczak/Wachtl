"""Sprachtest der Server-Probe: RTP-Strom senden, Antworten des Reflektors auswerten (wie RtpTest.cs)."""
from __future__ import annotations

import random
import socket
import threading
import time

from . import CODECS, analyze, build_packet, parse

QUERY_TRIES = 3


def now_us() -> int:
    return time.perf_counter_ns() // 1000


def run(host: str, port: int, codec_key: str = "g711", ptime_ms: int = 20, duration_s: int = 30, dscp: int = 46,
        stop: threading.Event | None = None) -> dict:
    """Einen Test ausführen. Gibt das Ergebnis wie ``analyze`` plus Gegenstelle und Einstellungen zurück."""
    codec = CODECS.get(codec_key, CODECS["g711"])
    base = {"peer": f"{host}:{port}", "codec": codec.key, "ptime_ms": ptime_ms, "duration_s": duration_s}
    stop = stop or threading.Event()
    try:
        info = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except OSError as exc:
        return {**base, "error": f"Gegenstelle {host} nicht auflösbar: {exc}"}
    family, _, _, _, addr = sorted(info, key=lambda i: i[0] != socket.AF_INET)[0]
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if dscp:
            try:
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, dscp << 2)
                else:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, dscp << 2)
            except OSError:
                pass
        sock.connect(addr)
        sock.settimeout(0.2)
        return {**base, **_exchange(sock, codec, ptime_ms, duration_s, stop)}
    except OSError as exc:
        return {**base, "error": f"Senden an {host}:{port} fehlgeschlagen: {exc}"}
    finally:
        sock.close()


def _exchange(sock: socket.socket, codec, ptime_ms: int, duration_s: int, stop: threading.Event) -> dict:
    ssrc = random.getrandbits(32)
    first_seq = random.getrandbits(16)
    total = max(1, duration_s * 1000 // ptime_ms)
    records: dict[int, tuple[int, int, int, int]] = {}
    final: list[int] = []
    refused = [0]
    done = threading.Event()

    def receive() -> None:
        while not done.is_set():
            try:
                data = sock.recv(2048)
            except socket.timeout:
                continue
            except ConnectionRefusedError:      # ICMP „Port unreachable“
                refused[0] += 1
                continue
            except OSError:
                if done.is_set():
                    return
                continue
            t4 = now_us()
            reply = parse(data)
            if reply is None or reply.ssrc != ssrc:
                continue
            if reply.query:
                final.append(reply.count)
                continue
            index = (reply.seq - first_seq) & 0xFFFF
            if index < total and index not in records:
                records[index] = (reply.t1_us, reply.t2_us, reply.count, t4)

    receiver = threading.Thread(target=receive, name="rtp-receive", daemon=True)
    receiver.start()
    sent = 0
    start = time.perf_counter()
    try:
        for i in range(total):
            due = start + i * ptime_ms / 1000
            while (delay := due - time.perf_counter()) > 0:
                if stop.wait(min(delay, 0.05)):
                    break
            if stop.is_set():
                break
            seq = (first_seq + i) & 0xFFFF
            try:
                sock.send(build_packet(codec, ptime_ms, seq, ssrc, now_us(), first=i == 0))
            except ConnectionRefusedError:
                refused[0] += 1
            sent += 1
        # Nachzügler abwarten, dann den Zähler des Reflektors abfragen
        stop.wait(1.0)
        for attempt in range(QUERY_TRIES):
            if final or stop.is_set() or not records:
                break
            try:
                sock.send(build_packet(codec, ptime_ms, (first_seq + total + attempt) & 0xFFFF, ssrc, now_us(),
                                       query=True))
            except OSError:
                pass
            stop.wait(0.5)
    finally:
        done.set()
        receiver.join(timeout=2)
    result = analyze(sent, dict(records), max(final) if final else None, codec, ptime_ms)
    if not records and refused[0]:
        result["error"] = "Gegenstelle lehnt ab (UDP-Port geschlossen – Reflektor aus?)"
    if stop.is_set():
        result["error"] = "Test abgebrochen"
    return result
