"""Ein einzelner ICMP-Echo – für Dauerpings, Traceroute (TTL) und Hop-Pings.

- Windows: ``IcmpSendEcho`` aus iphlpapi.dll (ohne Administratorrechte, sprachunabhängig, liefert
  bei TTL-Ablauf den antwortenden Router).
- Linux/macOS: das System-``ping`` (iputils), Ausgabe mit ``LC_ALL=C`` ausgewertet.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass

IS_WINDOWS = os.name == "nt"


@dataclass
class Reply:
    success: bool
    rtt_ms: float = 0.0
    ttl: int | None = None
    source: str | None = None     # antwortende Adresse (bei TTL-Ablauf der Router)
    ttl_expired: bool = False
    error: str = ""


def resolve(target: str, gateway: str | None = None) -> tuple[str | None, str]:
    """IPv4-Adresse für ein Ziel: IP, Hostname oder „gateway“."""
    if target == "gateway":
        return (gateway, "") if gateway else (None, "kein Default-Gateway gefunden")
    try:
        return str(ipaddress.IPv4Address(target)), ""
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET)
    except (socket.gaierror, UnicodeError) as exc:
        return None, f"DNS-Auflösung fehlgeschlagen: {exc}"
    return (infos[0][4][0], "") if infos else (None, "DNS liefert keine IPv4-Adresse")


# -- Linux / macOS ------------------------------------------------------------------------
_TIME_RE = re.compile(r"time[=<]([\d.]+)\s*ms")
_TTL_RE = re.compile(r"ttl=(\d+)", re.I)
_FROM_RE = re.compile(r"From (\d+\.\d+\.\d+\.\d+)")
_REPLY_FROM_RE = re.compile(r"bytes from (\d+\.\d+\.\d+\.\d+)")


def parse_ping_output(out: str) -> Reply:
    """Ausgabe von ``ping -c 1`` (iputils, LC_ALL=C) auswerten."""
    m = _TIME_RE.search(out)
    if m and _REPLY_FROM_RE.search(out):
        ttl = _TTL_RE.search(out)
        return Reply(True, float(m.group(1)), int(ttl.group(1)) if ttl else None, _REPLY_FROM_RE.search(out).group(1))
    if "Time to live exceeded" in out or "Time exceeded" in out:
        src = _FROM_RE.search(out)
        return Reply(False, source=src.group(1) if src else None, ttl_expired=True, error="TtlExpired")
    if "Unreachable" in out:
        return Reply(False, error="DestinationUnreachable")
    return Reply(False, error="TimedOut")


def _ping_posix(address: str, timeout_ms: int, size: int, ttl: int) -> Reply:
    timeout_s = max(0.2, timeout_ms / 1000)
    args = ["ping", "-n", "-c", "1", "-W", f"{timeout_s:g}", "-s", str(size), "-t", str(ttl), address]
    start = time.perf_counter()
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout_s + 2,
                              env={**os.environ, "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        return Reply(False, error="TimedOut")
    except OSError as exc:
        return Reply(False, error=f"ping nicht ausführbar: {exc}")
    reply = parse_ping_output(proc.stdout + proc.stderr)
    if reply.ttl_expired:
        reply.rtt_ms = round((time.perf_counter() - start) * 1000, 3)
    return reply


# -- Windows --------------------------------------------------------------------------------
_icmp = None


def _windows_api():
    global _icmp
    if _icmp is None:
        import ctypes
        from ctypes import wintypes

        class IpOptionInformation(ctypes.Structure):
            _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                        ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

        class IcmpEchoReply(ctypes.Structure):
            _fields_ = [("Address", wintypes.ULONG), ("Status", wintypes.ULONG), ("RoundTripTime", wintypes.ULONG),
                        ("DataSize", wintypes.USHORT), ("Reserved", wintypes.USHORT), ("Data", ctypes.c_void_p),
                        ("Options", IpOptionInformation)]

        lib = ctypes.WinDLL("iphlpapi.dll")
        lib.IcmpCreateFile.restype = wintypes.HANDLE
        lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        lib.IcmpSendEcho.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
                                     ctypes.POINTER(IpOptionInformation), ctypes.c_void_p, wintypes.DWORD,
                                     wintypes.DWORD]
        lib.IcmpSendEcho.restype = wintypes.DWORD
        _icmp = (ctypes, lib, IpOptionInformation, IcmpEchoReply)
    return _icmp


IP_SUCCESS = 0
IP_TTL_EXPIRED_TRANSIT = 11013
IP_TTL_EXPIRED_REASSEM = 11014
_WIN_STATUS = {11002: "DestinationNetworkUnreachable", 11003: "DestinationHostUnreachable",
               11010: "TimedOut", 11013: "TtlExpired", 11050: "GeneralFailure"}


def _ping_windows(address: str, timeout_ms: int, size: int, ttl: int) -> Reply:
    ctypes, lib, Options, EchoReply = _windows_api()
    handle = lib.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        return Reply(False, error="IcmpCreateFile fehlgeschlagen")
    try:
        dest = int.from_bytes(socket.inet_aton(address), "little")
        payload = ctypes.create_string_buffer(b"\x61" * size, size) if size else None
        opts = Options(Ttl=ttl)
        buf_size = ctypes.sizeof(EchoReply) + size + 8 + 64
        buf = ctypes.create_string_buffer(buf_size)
        start = time.perf_counter()
        count = lib.IcmpSendEcho(handle, dest, payload, size, ctypes.byref(opts), buf, buf_size, timeout_ms)
        elapsed = round((time.perf_counter() - start) * 1000, 3)
        if count == 0:
            return Reply(False, error="TimedOut")
        reply = EchoReply.from_buffer_copy(buf)
        source = socket.inet_ntoa(int(reply.Address).to_bytes(4, "little"))
        # Windows liefert ganze ms (bei TTL-Ablauf oft 0) – für kleine Werte die Stoppuhr nehmen
        rtt = float(reply.RoundTripTime) if reply.RoundTripTime >= 2 else elapsed
        if reply.Status == IP_SUCCESS:
            return Reply(True, rtt, int(reply.Options.Ttl), source)
        if reply.Status in (IP_TTL_EXPIRED_TRANSIT, IP_TTL_EXPIRED_REASSEM):
            return Reply(False, rtt, None, source, ttl_expired=True, error="TtlExpired")
        return Reply(False, error=_WIN_STATUS.get(reply.Status, f"Status {reply.Status}"))
    finally:
        lib.IcmpCloseHandle(handle)


def ping(address: str, timeout_ms: int = 1000, size: int = 32, ttl: int = 128) -> Reply:
    size = max(0, min(1472, int(size)))
    ttl = max(1, min(255, int(ttl)))
    timeout_ms = max(100, min(5000, int(timeout_ms)))
    return _ping_windows(address, timeout_ms, size, ttl) if IS_WINDOWS else _ping_posix(address, timeout_ms, size, ttl)
