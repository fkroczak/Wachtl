"""Netzwerkscan der Server-Probe (Check-Typ ``netscan``, Vertrag: docs/NETZWERKSCAN.md).

Geräteerkennung (ICMP, TCP, ARP-Tabelle), Reverse-DNS, TCP-Connect-Portscan und eine einfache
Diensterkennung (Banner, HTTP, TLS). Nur Standardbibliothek (plus ``cryptography`` für den
Zertifikatsnamen, falls vorhanden) – läuft unter Linux/Docker und im eingebetteten Python unter Windows.

Nur TCP-Connect, kein SYN-Scan, keine Exploits; gescannt werden ausschließlich die eingestellten Netze.
"""
from __future__ import annotations

import errno
import html
import ipaddress
import logging
import os
import re
import socket
import ssl
import struct
import subprocess
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from typing import Callable, Iterable

from . import icmp, net

log = logging.getLogger("wachtl.serverprobe")
IS_WINDOWS = os.name == "nt"

DEFAULT_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,515,554,631,993,995,1883,3306,3389,5060,5432,5900,8006,8080,8443,9100"
MAX_PORTS = 1024
DISCOVERY_PORTS = (80, 443, 445, 22)
HTTP_PORTS = frozenset((80, 8080, 8000, 8006, 8443, 443))     # 631 und 9100 bewusst nicht (Drucker)
TLS_PORTS = frozenset((443, 8443, 8006))
AUTO_MAX_PREFIX = 22            # auto: größere Netze auf das /22 um die eigene Adresse kürzen
TEXT_MAX = 200
BANNER_WAIT_S = 1.0
SERVICE_BUDGET_S = 2.0
TITLE_MAX_BYTES = 16 * 1024
DNS_TIMEOUT_S = 1.0
# Schnittstellen von Containern/VMs auf dem Host gehören nicht zum Kundennetz
VIRTUAL_IFACES = ("lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "podman", "vmnet", "vboxnet")


class ScanError(ValueError):
    """Scan kann nicht laufen (Ziel/Ports ungültig, zu viele Adressen …) – Text geht als ``error`` an den Server."""


# -- reine Hilfsfunktionen (getestet) ------------------------------------------------------------
def parse_ports(value) -> list[int]:
    """``"22,80,8000-8010"`` oder Liste → sortierte, eindeutige Ports; höchstens 1024."""
    if value is None or value == "":
        value = DEFAULT_PORTS
    items = value if isinstance(value, (list, tuple)) else str(value).replace(";", ",").split(",")
    ports: set[int] = set()
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        m = re.fullmatch(r"(\d{1,5})\s*(?:-\s*(\d{1,5}))?", text)
        if not m:
            raise ScanError(f"Ungültige Port-Angabe: {text}")
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= lo <= hi <= 65535):
            raise ScanError(f"Ungültiger Port-Bereich: {text}")
        if hi - lo + 1 > MAX_PORTS:
            raise ScanError(f"Höchstens {MAX_PORTS} Ports")
        ports.update(range(lo, hi + 1))
        if len(ports) > MAX_PORTS:
            raise ScanError(f"Höchstens {MAX_PORTS} Ports")
    return sorted(ports)


def usable_address(ip: str) -> bool:
    a = ipaddress.IPv4Address(ip)
    return not (a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast)


def auto_network(ip: str, prefix: int) -> ipaddress.IPv4Network:
    """Netz einer Schnittstelle; größer als /22 → das /22 um die eigene Adresse."""
    return ipaddress.IPv4Network(f"{ip}/{max(int(prefix), AUTO_MAX_PREFIX)}", strict=False)


def plan_networks(target: str | None, interfaces: Iterable[tuple[str, int]]) -> list[ipaddress.IPv4Network]:
    """Zu scannende Netze: ``auto`` (eigene Schnittstellen) oder CIDR-Liste, Komma-getrennt."""
    target = (target or "auto").strip()
    nets: list[ipaddress.IPv4Network] = []
    if target.lower() == "auto":
        for ip, prefix in interfaces:
            if not usable_address(ip):
                continue
            n = auto_network(ip, prefix)
            if n not in nets:
                nets.append(n)
        if not nets:
            raise ScanError("Keine eigene IPv4-Adresse gefunden (Ziel „auto“)")
        return nets
    for part in re.split(r"[,;\s]+", target):
        if not part:
            continue
        try:
            n = ipaddress.IPv4Network(part, strict=False)
        except ValueError as exc:
            raise ScanError(f"Ungültiges Netz: {part}") from exc
        if n.is_multicast or n.is_unspecified:
            raise ScanError(f"Netz nicht scanbar: {part}")
        if n not in nets:
            nets.append(n)
    if not nets:
        raise ScanError("Kein Netz angegeben")
    return nets


def plan_hosts(networks: list[ipaddress.IPv4Network], max_hosts: int) -> list[str]:
    """Alle Host-Adressen der Netze (ohne Netz-/Broadcastadresse); mehr als ``max_hosts`` → Fehler."""
    total = sum(max(1, n.num_addresses - 2) if n.prefixlen < 31 else n.num_addresses for n in networks)
    if total > max_hosts:
        raise ScanError(f"{total} Adressen sind mehr als erlaubt ({max_hosts}) – kleineres Netz oder max_hosts erhöhen")
    seen: dict[str, None] = {}
    for n in networks:
        for h in (n.hosts() if n.prefixlen < 31 else n):
            seen.setdefault(str(h), None)
    return list(seen)


def norm_mac(text: str) -> str | None:
    parts = re.split(r"[:-]", text.strip())
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in parts):
        return None
    mac = ":".join(p.zfill(2).upper() for p in parts)
    if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") or int(parts[0], 16) & 1:   # leer, Broadcast, Multicast
        return None
    return mac


def parse_proc_arp(text: str) -> dict[str, str]:
    """/proc/net/arp (Linux): IP → MAC, nur vollständige Einträge (Flags ≠ 0)."""
    out: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            if int(parts[2], 16) == 0:
                continue
        except ValueError:
            continue
        mac = norm_mac(parts[3])
        if mac:
            out[parts[0]] = mac
    return out


_ARP_A = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\b", re.M)


def parse_arp_a(text: str) -> dict[str, str]:
    """``arp -a`` (Windows, jede Sprache): IP → MAC; Broadcast/Multicast entfallen."""
    out: dict[str, str] = {}
    for m in _ARP_A.finditer(text):
        ip = m.group(1)
        try:
            if ipaddress.IPv4Address(ip).is_multicast or ip == "255.255.255.255":
                continue
        except ValueError:
            continue
        mac = norm_mac(m.group(2))
        if mac:
            out[ip] = mac
    return out


_IP_ADDR = re.compile(r"^\d+:\s+(\S+?)(?:@\S+)?\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", re.M)


def parse_ip_addr(text: str) -> list[tuple[str, str, int]]:
    """``ip -4 -o addr show`` (Linux): (Schnittstelle, Adresse, Präfix)."""
    return [(m.group(1), m.group(2), int(m.group(3))) for m in _IP_ADDR.finditer(text)]


_IPV4 = re.compile(r":\s*(\d{1,3}(?:\.\d{1,3}){3})(?:\(|\s|$)")


def parse_ipconfig(text: str) -> list[tuple[str, int]]:
    """``ipconfig`` (Windows, jede Sprache): IPv4-Adresse, gefolgt von ihrer Subnetzmaske → (Adresse, Präfix)."""
    out: list[tuple[str, int]] = []
    pending: str | None = None
    for line in text.splitlines():
        m = _IPV4.search(line)
        if not m:
            if line and not line[0].isspace():
                pending = None          # neuer Adapter-Abschnitt
            continue
        value = m.group(1)
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{value}").prefixlen if value.startswith("255.") else None
        except ValueError:
            prefix = None
        if prefix is not None and pending:
            out.append((pending, prefix))
            pending = None
        elif prefix is None:
            pending = value
    return out


def trim(text: str | None) -> str | None:
    if text is None:
        return None
    text = re.sub(r"\s+", " ", text).strip()
    return text[:TEXT_MAX] or None


def banner_text(data: bytes) -> str | None:
    """Erste aussagekräftige Zeile eines Banners, nur druckbare Zeichen, höchstens 200 Zeichen."""
    text = data.decode("utf-8", errors="replace") if data else ""
    text = "".join(ch if ch.isprintable() or ch in "\r\n" else " " for ch in text.replace("�", " "))
    for line in re.split(r"[\r\n]+", text):
        if len(line.strip()) >= 3:
            return trim(line)
    return trim(text)


def looks_like_tls(data: bytes) -> bool:
    return len(data) >= 3 and data[0] in (0x15, 0x16) and data[1] == 0x03


def parse_http_response(data: bytes) -> tuple[int | None, str | None, str | None]:
    """(Status, Server-Header, Titel) aus einer rohen HTTP-Antwort."""
    if not data.startswith(b"HTTP/"):
        return None, None, None
    head, _, body = data.partition(b"\r\n\r\n")
    if not _:
        head, _, body = data.partition(b"\n\n")
    lines = head.decode("iso-8859-1").splitlines()
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0]) if lines else None
    status = int(m.group(1)) if m else None
    headers = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers.setdefault(k.strip().lower(), v.strip())
    charset = re.search(r"charset=([\w.-]+)", headers.get("content-type", ""), re.I)
    return status, trim(headers.get("server")), html_title(body, charset.group(1) if charset else None)


def html_title(body: bytes, charset: str | None = None) -> str | None:
    m = re.search(rb"<title[^>]*>(.*?)</title", body[:TITLE_MAX_BYTES], re.I | re.S)
    if not m:
        return None
    raw = m.group(1)
    meta = re.search(rb"<meta[^>]+charset=[\"']?([\w.-]+)", body[:TITLE_MAX_BYTES], re.I)
    for enc in (charset, meta.group(1).decode() if meta else None, "utf-8"):
        if not enc:
            continue
        try:
            text = raw.decode(enc)
            break
        except (LookupError, UnicodeDecodeError):
            continue
    else:
        text = raw.decode("iso-8859-1")
    return trim(html.unescape(text))


def cert_subject(der: bytes | None) -> str | None:
    if not der:
        return None
    try:
        from cryptography import x509

        return trim(x509.load_der_x509_certificate(der).subject.rfc4514_string())
    except Exception:  # noqa: BLE001 – kaputte Zertifikate alter Geräte, fehlendes cryptography
        return None


# -- System: eigene Netze und ARP-Tabelle ---------------------------------------------------------
def _run(args: list[str]) -> str:
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        return subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=15,
                              creationflags=flags).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _linux_ioctl_interfaces() -> list[tuple[str, str, int]]:
    """Adresse und Netzmaske jeder aktiven Schnittstelle per ioctl – braucht kein ``ip`` (fehlt im Docker-Image)."""
    import fcntl

    out = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _, name in socket.if_nameindex():
            req = struct.pack("256s", name.encode()[:15])
            try:
                flags = struct.unpack("H", fcntl.ioctl(s.fileno(), 0x8913, req)[16:18])[0]   # SIOCGIFFLAGS
                if not flags & 0x1:                                                          # IFF_UP
                    continue
                addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, req)[20:24])         # SIOCGIFADDR
                mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891B, req)[20:24])         # SIOCGIFNETMASK
            except OSError:
                continue
            out.append((name, addr, ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen))
    return out


def local_interfaces() -> list[tuple[str, int]]:
    """Eigene IPv4-Adressen mit Präfix (ohne Loopback/APIPA und virtuelle Container-/VM-Brücken).

    In Docker sieht die Server-Probe nur das Container-Netz (z. B. 172.17.0.0/16 → /22) – mit „auto“
    wird dann dieses gescannt. Für das echte LAN im Check ausdrückliche Netze (CIDR) eintragen oder
    den Container mit ``network_mode: host`` betreiben.
    """
    found: list[tuple[str, str, int]] = []
    if IS_WINDOWS:
        found = [("", ip, p) for ip, p in parse_ipconfig(_run(["ipconfig"]))]
    else:
        try:
            found = _linux_ioctl_interfaces()
        except (ImportError, OSError):
            found = []
        if not found:
            found = parse_ip_addr(_run(["ip", "-4", "-o", "addr", "show"]))
    out: list[tuple[str, int]] = []
    for name, ip, prefix in found:
        if name.startswith(VIRTUAL_IFACES) or not usable_address(ip):
            continue
        if (ip, prefix) not in out:
            out.append((ip, prefix))
    if not out:     # letzte Rettung: Adresse der Default-Route, Präfix /24 angenommen
        out = [(a, 24) for a in net.local_addresses()[:1]]
    return out


def arp_table() -> dict[str, str]:
    if IS_WINDOWS:
        return parse_arp_a(_run(["arp", "-a"]))
    try:
        with open("/proc/net/arp", encoding="ascii", errors="replace") as f:
            return parse_proc_arp(f.read())
    except OSError:
        return {}


# -- Netzwerkzugriffe ------------------------------------------------------------------------------
def tcp_probe(ip: str, port: int, timeout_s: float) -> str:
    """'open', 'closed' (RST – Gerät antwortet) oder 'none'."""
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError as exc:
        return "closed" if exc.errno in (errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", -1)) else "none"


def _recv_until(sock: socket.socket, deadline: float, limit: int, stop_at: bytes | None = None) -> bytes:
    data = b""
    while len(data) < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(min(4096, limit - len(data)))
        except (socket.timeout, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        data += chunk
        if stop_at and stop_at in data:
            break
    return data


def _tls_context() -> ssl.SSLContext:
    # nur zur Erkennung: Zertifikat wird nicht geprüft, auch alte Geräte (TLS 1.0, schwache Chiffren) zulassen
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def _http(ip: str, port: int, use_tls: bool, method: str, deadline: float, sock: socket.socket | None = None
          ) -> tuple[bytes, str | None]:
    """Eine HTTP/1.0-Anfrage; liefert (Antwort, TLS-Zertifikatsname)."""
    subject = None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return b"", None
    if sock is None:
        sock = socket.create_connection((ip, port), timeout=remaining)
    try:
        if use_tls:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            sock = _tls_context().wrap_socket(sock)
            subject = cert_subject(sock.getpeercert(binary_form=True))
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        host = ip if port in (80, 443) else f"{ip}:{port}"
        sock.sendall(f"{method} / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Wachtl-Netzwerkscan\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n".encode())
        limit = TITLE_MAX_BYTES + 4096 if method == "GET" else 8192
        return _recv_until(sock, deadline, limit, b"</title" if method == "GET" else b"\r\n\r\n"), subject
    finally:
        sock.close()


def identify(sock: socket.socket, ip: str, port: int) -> dict:
    """Diensterkennung auf einer offenen Verbindung, höchstens 2 s."""
    result = {"port": port, "banner": None, "tls": False, "http_status": None, "http_server": None,
              "http_title": None, "tls_subject": None}
    deadline = time.monotonic() + SERVICE_BUDGET_S
    try:
        first = _recv_until(sock, time.monotonic() + BANNER_WAIT_S, 1024, b"\n")
    except OSError:
        first = b""
    if first and not looks_like_tls(first):
        if first.startswith(b"HTTP/"):
            result["http_status"], result["http_server"], result["http_title"] = parse_http_response(first)
        else:
            result["banner"] = banner_text(first)
        sock.close()
        return result
    if port not in HTTP_PORTS and not looks_like_tls(first):
        sock.close()
        return result
    use_tls = port in TLS_PORTS or looks_like_tls(first)
    head = b""
    try:
        if use_tls:
            sock.close()
            head, result["tls_subject"] = _http(ip, port, True, "HEAD", deadline)
            result["tls"] = True
        else:
            head, _ = _http(ip, port, False, "HEAD", deadline, sock)
            if looks_like_tls(head) or (head.startswith(b"HTTP/1.1 400")
                                        and re.search(rb"https? (port|server)|speak https|TLS", head[:2048], re.I)):
                head, result["tls_subject"] = _http(ip, port, True, "HEAD", deadline)
                use_tls, result["tls"] = True, True
    except (OSError, ssl.SSLError, ValueError):
        if use_tls and not result["tls"]:
            # kein TLS → vielleicht doch einfaches HTTP
            try:
                head, _ = _http(ip, port, False, "HEAD", deadline)
                use_tls = False
            except (OSError, ValueError):
                return result
        else:
            return result
    finally:
        sock.close()
    status, server, _ = parse_http_response(head)
    if status is None:
        return result
    result["http_status"], result["http_server"] = status, server
    try:
        body, _ = _http(ip, port, use_tls, "GET", deadline)
        g_status, g_server, title = parse_http_response(body)
        result["http_title"] = title
        result["http_server"] = result["http_server"] or g_server
    except (OSError, ssl.SSLError, ValueError):
        pass
    return result


def scan_port(ip: str, port: int, timeout_s: float, detect: bool = True) -> dict | None:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout_s)
    except OSError:
        return None
    if not detect:
        sock.close()
        return {"port": port, "banner": None, "tls": False, "http_status": None, "http_server": None,
                "http_title": None, "tls_subject": None}
    try:
        return identify(sock, ip, port)
    except Exception:  # noqa: BLE001 – Erkennung ist Beiwerk, der Port ist trotzdem offen
        sock.close()
        return {"port": port, "banner": None, "tls": False, "http_status": None, "http_server": None,
                "http_title": None, "tls_subject": None}


def reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    return trim(name.rstrip(".")) if name and name != ip else None


# -- Scan ------------------------------------------------------------------------------------------
def _p(params: dict, key: str, default):
    value = params.get(key, default)
    return default if value is None or value == "" else value


def _clamp(v, lo, hi):
    return max(lo, min(hi, v))


class Scanner:
    """Ein Scan-Lauf. Systemzugriffe sind austauschbar (Tests)."""

    def __init__(self, check: dict, stop: threading.Event | None = None, pinger=icmp.ping,
                 interfaces: Callable[[], list[tuple[str, int]]] = local_interfaces,
                 arp: Callable[[], dict[str, str]] = arp_table, resolver: Callable[[str], str | None] = reverse_dns,
                 tcp: Callable[[str, int, float], str] = tcp_probe):
        params = check.get("params") or {}
        self.check, self.stop = check, stop or threading.Event()
        self.target = str(check.get("target") or _p(params, "subnets", "auto"))
        self.ports = parse_ports(_p(params, "ports", DEFAULT_PORTS))
        self.port_scan = bool(_p(params, "port_scan", True))
        self.timeout_ms = int(_clamp(int(_p(params, "timeout_ms", 500)), 50, 10000))
        self.parallel = int(_clamp(int(_p(params, "parallel", 64)), 1, 256))
        self.max_hosts = int(_clamp(int(_p(params, "max_hosts", 1024)), 1, 65536))
        self.pinger, self.interfaces, self.arp, self.resolver, self.tcp = pinger, interfaces, arp, resolver, tcp

    def _pool(self, name: str) -> ThreadPoolExecutor:
        return ThreadPoolExecutor(max_workers=self.parallel, thread_name_prefix=f"netscan-{self.check['id']}-{name}")

    def _map(self, name: str, fn, items: list) -> dict:
        """fn je Element parallel; bricht bei stop ab. Liefert {Element: Ergebnis}."""
        out = {}
        if not items:
            return out
        pool = self._pool(name)
        try:
            futures = {pool.submit(lambda i=i: None if self.stop.is_set() else fn(i)): i for i in items}
            for f in as_completed(futures):
                if self.stop.is_set():
                    break
                out[futures[f]] = f.result()
        finally:
            pool.shutdown(wait=not self.stop.is_set(), cancel_futures=True)
        return out

    def _check_stop(self) -> None:
        if self.stop.is_set():
            raise ScanError("Scan abgebrochen")

    def discover(self, addresses: list[str]) -> dict[str, dict]:
        timeout_s = self.timeout_ms / 1000
        icmp_ok = self.pinger("127.0.0.1", self.timeout_ms, 32, 64).success   # ICMP erlaubt? (Docker ohne NET_RAW)
        if not icmp_ok:
            log.info("Netzwerkscan %s: ICMP nicht verfügbar, nur TCP/ARP", self.check["id"])

        def probe(ip: str) -> dict | None:
            via, rtt = [], None
            if icmp_ok:
                r = self.pinger(ip, self.timeout_ms, 32, 64)
                if r.success and (r.source in (None, ip)):
                    via.append("icmp")
                    rtt = round(r.rtt_ms, 3)
            if not via:
                for port in DISCOVERY_PORTS:
                    if self.stop.is_set():
                        break
                    if self.tcp(ip, port, timeout_s) != "none":
                        via.append("tcp")
                        break
            return {"via": via, "rtt_ms": rtt} if via else None

        found = {ip: r for ip, r in self._map("discover", probe, addresses).items() if r}
        self._check_stop()
        wanted = set(addresses)
        for ip, mac in self.arp().items():
            if ip not in wanted:
                continue
            entry = found.setdefault(ip, {"via": [], "rtt_ms": None})
            entry["mac"] = mac
            if "arp" not in entry["via"]:
                entry["via"].append("arp")
        return found

    def resolve_names(self, ips: list[str]) -> dict[str, str | None]:
        names: dict[str, str | None] = {}
        if not ips:
            return names
        pool = self._pool("dns")
        try:
            futures = {pool.submit(self.resolver, ip): ip for ip in ips}
            batches = -(-len(ips) // self.parallel)
            done, _ = wait(futures, timeout=DNS_TIMEOUT_S * batches + 0.5)
            for f in done:
                try:
                    names[futures[f]] = f.result()
                except Exception:  # noqa: BLE001
                    names[futures[f]] = None
        finally:
            pool.shutdown(wait=False, cancel_futures=True)     # hängende DNS-Anfragen nicht abwarten
        return names

    def scan(self) -> tuple[list[str], list[dict]]:
        interfaces = self.interfaces()
        networks = plan_networks(self.target, interfaces)
        addresses = plan_hosts(networks, self.max_hosts)
        own = {ip for ip, _ in interfaces} | set(net.local_addresses())
        found = self.discover(addresses)
        for ip in own:
            if ip in addresses and ip not in found:
                found[ip] = {"via": [], "rtt_ms": None}
        ips = sorted(found, key=lambda a: ipaddress.IPv4Address(a))
        names = self.resolve_names(ips)
        self._check_stop()
        open_ports: dict[str, list[dict]] = {ip: [] for ip in ips}
        if self.port_scan and ips:
            jobs = [(ip, port) for ip in ips for port in self.ports]
            results = self._map("ports", lambda j: scan_port(j[0], j[1], self.timeout_ms / 1000), jobs)
            self._check_stop()
            for (ip, _), r in results.items():
                if r:
                    open_ports[ip].append(r)
        hosts = []
        for ip in ips:
            f = found[ip]
            ports = sorted(open_ports[ip], key=lambda p: p["port"])
            via = list(f["via"])
            if ports and "tcp" not in via:
                via.append("tcp")
            hosts.append({"ip": ip, "mac": f.get("mac"), "hostname": names.get(ip), "rtt_ms": f.get("rtt_ms"),
                          "via": via, "self": ip in own, "ports": ports})
        return [str(n) for n in networks], hosts


def run_scan(check: dict, trigger: str, stop: threading.Event | None = None, **system) -> dict:
    """Kompletter Scan → Nutzlast für ``POST /api/probe/v1/results/netscan``; Fehler stehen in ``error``."""
    started = time.monotonic()
    result = {"check_id": check["id"], "ts": int(time.time()), "trigger": trigger, "duration_s": 0.0,
              "subnets": [], "error": None, "hosts": []}
    try:
        scanner = Scanner(check, stop, **system)
        result["subnets"], result["hosts"] = scanner.scan()
    except ScanError as exc:
        result["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001 – Fehler als Ergebnis melden, nie die Probe beenden
        log.exception("Netzwerkscan %s fehlgeschlagen", check.get("id"))
        result["error"] = f"Scan fehlgeschlagen: {exc}"[:TEXT_MAX]
    result["duration_s"] = round(time.monotonic() - started, 1)
    return result
