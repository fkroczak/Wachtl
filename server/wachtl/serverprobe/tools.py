"""Werkzeuge der Server-Probe (docs/WERKZEUGE.md): Ping, MTU, Traceroute, DNS, Port, HTTP(S), Zertifikat.

Jedes Werkzeug bekommt die geprüften Argumente (services/tools.py) und eine Funktion ``report`` für den Fortschritt:
``report(progress=0..1, step="…", line="…")``. Es gibt ``(ok, result, error)`` zurück; ``result`` hat das Format,
das das Web-UI anzeigt: headline, verdict (ok|warn|bad), summary [[Bezeichnung, Wert, Klasse]], stats, table.
Dieselben Werkzeuge mit demselben Ergebnisformat gibt es in der Windows-Probe (probe/Wachtl.Probe/Tools).
Ohne Fremdprogramme: Ping über icmp.py, DNS als eigener kleiner Client, alles andere mit der Standardbibliothek.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import random
import re
import socket
import ssl
import statistics
import struct
import time
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlparse

from . import icmp

Report = Callable[..., None]
Result = tuple[bool, dict, str | None]

ERRORS = {"TimedOut": "Zeitüberschreitung", "DestinationUnreachable": "Ziel nicht erreichbar",
          "DestinationHostUnreachable": "Host nicht erreichbar", "DestinationNetworkUnreachable": "Netz nicht erreichbar",
          "PacketTooBig": "Paket zu groß (Fragmentierung nötig)", "TtlExpired": "TTL abgelaufen",
          "GeneralFailure": "allgemeiner Fehler"}
MTU_HINTS = ((9000, "Jumbo-Frames"), (1500, "Ethernet ohne Tunnel – volle Größe"), (1492, "PPPoE (DSL)"),
             (1480, "6in4-Tunnel"), (1476, "GRE-Tunnel"), (1420, "WireGuard"), (1400, "IPsec oder anderer VPN-Tunnel"))


def fmt_ms(v: float | None) -> str:
    if v is None:
        return "–"
    return f"{v:.2f}".replace(".", ",") if v < 10 else f"{v:.1f}".replace(".", ",")


def _err(code: str) -> str:
    return ERRORS.get(code, code or "keine Antwort")


def _resolve(host: str) -> tuple[str | None, str]:
    """IPv4 für die ICMP-Werkzeuge."""
    try:
        if ipaddress.ip_address(host).version == 6:
            return None, "IPv6 wird von den ICMP-Werkzeugen noch nicht unterstützt."
    except ValueError:
        pass
    return icmp.resolve(host)


def _ptr(ip: str, timeout: float = 1.5) -> str | None:
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        fut = pool.submit(socket.gethostbyaddr, ip)
        try:
            return fut.result(timeout)[0]
        except Exception:  # noqa: BLE001 – kein Rückwärtsname ist kein Fehler
            return None


def _target_text(host: str, ip: str) -> str:
    return ip if host == ip else f"{host} ({ip})"


# -- Ping ----------------------------------------------------------------------------------
def tool_ping(a: dict, report: Report, pinger=icmp.ping, sleep=time.sleep) -> Result:
    ip, err = _resolve(a["host"])
    if not ip:
        return False, {}, err
    count, size, df = a["count"], a["size"], a.get("df", False)
    rtts: list[float] = []
    too_big = False
    report(line=f"Ping {_target_text(a['host'], ip)} mit {size} Byte Nutzdaten{' (nicht fragmentieren)' if df else ''}:")
    for i in range(1, count + 1):
        t0 = time.monotonic()
        r = pinger(ip, 2000, size, 128, df) if df else pinger(ip, 2000, size, 128)
        if not r.success and r.error.startswith("ping nicht ausführbar"):
            return False, {}, r.error
        if r.success:
            rtts.append(r.rtt_ms)
            line = f"Antwort von {r.source or ip}: Bytes={size} Zeit={fmt_ms(r.rtt_ms)} ms TTL={r.ttl or '–'}"
        else:
            too_big = too_big or r.error == "PacketTooBig"
            line = f"Paket {i}: {_err(r.error)}"
        report(progress=i / count, step=f"Paket {i} von {count}: {fmt_ms(r.rtt_ms) + ' ms' if r.success else _err(r.error)}",
               line=line)
        if i < count:
            sleep(max(0.0, a["interval"] - (time.monotonic() - t0)))
    got = len(rtts)
    loss = round((count - got) * 100 / count, 1)
    stats = {"sent": count, "received": got, "loss": loss,
             "min": min(rtts) if rtts else None, "avg": round(statistics.fmean(rtts), 2) if rtts else None,
             "max": max(rtts) if rtts else None, "mdev": round(statistics.pstdev(rtts), 2) if len(rtts) > 1 else 0.0 if rtts else None}
    verdict = "ok" if loss == 0 else "bad" if loss >= 50 else "warn"
    headline = ("Alle Pakete beantwortet" if loss == 0 else "Keine Antwort" if not got
                else f"{count - got} von {count} Paketen ohne Antwort")
    summary = [["Ziel", _target_text(a["host"], ip), ""], ["Pakete", f"{count} × {size} Byte Nutzdaten "
               f"({size + 28} Byte IP-Paket){', nicht fragmentieren' if df else ''}", ""]]
    if too_big:
        summary.append(["Hinweis", "Paket zu groß für den Weg – Größe verkleinern oder DF ausschalten; die passende "
                                   "Größe zeigt der MTU-Test.", "warn"])
    return True, {"headline": headline, "verdict": verdict, "stats": stats, "summary": summary}, None


# -- MTU -----------------------------------------------------------------------------------
def _mtu_hint(mtu: int) -> str:
    for size, text in MTU_HINTS:
        if mtu >= size:
            return text
    return "kleiner als üblich – Tunnel oder Fehlkonfiguration auf dem Weg"


def tool_mtu(a: dict, report: Report, pinger=icmp.ping) -> Result:
    ip, err = _resolve(a["host"])
    if not ip:
        return False, {}, err
    tries, lo, hi = a["tries"], a["min"], a["max"]
    steps = max(1, (hi - lo).bit_length()) + 2
    done = 0

    def fits(mtu: int) -> tuple[bool, str]:
        nonlocal done
        done += 1
        last = ""
        for _ in range(tries):
            r = pinger(ip, 1500, mtu - 28, 128, True)
            if r.success:
                report(progress=min(0.95, done / steps), step=f"{mtu} Byte: passt", line=f"{mtu} Byte: Antwort nach {fmt_ms(r.rtt_ms)} ms")
                return True, "passt"
            last = r.error
        report(progress=min(0.95, done / steps), step=f"{mtu} Byte: {_err(last)}", line=f"{mtu} Byte: {_err(last)}")
        return False, last

    ok_lo, why = fits(lo)
    if not ok_lo:
        return False, {"summary": [["Ziel", _target_text(a["host"], ip), ""]]}, \
            f"Schon {lo} Byte kommen nicht durch ({_err(why)}) – Ziel antwortet nicht auf Ping oder ICMP ist gefiltert."
    ok_hi, why_hi = fits(hi)
    if ok_hi:
        best, blackhole = hi, False
    else:
        good, bad = lo, hi
        while bad - good > 1:
            mid = (good + bad) // 2
            if fits(mid)[0]:
                good = mid
            else:
                bad = mid
        best, blackhole = good, why_hi == "TimedOut"
    summary = [["Ziel", _target_text(a["host"], ip), ""],
               ["Pfad-MTU", f"{best} Byte{' oder mehr' if ok_hi else ''}", "good" if best >= 1500 else "warn"],
               ["Einordnung", _mtu_hint(best), ""],
               ["TCP-MSS dazu", f"{best - 40} Byte", ""]]
    if blackhole:
        summary.append(["Hinweis", "Zu große Pakete verschwinden ohne Fehlermeldung (keine ICMP-Meldung "
                                   "„Fragmentierung nötig“) – möglicher PMTU-Blackhole: große Downloads oder VPN können hängen.",
                        "warn"])
    return True, {"headline": f"Pfad-MTU {best} Byte", "verdict": "ok" if best >= 1500 or ok_hi else "warn",
                  "summary": summary}, None


# -- Traceroute ----------------------------------------------------------------------------
def tool_trace(a: dict, report: Report, pinger=icmp.ping, ptr=_ptr) -> Result:
    ip, err = _resolve(a["host"])
    if not ip:
        return False, {}, err
    count, max_hops = a["count"], a["max_hops"]
    rows, classes = [], []
    reached = False
    report(line=f"Traceroute zu {_target_text(a['host'], ip)}, höchstens {max_hops} Hops, {count} Pakete je Hop")
    for ttl in range(1, max_hops + 1):
        rtts, source = [], None
        for _ in range(count):
            r = pinger(ip, 1500, 32, ttl)
            if r.success or r.ttl_expired:
                source = source or r.source
                rtts.append(r.rtt_ms)
                reached = reached or r.success
        loss = round((count - len(rtts)) * 100 / count)
        name = ptr(source) if source and a.get("names", True) else None
        addr = (f"{name} ({source})" if name else source) or "*"
        rows.append([str(ttl), addr, f"{loss} %", fmt_ms(min(rtts)) if rtts else "–",
                     fmt_ms(statistics.fmean(rtts)) if rtts else "–", fmt_ms(max(rtts)) if rtts else "–"])
        classes.append("" if not rtts or loss == 0 else "warn")
        line = f"{ttl:>3}  {addr:<45} {loss:>3} %  " + (" ".join(f"{fmt_ms(x)} ms" for x in rtts) if rtts else "keine Antwort")
        report(progress=ttl / max_hops if not reached else 1.0, step=f"Hop {ttl}: {addr}", line=line)
        if reached:
            break
    hops = len(rows)
    summary = [["Ziel", _target_text(a["host"], ip), ""],
               ["Ziel erreicht", f"ja, nach {hops} {'Hop' if hops == 1 else 'Hops'}" if reached
                else f"nein – nach {hops} {'Hop' if hops == 1 else 'Hops'} abgebrochen",
                "good" if reached else "bad"]]
    silent = [r[0] for r in rows if r[1] == "*"]
    if silent and reached:
        summary.append(["Ohne Antwort", f"Hop {', '.join(silent)} – viele Router beantworten Traceroute nicht, das ist "
                                        "meist unbedenklich, solange das Ziel antwortet.", ""])
    table = {"title": "Weg", "head": ["Hop", "Router", "Verlust", "min ms", "Mittel ms", "max ms"], "rows": rows,
             "classes": classes}
    return True, {"headline": f"{'Ziel erreicht' if reached else 'Ziel nicht erreicht'} – {hops} {'Hop' if hops == 1 else 'Hops'}",
                  "verdict": "ok" if reached else "bad", "summary": summary, "table": table}, None


# -- DNS -----------------------------------------------------------------------------------
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257}
QNAMES = {v: k for k, v in QTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def system_resolvers() -> list[str]:
    """DNS-Server der Probe: /etc/resolv.conf bzw. die Windows-Registry."""
    out: list[str] = []
    if os.name == "nt":
        try:
            import winreg

            base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            keys = [base] + [f"{base}\\Interfaces\\{n}" for n in _reg_subkeys(winreg, base + r"\Interfaces")]
            for k in keys:
                for value in ("NameServer", "DhcpNameServer"):
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, k) as h:
                            raw = winreg.QueryValueEx(h, value)[0]
                    except OSError:
                        continue
                    out += [x for x in re.split(r"[ ,]+", raw or "") if x]
        except ImportError:
            pass
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        out.append(parts[1])
        except OSError:
            pass
    seen: list[str] = []
    for x in out:
        try:
            ipaddress.ip_address(x)
        except ValueError:
            continue
        if x not in seen:
            seen.append(x)
    return seen


def _reg_subkeys(winreg, path: str) -> list[str]:
    names = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as h:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(h, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return names


def dns_query(name: str, qtype: int) -> tuple[int, bytes]:
    qid = random.randint(0, 0xFFFF)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        q += bytes([len(raw)]) + raw
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    return qid, q


def _name(msg: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    while True:
        if off >= len(msg) or depth > 20:
            raise ValueError("Antwort beschädigt")
        n = msg[off]
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            off, jumped, depth = ptr, True, depth + 1
            continue
        if n == 0:
            if not jumped:
                end = off + 1
            break
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += n + 1
    return ".".join(labels) + ".", end


def _rdata(msg: bytes, rtype: int, off: int, rdlen: int) -> str:
    rd = msg[off:off + rdlen]
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntoa(rd)
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, rd)
    if rtype in (2, 5, 12):
        return _name(msg, off)[0]
    if rtype == 15:
        return f"{struct.unpack('!H', rd[:2])[0]} {_name(msg, off + 2)[0]}"
    if rtype == 16:
        parts, i = [], 0
        while i < len(rd):
            n = rd[i]
            parts.append(rd[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += n + 1
        return " ".join(f'"{p}"' for p in parts)
    if rtype == 6:
        mname, o = _name(msg, off)
        rname, o = _name(msg, o)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", msg[o:o + 20])
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    if rtype == 33:
        prio, weight, port = struct.unpack("!HHH", rd[:6])
        return f"{prio} {weight} {port} {_name(msg, off + 6)[0]}"
    if rtype == 257 and rdlen >= 2:
        flags, tl = rd[0], rd[1]
        return f'{flags} {rd[2:2 + tl].decode("ascii", "replace")} "{rd[2 + tl:].decode("utf-8", "replace")}"'
    return rd.hex()


def dns_parse(msg: bytes, qid: int) -> dict:
    if len(msg) < 12:
        raise ValueError("Antwort zu kurz")
    rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid:
        raise ValueError("Antwort gehört nicht zur Anfrage")
    off = 12
    for _ in range(qd):
        off = _name(msg, off)[1] + 4
    answers = []
    for i in range(an + ns):
        name, off = _name(msg, off)
        rtype, _cls, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        answers.append({"section": "answer" if i < an else "authority", "name": name,
                        "type": QNAMES.get(rtype, str(rtype)), "ttl": ttl, "data": _rdata(msg, rtype, off, rdlen)})
        off += rdlen
    return {"rcode": RCODES.get(flags & 0xF, str(flags & 0xF)), "truncated": bool(flags & 0x0200),
            "authoritative": bool(flags & 0x0400), "answers": answers}


def dns_ask(server: str, name: str, qtype: int, timeout: float = 3.0) -> dict:
    qid, q = dns_query(name, qtype)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, (server, 53))
        while True:
            data, _addr = s.recvfrom(4096)
            if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == qid:
                break
    res = dns_parse(data, qid)
    if res["truncated"]:            # zu groß für UDP: noch einmal über TCP
        with socket.create_connection((server, 53), timeout=timeout) as s:
            s.sendall(struct.pack("!H", len(q)) + q)
            n = struct.unpack("!H", _recv_exact(s, 2))[0]
            res = dns_parse(_recv_exact(s, n), qid)
        res["tcp"] = True
    return res


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Verbindung vorzeitig beendet")
        buf += chunk
    return buf


def tool_dns(a: dict, report: Report, ask=dns_ask, resolvers=system_resolvers) -> Result:
    servers = [a["server"]] if a.get("server") else resolvers()[:3]
    if not servers:
        return False, {}, "Kein DNS-Server gefunden – bitte einen DNS-Server angeben."
    rtype = a["type"]
    summary = [["Name", a["name"], ""], ["Typ", rtype, ""]]
    rows, first = [], None
    for i, server in enumerate(servers):
        report(progress=i / len(servers), step=f"Frage {server} …")
        t0 = time.monotonic()
        try:
            res = ask(server, a["name"], QTYPES[rtype])
        except (OSError, ValueError) as exc:
            msg = "keine Antwort (Zeitüberschreitung)" if isinstance(exc, socket.timeout) else str(exc)
            summary.append([f"Server {server}", msg, "bad"])
            report(line=f"{server}: {msg}")
            continue
        ms = (time.monotonic() - t0) * 1000
        answers = [x for x in res["answers"] if x["section"] == "answer"]
        cls = "good" if res["rcode"] == "NOERROR" and answers else "warn" if res["rcode"] == "NOERROR" else "bad"
        summary.append([f"Server {server}", f"{res['rcode']} · {len(answers)} Einträge · {fmt_ms(ms)} ms"
                        f"{' · autoritativ' if res['authoritative'] else ''}{' · über TCP' if res.get('tcp') else ''}", cls])
        report(line=f"{server}: {res['rcode']}, {len(answers)} Einträge in {fmt_ms(ms)} ms")
        if first is None:
            first = res
            rows = [[x["name"], x["type"], str(x["ttl"]), x["data"]] for x in answers]
            for x in answers:
                report(line=f"  {x['name']} {x['ttl']} {x['type']} {x['data']}")
    if first is None:
        return False, {"summary": summary}, "Kein DNS-Server hat geantwortet."
    n = len(rows)
    verdict = "ok" if first["rcode"] == "NOERROR" and n else "warn" if first["rcode"] == "NOERROR" else "bad"
    headline = (f"{n} {'Eintrag' if n == 1 else 'Einträge'}" if n else
                "Name existiert nicht (NXDOMAIN)" if first["rcode"] == "NXDOMAIN" else
                f"Keine {rtype}-Einträge" if first["rcode"] == "NOERROR" else f"Fehler: {first['rcode']}")
    out = {"headline": headline, "verdict": verdict, "summary": summary}
    if rows:
        out["table"] = {"title": "Einträge", "head": ["Name", "Typ", "TTL", "Wert"], "rows": rows}
    return True, out, None


# -- Port ----------------------------------------------------------------------------------
PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
              139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
              587: "Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1433: "MS SQL",
              1723: "PPTP", 3306: "MySQL", 3389: "RDP", 4433: "HTTPS alt", 4443: "HTTPS alt", 4444: "Sophos Admin",
              5060: "SIP", 5061: "SIP-TLS", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP alt", 8291: "MikroTik Winbox",
              8443: "HTTPS alt", 10443: "FortiGate SSL-VPN"}


def check_port(ip: str, port: int, timeout: float) -> tuple[str, float | None, str]:
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "offen", (time.monotonic() - t0) * 1000, ""
    except ConnectionRefusedError:
        return "geschlossen", (time.monotonic() - t0) * 1000, "abgewiesen (RST)"
    except socket.timeout:
        return "gefiltert", None, "keine Antwort – Firewall verwirft"
    except OSError as exc:
        return "Fehler", None, str(exc)[:120]


def tool_port(a: dict, report: Report, check=check_port) -> Result:
    try:
        ip = socket.getaddrinfo(a["host"], None, socket.AF_INET)[0][4][0]
    except (OSError, IndexError) as exc:
        return False, {}, f"DNS-Auflösung fehlgeschlagen: {exc}"
    rows, classes, n_open = [], [], 0
    for i, port in enumerate(a["ports"], 1):
        state, ms, detail = check(ip, port, a["timeout"])
        n_open += state == "offen"
        rows.append([str(port), PORT_NAMES.get(port, ""), state, fmt_ms(ms) + " ms" if ms is not None else "–", detail])
        classes.append("" if state == "offen" else "warn" if state == "geschlossen" else "bad")
        report(progress=i / len(a["ports"]), step=f"Port {port}: {state}", line=f"{port:>5}/tcp  {state}  {detail}")
    total = len(a["ports"])
    return True, {"headline": f"{n_open} von {total} {'Port' if total == 1 else 'Ports'} offen",
                  "verdict": "ok" if n_open == total else "warn" if n_open else "bad",
                  "summary": [["Ziel", _target_text(a["host"], ip), ""]],
                  "table": {"title": "Ports", "head": ["Port", "Dienst", "Zustand", "Antwort", "Details"],
                            "rows": rows, "classes": classes}}, None


# -- HTTP(S) und Zertifikat -----------------------------------------------------------------
def _cert_info(der: bytes) -> dict:
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(), "san": san,
            "not_after": not_after, "not_before": not_before,
            "days": int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)}


def _tls_connect(host: str, port: int, sni: str | None, timeout: float, verify: bool):
    """TLS-Verbindung; gibt (ssl-Socket, Prüffehler oder None, Zeiten) zurück."""
    t0 = time.monotonic()
    ip = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0]
    t_dns = time.monotonic()
    raw = socket.create_connection((ip, port), timeout=timeout)
    t_conn = time.monotonic()
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        s = ctx.wrap_socket(raw, server_hostname=sni or host)
    except BaseException:
        raw.close()
        raise
    return s, ip, {"dns": (t_dns - t0) * 1000, "connect": (t_conn - t_dns) * 1000,
                   "tls": (time.monotonic() - t_conn) * 1000}


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _verify_error(host: str, port: int, sni: str | None, timeout: float) -> str | None:
    try:
        s, _ip, _t = _tls_connect(host, port, sni, timeout, True)
        s.close()
        return None
    except ssl.SSLCertVerificationError as exc:
        return exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        return str(exc)


def _cert_rows(info: dict, verify_err: str | None) -> list[list[str]]:
    days = info["days"]
    return [["Zertifikat für", ", ".join(info["san"][:8]) or info["subject"], ""],
            ["Aussteller", info["issuer"], ""],
            ["Gültig bis", f"{info['not_after']:%d.%m.%Y} ({'ABGELAUFEN' if days < 0 else f'noch {days} Tage'})",
             "bad" if days < 0 else "warn" if days < 21 else "good"],
            ["Vertrauen", "in Ordnung" if not verify_err else f"FEHLER: {verify_err}", "good" if not verify_err else "bad"]]


def tool_tls(a: dict, report: Report) -> Result:
    host, port, sni = a["host"], a["port"], a.get("sni") or None
    report(progress=0.2, step=f"Verbinde mit {host}:{port} …")
    try:
        s, ip, times = _tls_connect(host, port, sni, 8, False)
    except (OSError, ssl.SSLError) as exc:
        return False, {}, f"Keine TLS-Verbindung: {exc}"
    with s:
        der, proto, cipher = s.getpeercert(True), s.version(), (s.cipher() or ("",))[0]
    report(progress=0.6, step="Prüfe Vertrauen …")
    verify_err = _verify_error(host, port, sni, 8)
    info = _cert_info(der)
    rows = [["Ziel", f"{host}:{port}" + (f" ({ip})" if ip != host else ""), ""]] + _cert_rows(info, verify_err) + [
        ["Protokoll", f"{proto} · {cipher}", "warn" if proto in ("TLSv1", "TLSv1.1") else ""],
        ["Handshake", f"{fmt_ms(times['tls'])} ms", ""]]
    bad = verify_err or info["days"] < 0
    return True, {"headline": "Zertifikat in Ordnung" if not bad else "Zertifikat mit Problem",
                  "verdict": "bad" if bad else "warn" if info["days"] < 21 else "ok", "summary": rows}, None


HTTP_TEXT = {200: "OK", 204: "Kein Inhalt", 301: "Dauerhaft verschoben", 302: "Vorübergehend verschoben",
             303: "Siehe andere Adresse", 304: "Nicht geändert", 307: "Vorübergehend umgeleitet", 308: "Dauerhaft umgeleitet",
             400: "Ungültige Anfrage", 401: "Anmeldung erforderlich", 403: "Zugriff verweigert", 404: "Nicht gefunden",
             405: "Methode nicht erlaubt (GET statt HEAD versuchen)", 429: "Zu viele Anfragen", 500: "Interner Serverfehler",
             502: "Fehlerhaftes Gateway", 503: "Dienst nicht verfügbar", 504: "Gateway-Zeitüberschreitung"}


def tool_http(a: dict, report: Report) -> Result:
    u = urlparse(a["url"])
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    host_header = u.hostname + (f":{u.port}" if u.port else "")
    report(progress=0.1, step=f"Verbinde mit {u.hostname}:{port} …")
    t0 = time.monotonic()
    try:
        if https:
            s, ip, times = _tls_connect(u.hostname, port, None, 10, not a.get("insecure"))
        else:
            ip = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)[0][4][0]
            t_dns = time.monotonic()
            s = socket.create_connection((ip, port), timeout=10)
            times = {"dns": (t_dns - t0) * 1000, "connect": (time.monotonic() - t_dns) * 1000, "tls": None}
    except ssl.SSLCertVerificationError as exc:
        return False, {"summary": [["Adresse", a["url"], ""]]}, \
            f"Zertifikat abgelehnt: {exc.verify_message or exc} – zum Testen „Zertifikatsfehler ignorieren“ wählen."
    except (OSError, ssl.SSLError) as exc:
        return False, {"summary": [["Adresse", a["url"], ""]]}, f"Keine Verbindung: {exc}"
    report(progress=0.5, step="Warte auf Antwort …")
    der = None
    with s:
        if https:
            der = s.getpeercert(True)
        t_send = time.monotonic()
        s.sendall(f"{a['method']} {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Wachtl-Werkzeug\r\n"
                  f"Accept: */*\r\nConnection: close\r\n\r\n".encode())
        buf, ttfb = b"", None
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = s.recv(4096)
            if not chunk:
                break
            ttfb = ttfb if ttfb is not None else (time.monotonic() - t_send) * 1000
            buf += chunk
        body = len(buf.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in buf else 0
        if a["method"] == "GET":
            while body < 5_000_000:
                chunk = s.recv(65536)
                if not chunk:
                    break
                body += len(chunk)
    total = (time.monotonic() - t0) * 1000
    head = buf.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace").split("\r\n")
    m = re.match(r"HTTP/([\d.]+)\s+(\d{3})", head[0] if head else "")
    if not m:
        return False, {"summary": [["Adresse", a["url"], ""]]}, "Keine gültige HTTP-Antwort erhalten."
    code = int(m.group(2))
    headers = {}
    for line in head[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.setdefault(k.strip().lower(), v.strip())
    for line in head:
        report(line=line)
    cls = "good" if code < 300 else "" if code < 400 else "warn" if code < 500 else "bad"
    rows = [["Adresse", a["url"], ""], ["Status", f"HTTP {code} {HTTP_TEXT.get(code, '')} (HTTP/{m.group(1)})", cls],
            ["Server-IP", ip, ""],
            ["Zeiten", f"DNS {fmt_ms(times['dns'])} ms · Verbindung {fmt_ms(times['connect'])} ms"
                       + (f" · TLS {fmt_ms(times['tls'])} ms" if times.get("tls") is not None else "")
                       + f" · erstes Byte {fmt_ms(ttfb)} ms · gesamt {fmt_ms(total)} ms", ""]]
    if headers.get("location"):
        rows.append(["Weiterleitung", headers["location"], "warn"])
    if headers.get("server"):
        rows.append(["Server", headers["server"], ""])
    if headers.get("content-type"):
        rows.append(["Inhalt", headers["content-type"] + (f" · {body} Byte" if a["method"] == "GET" else ""), ""])
    if der:
        try:
            # ohne „ignorieren“ ist das Zertifikat schon beim Verbinden geprüft worden
            rows += _cert_rows(_cert_info(der), _verify_error(u.hostname, port, None, 8) if a.get("insecure") else None)
        except Exception:  # noqa: BLE001 – Zertifikat nur Zusatz
            pass
    return True, {"headline": f"HTTP {code} {HTTP_TEXT.get(code, '')}".strip(),
                  "verdict": "ok" if code < 400 else "warn" if code < 500 else "bad", "summary": rows}, None


TOOLS: dict[str, Callable[[dict, Report], Result]] = {
    "ping": tool_ping, "mtu": tool_mtu, "trace": tool_trace, "dns": tool_dns, "port": tool_port,
    "http": tool_http, "tls": tool_tls,
}


def run(job: dict, send: Callable[[dict], None], min_interval: float = 0.5) -> None:
    """Auftrag ausführen; ``send`` überträgt Fortschritt bzw. Ergebnis an den Server (Probe-API)."""
    state = {"lines": [], "last": 0.0, "progress": None, "step": None}

    def report(progress: float | None = None, step: str | None = None, line: str | None = None) -> None:
        if progress is not None:
            state["progress"] = progress
        if step is not None:
            state["step"] = step
        if line is not None:
            state["lines"].append(line)
        now = time.monotonic()
        if now - state["last"] >= min_interval:
            state["last"] = now
            payload = {"progress": state["progress"], "step": state["step"], "lines": state["lines"]}
            state["lines"] = []
            send(payload)

    fn = TOOLS.get(job.get("tool"))
    try:
        if fn is None:
            raise ValueError(f"Werkzeug {job.get('tool')} wird von dieser Probe nicht unterstützt.")
        ok, result, error = fn(job["args"], report)
    except Exception as exc:  # noqa: BLE001 – jeder Fehler wird als Ergebnis gemeldet
        ok, result, error = False, {}, f"{exc.__class__.__name__}: {exc}"
    send({"done": True, "ok": ok, "result": result, "error": error, "lines": state["lines"]})


def loop(api_getter: Callable, stop, poll_s: float = 2.0) -> None:
    """Server-Probe: alle ``poll_s`` Sekunden nach einem Auftrag fragen (lokal, kostet fast nichts) und ihn ausführen."""
    import logging

    log = logging.getLogger("wachtl.serverprobe")
    while not stop.is_set():
        api = api_getter()
        job = None
        if api is not None:
            try:
                job = api.json("GET", "tools/next", ok=(200,)).get("job")
            except Exception as exc:  # noqa: BLE001 – Server kurz nicht erreichbar
                log.debug("Werkzeug-Aufträge nicht abrufbar: %s", exc)
        if job:
            log.info("Werkzeug %s für %s gestartet (Auftrag %s)", job.get("tool"), job.get("args", {}).get("host")
                     or job.get("args", {}).get("name") or job.get("args", {}).get("url"), job.get("id"))

            def send(payload: dict, job_id=job["id"]) -> None:
                try:
                    api.json("POST", f"tools/{job_id}", payload, ok=(200,))
                except Exception as exc:  # noqa: BLE001 – Fortschritt ist nur Anzeige; das Ergebnis zählt
                    log.debug("Werkzeug-Fortschritt nicht übertragen: %s", exc)

            run(job, send)
            continue
        stop.wait(poll_s)
