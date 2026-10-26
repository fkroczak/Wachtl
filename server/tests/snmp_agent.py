"""Falscher SNMP-Agent für Tests: UDP auf 127.0.0.1 (freier Port), eigener Thread.

v1/v2c/v3 (USM mit allen Auth/Priv-Verfahren aus ``wachtl.snmp``), GET/GETNEXT/GETBULK, Reports für
Discovery, unbekannte Benutzer, falsche Digests, Entschlüsselungsfehler und Zeitfenster. Falsche Community
→ keine Antwort. Für Sonderfälle ``answer`` in einer Unterklasse überschreiben.
"""
from __future__ import annotations

import bisect
import os
import socket
import threading
import time

from wachtl import snmp as s


class Counter32(int):
    TAG = 0x41


class Gauge32(int):
    TAG = 0x42


class TimeTicks(int):
    TAG = 0x43


class Counter64(int):
    TAG = 0x46


class IpAddress(str):
    pass


class Oid(str):
    pass


class Opaque(bytes):
    pass


def encode_value(value) -> bytes:
    """Python-Wert aus der MIB → BER."""
    if value is None:
        return s.NULL
    if hasattr(value, "TAG"):
        return s._uint(int(value), value.TAG)
    if isinstance(value, int):
        return s._int(value)
    if isinstance(value, IpAddress):
        return s._tlv(0x40, socket.inet_aton(value))
    if isinstance(value, Oid):
        return s._oid(s.parse_oid(value))
    if isinstance(value, Opaque):
        return s._tlv(0x44, bytes(value))
    if isinstance(value, str):
        value = value.encode()
    return s._tlv(0x04, bytes(value))


JUNK = (b"", b"\x00", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x30\x80\x02\x01\x00\x00\x00",
        b"\x30\x03\x02\x01", b"\x30\x02\x30\x00", b"\x30\x05\x02\x01\x01\x04\x00",
        b"\x30\x0b\x02\x01\x03\x30\x00\x04\x00\x30\x02\x06\x00", b"\x9f\x81\x01\x00",
        b"\x30\x0e\x02\x01\x01\x04\x06public\xa2\x01\x00")


class FakeAgent:
    def __init__(self, mib: dict[str, object], community="public", v1=True, v2c=True,
                 users: dict[str, tuple[str, str, str, str]] | None = None,
                 engine_id: bytes = b"\x80\x00\x1f\x88\x80wachtltest", boots: int = 1,
                 drop: bool = False, junk: bool = False, bulk_limit: int | None = None):
        self.mib = {s.parse_oid(k): v for k, v in mib.items()}
        self.keys = sorted(self.mib)
        self.community, self.v1, self.v2c = community.encode(), v1, v2c
        self.users = users
        self.engine_id, self.boots = engine_id, boots
        self.drop, self.junk, self.bulk_limit = drop, junk, bulk_limit
        self.requests = 0
        self.port = 0
        self.errors: list[BaseException] = []        # Ausnahmen beim Verarbeiten (Fehlersuche)
        self.time_offset = 0
        self._start = time.monotonic()
        self._salt = int.from_bytes(os.urandom(8), "big")
        self._stats = [0] * 7
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    # -- Lebenszyklus -----------------------------------------------------------------------------
    def start(self) -> "FakeAgent":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(0.05)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, name="fake-snmp-agent", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(2)
        if self._sock:
            self._sock.close()

    def __enter__(self) -> "FakeAgent":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def engine_time(self) -> int:
        return int(time.monotonic() - self._start) + self.time_offset

    def reboot(self) -> None:
        """Neustart simulieren: engineBoots + 1, engineTime von vorn."""
        self.boots += 1
        self._start, self.time_offset = time.monotonic(), 0

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            self.requests += 1
            try:
                reply = self._handle(data)
            except Exception as e:                     # Agent soll nie sterben
                self.errors.append(e)
                reply = None
            try:
                if self.junk:
                    for j in JUNK + (os.urandom(60), (reply or b"")[:-3]):
                        self._sock.sendto(j, addr)
                if reply and not self.drop:
                    self._sock.sendto(reply, addr)
            except OSError:
                pass

    # -- Protokoll --------------------------------------------------------------------------------
    def _handle(self, data: bytes) -> bytes | None:
        items = s._top(data)
        version = s._get_int(data, items[0])
        if version == 3:
            return self._handle_v3(data) if self.users is not None else None
        if (version, True) not in ((0, self.v1), (1, self.v2c)) or len(items) != 3:
            return None
        if s._get_bytes(data, items[1]) != self.community:
            return None                                # falsche Community → Schweigen
        pdu = items[2]
        if pdu[0] not in (s.GET, s.GETNEXT, s.GETBULK) or (pdu[0] == s.GETBULK and version == 0):
            return None
        reqid, a, b, vbs = s._parse_pdu(data, pdu)
        status, index, out = self._answer_sized(pdu[0], a, b, vbs, version == 0)
        return s._tlv(0x30, s._int(version) + s._tlv(4, self.community) + s._pdu(s.RESPONSE, reqid, status, index, out))

    def _answer_sized(self, tag, a, b, vbs, v1):
        status, index, out = self.answer(tag, a, b, vbs, v1)
        if sum(len(v) + 30 for _, v in out) > s.MAX_MSG - 200:
            return 1, 0, []
        return status, index, out

    def _next(self, oid, v1):
        i = bisect.bisect_right(self.keys, oid)
        while i < len(self.keys):
            key = self.keys[i]
            if not (v1 and isinstance(self.mib[key], Counter64)):
                return key, encode_value(self.mib[key])
            i += 1
        return None

    def answer(self, tag, a, b, vbs, v1):
        """Anfrage beantworten → (error-status, error-index, [(OID, kodierter Wert)])."""
        echo = [(oid, s.NULL) for oid, _, _ in vbs]
        out = []
        if tag == s.GET:
            for i, (oid, _, _) in enumerate(vbs, 1):
                value = self.mib.get(oid, KeyError)
                if value is KeyError or (v1 and isinstance(value, Counter64)):
                    if v1:
                        return 2, i, echo
                    out.append((oid, b"\x81\x00" if oid[:-1] in {k[:-1] for k in self.keys} else b"\x80\x00"))
                else:
                    out.append((oid, encode_value(value)))
            return 0, 0, out
        if tag == s.GETNEXT:
            for i, (oid, _, _) in enumerate(vbs, 1):
                nxt = self._next(oid, v1)
                if nxt is None and v1:
                    return 2, i, echo
                out.append(nxt or (oid, b"\x82\x00"))
            return 0, 0, out
        nonrep, maxrep = max(0, a), max(0, b)               # GETBULK
        if self.bulk_limit is not None and maxrep > self.bulk_limit:
            return 1, 0, []
        for oid, _, _ in vbs[:nonrep]:
            out.append(self._next(oid, False) or (oid, b"\x82\x00"))
        cur = [oid for oid, _, _ in vbs[nonrep:]]
        for _ in range(maxrep):
            if not cur:
                break
            ended = True
            for j, oid in enumerate(cur):
                nxt = self._next(oid, False)
                if nxt:
                    ended = False
                    cur[j] = nxt[0]
                out.append(nxt or (oid, b"\x82\x00"))
            if ended:
                break
        return 0, 0, out

    def _handle_v3(self, data: bytes) -> bytes | None:
        m = s._parse_v3(data)
        reportable = bool(m.flags & 0x04)
        now = self.engine_time()

        def report(kind, auth=None):
            if not reportable:
                return None
            self._stats[kind] += 1
            scoped = s._tlv(0x30, s._tlv(4, self.engine_id) + s._tlv(4, b"") + s._pdu(
                s.REPORT, 0, 0, 0, [(s.USM_STATS + (kind, 0), s._uint(self._stats[kind], 0x41))]))
            proto, key = auth or ("none", None)
            return s._build_v3(m.msg_id, 0x01 if key else 0, self.engine_id, self.boots, now,
                               m.user, proto, key, b"", scoped)

        if m.engine_id != self.engine_id:
            return report(4)                           # usmStatsUnknownEngineIDs (Discovery)
        user = self.users.get(m.user.decode("utf-8", "replace"))
        if user is None:
            return report(3)
        auth_p, auth_k, priv_p, priv_k = user
        want_auth, want_priv = auth_p != "none", priv_p != "none"
        if bool(m.flags & 0x01) != want_auth or bool(m.flags & 0x02) != want_priv:
            return report(1)
        akey = pkey = None
        if want_auth:
            akey = s._auth_key(auth_p, auth_k.encode(), self.engine_id)
            if not s._verify(auth_p, akey, data, m):
                return report(5)
            if m.boots != self.boots or abs(m.time - now) > 150:
                return report(2, (auth_p, akey))       # notInTimeWindow, authentisiert
        if want_priv:
            pkey = s._priv_key(auth_p, priv_p, priv_k.encode(), self.engine_id)
            try:
                body = s._decrypt(priv_p, pkey, m.boots, m.time, m.priv, s._get_bytes(data, m.data))
                item = s._tlv_at(body, 0, len(body))
                _, ctx_name, pdu = s._seq(body, item, 3)
                parsed = s._parse_pdu(body, pdu)
            except ValueError:
                return report(6)
        else:
            body = data
            _, ctx_name, pdu = s._seq(body, m.data, 3)
            parsed = s._parse_pdu(body, pdu)
        if pdu[0] not in (s.GET, s.GETNEXT, s.GETBULK):
            return None
        reqid, a, b, vbs = parsed
        status, index, out = self._answer_sized(pdu[0], a, b, vbs, False)
        scoped = s._tlv(0x30, s._tlv(4, self.engine_id) + s._tlv(4, s._get_bytes(body, ctx_name))
                        + s._pdu(s.RESPONSE, reqid, status, index, out))
        priv_params = b""
        if want_priv:
            self._salt += 1
            cipher, priv_params = s._encrypt(priv_p, pkey, self.boots, now, self._salt, scoped)
            scoped = s._tlv(4, cipher)
        return s._build_v3(m.msg_id, m.flags & 0x03, self.engine_id, self.boots, now, m.user,
                           auth_p, akey, priv_params, scoped)
