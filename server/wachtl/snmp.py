"""SNMP-Client (v1, v2c, v3) ohne Fremdpakete – Standardbibliothek plus ``cryptography`` für Priv.

``Session.get`` und ``Session.walk`` (GETNEXT bzw. GETBULK); Werte als int, bytes oder str.
SNMPv3 mit USM nach RFC 3414: MD5/SHA-1, SHA-2 nach RFC 7860, DES (RFC 3414), AES-128 (RFC 3826),
AES-192/256 mit Schlüsselverlängerung nach Blumenthal (net-snmp „AES192/AES256“) oder Reeder/Cisco
(net-snmp „AES192C/AES256C“).

Eingehende Pakete mit falscher Request-ID/msgID, kaputtem BER oder falschem HMAC gelten als fremd und
werden verworfen – sie führen höchstens zur Zeitüberschreitung. Eine Session gehört einem Thread;
mehrere Sessions dürfen parallel laufen.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import secrets
import socket
import struct
import time
from dataclasses import dataclass
from functools import lru_cache
from types import SimpleNamespace

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
except ImportError:                                     # pragma: no cover
    Cipher = None
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:                                     # pragma: no cover – cryptography < 47
    CFB = getattr(modes, "CFB", None) if Cipher else None
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:                                     # pragma: no cover – ältere cryptography
    try:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    except ImportError:
        TripleDES = None

AUTH_PROTOCOLS = ("none", "md5", "sha", "sha224", "sha256", "sha384", "sha512")
PRIV_PROTOCOLS = ("none", "des", "aes", "aes192", "aes256", "aes192c", "aes256c")

_HASH = {"md5": ("md5", 12), "sha": ("sha1", 12), "sha224": ("sha224", 16),       # Name, HMAC-Länge
         "sha256": ("sha256", 24), "sha384": ("sha384", 32), "sha512": ("sha512", 48)}
_PRIV_LEN = {"des": 16, "aes": 16, "aes192": 24, "aes256": 32, "aes192c": 24, "aes256c": 32}

GET, GETNEXT, RESPONSE, GETBULK, REPORT = 0xA0, 0xA1, 0xA2, 0xA5, 0xA8
NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB = 0x80, 0x81, 0x82
NULL = b"\x05\x00"
MAX_MSG = 65507
USM_STATS = (1, 3, 6, 1, 6, 3, 15, 1, 1)                # usmStats…: .1 unsupportedSecLevels … .6 decryptionErrors
CHUNK = 20
_ERRORS = {1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr", 6: "noAccess",
           13: "resourceUnavailable", 16: "authorizationError"}
_DES_MISSING = "DES wird von dieser Installation nicht unterstützt – bitte AES verwenden"


class SnmpError(Exception):
    """SNMP-Fehler; der Text ist deutsch und wird so in der Oberfläche gezeigt."""


class SnmpTimeout(SnmpError):
    """Keine Antwort (bei v1/v2c auch: falsche Community – Agenten schweigen dann)."""


class SnmpAuthError(SnmpError):
    """SNMPv3: Benutzer unbekannt, Passwort/Verfahren falsch, Sicherheitsstufe nicht unterstützt."""


class _Bad(ValueError):
    """Kaputtes oder fremdes Paket (intern, wird verworfen)."""


@dataclass(frozen=True)
class Credentials:
    version: str = "2c"           # "1" | "2c" | "3"
    community: str = "public"
    user: str = ""
    auth_proto: str = "none"
    auth_key: str = ""
    priv_proto: str = "none"
    priv_key: str = ""
    context: str = ""


# -- OIDs und BER ---------------------------------------------------------------------------------
def parse_oid(text: str) -> tuple[int, ...]:
    """``"1.3.6.1.2.1.1.5.0"`` (auch mit führendem Punkt) → Tupel."""
    parts = str(text).strip().removeprefix(".").split(".")
    if len(parts) < 2 or not all(p.isascii() and p.isdigit() for p in parts):
        raise SnmpError(f"Ungültige OID: {text}")
    oid = tuple(int(p) for p in parts)
    if oid[0] > 2 or (oid[0] < 2 and oid[1] >= 40):
        raise SnmpError(f"Ungültige OID: {text}")
    return oid


def format_oid(oid: tuple[int, ...]) -> str:
    return ".".join(map(str, oid))


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _int(value: int, tag: int = 0x02) -> bytes:
    """INTEGER mit Vorzeichen (Zweierkomplement, minimal)."""
    return _tlv(tag, value.to_bytes((value + (value < 0)).bit_length() // 8 + 1, "big", signed=True))


def _uint(value: int, tag: int) -> bytes:
    """Counter32/Gauge32/TimeTicks/Counter64 – ohne Vorzeichen (führende Null bei gesetztem Bit 7)."""
    return _tlv(tag, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def _oid(oid: tuple[int, ...]) -> bytes:
    out = bytearray()
    for sub in (oid[0] * 40 + oid[1], *oid[2:]):
        chunk = [sub & 0x7F]
        while sub > 0x7F:
            sub >>= 7
            chunk.append(0x80 | (sub & 0x7F))
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


def _tlv_at(buf: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """TLV an ``pos`` → (Tag, Inhaltsanfang, Inhaltsende)."""
    if pos + 2 > end:
        raise _Bad("kurz")
    tag, n = buf[pos], buf[pos + 1]
    if tag & 0x1F == 0x1F:
        raise _Bad("Tag")
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        if not 0 < k <= 4 or pos + k > end:
            raise _Bad("Länge")
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    if pos + n > end:
        raise _Bad("Länge")
    return tag, pos, pos + n


def _children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    items, pos = [], start
    while pos < end:
        item = _tlv_at(buf, pos, end)
        items.append(item)
        pos = item[2]
    return items


def _seq(buf: bytes, item, count: int | None = None, tag: int = 0x30) -> list[tuple[int, int, int]]:
    if item[0] != tag:
        raise _Bad("SEQUENCE erwartet")
    items = _children(buf, item[1], item[2])
    if count is not None and len(items) != count:
        raise _Bad("Elementanzahl")
    return items


def _get_int(buf: bytes, item, tag: int = 0x02) -> int:
    if item[0] != tag or item[1] == item[2]:
        raise _Bad("INTEGER erwartet")
    return int.from_bytes(buf[item[1]:item[2]], "big", signed=True)


def _get_bytes(buf: bytes, item, tag: int = 0x04) -> bytes:
    if item[0] != tag:
        raise _Bad("OCTET STRING erwartet")
    return bytes(buf[item[1]:item[2]])


def _dec_oid(raw: bytes) -> tuple[int, ...]:
    if not raw or raw[-1] & 0x80:
        raise _Bad("OID")
    subs, cur = [], 0
    for b in raw:
        cur = (cur << 7) | (b & 0x7F)
        if not b & 0x80:
            subs.append(cur)
            cur = 0
    first = subs[0]
    head = (first // 40, first % 40) if first < 80 else (2, first - 80)
    return head + tuple(subs[1:])


def _dec_value(tag: int, raw: bytes):
    if tag == 0x02:
        return int.from_bytes(raw, "big", signed=True) if raw else 0
    if tag in (0x41, 0x42, 0x43, 0x46, 0x47):             # Counter32, Gauge32, TimeTicks, Counter64, UInteger32
        return int.from_bytes(raw, "big")
    if tag == 0x06:
        return format_oid(_dec_oid(raw))
    if tag == 0x40:
        return ".".join(map(str, raw))
    if tag in (0x05, NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB):
        return None
    return bytes(raw)                                     # OCTET STRING, Opaque, Unbekanntes


def _pdu(tag: int, reqid: int, a: int, b: int, varbinds) -> bytes:
    """PDU; ``varbinds`` = [(OID-Tupel, fertig kodierter Wert)]."""
    vbl = b"".join(_tlv(0x30, _oid(oid) + val) for oid, val in varbinds)
    return _tlv(tag, _int(reqid) + _int(a) + _int(b) + _tlv(0x30, vbl))


def _parse_pdu(buf: bytes, item):
    """PDU → (Request-ID, error-status, error-index, [(OID-Tupel, Tag, Wert)])."""
    reqid, a, b, vbl = _seq(buf, item, 4, tag=item[0])
    vbs = []
    for vb in _seq(buf, vbl):
        oid_item, val = _seq(buf, vb, 2)
        oid = _dec_oid(_get_bytes(buf, oid_item, 0x06))
        vbs.append((oid, val[0], _dec_value(val[0], buf[val[1]:val[2]])))
    return _get_int(buf, reqid), _get_int(buf, a), _get_int(buf, b), vbs


def _top(buf: bytes) -> list[tuple[int, int, int]]:
    return _seq(buf, _tlv_at(buf, 0, len(buf)))


# -- SNMPv3: Nachricht, Schlüssel, Verschlüsselung ------------------------------------------------
def _build_v3(msg_id, flags, engine_id, boots, etime, user, auth_proto, auth_key, priv_params, data) -> bytes:
    """v3-Nachricht; mit ``auth_key`` wird der HMAC über die ganze Nachricht eingesetzt."""
    tlen = _HASH[auth_proto][1] if auth_key else 0
    sec = _tlv(0x30, _tlv(4, engine_id) + _int(boots) + _int(etime) + _tlv(4, user)
               + _tlv(4, bytes(tlen)) + _tlv(4, priv_params))
    header = _tlv(0x30, _int(msg_id) + _int(MAX_MSG) + _tlv(4, bytes([flags])) + _int(3))
    msg = bytearray(_tlv(0x30, _int(3) + header + _tlv(4, sec) + data))
    if auth_key:                                          # hinter den Auth-Parametern stehen nur noch Priv-Parameter und Daten
        off = len(msg) - len(data) - len(_tlv(4, priv_params)) - tlen
        msg[off:off + tlen] = _mac(auth_proto, auth_key, bytes(msg))
    return bytes(msg)


def _parse_v3(buf: bytes) -> SimpleNamespace:
    items = _top(buf)
    if len(items) != 4:
        raise _Bad("keine v3-Nachricht")
    version, header, secp, data = items
    if _get_int(buf, version) != 3:
        raise _Bad("keine v3-Nachricht")
    msg_id, max_size, flags, model = _seq(buf, header, 4)
    flag_bytes = _get_bytes(buf, flags)
    if len(flag_bytes) != 1 or _get_int(buf, model) != 3:
        raise _Bad("Kopf")
    _get_bytes(buf, secp)
    eid, boots, etime, user, auth, priv = _seq(buf, _tlv_at(buf, secp[1], secp[2]), 6)
    if data[0] not in (0x30, 0x04):
        raise _Bad("Daten")
    return SimpleNamespace(msg_id=_get_int(buf, msg_id), max_size=_get_int(buf, max_size),
                           flags=flag_bytes[0], engine_id=_get_bytes(buf, eid), boots=_get_int(buf, boots),
                           time=_get_int(buf, etime), user=_get_bytes(buf, user), auth=_get_bytes(buf, auth),
                           auth_pos=(auth[1], auth[2]), priv=_get_bytes(buf, priv), data=data)


def _mac(auth_proto: str, key: bytes, msg: bytes) -> bytes:
    name, tlen = _HASH[auth_proto]
    return hmac.new(key, msg, name).digest()[:tlen]


def _verify(auth_proto: str, key: bytes, buf: bytes, m: SimpleNamespace) -> bool:
    s, e = m.auth_pos
    if e - s != _HASH[auth_proto][1]:
        return False
    zeroed = buf[:s] + bytes(e - s) + buf[e:]
    return hmac.compare_digest(_mac(auth_proto, key, zeroed), buf[s:e])


@lru_cache(maxsize=64)
def _password_to_key(auth_proto: str, password: bytes) -> bytes:
    """RFC 3414 A.2: Passwort auf 1 MiB wiederholen und hashen (Ku)."""
    if not password:
        raise SnmpError("Leeres SNMPv3-Passwort")
    n = 1048576
    return hashlib.new(_HASH[auth_proto][0], (password * (n // len(password) + 1))[:n]).digest()


def _localize(auth_proto: str, ku: bytes, engine_id: bytes) -> bytes:
    return hashlib.new(_HASH[auth_proto][0], ku + engine_id + ku).digest()


@lru_cache(maxsize=256)
def _auth_key(auth_proto: str, password: bytes, engine_id: bytes) -> bytes:
    return _localize(auth_proto, _password_to_key(auth_proto, password), engine_id)


@lru_cache(maxsize=256)
def _priv_key(auth_proto: str, priv_proto: str, password: bytes, engine_id: bytes) -> bytes:
    """Lokalisierter Priv-Schlüssel, bei Bedarf verlängert (Blumenthal bzw. Reeder bei *c)."""
    key, need = _auth_key(auth_proto, password, engine_id), _PRIV_LEN[priv_proto]
    while len(key) < need:
        if priv_proto.endswith("c"):                      # Reeder: bisherigen Schlüssel als Passwort nehmen
            key += _localize(auth_proto, _password_to_key(auth_proto, key), engine_id)
        else:                                             # Blumenthal: Kul || H(Kul) || H(Kul||H(Kul)) …
            key += hashlib.new(_HASH[auth_proto][0], key).digest()
    return key[:need]


def _cipher(priv_proto: str, key: bytes, iv: bytes, encrypt: bool):
    if Cipher is None:                                    # pragma: no cover
        raise SnmpError("Verschlüsselung (Priv) braucht das Python-Paket „cryptography“")
    try:
        if priv_proto == "des":
            if TripleDES is None:
                raise ValueError
            c = Cipher(TripleDES(key[:8] * 3), modes.CBC(iv))   # K|K|K = einfaches DES
        else:
            c = Cipher(AES(key), CFB(iv))
        return c.encryptor() if encrypt else c.decryptor()
    except Exception:
        if priv_proto == "des":
            raise SnmpError(_DES_MISSING) from None
        raise


def _encrypt(priv_proto: str, key: bytes, boots: int, etime: int, salt: int, data: bytes) -> tuple[bytes, bytes]:
    """→ (Chiffrat, msgPrivacyParameters)."""
    if priv_proto == "des":                               # RFC 3414 8.1.1.1
        params = struct.pack(">II", boots & 0xFFFFFFFF, salt & 0xFFFFFFFF)
        iv = bytes(x ^ y for x, y in zip(params, key[8:16]))
        data += bytes(-len(data) % 8)
    else:                                                 # RFC 3826 3.1.2.1
        params = struct.pack(">Q", salt & 0xFFFFFFFFFFFFFFFF)
        iv = struct.pack(">II", boots, etime) + params
    enc = _cipher(priv_proto, key, iv, True)
    return enc.update(data) + enc.finalize(), params


def _decrypt(priv_proto: str, key: bytes, boots: int, etime: int, params: bytes, data: bytes) -> bytes:
    if len(params) != 8 or (priv_proto == "des" and len(data) % 8):
        raise _Bad("Priv-Parameter")
    if priv_proto == "des":
        iv = bytes(x ^ y for x, y in zip(params, key[8:16]))
    else:
        iv = struct.pack(">II", boots & 0xFFFFFFFF, etime & 0xFFFFFFFF) + params
    dec = _cipher(priv_proto, key, iv, False)
    return dec.update(data) + dec.finalize()


def _check(creds: Credentials) -> Credentials:
    """Zugangsdaten prüfen und vereinheitlichen."""
    version = str(creds.version).strip().lower().removeprefix("v")
    version = {"2": "2c"}.get(version, version)
    if version not in ("1", "2c", "3"):
        raise SnmpError(f"Unbekannte SNMP-Version: {creds.version}")
    auth, priv = str(creds.auth_proto or "none").lower(), str(creds.priv_proto or "none").lower()
    if version != "3":
        return dataclasses.replace(creds, version=version)
    if not creds.user:
        raise SnmpError("Für SNMPv3 ist ein Benutzername nötig")
    if auth not in AUTH_PROTOCOLS:
        raise SnmpError(f"Unbekanntes Auth-Verfahren: {creds.auth_proto}")
    if priv not in PRIV_PROTOCOLS:
        raise SnmpError(f"Unbekanntes Priv-Verfahren: {creds.priv_proto}")
    if priv != "none" and auth == "none":
        raise SnmpError("Verschlüsselung (Priv) setzt eine Anmeldung (Auth) voraus")
    if auth != "none" and len(creds.auth_key) < 8:
        raise SnmpError("Das Passwort für die Anmeldung (Auth) muss mindestens 8 Zeichen lang sein")
    if priv != "none" and len(creds.priv_key) < 8:
        raise SnmpError("Das Passwort für die Verschlüsselung (Priv) muss mindestens 8 Zeichen lang sein")
    return dataclasses.replace(creds, version=version, auth_proto=auth, priv_proto=priv)


# -- Session --------------------------------------------------------------------------------------
class Session:
    """SNMP-Sitzung zu einem Gerät (ein UDP-Socket). Nicht threadsicher – eine Session pro Thread."""

    def __init__(self, host: str, creds: Credentials, port: int = 161, timeout: float = 2.0, retries: int = 1):
        self.host, self.port = host, int(port)
        self.timeout, self.retries = float(timeout), max(0, int(retries))
        self.creds = _check(creds)
        self.engine_id: bytes | None = None
        self._boots, self._time0, self._mono0 = 0, 0, time.monotonic()
        self._salt = secrets.randbits(64)
        try:
            family, _, _, _, addr = socket.getaddrinfo(host, self.port, 0, socket.SOCK_DGRAM)[0]
        except (OSError, UnicodeError) as e:
            raise SnmpError(f"Adresse {host} nicht gefunden ({getattr(e, 'strerror', None) or e})") from None
        self._sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            self._sock.connect(addr)                      # Kernel filtert Pakete anderer Absender
        except OSError as e:
            self._sock.close()
            raise SnmpError(f"{host} nicht erreichbar ({e.strerror or e})") from None

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._sock.close()

    # -- öffentlich -------------------------------------------------------------------------------
    def get(self, oids: list[str]) -> dict[str, object]:
        """Werte zu den OIDs; ``None`` für fehlende Objekte."""
        wanted = [parse_oid(o) for o in oids]
        out: dict[str, object] = {format_oid(o): None for o in wanted}
        for i in range(0, len(wanted), CHUNK):
            todo = list(dict.fromkeys(wanted[i:i + CHUNK]))
            while todo:
                status, index, vbs = self._request(GET, [(o, NULL) for o in todo])
                if status == 2 and self.creds.version == "1" and 1 <= index <= len(todo):
                    del todo[index - 1]                   # v1: unbekannte OID weglassen, Rest neu fragen
                    continue
                if status:
                    raise self._status_error(status, index)
                if len(vbs) != len(todo):
                    raise SnmpError(f"Unvollständige Antwort von {self.host}")
                for oid, (_, _, value) in zip(todo, vbs):
                    out[format_oid(oid)] = value
                break
        return out

    def walk(self, base_oid: str, max_rows: int = 20000, bulk: int = 25) -> list[tuple[str, object]]:
        """Alle (OID, Wert) unterhalb von ``base_oid`` in Reihenfolge."""
        base = parse_oid(base_oid)
        rows: list[tuple[str, object]] = []
        cur, reps = base, max(1, int(bulk))
        while len(rows) < max_rows:
            if self.creds.version == "1":
                status, index, vbs = self._request(GETNEXT, [(cur, NULL)])
                if status == 2:
                    break
            else:
                status, index, vbs = self._request(GETBULK, [(cur, NULL)], 0, min(reps, max_rows - len(rows)))
                if status == 1 and reps > 1:              # tooBig: kleinere Portionen
                    reps = max(1, reps // 2)
                    continue
            if status:
                raise self._status_error(status, index)
            if not vbs:
                break
            for oid, tag, value in vbs:
                if tag == END_OF_MIB or oid[:len(base)] != base or len(oid) <= len(base) or oid <= cur:
                    return rows                           # Teilbaum verlassen, Ende oder Agent läuft rückwärts
                rows.append((format_oid(oid), value))
                cur = oid
                if len(rows) >= max_rows:
                    break
        return rows

    # -- intern -----------------------------------------------------------------------------------
    def _status_error(self, status: int, index: int) -> SnmpError:
        name = _ERRORS.get(status, f"Status {status}")
        if status in (6, 16):
            return SnmpError(f"{self.host} verweigert den Zugriff ({name}) – Freigaben (View/ACL) prüfen")
        return SnmpError(f"{self.host} meldet Fehler {name} (Index {index})")

    def _timeout(self) -> SnmpTimeout:
        where = self.host if self.port == 161 else f"{self.host}:{self.port}"
        return SnmpTimeout(f"Keine Antwort von {where} (Zeitüberschreitung) – Adresse, Community bzw. Benutzer "
                           f"und Firewall (UDP {self.port}) prüfen.")

    def _exchange(self, packet: bytes, match):
        """Senden, auf passende Antwort warten (``match`` → Ergebnis oder None), mit Wiederholungen."""
        for _ in range(self.retries + 1):
            try:
                self._sock.send(packet)
            except OSError as e:
                raise SnmpError(f"Senden an {self.host} fehlgeschlagen ({e.strerror or e})") from None
            deadline = time.monotonic() + self.timeout
            while (left := deadline - time.monotonic()) > 0:
                self._sock.settimeout(left)
                try:
                    data = self._sock.recv(65535)
                except TimeoutError:
                    break
                except OSError:                           # z. B. ICMP „Port unreachable“
                    continue
                try:
                    result = match(data)
                except (ValueError, IndexError, OverflowError):   # kaputtes/fremdes Paket
                    continue
                if result is not None:
                    return result
        raise self._timeout()

    def _request(self, tag: int, varbinds, a: int = 0, b: int = 0):
        """Eine Anfrage → (error-status, error-index, [(OID, Tag, Wert)])."""
        if self.creds.version == "3":
            return self._request_v3(tag, varbinds, a, b)
        version = 0 if self.creds.version == "1" else 1
        community = self.creds.community.encode()
        reqid = secrets.randbits(31)
        packet = _tlv(0x30, _int(version) + _tlv(4, community) + _pdu(tag, reqid, a, b, varbinds))

        def match(data):
            ver, comm, pdu = _top(data)
            if _get_int(data, ver) != version or _get_bytes(data, comm) != community or pdu[0] != RESPONSE:
                return None
            rid, status, index, vbs = _parse_pdu(data, pdu)
            return (status, index, vbs) if rid == reqid else None

        return self._exchange(packet, match)

    def _engine_time(self) -> int:
        return min(self._time0 + int(time.monotonic() - self._mono0), 2**31 - 1)

    def _set_time(self, boots: int, etime: int) -> None:
        self._boots, self._time0, self._mono0 = boots, etime, time.monotonic()

    def _request_v3(self, tag, varbinds, a, b):
        if self.engine_id is None:
            if self._send_v3(GET, [], 0, 0, discovery=True) != "engine" or not self.engine_id:
                raise SnmpError(f"{self.host} liefert keine SNMPv3-Engine-ID")
        for _ in range(3):                                # Neusynchronisation (Zeit/Engine) höchstens zweimal
            result = self._send_v3(tag, varbinds, a, b)
            if isinstance(result, tuple):
                return result
        raise SnmpAuthError(f"Zeitabgleich mit {self.host} fehlgeschlagen (SNMPv3 notInTimeWindow)")

    def _send_v3(self, tag, varbinds, a, b, discovery=False):
        """Eine v3-Anfrage → Ergebnis-Tupel, oder "engine"/"time" nach Neusynchronisation."""
        c = self.creds
        use_auth = c.auth_proto != "none" and not discovery
        use_priv = c.priv_proto != "none" and not discovery
        eid = self.engine_id or b""
        user = b"" if discovery else c.user.encode()
        boots, etime = (self._boots, self._engine_time()) if eid else (0, 0)
        akey = _auth_key(c.auth_proto, c.auth_key.encode(), eid) if use_auth else None
        pkey = _priv_key(c.auth_proto, c.priv_proto, c.priv_key.encode(), eid) if use_priv else None
        msg_id = reqid = secrets.randbits(31)
        scoped = _tlv(0x30, _tlv(4, eid) + _tlv(4, c.context.encode()) + _pdu(tag, reqid, a, b, varbinds))
        priv_params = b""
        if use_priv:
            self._salt = (self._salt + 1) & 0xFFFFFFFFFFFFFFFF
            cipher, priv_params = _encrypt(c.priv_proto, pkey, boots, etime, self._salt, scoped)
            scoped = _tlv(4, cipher)
        flags = 0x04 | (0x01 if use_auth else 0) | (0x02 if use_priv else 0)
        packet = _build_v3(msg_id, flags, eid, boots, etime, user, c.auth_proto, akey, priv_params, scoped)

        def match(data):
            m = _parse_v3(data)
            if m.msg_id != msg_id or (m.flags & 0x02 and not m.flags & 0x01):
                return None
            if m.flags & 0x01 and not (akey and m.engine_id == eid and _verify(c.auth_proto, akey, data, m)):
                return None                               # HMAC falsch → fremdes Paket
            if m.flags & 0x02:
                if not pkey:
                    return None
                raw = _decrypt(c.priv_proto, pkey, m.boots, m.time, m.priv, _get_bytes(data, m.data))
                body, item = raw, _tlv_at(raw, 0, len(raw))   # DES: Füllbytes am Ende ignorieren
            else:
                body, item = data, m.data
            _ctx_eid, _ctx_name, pdu = _seq(body, item, 3)
            if pdu[0] == REPORT:
                return self._report(body, pdu, m, discovery)
            if pdu[0] != RESPONSE or (use_auth and not m.flags & 0x01):
                return None
            rid, status, index, vbs = _parse_pdu(body, pdu)
            if rid != reqid:
                return None
            if m.flags & 0x01 and (m.boots > self._boots or (m.boots == self._boots and m.time > self._engine_time())):
                self._set_time(m.boots, m.time)
            return status, index, vbs

        return self._exchange(packet, match)

    def _report(self, body, pdu, m, discovery):
        """Report-PDU auswerten: Neusynchronisation oder passende Fehlermeldung."""
        vbs = _parse_pdu(body, pdu)[3]
        oid = vbs[0][0] if vbs else ()
        kind = oid[9] if len(oid) == 11 and oid[:9] == USM_STATS else None
        user = self.creds.user
        if kind == 4:                                     # usmStatsUnknownEngineIDs: Discovery-Antwort
            if not m.engine_id:
                raise _Bad("leere Engine-ID")
            self.engine_id = m.engine_id
            self._set_time(m.boots, m.time)
            return "engine"
        if discovery:
            raise SnmpError(f"{self.host}: unerwartete Antwort auf die SNMPv3-Erkennung ({format_oid(oid)})")
        if kind == 2:                                     # usmStatsNotInTimeWindows
            self._set_time(m.boots, m.time)
            return "time"
        if kind == 3:
            raise SnmpAuthError(f"Benutzer „{user}“ ist dem Switch {self.host} unbekannt (SNMPv3-Benutzername prüfen).")
        if kind == 5:
            raise SnmpAuthError(f"Passwort für die Anmeldung (Auth) falsch oder falsches Verfahren "
                                f"(Benutzer „{user}“, {self.creds.auth_proto.upper()}).")
        if kind == 6:
            raise SnmpAuthError(f"Passwort für die Verschlüsselung (Priv) falsch oder falsches Verfahren "
                                f"(Benutzer „{user}“, {self.creds.priv_proto.upper()}).")
        if kind == 1:
            raise SnmpAuthError(f"Sicherheitsstufe wird für Benutzer „{user}“ nicht unterstützt – "
                                f"Auth/Priv-Einstellung mit dem Switch abgleichen.")
        raise SnmpError(f"{self.host} meldet {format_oid(oid) or 'einen Fehler'} (SNMPv3-Report)")
