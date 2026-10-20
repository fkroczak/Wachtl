"""HTTP(S)-Client für die Probe-API mit SPKI-Pinning – dasselbe Vertrauensmodell wie die Windows-Probe.

Die Server-Probe spricht den Server über die lokale Adresse an (https://127.0.0.1:<Port>). Das
selbstsignierte Zertifikat wird nicht über eine Zertifizierungsstelle, sondern über den SHA-256 des
öffentlichen Schlüssels geprüft (WACHTL_SPKI_PIN).
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import http.client
import json
import ssl
from urllib.parse import urlparse

from .. import __version__

PREFIX = "/api/probe/v1/"


class ApiError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status

    @property
    def auth_error(self) -> bool:
        return self.status in (401, 403)


def spki_pin(der_cert: bytes) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    key = x509.load_der_x509_certificate(der_cert).public_key()
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


class Api:
    def __init__(self, base_url: str, pin: str = "", token: str | None = None, timeout: float = 30):
        u = urlparse(base_url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"Ungültige Server-Adresse: {base_url}")
        self.https = u.scheme == "https"
        if self.https and not pin:
            raise ValueError("Für https ist ein SPKI-Pin nötig (WACHTL_SPKI_PIN).")
        self.host = u.hostname
        self.port = u.port or (443 if self.https else 80)
        self.pin = pin.strip()
        self.token = token
        self.timeout = timeout

    def _connection(self) -> http.client.HTTPConnection:
        if not self.https:
            return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE          # ersetzt durch den Pin-Vergleich unten
        return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ctx)

    def request(self, method: str, path: str, body: bytes | None = None,
                headers: dict | None = None) -> tuple[int, dict, bytes]:
        conn = self._connection()
        try:
            conn.connect()
            if self.https:
                der = conn.sock.getpeercert(binary_form=True)
                if not der or not hmac.compare_digest(spki_pin(der), self.pin):
                    raise ApiError(495, "Zertifikat passt nicht zum SPKI-Pin")
            h = {"User-Agent": f"wachtl-serverprobe/{__version__}", **(headers or {})}
            if self.token:
                h["Authorization"] = f"Bearer {self.token}"
            conn.request(method, PREFIX + path.lstrip("/"), body=body, headers=h)
            resp = conn.getresponse()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
        finally:
            conn.close()

    def json(self, method: str, path: str, payload: dict | None = None, ok=(200, 201)) -> dict:
        body = json.dumps(payload or {}).encode()
        status, _, data = self.request(method, path, body, {"Content-Type": "application/json"})
        if status not in ok:
            raise ApiError(status, _message(data))
        return json.loads(data or b"{}")

    # -- Endpunkte ------------------------------------------------------------
    def enroll(self, token: str, hostname: str, os_name: str) -> dict:
        return self.json("POST", "enroll", {"enrollment_token": token, "hostname": hostname, "os": os_name,
                                            "version": __version__})

    def config(self, etag: str | None) -> dict | None:
        status, _, data = self.request("GET", "config", headers={"If-None-Match": f'"{etag}"'} if etag else None)
        if status == 304:
            return None
        if status != 200:
            raise ApiError(status, _message(data))
        return json.loads(data)

    def heartbeat(self, payload: dict) -> dict:
        return self.json("POST", "heartbeat", payload, ok=(200,))

    def ingest(self, batch_id: str, lines: list[str]) -> None:
        body = gzip.compress(("\n".join(lines) + "\n").encode())
        status, _, data = self.request("POST", "ingest", body, {"Content-Type": "text/plain", "Content-Encoding": "gzip",
                                                               "X-Batch-Id": batch_id})
        if status not in (204, 422):     # 422 = alle Zeilen verworfen (z. B. Check inzwischen gelöscht)
            raise ApiError(status, _message(data))

    def result(self, kind: str, payload: dict) -> None:
        self.json("POST", f"results/{kind}", payload)

    def findings(self, items: list[dict]) -> dict:
        """Client-Hinweise dieses Servers (docs/CLIENT-HINWEISE.md)."""
        return self.json("POST", "findings", {"findings": items}, ok=(200,))

    def report(self, payload: dict) -> dict:
        """Störungsmeldung vom Tray-Symbol weiterleiten (201 neu, 200 schon bekannt)."""
        return self.json("POST", "report", payload)


def _message(data: bytes) -> str:
    try:
        return str(json.loads(data).get("error") or data[:200])
    except (ValueError, AttributeError):
        return data[:200].decode("utf-8", errors="replace")
