"""Zugangsdaten verschlüsselt speichern (SNMP-Community, v3-Passwörter).

Schlüssel: aus WACHTL_SECRET_KEY abgeleitet (HKDF-SHA256), Verfahren Fernet (AES-128-CBC + HMAC-SHA256).
Wer nur die Datenbank (oder ein Backup davon) hat, kann die Zugangsdaten nicht lesen. Ändert sich der
Server-Schlüssel, sind sie verloren und müssen im Web-UI neu eingegeben werden.
"""
from __future__ import annotations

import base64
import json

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app


class SecretError(ValueError):
    pass


def _fernet(secret_key: str | None = None) -> Fernet:
    key = (secret_key or current_app.secret_key or "").encode()
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"wachtl-secretbox", info=b"snmp-credentials").derive(key)
    return Fernet(base64.urlsafe_b64encode(raw))


def seal(data: dict, secret_key: str | None = None) -> str:
    return _fernet(secret_key).encrypt(json.dumps(data, separators=(",", ":")).encode()).decode()


def unseal(token: str, secret_key: str | None = None) -> dict:
    try:
        return json.loads(_fernet(secret_key).decrypt((token or "").encode()))
    except (InvalidToken, ValueError):
        raise SecretError("Zugangsdaten nicht lesbar – wurde der Server-Schlüssel geändert? "
                          "Bitte die Zugangsdaten neu eingeben.") from None
