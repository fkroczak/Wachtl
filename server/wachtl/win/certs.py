"""Selbstsigniertes Server-Zertifikat und SPKI-Pin.

Der Schlüssel bleibt bei einer Erneuerung erhalten – damit ändert sich der Pin nicht und
die Probes verbinden sich weiter, ohne dass sie neu installiert werden müssen.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VALID_DAYS = 3650
RENEW_BEFORE_DAYS = 30


def _san(names: list[str]) -> list[x509.GeneralName]:
    result: list[x509.GeneralName] = []
    for name in names:
        try:
            result.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            result.append(x509.DNSName(name))
    return result


def _name_constraints(names: list[str]) -> x509.NameConstraints:
    """Das Zertifikat liegt auf den PCs als Stammzertifikat. Die Namensbeschränkung sorgt dafür, dass es –
    selbst wenn der Schlüssel abhandenkäme – nur für die Adressen des Wachtl-Servers gilt, nicht für fremde Seiten."""
    permitted: list[x509.GeneralName] = []
    for name in names:
        if _is_ip(name):
            ip = ipaddress.ip_address(name)
            permitted.append(x509.IPAddress(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}")))
        else:
            permitted.append(x509.DNSName(name))
    return x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=None)


def load_or_create_key(key_file: Path) -> ec.EllipticCurvePrivateKey:
    if key_file.exists():
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError(f"{key_file} ist kein EC-Schlüssel")
        return key
    key = ec.generate_private_key(ec.SECP256R1())
    key_file.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


def create_certificate(names: list[str], key_file: Path, cert_file: Path, days: int = VALID_DAYS) -> x509.Certificate:
    if not names:
        raise ValueError("Mindestens ein Servername oder eine IP-Adresse ist nötig.")
    key = load_or_create_key(key_file)
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wachtl"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(_san(names)), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False, key_agreement=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(_name_constraints(names), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file.parent.mkdir(parents=True, exist_ok=True)
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def load_certificate(cert_file: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_file.read_bytes())


def spki_pin(cert_file: Path) -> str:
    """Base64(SHA-256(SubjectPublicKeyInfo)) – identisch zur Berechnung in der Probe."""
    spki = load_certificate(cert_file).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def needs_renewal(cert_file: Path, names: list[str]) -> str | None:
    """Grund für eine Erneuerung oder None."""
    if not cert_file.exists():
        return "kein Zertifikat vorhanden"
    cert = load_certificate(cert_file)
    remaining = cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)
    if remaining < dt.timedelta(days=RENEW_BEFORE_DAYS):
        return f"läuft in {remaining.days} Tagen ab"
    try:
        current = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return "keine Servernamen im Zertifikat"
    have = {str(v) for v in current.get_values_for_type(x509.DNSName)}
    have |= {str(v) for v in current.get_values_for_type(x509.IPAddress)}
    want = {str(ipaddress.ip_address(n)) if _is_ip(n) else n for n in names}
    if have != want:
        return "Servernamen haben sich geändert"
    try:
        cert.extensions.get_extension_for_class(x509.NameConstraints)
    except x509.ExtensionNotFound:
        return "ohne Namensbeschränkung (vor 0.9.3 ausgestellt)"
    return None


def ensure_certificate(names: list[str], key_file: Path, cert_file: Path) -> tuple[str, str | None]:
    """Zertifikat bei Bedarf (neu) ausstellen. Gibt (Pin, Grund oder None) zurück."""
    reason = needs_renewal(cert_file, names)
    if reason:
        create_certificate(names, key_file, cert_file)
    return spki_pin(cert_file), reason


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
