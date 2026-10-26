"""Eigene Wachtl-CA, Server-Zertifikat und SPKI-Pin.

Aufbau
  wachtl-ca.key / wachtl-ca.crt   Wachtl-CA, 10 Jahre. Sie liegt auf den PCs unter „Vertrauenswürdige
                                  Stammzertifizierungsstellen“. Eine Namensbeschränkung lässt sie nur Zertifikate
                                  für die Namen und IP-Adressen dieses Servers ausstellen.
  wachtl.key / wachtl.crt         Server-Zertifikat, 397 Tage (Apple akzeptiert höchstens 825, Browser-Regeln
                                  398 Tage), von der CA signiert. wachtl.crt enthält die Kette: Server, dann CA.

Der Schlüssel des Server-Zertifikats bleibt bei jeder Erneuerung erhalten – damit ändert sich der Pin der Probes
nie. Das Server-Zertifikat wird 30 Tage vor Ablauf automatisch erneuert; die PCs merken davon nichts, weil sie
der CA vertrauen.

Auch als Kommando (Linux-Server, im App-Container):
    python -m wachtl.win.certs ensure --dir /certs --names wachtl.kunde.local[,10.0.0.5]
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_VALID_DAYS = 3650
CA_RENEW_BEFORE_DAYS = 365
VALID_DAYS = 397
RENEW_BEFORE_DAYS = 30


def ca_paths(cert_file: Path) -> tuple[Path, Path]:
    """CA-Schlüssel und -Zertifikat liegen neben dem Server-Zertifikat."""
    return cert_file.with_name("wachtl-ca.key"), cert_file.with_name("wachtl-ca.crt")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _san(names: list[str]) -> list[x509.GeneralName]:
    return [x509.IPAddress(ipaddress.ip_address(n)) if _is_ip(n) else x509.DNSName(n) for n in names]


def _wanted(names: list[str]) -> set[str]:
    return {str(ipaddress.ip_address(n)) if _is_ip(n) else n for n in names}


def _name_constraints(names: list[str]) -> x509.NameConstraints:
    """Die CA liegt auf den PCs als Stammzertifikat. Die Namensbeschränkung sorgt dafür, dass sie – selbst wenn
    ihr Schlüssel abhandenkäme – nur für die Adressen des Wachtl-Servers gilt, nicht für fremde Seiten."""
    permitted: list[x509.GeneralName] = []
    for name in names:
        if _is_ip(name):
            ip = ipaddress.ip_address(name)
            permitted.append(x509.IPAddress(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}")))
        else:
            permitted.append(x509.DNSName(name))
    return x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=None)


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _write_public(path: Path, data: bytes) -> None:
    """Atomar ersetzen: der HTTPS-Server liest die Datei womöglich gerade."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def load_or_create_key(key_file: Path) -> ec.EllipticCurvePrivateKey:
    if key_file.exists():
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError(f"{key_file} ist kein EC-Schlüssel")
        return key
    key = ec.generate_private_key(ec.SECP256R1())
    _write_private(key_file, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    return key


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# -- CA ------------------------------------------------------------------------------------
def create_ca(names: list[str], ca_key_file: Path, ca_cert_file: Path, days: int = CA_VALID_DAYS) -> x509.Certificate:
    if not names:
        raise ValueError("Mindestens ein Servername oder eine IP-Adresse ist nötig.")
    key = load_or_create_key(ca_key_file)
    now = _now()
    # gleicher Schlüssel und gleicher Name bei einer Neuausstellung: Server-Zertifikate bleiben gültig
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"Wachtl CA {names[0]}"[:64]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wachtl"),
    ])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(_name_constraints(names), critical=True)
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_public(ca_cert_file, _pem(cert))
    return cert


def ca_needs_renewal(ca_cert_file: Path, names: list[str]) -> str | None:
    if not ca_cert_file.exists():
        return "keine Wachtl-CA vorhanden"
    ca = x509.load_pem_x509_certificate(ca_cert_file.read_bytes())
    remaining = ca.not_valid_after_utc - _now()
    if remaining < dt.timedelta(days=CA_RENEW_BEFORE_DAYS):
        return f"Wachtl-CA läuft in {remaining.days} Tagen ab"
    try:
        nc = ca.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return "Wachtl-CA ohne Namensbeschränkung"
    have = set()
    for sub in nc.permitted_subtrees or []:
        if isinstance(sub, x509.IPAddress):
            have.add(str(sub.value.network_address))
        else:
            have.add(str(sub.value))
    if have != _wanted(names):
        return "Servernamen der Wachtl-CA haben sich geändert"
    return None


# -- Server-Zertifikat --------------------------------------------------------------------
def create_certificate(names: list[str], key_file: Path, cert_file: Path, days: int = VALID_DAYS,
                       ca: tuple[ec.EllipticCurvePrivateKey, x509.Certificate] | None = None) -> x509.Certificate:
    """Server-Zertifikat von der CA ausstellen; wachtl.crt enthält danach Server- und CA-Zertifikat."""
    if not names:
        raise ValueError("Mindestens ein Servername oder eine IP-Adresse ist nötig.")
    if ca is None:
        ca_key_file, ca_cert_file = ca_paths(cert_file)
        if ca_needs_renewal(ca_cert_file, names):
            create_ca(names, ca_key_file, ca_cert_file)
        ca = (load_or_create_key(ca_key_file), x509.load_pem_x509_certificate(ca_cert_file.read_bytes()))
    ca_key, ca_cert = ca
    key = load_or_create_key(key_file)
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wachtl"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(min(now + dt.timedelta(days=days), ca_cert.not_valid_after_utc))
        .add_extension(x509.SubjectAlternativeName(_san(names)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _write_public(cert_file, _pem(cert) + _pem(ca_cert))
    return cert


def load_certificate(cert_file: Path) -> x509.Certificate:
    """Erstes Zertifikat der Datei: das Server-Zertifikat."""
    return x509.load_pem_x509_certificate(cert_file.read_bytes())


def load_chain(cert_file: Path) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(cert_file.read_bytes())


def root_certificate(cert_file: Path) -> x509.Certificate:
    """Zertifikat für den Stammspeicher: die CA (letztes der Kette); bei alten Installationen das selbstsignierte."""
    return load_chain(cert_file)[-1]


def spki_pin(cert_file: Path) -> str:
    """Base64(SHA-256(SubjectPublicKeyInfo)) des Server-Zertifikats – identisch zur Berechnung in der Probe."""
    spki = load_certificate(cert_file).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def needs_renewal(cert_file: Path, names: list[str]) -> str | None:
    """Grund für eine Neuausstellung des Server-Zertifikats (oder der CA) oder None."""
    ca_key_file, ca_cert_file = ca_paths(cert_file)
    if reason := ca_needs_renewal(ca_cert_file, names):
        return reason
    if not cert_file.exists():
        return "kein Zertifikat vorhanden"
    chain = load_chain(cert_file)
    cert, ca = chain[0], x509.load_pem_x509_certificate(ca_cert_file.read_bytes())
    try:
        cert.verify_directly_issued_by(ca)
    except (ValueError, TypeError, InvalidSignature):
        return "nicht von der Wachtl-CA ausgestellt"
    if chain[-1] != ca:
        return "Kette ohne aktuelle Wachtl-CA"
    remaining = cert.not_valid_after_utc - _now()
    if remaining < dt.timedelta(days=RENEW_BEFORE_DAYS):
        return f"läuft in {remaining.days} Tagen ab"
    try:
        current = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return "keine Servernamen im Zertifikat"
    have = {str(v) for v in current.get_values_for_type(x509.DNSName)}
    have |= {str(v) for v in current.get_values_for_type(x509.IPAddress)}
    if have != _wanted(names):
        return "Servernamen haben sich geändert"
    return None


def ensure_certificate(names: list[str], key_file: Path, cert_file: Path) -> tuple[str, str | None]:
    """CA und Server-Zertifikat bei Bedarf (neu) ausstellen. Gibt (Pin, Grund oder None) zurück."""
    reason = needs_renewal(cert_file, names)
    if reason:
        create_certificate(names, key_file, cert_file)
    return spki_pin(cert_file), reason


# -- Kommando -------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m wachtl.win.certs")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("ensure", help="CA und Server-Zertifikat prüfen und bei Bedarf erneuern")
    e.add_argument("--dir", required=True, type=Path, help="Ordner mit wachtl.key / wachtl.crt")
    e.add_argument("--names", required=True, help="Servernamen und IP-Adressen, mit Komma getrennt")
    args = p.parse_args(argv)
    names = [n.strip() for n in args.names.split(",") if n.strip()]
    pin, reason = ensure_certificate(names, args.dir / "wachtl.key", args.dir / "wachtl.crt")
    print(f"pin={pin}")
    print(f"renewed={'1' if reason else '0'}")
    print(f"reason={reason or ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
