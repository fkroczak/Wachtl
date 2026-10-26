"""Setup-Datei für die Probes mit eingebauter Vorbelegung (Server-Adressen, Pin, Token).

Das Wachtl-Setup (Inno Setup) liest beim Start die letzten Kilobytes seiner eigenen Datei.
Steht dort ein Block zwischen ``@@WACHTL-SETUP-CONFIG@@`` und ``@@WACHTL-SETUP-END@@``,
installiert es ohne Rückfragen eine Probe mit diesen Werten. Windows und das Setup
ignorieren Daten hinter dem eigentlichen Programm, die Datei bleibt also gültig.
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Iterator

BEGIN = b"@@WACHTL-SETUP-CONFIG@@"
END = b"@@WACHTL-SETUP-END@@"
MAX_BLOCK = 7000          # das Setup liest die letzten 8 KB
SETUP_GLOBS = ("WachtlSetup-*.exe", "WachtlProbeSetup-*.exe")


def _version_key(f: Path) -> tuple:
    """Sortierschlüssel nach Versionsnummer im Dateinamen (0.9.10 > 0.9.3), bei Gleichstand nach Dateidatum."""
    m = re.search(r"-(\d+(?:\.\d+)*)\.exe$", f.name, re.IGNORECASE)
    version = tuple(int(x) for x in m.group(1).split(".")) if m else ()
    return version, f.stat().st_mtime


def find_setup(probe_dir: str) -> Path | None:
    """Neuestes Setup im Probe-Ordner: bevorzugt das gemeinsame WachtlSetup, sonst das alte Probe-Setup.

    Maßgeblich ist die Versionsnummer, nicht das Dateidatum: eine später kopierte ältere Datei
    darf das aktuelle Setup nicht verdrängen.
    """
    if not probe_dir:
        return None
    for pattern in SETUP_GLOBS:
        files = sorted(Path(probe_dir).glob(pattern), key=_version_key)
        if files:
            return files[-1]
    return None


def ascii_text(value: str) -> str:
    """Für Anzeigetexte im Setup: Umlaute umschreiben, Steuerzeichen entfernen (der Block ist ASCII)."""
    value = value.replace("ä", "ae").replace("ö", "oe").replace("ü", "ue").replace("Ä", "Ae").replace(
        "Ö", "Oe").replace("Ü", "Ue").replace("ß", "ss")
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[\x00-\x1f\x7f]", "", value).strip()


def config_block(servers: list[str], pin: str, token: str, site: str, proxy: str = "") -> bytes:
    for value in (*servers, pin, token, proxy):
        if any(c in value for c in "\r\n\x00") or not value.isascii():
            raise ValueError("ungültiger Wert für die Vorbelegung")
    lines = [
        "[wachtl]",
        "role=client",
        "servers=" + ",".join(servers),
        "pin=" + pin,
        "token=" + token,
        "site=" + ascii_text(site)[:100],
        "proxy=" + proxy,
    ]
    block = b"\r\n" + BEGIN + b"\r\n" + "\r\n".join(lines).encode("ascii") + b"\r\n" + END + b"\r\n"
    if len(block) > MAX_BLOCK:
        raise ValueError("Vorbelegung zu lang")
    return block


def prefilled(setup: Path, block: bytes, chunk: int = 1024 * 1024) -> tuple[Iterator[bytes], int]:
    """Setup-Datei plus Konfigurationsblock als Datenstrom und Gesamtlänge."""
    size = setup.stat().st_size

    def stream() -> Iterator[bytes]:
        with open(setup, "rb") as f:
            while data := f.read(chunk):
                yield data
        yield block

    return stream(), size + len(block)


def read_block(data: bytes) -> dict[str, str]:
    """Gegenstück für Tests: Werte aus dem Ende einer Setup-Datei lesen."""
    tail = data[-8192:]
    start = tail.rfind(BEGIN)
    end = tail.rfind(END)
    if start < 0 or end < start:
        return {}
    values = {}
    for line in tail[start + len(BEGIN):end].decode("ascii").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values
