"""Ordner, Konfigurationsdatei und abgeleitete Umgebung der Windows-Installation."""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SERVICE_ID = "WachtlServer"
SERVICE_ACCOUNT = f"NT SERVICE\\{SERVICE_ID}"
EXE = ".exe" if os.name == "nt" else ""

DEFAULTS = {
    "WACHTL_HOSTNAMES": "",
    "WACHTL_PUBLIC_URL": "",
    "WACHTL_HTTPS_PORT": "443",
    "WACHTL_HTTP_PORT": "80",
    "WACHTL_BIND": "0.0.0.0",
    "WACHTL_SECRET_KEY": "",
    "WACHTL_WEBHOOK_SECRET": "",
    "WACHTL_SPKI_PIN": "",
    "RAW_RETENTION": "30d",
    "AGG_RETENTION": "13",
    "PORT_INTERNAL": "8427",
    "PORT_VM_RAW": "8428",
    "PORT_VM_AGG": "8429",
    "PORT_VMALERT": "8880",
    "PORT_ALERTMANAGER": "9093",
    "PORT_IPERF": "5201",           # iperf3-Gegenstelle für Probes, öffentlich (TCP+UDP); 0 = aus
    "SERVER_PROBE": "1",            # Server misst selbst (Server-Probe); 0 = aus
    "BACKUP_KEEP_DAYS": "14",
}
SUBDIRS = ("config", "certs", "data", "vm-raw", "vm-agg", "rules", "alertmanager", "logs", "backups", "serverprobe")
_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def default_install_dir() -> Path:
    if os.environ.get("WACHTL_INSTALL_DIR"):
        return Path(os.environ["WACHTL_INSTALL_DIR"])
    # {Programmordner}\python\python.exe
    return Path(sys.executable).resolve().parent.parent


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.lstrip().startswith("#"):
            continue
        m = _LINE.match(raw)
        if m:
            value = m.group(2)
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            values[m.group(1)] = value
    return values


def write_env(path: Path, values: dict[str, str]) -> None:
    lines = [
        "# Wachtl Server – Konfiguration. Vom Setup erzeugt.",
        "# Nach Änderungen den Dienst neu starten: Restart-Service WachtlServer",
        "",
    ]
    for key in list(DEFAULTS) + sorted(k for k in values if k not in DEFAULTS):
        if key in values:
            value = str(values[key])
            if "\n" in value or "\r" in value:
                raise ValueError(f"Zeilenumbruch in {key} nicht erlaubt")
            lines.append(f"{key}={value}")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(tmp, path)


@dataclass
class Layout:
    install_dir: Path
    data_dir: Path
    env: dict[str, str] = field(default_factory=dict)

    # -- Konstruktion ------------------------------------------------------
    @classmethod
    def load(cls, data_dir: str | Path | None = None, install_dir: str | Path | None = None) -> "Layout":
        inst = Path(install_dir) if install_dir else default_install_dir()
        if data_dir is None:
            marker = inst / "datadir.txt"
            if not marker.exists():
                raise FileNotFoundError(f"Datenordner unbekannt ({marker} fehlt). Bitte --data angeben.")
            data_dir = marker.read_text(encoding="utf-8").strip()
        layout = cls(inst, Path(data_dir))
        layout.env = {**DEFAULTS, **read_env(layout.env_file)}
        return layout

    # -- Pfade ----------------------------------------------------------------
    @property
    def env_file(self) -> Path:
        return self.data_dir / "config" / "wachtl.env"

    @property
    def cert_file(self) -> Path:
        return self.data_dir / "certs" / "wachtl.crt"

    @property
    def key_file(self) -> Path:
        return self.data_dir / "certs" / "wachtl.key"

    @property
    def db_file(self) -> Path:
        return self.data_dir / "data" / "wachtl.db"

    @property
    def am_config(self) -> Path:
        return self.data_dir / "alertmanager" / "alertmanager.yml"

    @property
    def logs(self) -> Path:
        return self.data_dir / "logs"

    @property
    def backups(self) -> Path:
        return self.data_dir / "backups"

    @property
    def python(self) -> Path:
        if os.environ.get("WACHTL_PYTHON"):
            return Path(os.environ["WACHTL_PYTHON"])
        return Path(sys.executable)

    def binary(self, name: str) -> Path:
        bin_dir = Path(os.environ.get("WACHTL_BIN_DIR", self.install_dir / "bin"))
        return bin_dir / f"{name}{EXE}"

    @property
    def winsw_exe(self) -> Path:
        return self.install_dir / "service" / f"{SERVICE_ID}.exe"

    @property
    def winsw_xml(self) -> Path:
        return self.install_dir / "service" / f"{SERVICE_ID}.xml"

    def port(self, key: str) -> int:
        return int(self.env[f"PORT_{key}"] or 0)

    @property
    def iperf_exe(self) -> Path:
        bin_dir = Path(os.environ.get("WACHTL_BIN_DIR", self.install_dir / "bin"))
        return bin_dir / "iperf3" / f"iperf3{EXE}"

    @property
    def https_port(self) -> int:
        return int(self.env["WACHTL_HTTPS_PORT"])

    @property
    def http_port(self) -> int:
        return int(self.env["WACHTL_HTTP_PORT"] or 0)

    @property
    def hostnames(self) -> list[str]:
        return [h.strip() for h in self.env["WACHTL_HOSTNAMES"].split(",") if h.strip()]

    @property
    def internal_url(self) -> str:
        return f"http://127.0.0.1:{self.port('INTERNAL')}"

    def local(self, key: str) -> str:
        return f"http://127.0.0.1:{self.port(key)}"

    def ensure_dirs(self) -> None:
        for sub in SUBDIRS:
            (self.data_dir / sub).mkdir(parents=True, exist_ok=True)

    # -- Umgebung für die App ----------------------------------------------------
    def app_env(self) -> dict[str, str]:
        """Umgebungsvariablen, mit denen die Flask-App unter Windows läuft."""
        e = self.env
        return {
            "WACHTL_SECRET_KEY": e["WACHTL_SECRET_KEY"],
            "WACHTL_WEBHOOK_SECRET": e["WACHTL_WEBHOOK_SECRET"],
            "WACHTL_SPKI_PIN": e["WACHTL_SPKI_PIN"],
            "WACHTL_PUBLIC_URL": e["WACHTL_PUBLIC_URL"],
            "WACHTL_DATABASE_URL": "sqlite:///" + str(self.db_file),
            "WACHTL_VM_RAW_URL": self.local("VM_RAW"),
            "WACHTL_VM_AGG_URL": self.local("VM_AGG"),
            "WACHTL_VMALERT_URL": self.local("VMALERT"),
            "WACHTL_ALERTMANAGER_URL": self.local("ALERTMANAGER"),
            "WACHTL_RULES_DIR": str(self.data_dir / "rules"),
            "WACHTL_AM_CONFIG": str(self.am_config),
            "WACHTL_INTERNAL_URL": self.internal_url,
            "WACHTL_TRUST_PROXY": "0",
            "WACHTL_COOKIE_SECURE": "1",
            "WACHTL_PROBE_DIR": str(self.install_dir / "probe"),
            "WACHTL_IPERF_PORT": str(self.port("IPERF")),
            "WACHTL_SERVER_PROBE": "1" if self.env.get("SERVER_PROBE", "1") != "0" else "0",
            "WACHTL_SERVER_PROBE_DIR": str(self.data_dir / "serverprobe"),
            # nur für den HTTPS-Server (wachtl.win.serve)
            "WACHTL_HTTPS_PORT": str(self.https_port),
            "WACHTL_HTTP_PORT": str(self.http_port),
            "WACHTL_BIND": e["WACHTL_BIND"],
            "WACHTL_INTERNAL_PORT": str(self.port("INTERNAL")),
            "WACHTL_CERT_FILE": str(self.cert_file),
            "WACHTL_KEY_FILE": str(self.key_file),
            "WACHTL_LOG_DIR": str(self.logs),
        }


def server_probe_env(layout: "Layout") -> dict[str, str]:
    """Umgebung der Server-Probe: über HTTPS mit Pin an den eigenen Server, iperf3 aus dem Programmordner."""
    return {
        "WACHTL_SERVER_PROBE": layout.app_env()["WACHTL_SERVER_PROBE"],
        "WACHTL_SERVER_PROBE_URL": f"https://127.0.0.1:{layout.https_port}",
        "WACHTL_SPKI_PIN": layout.env["WACHTL_SPKI_PIN"],
        "WACHTL_SERVER_PROBE_DIR": str(layout.data_dir / "serverprobe"),
        "WACHTL_IPERF_EXE": str(layout.iperf_exe),
        # lokaler Endpunkt für das Tray-Symbol (Störungsmeldungen, „Dashboard öffnen“), nur 127.0.0.1
        "WACHTL_TRAY_PORT": layout.env.get("TRAY_PORT") or "47251",
        "WACHTL_PUBLIC_URL": layout.env.get("WACHTL_PUBLIC_URL", ""),
        "PYTHONUTF8": "1",
    }


def public_url(hostname: str, https_port: int) -> str:
    return f"https://{hostname}" + ("" if https_port == 443 else f":{https_port}")
