"""Start: ``python -m wachtl.serverprobe`` (Einstellungen aus der Umgebung)."""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from pathlib import Path

from .probe import ServerProbe


def main() -> int:
    logging.basicConfig(level=os.environ.get("WACHTL_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout)
    url = os.environ.get("WACHTL_SERVER_PROBE_URL", "https://127.0.0.1")
    pin = os.environ.get("WACHTL_SPKI_PIN", "")
    state_dir = Path(os.environ.get("WACHTL_SERVER_PROBE_DIR", "/serverprobe"))
    stop = threading.Event()
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: stop.set())
    if os.environ.get("WACHTL_SERVER_PROBE", "1") == "0":
        # abgeschaltet: ruhig warten statt beenden, damit Docker/Supervisor nicht dauernd neu starten
        logging.getLogger("wachtl.serverprobe").info("Server-Probe abgeschaltet (WACHTL_SERVER_PROBE=0)")
        stop.wait()
        return 0
    # Tray-Endpunkt nur, wenn ein Port gesetzt ist (Windows-Server; im Docker-Container gibt es kein Tray)
    tray_port = int(os.environ.get("WACHTL_TRAY_PORT") or 0) or None
    ServerProbe(url, pin, state_dir, os.environ.get("WACHTL_IPERF_EXE"), stop, tray_port=tray_port,
                public_url=os.environ.get("WACHTL_PUBLIC_URL", ""), diag_exe=os.environ.get("WACHTL_DIAG_EXE")).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
