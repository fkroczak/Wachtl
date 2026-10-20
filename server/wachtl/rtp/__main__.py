"""Start: ``python -m wachtl.rtp [Port]`` – RTP-Reflektor des Wachtl-Servers (Port auch aus WACHTL_RTP_PORT)."""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading

from . import DEFAULT_PORT
from .reflector import serve


def main(argv: list[str]) -> int:
    logging.basicConfig(level=os.environ.get("WACHTL_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout)
    port = int(argv[0] if argv else os.environ.get("WACHTL_RTP_PORT") or DEFAULT_PORT)
    stop = threading.Event()
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: stop.set())
    if port == 0:
        logging.getLogger("wachtl.rtp").info("RTP-Reflektor abgeschaltet (Port 0)")
        stop.wait()
        return 0
    serve(port, stop)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
