"""Switch-Abfragen der Server-Probe (docs/TOPOLOGIE.md): fällige Switches holen, abfragen (SNMP oder Weboberfläche), melden."""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .. import easysmart, snmp, snmpcollect

log = logging.getLogger("wachtl.serverprobe")
PARALLEL = 4


def poll(job: dict) -> dict:
    """Einen Switch abfragen. Gibt das Ergebnis für POST results/topology zurück (nie eine Ausnahme)."""
    ts = int(time.time())
    if job.get("access") == "easysmart":
        try:
            return {"switch_id": job["switch_id"], "ts": ts,
                    "snapshot": easysmart.poll(job["host"], job.get("credentials") or {}, port=int(job.get("port") or 80))}
        except easysmart.EasySmartError as exc:
            return {"switch_id": job["switch_id"], "ts": ts, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            log.exception("Switch %s: Abfrage unerwartet fehlgeschlagen", job.get("host"))
            return {"switch_id": job["switch_id"], "ts": ts, "error": f"Abfrage fehlgeschlagen: {exc}"[:200]}
    try:
        creds = snmp.Credentials(**{k: v for k, v in (job.get("credentials") or {}).items()
                                    if k in snmp.Credentials.__dataclass_fields__})
        with snmp.Session(job["host"], creds, port=int(job.get("port") or 161), timeout=2.0, retries=1) as sess:
            snapshot = snmpcollect.collect(sess)
        return {"switch_id": job["switch_id"], "ts": ts, "snapshot": snapshot}
    except snmp.SnmpError as exc:
        return {"switch_id": job["switch_id"], "ts": ts, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 – ein kaputter Switch darf die Probe nie beenden
        log.exception("Switch %s: Abfrage unerwartet fehlgeschlagen", job.get("host"))
        return {"switch_id": job["switch_id"], "ts": ts, "error": f"Abfrage fehlgeschlagen: {exc}"[:200]}


def loop(api_getter: Callable, stop: threading.Event, poller: Callable[[dict], dict] = poll) -> None:
    """Alle 30 s fällige Abfragen holen und erledigen; Ergebnisse sofort melden."""
    with ThreadPoolExecutor(max_workers=PARALLEL, thread_name_prefix="snmp") as pool:
        while not stop.is_set():
            wait = 30
            api = api_getter()
            if api is not None:
                try:
                    resp = api.json("GET", "topology/jobs", ok=(200,))
                    wait = max(10, int(resp.get("poll_s") or 30))
                    jobs = resp.get("jobs") or []
                    for result in pool.map(poller, jobs):
                        if result.get("error"):
                            log.warning("Switch %s: %s", result["switch_id"], result["error"])
                        api.result("topology", result)
                except Exception as exc:  # noqa: BLE001 – Server kurz nicht erreichbar, später erneut
                    log.debug("Switch-Abfragen nicht möglich: %s", exc)
            stop.wait(wait)
