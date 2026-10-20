"""Mess-Schleifen der Server-Probe: Dauerping, Pfad (Traceroute + Hop-Pings), Bandbreite.

Jede Regel entspricht der Windows-Probe (PingRunner.cs, PathRunner.cs, BandwidthRunner.cs), damit
Server und Probes vergleichbare Werte liefern.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable

from .. import schedule
from . import bandwidth, icmp, net

log = logging.getLogger("wachtl.serverprobe")
Sink = Callable[[str], None]


def fmt(value: float) -> str:
    text = f"{value:.3f}".rstrip("0").rstrip(".")
    return text or "0"


def metric(name: str, check_id: int, value: float, ts_ms: int) -> str:
    return f'{name}{{check_id="{check_id}"}} {fmt(value)} {ts_ms}'


def hop_metric(name: str, check_id: int, hop: int, ip: str, value: float, ts_ms: int) -> str:
    return f'{name}{{check_id="{check_id}",hop="{hop}",hop_ip="{ip}"}} {fmt(value)} {ts_ms}'


class Jitter:
    """Mittlere absolute Differenz aufeinanderfolgender Antwortzeiten, Verluste übersprungen."""

    def __init__(self):
        self.last: float | None = None
        self.total = 0.0
        self.count = 0

    def add(self, rtt: float | None) -> None:
        if rtt is None:
            return
        if self.last is not None:
            self.total += abs(rtt - self.last)
            self.count += 1
        self.last = rtt

    def take(self) -> float | None:
        if not self.count:
            return None
        value = self.total / self.count
        self.total, self.count = 0.0, 0
        return value


def _p(check: dict, key: str, default):
    value = (check.get("params") or {}).get(key, default)
    return default if value is None else value


def _clamp(v, lo, hi):
    return max(lo, min(hi, v))


class Runner:
    def __init__(self, check: dict):
        self.check = check
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._safe_run, name=f"check-{check['id']}", daemon=True)

    @property
    def key(self) -> str:
        return check_key(self.check)

    def start(self) -> "Runner":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.stop_event.set()

    def _safe_run(self) -> None:
        try:
            self.run()
        except Exception:  # noqa: BLE001 – ein Check darf die Probe nie beenden
            log.exception("Check %s unerwartet beendet", self.check["id"])

    def run(self) -> None:
        raise NotImplementedError

    def ticks(self, interval_s: float):
        """Takt wie PeriodicTimer: feste Abstände ohne Drift; verpasste Takte entfallen."""
        next_at = time.monotonic()
        while not self.stop_event.is_set():
            yield
            next_at += interval_s
            now = time.monotonic()
            if next_at < now:
                next_at = now + interval_s - ((now - next_at) % interval_s)
            if self.stop_event.wait(max(0.0, next_at - now)):
                return


def check_key(check: dict) -> str:
    """Neu starten, sobald sich etwas am Check ändert (wie CheckConfig.Key)."""
    import json

    return json.dumps({k: check.get(k) for k in ("id", "type", "target", "interval_s", "timeout_ms", "params", "peer")},
                      sort_keys=True)


class PingRunner(Runner):
    def __init__(self, check: dict, sink: Sink, pinger=icmp.ping, gateway=net.gateway):
        super().__init__(check)
        self.sink, self.pinger, self.gateway = sink, pinger, gateway

    def run(self) -> None:
        c = self.check
        interval = max(1, int(c["interval_s"]))
        timeout = _clamp(int(c["timeout_ms"]), 100, interval * 1000)
        size = _clamp(int(_p(c, "size_bytes", 32)), 0, 1472)
        ttl = _clamp(int(_p(c, "ttl", 128)), 1, 255)
        jitter_every = _clamp(int(_p(c, "jitter_window_s", 60)), 10, 3600)
        jitter, next_jitter, last_error = Jitter(), time.monotonic() + jitter_every, ""
        log.info("Ping-Check %s gestartet: %s alle %s s", c["id"], c["target"], interval)
        for _ in self.ticks(interval):
            ts = int(time.time() * 1000)
            address, error = icmp.resolve(c["target"], self.gateway() if c["target"] == "gateway" else None)
            reply = self.pinger(address, timeout, size, ttl) if address else icmp.Reply(False, error=error)
            self.sink(metric("wachtl_ping_up", c["id"], 1 if reply.success else 0, ts))
            if reply.success:
                self.sink(metric("wachtl_ping_rtt_ms", c["id"], reply.rtt_ms, ts))
                if reply.ttl is not None:
                    self.sink(metric("wachtl_ping_ttl", c["id"], reply.ttl, ts))
                jitter.add(reply.rtt_ms)
            if reply.error != last_error:
                if reply.error:
                    log.warning("Ping %s (Check %s): %s", c["target"], c["id"], reply.error)
                elif last_error:
                    log.info("Ping %s (Check %s) wieder erfolgreich", c["target"], c["id"])
                last_error = reply.error
            if time.monotonic() >= next_jitter:
                if (j := jitter.take()) is not None:
                    self.sink(metric("wachtl_ping_jitter_ms", c["id"], j, ts))
                next_jitter += jitter_every
        log.info("Ping-Check %s beendet", c["id"])


def is_private(ip: str) -> bool:
    a = ipaddress.IPv4Address(ip)
    return a.is_private or a in ipaddress.IPv4Network("100.64.0.0/10")


class PathRunner(Runner):
    LOSS_RETRACE_AFTER = 3
    MIN_RETRACE_GAP = 60
    MAX_SILENT_HOPS = 6

    def __init__(self, check: dict, sink: Sink, report: Callable[[dict], None], pinger=icmp.ping,
                 gateway=net.gateway):
        super().__init__(check)
        self.sink, self.report, self.pinger, self.gateway = sink, report, pinger, gateway
        self.retrace = threading.Event()
        self.retrace_reason = "manual"

    def request_retrace(self, reason: str = "manual") -> None:
        self.retrace_reason = reason
        self.retrace.set()

    def trace(self, reason: str) -> dict | None:
        c = self.check
        destination, error = icmp.resolve(c["target"], self.gateway())
        if destination is None:
            log.warning("Pfad-Check %s: %s", c["id"], error)
            return None
        max_hops = _clamp(int(_p(c, "max_hops", 20)), 1, 64)
        attempts = _clamp(int(_p(c, "probes_per_hop", 2)), 1, 5)
        timeout = _clamp(int(_p(c, "trace_timeout_ms", 1000)), 100, 5000)
        hops, reached, silent = [], False, 0
        for ttl in range(1, max_hops + 1):
            if self.stop_event.is_set():
                return None
            hop = {"hop": ttl, "ip": None, "rtt_ms": None}
            for _ in range(attempts):
                r = self.pinger(destination, timeout, 32, ttl)
                if r.success:
                    hop = {"hop": ttl, "ip": r.source or destination, "rtt_ms": r.rtt_ms}
                    reached = True
                    break
                if r.ttl_expired and r.source:
                    hop = {"hop": ttl, "ip": r.source, "rtt_ms": r.rtt_ms}
                    break
            hops.append(hop)
            silent = silent + 1 if hop["ip"] is None else 0
            if reached or silent >= self.MAX_SILENT_HOPS:
                break
        while hops and hops[-1]["ip"] is None:
            hops.pop()
        if not hops:
            hops = [{"hop": 1, "ip": None, "rtt_ms": None}]
        log.info("Pfad-Check %s: %d Hops bis %s, Ziel %s", c["id"], len(hops), c["target"],
                 "erreicht" if reached else "nicht erreicht")
        return {"check_id": c["id"], "ts": int(time.time()), "reason": reason, "reached": reached, "hops": hops}

    def hop_list(self, trace: dict) -> list[tuple[int, str, bool]]:
        c = self.check
        mode = _p(c, "ping_hops", "all")
        first_n = _clamp(int(_p(c, "first_n", 5)), 1, 64)
        skip_private = bool(_p(c, "skip_private", False))
        if mode == "none":
            return []
        out = []
        last = trace["hops"][-1]
        for h in trace["hops"]:
            if not h["ip"]:
                continue
            dest = trace["reached"] and h is last
            if not dest and mode == "first" and h["hop"] > first_n:
                continue
            if not dest and skip_private and is_private(h["ip"]):
                continue
            out.append((h["hop"], h["ip"], dest))
        if not trace["reached"]:
            destination, _ = icmp.resolve(c["target"], self.gateway())
            if destination:
                out.append((min(trace["hops"][-1]["hop"] + 1, 64), destination, True))
        return out

    def run(self) -> None:
        c = self.check
        interval = max(1, int(c["interval_s"]))
        timeout = _clamp(int(c["timeout_ms"]), 100, interval * 1000)
        trace_every = _clamp(int(_p(c, "trace_interval_min", 10)), 1, 1440) * 60
        retrace_on_loss = bool(_p(c, "retrace_on_loss", True))
        size = _clamp(int(_p(c, "hop_size_bytes", 32)), 0, 1472)
        hops: list[tuple[int, str, bool]] = []
        jitters: dict[tuple[int, str], Jitter] = {}
        reason, next_trace, last_trace = "start", 0.0, 0.0
        next_jitter = time.monotonic() + 60
        failures = 0
        log.info("Pfad-Check %s gestartet: %s, Hops alle %s s", c["id"], c["target"], interval)
        with ThreadPoolExecutor(max_workers=16, thread_name_prefix=f"hops-{c['id']}") as pool:
            for _ in self.ticks(interval):
                if self.retrace.is_set():
                    self.retrace.clear()
                    reason, next_trace = self.retrace_reason, 0.0
                if time.monotonic() >= next_trace:
                    result = self.trace(reason)
                    last_trace = time.monotonic()
                    next_trace = last_trace + trace_every
                    reason, failures = "schedule", 0
                    if result is not None:
                        hops = self.hop_list(result)
                        jitters = {(h, ip): jitters.get((h, ip)) or Jitter() for h, ip, _ in hops}
                        threading.Thread(target=self.report, args=(result,), daemon=True).start()
                if not hops or self.stop_event.is_set():
                    continue
                ts = int(time.time() * 1000)
                replies = list(pool.map(lambda h: self.pinger(h[1], timeout, size, 128), hops))
                for (hop, ip, dest), r in zip(hops, replies):
                    self.sink(hop_metric("wachtl_hop_up", c["id"], hop, ip, 1 if r.success else 0, ts))
                    if r.success:
                        self.sink(hop_metric("wachtl_hop_rtt_ms", c["id"], hop, ip, r.rtt_ms, ts))
                        jitters[(hop, ip)].add(r.rtt_ms)
                    if dest:
                        failures = 0 if r.success else failures + 1
                if time.monotonic() >= next_jitter:
                    for (hop, ip), j in jitters.items():
                        if (value := j.take()) is not None:
                            self.sink(hop_metric("wachtl_hop_jitter_ms", c["id"], hop, ip, value, ts))
                    next_jitter += 60
                if retrace_on_loss and failures >= self.LOSS_RETRACE_AFTER and \
                        time.monotonic() - last_trace >= self.MIN_RETRACE_GAP:
                    log.info("Pfad-Check %s: Ziel %s antwortet nicht, Pfad wird neu ermittelt", c["id"], c["target"])
                    reason, next_trace = "loss", 0.0
        log.info("Pfad-Check %s beendet", c["id"])


class ScheduledRunner(Runner):
    """Misst nach Zeitplan (schedule_min, Zeitfenster, Wochentage) oder auf Anforderung „Jetzt messen“."""

    label = "Check"

    def __init__(self, check: dict):
        super().__init__(check)
        self.manual = threading.Event()

    def run_now(self) -> None:
        self.manual.set()

    def _measure_and_report(self, trigger: str) -> None:
        raise NotImplementedError

    def run(self) -> None:
        c = self.check
        log.info("%s %s (%s) gestartet: %s", self.label, c["id"], c["type"], c["target"])
        while not self.stop_event.is_set():
            nxt = schedule.next_run(datetime.now(), int(_p(c, "schedule_min", 60)), int(_p(c, "offset_min", 0)),
                                    _p(c, "window_start", "00:00"), _p(c, "window_end", "23:59"),
                                    str(_p(c, "weekdays", "1234567")))
            wait = (nxt - datetime.now()).total_seconds() if nxt else None
            # lange Wartezeiten stückeln (Zeitumstellung, Ruhezustand)
            if wait is None or wait > 300:
                if self._wait_manual(300):
                    self._measure_and_report("manual")
                continue
            manual = self._wait_manual(max(0.0, wait))
            if self.stop_event.is_set():
                break
            self._measure_and_report("manual" if manual else "schedule")
            if not manual:
                self.stop_event.wait(61)     # nicht zweimal im selben Takt
        log.info("%s %s beendet", self.label, c["id"])

    def _wait_manual(self, seconds: float) -> bool:
        deadline = time.monotonic() + seconds
        while not self.stop_event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if self.manual.wait(min(remaining, 1.0)):
                self.manual.clear()
                return True
        return False



class BandwidthRunner(ScheduledRunner):
    """Bandbreite; je Probe immer nur eine Bandbreitenmessung gleichzeitig."""

    label = "Bandbreiten-Check"
    one_at_a_time = threading.Lock()

    def __init__(self, check: dict, report: Callable[[dict], None], iperf_exe: str | None = None,
                 measure: Callable[[dict], list[dict]] | None = None):
        super().__init__(check)
        self.report = report
        self.measure = measure or (lambda c: bandwidth.measure(c, iperf_exe))

    def _measure_and_report(self, trigger: str) -> None:
        with self.one_at_a_time:
            log.info("Bandbreiten-Check %s: Messung startet (%s)", self.check["id"], trigger)
            ts = int(time.time())
            results = self.measure(self.check)
        for r in results:
            if r.get("error"):
                log.warning("Bandbreiten-Check %s: %s fehlgeschlagen: %s", self.check["id"], r["direction"], r["error"])
            else:
                log.info("Bandbreiten-Check %s: %s %s Mbit/s", self.check["id"], r["direction"], r.get("mbps"))
        if results:
            self.report({"check_id": self.check["id"], "ts": ts, "trigger": trigger, "results": results})


class RtpRunner(ScheduledRunner):
    """Sprachtest (RTP); läuft unabhängig von Bandbreitenmessungen – Sprache unter Last ist aufschlussreich."""

    label = "Sprachtest"

    def __init__(self, check: dict, report: Callable[[dict], None], measure: Callable[[dict], dict] | None = None):
        super().__init__(check)
        self.report = report
        self.measure = measure or (lambda c: measure_rtp(c, self.stop_event))

    def _measure_and_report(self, trigger: str) -> None:
        log.info("Sprachtest %s: Test startet (%s)", self.check["id"], trigger)
        ts = int(time.time())
        result = self.measure(self.check)
        if self.stop_event.is_set():
            return
        if result.get("error"):
            log.warning("Sprachtest %s fehlgeschlagen: %s", self.check["id"], result["error"])
        else:
            log.info("Sprachtest %s: MOS %s, Laufzeit %s ms, Verlust %s %%, Jitter %s ms", self.check["id"],
                     result.get("mos"), result.get("rtt_ms"), result.get("loss_pct"), result.get("jitter_ms"))
        self.report({"check_id": self.check["id"], "ts": ts, "trigger": trigger, "result": result})


def measure_rtp(check: dict, stop: threading.Event | None = None) -> dict:
    from ..rtp import stream

    peer = check.get("peer") or {}
    codec, ptime = str(_p(check, "codec", "g711")), int(_clamp(int(_p(check, "ptime_ms", 20)), 10, 60))
    duration = int(_clamp(int(_p(check, "duration_s", 30)), 5, 300))
    if peer.get("error") or not peer.get("host"):
        return {"codec": codec, "ptime_ms": ptime, "duration_s": duration,
                "error": peer.get("error") or "Gegenstelle unbekannt"}
    return stream.run(peer["host"], int(peer.get("port") or 5004), codec, ptime, duration,
                      int(_clamp(int(_p(check, "dscp", 46)), 0, 63)), stop)
