"""Bandbreitenmessung der Server-Probe: iperf3 (Programm) und HTTP-Speedtest – wie Iperf.cs / HttpSpeedTest.cs."""
from __future__ import annotations

import json
import os
import random
import shutil
import statistics
import subprocess
import threading
import time
from urllib.parse import urlparse

import requests

from .. import __version__

WARMUP_S = 1.0


def find_iperf(configured: str | None = None) -> str | None:
    for candidate in (configured, os.environ.get("WACHTL_IPERF_EXE"), shutil.which("iperf3")):
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def iperf_args(host: str, port: int, protocol: str, duration: int, omit: int, streams: int, udp_mbps: float,
               window_kb: int, reverse: bool) -> list[str]:
    args = ["-c", host, "-p", str(port), "-J", "-t", str(duration), "-P", str(max(1, min(32, streams))),
            "--connect-timeout", "5000"]
    if omit > 0:
        args += ["-O", str(omit)]
    if protocol == "udp":
        args += ["-u", "-b", f"{udp_mbps:g}M"]
    elif window_kb > 0:
        args += ["-w", f"{window_kb}K"]
    if reverse:
        args.append("-R")
    return args


def parse_iperf(output: str, protocol: str, result: dict) -> None:
    if not output.strip():
        result.setdefault("error", "keine Ausgabe von iperf3")
        return
    try:
        data = json.loads(output)
    except ValueError as exc:
        result["error"] = f"iperf3-Ausgabe nicht lesbar: {exc}"
        return
    if isinstance(data.get("error"), str):
        result["error"] = data["error"]
        return
    end = data.get("end")
    if not isinstance(end, dict):
        result["error"] = "iperf3-Ergebnis unvollständig"
        return
    if protocol == "udp":
        sr = end.get("sum_received") or {}
        summary = sr if "bits_per_second" in sr else end.get("sum", {})
        stats = end.get("sum") or summary
        result["jitter_ms"] = stats.get("jitter_ms")
        result["loss_pct"] = stats.get("lost_percent")
    else:
        summary = end.get("sum_received") or {}
        if isinstance((end.get("sum_sent") or {}).get("retransmits"), (int, float)):
            result["retransmits"] = int(end["sum_sent"]["retransmits"])
    if isinstance(summary.get("bits_per_second"), (int, float)):
        result["mbps"] = round(summary["bits_per_second"] / 1_000_000, 2)
    if isinstance(summary.get("seconds"), (int, float)):
        result["duration_s"] = round(summary["seconds"], 1)


def run_iperf(exe: str | None, host: str, port: int, protocol: str, direction: str, duration: int, omit: int,
              streams: int, udp_mbps: float, window_kb: int, timeout: int, stop: threading.Event | None = None) -> dict:
    result = {"direction": direction, "protocol": protocol, "peer": f"{host}:{port}"}
    if exe is None:
        result["error"] = "iperf3 nicht gefunden (auf dem Server installieren)"
        return result
    args = [exe] + iperf_args(host, port, protocol, duration, omit, streams, udp_mbps, window_kb, direction == "down")
    for attempt in range(4):
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=max(timeout, duration + 15))
            out, err, code = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            out, err, code = "", f"Abbruch nach {max(timeout, duration + 15)} s – Gegenstelle antwortet nicht", -1
        except OSError as exc:
            out, err, code = "", f"iperf3 nicht ausführbar: {exc}", -1
        result.pop("error", None)
        parse_iperf(out, protocol, result)
        if "error" not in result and code != 0 and result.get("mbps") is None:
            result["error"] = err.strip() or f"iperf3 beendet mit Code {code}"
        if "busy" in str(result.get("error", "")).lower() and attempt < 3:
            # ein iperf3-Server nimmt nur einen Test gleichzeitig an
            if stop is not None and stop.wait(20 + random.random() * 30):
                return result
            continue
        return result
    return result


class HttpSpeedTest:
    def __init__(self, use_proxy: bool):
        self.session = requests.Session()
        self.session.trust_env = use_proxy      # HTTPS_PROXY nur, wenn der Check es erlaubt
        self.session.headers["User-Agent"] = f"wachtl-serverprobe/{__version__}"

    def latency(self, url: str) -> float | None:
        samples = []
        for i in range(6):
            start = time.perf_counter()
            try:
                with self.session.get(url, timeout=5, stream=True) as r:
                    elapsed = (time.perf_counter() - start) * 1000
                    if i > 0 and r.ok:       # erste Anfrage baut nur die Verbindung auf
                        samples.append(elapsed)
            except requests.RequestException:
                pass
        return round(statistics.median(samples), 1) if samples else None

    def _measure(self, streams: int, duration: int, transfer, deadline: float) -> tuple[float | None, float, str | None]:
        counter = [0]
        lock = threading.Lock()
        errors: list[str] = []
        stop_at = time.monotonic() + max(2, duration) + WARMUP_S
        stop_at = min(stop_at, deadline)

        def add(n: int) -> None:
            with lock:
                counter[0] += n

        def worker():
            while time.monotonic() < stop_at:
                try:
                    transfer(add, stop_at)
                except requests.RequestException as exc:
                    errors.append(str(exc))
                    time.sleep(0.5)

        start = time.monotonic()
        threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, min(32, streams)))]
        for t in threads:
            t.start()
        time.sleep(min(WARMUP_S, max(0.0, stop_at - time.monotonic())))
        with lock:
            warm_bytes, warm_at = counter[0], time.monotonic()
        for t in threads:
            t.join(timeout=max(1.0, stop_at - time.monotonic() + 15))
        seconds = time.monotonic() - warm_at
        measured = counter[0] - warm_bytes
        mbps = measured * 8 / seconds / 1_000_000 if seconds > 0 and measured > 0 else None
        return mbps, time.monotonic() - start, errors[0] if errors else None

    def download(self, url: str, streams: int, duration: int, deadline: float) -> dict:
        result = {"direction": "down", "protocol": "http", "peer": urlparse(url).hostname or url}
        status_error: list[str] = []

        def transfer(add, stop_at):
            with self.session.get(url, stream=True, timeout=10) as r:
                if not r.ok:
                    status_error.append(f"HTTP {r.status_code} von {result['peer']}")
                    time.sleep(0.5)
                    return
                for chunk in r.iter_content(64 * 1024):
                    add(len(chunk))
                    if time.monotonic() >= stop_at:
                        return

        mbps, seconds, error = self._measure(streams, duration, transfer, deadline)
        return _finish(result, mbps, seconds, (status_error or [None])[0] or error)

    def upload(self, url: str, streams: int, duration: int, deadline: float) -> dict:
        result = {"direction": "up", "protocol": "http", "peer": urlparse(url).hostname or url}
        chunk = os.urandom(64 * 1024)
        status_error: list[str] = []

        def transfer(add, stop_at):
            def body():
                sent = 0
                while sent < 16 * 1024 * 1024 and time.monotonic() < stop_at:
                    yield chunk
                    sent += len(chunk)
                    add(len(chunk))

            r = self.session.post(url, data=body(), timeout=30, headers={"Content-Type": "application/octet-stream"})
            if not r.ok:
                status_error.append(f"HTTP {r.status_code} von {result['peer']}")
                time.sleep(0.5)

        mbps, seconds, error = self._measure(streams, duration, transfer, deadline)
        return _finish(result, mbps, seconds, (status_error or [None])[0] or error)


def _finish(result: dict, mbps: float | None, seconds: float, error: str | None) -> dict:
    result["duration_s"] = round(seconds, 1)
    if mbps and mbps > 0:
        result["mbps"] = round(mbps, 2)
    else:
        result["error"] = error or "keine Daten übertragen"
    return result


def measure(check: dict, iperf_exe: str | None = None, stop: threading.Event | None = None) -> list[dict]:
    p = check.get("params") or {}
    direction = p.get("direction", "both")
    directions = ["down", "up"] if direction == "both" else [direction]
    use_iperf = check["type"] == "iperf" or p.get("method", "http") == "iperf"
    if use_iperf:
        protocol = p.get("protocol", "tcp")
        peer = check.get("peer") or {}
        if peer.get("error") or not peer.get("host"):
            return [{"direction": d, "protocol": protocol, "error": peer.get("error") or "Gegenstelle unbekannt"}
                    for d in directions]
        exe = find_iperf(iperf_exe)
        return [run_iperf(exe, peer["host"], int(peer.get("port") or 5201), protocol, d,
                          max(1, min(120, int(p.get("duration_s", 10)))), max(0, min(30, int(p.get("omit_s", 1)))),
                          int(p.get("streams", 1)), float(p.get("udp_mbps", 100)), int(p.get("window_kb", 0)),
                          max(10, min(600, int(p.get("timeout_s", 60)))), stop) for d in directions]
    test = HttpSpeedTest(bool(p.get("use_proxy")))
    duration = max(2, min(120, int(p.get("duration_s", 10))))
    streams = max(1, min(32, int(p.get("streams", 4))))
    deadline = time.monotonic() + max(10, min(600, int(p.get("timeout_s", 90))))
    latency = test.latency(p["latency_url"]) if p.get("latency_url") else None
    out = []
    for d in directions:
        url = p.get("down_url" if d == "down" else "up_url") or ""
        if not url:
            continue
        if time.monotonic() >= deadline:
            out.append({"direction": d, "protocol": "http", "error": "Abbruch: Zeitlimit des Checks erreicht"})
            continue
        m = test.download(url, streams, duration, deadline) if d == "down" else test.upload(url, streams, duration, deadline)
        m["latency_ms"] = latency
        out.append(m)
    return out
