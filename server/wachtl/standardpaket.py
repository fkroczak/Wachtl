"""Standardpaket: fertige Checks für einen neuen Kunden oder Standort mit einem Klick.

Gedacht für den Rollout durch Kollegen ohne tiefe Netzwerkkenntnisse: Ping auf Gateway, Internet und
Wachtl-Server, Traceroute ins Internet und zum Server, iperf3 zum Server und ein WAN-Speedtest.
Bereits vorhandene Checks gleicher Art und gleichen Ziels werden nicht doppelt angelegt.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import checktypes, repo
from .db import q

SERVER = "{server}"   # Platzhalter für den Hostnamen aus der Server-URL


@dataclass(frozen=True)
class Item:
    key: str
    ctype: str
    name: str
    target: str
    description: str
    role: str = "target"
    interval_s: int = 1
    timeout_ms: int = 1000
    params: dict = field(default_factory=dict)


ITEMS: tuple[Item, ...] = (
    Item("ping_gateway", "ping", "Gateway", "gateway",
         "Dauerping auf den Router des Standorts. Fällt er aus, liegt das Problem im LAN.", role="gateway"),
    Item("ping_cloudflare", "ping", "Cloudflare DNS", "1.1.1.1", "Internet-Referenz 1", role="reference"),
    Item("ping_google", "ping", "Google DNS", "8.8.8.8", "Internet-Referenz 2", role="reference"),
    Item("ping_quad9", "ping", "Quad9 DNS", "9.9.9.9",
         "Internet-Referenz 3 – sind alle Referenzen weg, meldet Wachtl „WAN gestört“.", role="reference"),
    Item("ping_server", "ping", "Wachtl-Server", SERVER,
         "Erreichbarkeit des Wachtl-Servers vom Standort aus (VPN, Standortkopplung).", interval_s=5),
    Item("path_internet", "path", "Traceroute Internet", "1.1.1.1",
         "Weg ins Internet Hop für Hop, jeder Hop alle 5 s angepingt (wie MTR).", interval_s=5,
         params={"trace_interval_min": 10}),
    Item("path_server", "path", "Traceroute Wachtl-Server", SERVER,
         "Weg vom Standort zum Wachtl-Server.", interval_s=5, params={"trace_interval_min": 15}),
    Item("iperf_server", "iperf", "iperf3 zum Wachtl-Server", "",
         "Durchsatz LAN/VPN zwischen Probe und Server, TCP in beide Richtungen, alle 6 Stunden.",
         params={"peer": "server", "protocol": "tcp", "direction": "both", "duration_s": 10, "streams": 4,
                 "schedule_min": 360}),
    Item("speedtest_wan", "speedtest", "Speedtest Internet", "",
         "Download und Upload ins Internet (Cloudflare), alle 6 Stunden.",
         params={"method": "http", "direction": "both", "duration_s": 10, "streams": 4, "schedule_min": 360}),
)
BY_KEY = {i.key: i for i in ITEMS}


def server_host(public_url: str) -> str | None:
    host = urlparse(public_url or "").hostname or ""
    return host if host and repo.valid_target(host) and host not in ("localhost", "wachtl.local") else None


def resolve(item: Item, public_url: str) -> tuple[str, dict] | None:
    """Ziel und vollständige Parameter eines Eintrags; None, wenn der Server-Hostname unbekannt ist."""
    params = checktypes.merged(item.ctype, item.params)
    if item.ctype in checktypes.SCHEDULED_TYPES:
        return checktypes.target_for(item.ctype, params), params
    target = item.target
    if target == SERVER:
        target = server_host(public_url)
        if target is None:
            return None
    return target, params


def _exists(ctype: str, target: str, params: dict) -> bool:
    for c in q("SELECT type, target, params FROM checks WHERE type = ?", (ctype,)):
        if c["target"] != target:
            continue
        if ctype == "speedtest":
            other = checktypes.merged(ctype, json.loads(c["params"] or "{}"))
            if other.get("method") != params.get("method"):
                continue
        return True
    return False


def preview(public_url: str) -> list[dict]:
    """Einträge mit Ziel und Hinweis, ob es den Check schon gibt (für das Formular)."""
    out = []
    for item in ITEMS:
        resolved = resolve(item, public_url)
        target, params = resolved if resolved else ("", {})
        out.append({
            "item": item, "target": target, "available": resolved is not None,
            "exists": bool(resolved) and _exists(item.ctype, target, params),
            "summary": checktypes.summary({"type": item.ctype, "interval_s": item.interval_s}, params) if resolved else "",
        })
    return out


def apply(keys: list[str], scope: str, scope_id: int | None, public_url: str) -> tuple[list[tuple[int, Item]], list[str]]:
    """Ausgewählte Einträge anlegen. Gibt (angelegt, übersprungen mit Grund) zurück."""
    created, skipped = [], []
    for key in keys:
        item = BY_KEY.get(key)
        if item is None:
            continue
        resolved = resolve(item, public_url)
        if resolved is None:
            skipped.append(f"{item.name}: Hostname des Servers unbekannt (Server-URL prüfen)")
            continue
        target, params = resolved
        if _exists(item.ctype, target, params):
            skipped.append(f"{item.name}: gibt es schon")
            continue
        if item.ctype in checktypes.SCHEDULED_TYPES:
            interval, timeout = params["schedule_min"] * 60, params["timeout_s"] * 1000
        else:
            interval, timeout = item.interval_s, item.timeout_ms
        role = item.role if item.ctype == "ping" else checktypes.ROLE_DEFAULT[item.ctype]
        cid = repo.create_check(item.name, target, role, interval, timeout, scope, scope_id, item.ctype, params)
        created.append((cid, item))
    return created, skipped
