"""Netzwerkkarten des Wachtl-Servers überwachen: deaktiviert, Kabel getrennt, entfernt (wie AdapterReader.cs und
FindingEvaluator.cs der Windows-Probe, im kleinen Umfang).

Gelesen wird der Geräte-Manager (WMI ``Win32_NetworkAdapter``) über PowerShell – nur unter Windows. Daraus entstehen
Client-Hinweise im Format von ``POST /api/probe/v1/findings`` (docs/CLIENT-HINWEISE.md): sofort im Tray-Symbol
auf dem Server und im Web-UI unter Alarme › Hinweise der PCs.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess

log = logging.getLogger("wachtl.serverprobe.adapters")

UP, DISABLED, UNPLUGGED, DOWN = "up", "disabled", "unplugged", "down"

_PS = (
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
    "Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionID } | "
    "Select-Object GUID, NetConnectionID, Name, PhysicalAdapter, NetEnabled, NetConnectionStatus, "
    "ConfigManagerErrorCode | ConvertTo-Json -Compress"
)


def parse_wmi(text: str) -> list[dict]:
    """Ausgabe von ``ConvertTo-Json`` (ein Objekt oder eine Liste) → Karten mit Zustand."""
    data = json.loads(text) if text.strip() else []
    rows = data if isinstance(data, list) else [data]
    out = []
    for r in rows:
        if not isinstance(r, dict) or not r.get("NetConnectionID"):
            continue
        error = int(r.get("ConfigManagerErrorCode") or 0)
        status = r.get("NetConnectionStatus")
        if error == 22 or r.get("NetEnabled") is False:
            state = DISABLED
        elif status == 2:
            state = UP
        elif status == 7:                    # Medium getrennt: Kabel ab bzw. Gegenstelle aus
            state = UNPLUGGED
        else:
            state = DOWN
        out.append({"id": str(r.get("GUID") or r["NetConnectionID"]).strip("{}").lower(),
                    "name": str(r["NetConnectionID"]), "description": str(r.get("Name") or ""),
                    "physical": bool(r.get("PhysicalAdapter")), "state": state})
    return out


def read() -> list[dict] | None:
    """Karten aus dem Geräte-Manager; None, wenn nicht lesbar (kein Windows, PowerShell fehlt, Zeitüberschreitung)."""
    if os.name != "nt":
        return None
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS], capture_output=True,
                              timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if proc.returncode != 0:
            return None
        return parse_wmi(proc.stdout.decode("utf-8", errors="replace"))
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        log.debug("Netzwerkkarten nicht lesbar: %s", exc)
        return None


def _duration(seconds: float) -> str:
    seconds = max(int(seconds), 0)
    if seconds < 60:
        return f"{seconds} s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {seconds} s" if seconds else f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


def _paren(description: str, name: str) -> str:
    return f" ({description})" if description and description != name else ""


class AdapterWatch:
    """Merkt sich die Karten und liefert bei jeder Zustandsänderung einen Client-Hinweis.

    Gemeldet werden nur Karten, die in dieser Laufzeit schon einmal verbunden waren – ein seit jeher freier Port
    ist kein Problem. Ohne lesbaren Geräte-Manager bleibt alles beim Alten (nie falsch alarmieren).
    """

    def __init__(self):
        self.known: dict[str, dict] = {}     # Karten-ID → {"name", "description", "state", "since"}
        self.open: dict[str, dict] = {}      # Karten-ID → aktiver Hinweis

    def update(self, adapters: list[dict] | None, now: float) -> list[dict]:
        if adapters is None:
            return []
        current = {a["id"]: a for a in adapters}
        changes: list[dict] = []
        up = [a for a in adapters if a["state"] == UP]
        for aid, old in list(self.known.items()):
            a = current.get(aid)
            state = a["state"] if a else "removed"
            if state == old["state"]:
                continue
            old.update(state=state, since=now)
            if a:
                old.update(name=a["name"], description=a["description"])
            finding = self.open.pop(aid, None)
            if finding:
                changes.append(self._resolved(finding, now))
            if state in (DISABLED, UNPLUGGED, "removed"):
                fallback = next((u["name"] for u in up if u["id"] != aid), None)
                finding = self._active(aid, old, state, fallback, now)
                self.open[aid] = finding
                changes.append(finding)
        for a in adapters:
            if a["id"] not in self.known and a["state"] == UP:
                self.known[a["id"]] = {"name": a["name"], "description": a["description"], "state": UP, "since": now}
        return changes

    @property
    def offline_explained(self) -> bool:
        """Ein aktiver Hinweis, nach dem der PC kein Netz mehr hat (keine andere Karte verbunden)."""
        return any(f["severity"] == "critical" for f in self.open.values())

    @staticmethod
    def _active(aid: str, a: dict, state: str, fallback: str | None, now: float) -> dict:
        name, desc = a["name"], a["description"]
        tail = (" Der Server hat damit keine Netzwerkverbindung mehr – Gateway, Internet und alle Ziele sind von hier "
                "aus nicht erreichbar." if fallback is None else f" Die Verbindung läuft vorerst über „{fallback}“ weiter.")
        short = ", der Server hat kein Netzwerk mehr." if fallback is None else f", die Verbindung läuft über „{fallback}“."
        if state == DISABLED:
            kind, title = "adapter_disabled", "Netzwerkkarte deaktiviert"
            message = f"Die Netzwerkkarte „{name}“{_paren(desc, name)} wurde in Windows deaktiviert." + tail
            solution = ("Netzwerkkarte wieder aktivieren: Einstellungen › Netzwerk und Internet › Erweiterte "
                        "Netzwerkeinstellungen, bei der Karte „Aktivieren“ wählen (oder im Geräte-Manager: Rechtsklick › "
                        "Gerät aktivieren).")
            balloon = f"„{name}“ wurde deaktiviert{short}\nLösung: Netzwerkkarte wieder aktivieren."
        elif state == UNPLUGGED:
            kind, title = "cable_unplugged", "Netzwerkkabel getrennt"
            message = f"Die Netzwerkkarte „{name}“{_paren(desc, name)} hat keine Verbindung mehr (kein Link)." + tail
            solution = ("Netzwerkkabel am Server und am Switch prüfen (Stecker fest, Link-LED an), ggf. anderes Kabel "
                        "oder anderen Switch-Port testen.")
            balloon = f"„{name}“ hat keinen Link{short}\nLösung: Netzwerkkabel und Switch-Port prüfen."
        else:
            kind, title = "adapter_removed", "Netzwerkkarte entfernt"
            message = (f"Die Netzwerkkarte „{name}“{_paren(desc, name)} ist nicht mehr vorhanden (abgezogen oder vom "
                       "Treiber abgemeldet)." + tail)
            solution = "USB-Netzwerkadapter bzw. Dockingstation wieder anschließen, im Geräte-Manager Treiber prüfen."
            balloon = f"„{name}“ ist nicht mehr vorhanden{short}"
        return {
            "finding_id": f"{kind}:{aid}"[:128], "kind": kind, "severity": "critical" if fallback is None else "warning",
            "state": "active", "adapter": name, "adapter_description": desc, "title": title, "message": message,
            "solution": solution, "balloon": balloon[:255], "detected_at": int(now), "resolved_at": None,
            "details": {},
        }

    @staticmethod
    def _resolved(finding: dict, now: float) -> dict:
        name, took = finding["adapter"], _duration(now - finding["detected_at"])
        if finding["kind"] == "adapter_disabled":
            title, message = "Netzwerkkarte wieder aktiviert", f"Die Netzwerkkarte „{name}“ ist wieder aktiviert (deaktiviert für {took})."
        elif finding["kind"] == "cable_unplugged":
            title, message = "Netzwerkkabel wieder verbunden", f"Die Netzwerkkarte „{name}“ ist wieder verbunden (Unterbrechung {took})."
        else:
            title, message = "Netzwerkkarte wieder da", f"Die Netzwerkkarte „{name}“ ist wieder vorhanden (fehlte {took})."
        return {**finding, "state": "resolved", "title": title, "message": message, "solution": "",
                "balloon": message[:255], "resolved_at": int(now), "details": {"problem": finding["title"]}}
