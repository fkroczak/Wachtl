"""UI-Guardrails ohne Browser: Semantik, Formular-Beschriftungen und Farbkontraste.

Läuft mit pytest im normalen Server-Job und blockiert den Merge. Ergänzt die Browser-Tests unter
server/e2e (axe-core, Tastatur, Reflow) – siehe docs/quality-guardrails.md.
"""
from __future__ import annotations

import json
import os
import re
from html.parser import HTMLParser
from unittest import mock

from wachtl import checktypes, repo
from wachtl.db import ins
from wachtl.services import alerts

from .helpers import AppTestCase

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
CONTROLS = {"input", "select", "textarea"}


class _Node:
    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children: list = []
        self.text: list[str] = []

    def all_text(self) -> str:
        parts = list(self.text)
        for c in self.children:
            if isinstance(c, _Node) and "aria-hidden" not in c.attrs:
                parts.append(c.all_text())
        return " ".join(" ".join(parts).split())

    def name(self) -> str:
        """Zugänglicher Name (vereinfacht): aria-label, aria-labelledby wird separat geprüft, sonst Text."""
        if self.attrs.get("aria-label"):
            return self.attrs["aria-label"]
        if self.tag == "img":
            return self.attrs.get("alt") or ""
        imgs = [c for c in self.walk() if c.tag == "img" and c.attrs.get("alt")]
        return self.all_text() or (imgs[0].attrs["alt"] if imgs else "")

    def walk(self):
        for c in self.children:
            yield c
            yield from c.walk()

    def ancestors(self):
        n = self.parent
        while n is not None:
            yield n
            n = n.parent

    def hidden(self) -> bool:
        return any("hidden" in n.attrs for n in [self, *self.ancestors()])


class _Tree(HTMLParser):
    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.root = _Node("#root", [], None)
        self.cur = self.root
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, attrs, self.cur)
        self.cur.children.append(node)
        if tag not in VOID:
            self.cur = node

    def handle_endtag(self, tag):
        n = self.cur
        while n is not self.root and n.tag != tag:
            n = n.parent
        if n is not self.root:
            self.cur = n.parent

    def handle_data(self, data):
        if self.cur.tag not in ("script", "style"):
            self.cur.text.append(data)


def lint(html: str) -> list[str]:
    """Statische Prüfungen auf gerendertem HTML. Liefert verständliche Fehlertexte."""
    root = _Tree(html).root
    nodes = list(root.walk())
    problems: list[str] = []
    ids = [n.attrs["id"] for n in nodes if n.attrs.get("id")]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        problems.append(f"doppelte id: {sorted(dupes)}")
    idset = set(ids)
    html_el = next((n for n in nodes if n.tag == "html"), None)
    if not html_el or html_el.attrs.get("lang") != "de":
        problems.append('<html lang="de"> fehlt')
    if not any(n.tag == "title" and n.all_text() for n in nodes):
        problems.append("<title> fehlt")
    mains = [n for n in nodes if n.tag == "main"]
    if len(mains) != 1:
        problems.append(f"genau ein <main> erwartet, gefunden {len(mains)}")

    headings = [(int(n.tag[1]), n.all_text()) for n in nodes if re.fullmatch(r"h[1-6]", n.tag)]
    if [h for h in headings if h[0] == 1].__len__() != 1:
        problems.append(f"genau eine h1 erwartet: {[h for h in headings if h[0] == 1]}")
    last = 0
    for level, text in headings:
        if level > last + 1:
            problems.append(f"Überschrift springt von h{last} auf h{level}: „{text}“")
        last = level
        if not text:
            problems.append(f"leere h{level}")

    navs = [n for n in nodes if n.tag == "nav"]
    if len(navs) > 1 and any(not n.attrs.get("aria-label") for n in navs):
        problems.append("mehrere <nav> ohne aria-label")

    labels_for = {n.attrs.get("for") for n in nodes if n.tag == "label"}
    for n in nodes:
        if n.tag in CONTROLS and n.attrs.get("type") not in ("hidden", "submit", "button"):
            wrapped = any(a.tag == "label" for a in n.ancestors())
            named = (n.attrs.get("id") in labels_for or wrapped or n.attrs.get("aria-label")
                     or n.attrs.get("aria-labelledby"))
            if not named:
                problems.append(f"Formularfeld ohne Beschriftung: <{n.tag} name={n.attrs.get('name')}>")
            if n.attrs.get("placeholder") is not None and not named:
                problems.append(f"Platzhalter ersetzt kein Label: {n.attrs.get('name')}")
        for attr in ("aria-describedby", "aria-labelledby", "for"):
            if attr in n.attrs and (n.tag == "label" or attr != "for"):
                missing = [i for i in (n.attrs[attr] or "").split() if i not in idset]
                if missing:
                    problems.append(f"{attr} verweist auf fehlende id {missing} (<{n.tag}>)")
        if n.tag in ("button", "a") and not n.name() and "hidden" not in n.attrs:
            problems.append(f"<{n.tag}> ohne zugänglichen Namen: {n.attrs}")
        if n.tag == "a" and n.name().lower() in ("hier", "klicken", "mehr", "link", "hier klicken"):
            problems.append(f"nichtssagender Linktext: „{n.name()}“")
        if n.tag == "img" and "alt" not in n.attrs:
            problems.append(f"<img> ohne alt: {n.attrs.get('src')}")
        if n.tag == "th" and not n.all_text():
            problems.append("leerer Tabellenkopf <th> (Text oder <span class=sr-only> ergänzen)")
        if n.tag == "fieldset" and not any(c.tag == "legend" for c in n.children):
            problems.append("<fieldset> ohne <legend>")
        if n.attrs.get("aria-invalid") == "true" and not any(
                i.endswith("-error") for i in (n.attrs.get("aria-describedby") or "").split()):
            problems.append(f"aria-invalid ohne verknüpfte Fehlermeldung: {n.attrs.get('name')}")
        if n.attrs.get("tabindex", "0").lstrip("-").isdigit() and int(n.attrs.get("tabindex", "0")) > 0:
            problems.append(f"positiver tabindex verändert die Fokusreihenfolge: <{n.tag}>")
    return problems


class LintSelfTest(AppTestCase):
    """Der Linter selbst muss typische Fehler erkennen."""

    def test_detects_common_problems(self):
        bad = ('<html><head></head><body><main><h1>A</h1><h3>B</h3><input name="x"><th></th>'
               '<a href="/"></a><img src="a.png"><input aria-describedby="nope" aria-label="y"></main></body></html>')
        text = "\n".join(lint(bad))
        for expected in ("lang", "title", "springt von h1 auf h3", "ohne Beschriftung", "leerer Tabellenkopf",
                         "ohne zugänglichen Namen", "ohne alt", "fehlende id"):
            self.assertIn(expected, text)


class PageSemanticsTest(AppTestCase):
    """Alle Seitentypen mit realistischen Daten rendern und statisch prüfen."""

    def setUp(self):
        super().setUp()
        self.probe = self.enroll("PC-EMPFANG")
        self.make_user()
        self.make_user("leser", "readonly")  # Admin-Seite zeigt so auch das Formular „Passwort zurücksetzen“
        self.login()
        now = repo.now()
        self.path = repo.create_check("Pfad", "1.1.1.1", "target", 1, 1000, "all", None, "path",
                                      checktypes.merged("path", {}))
        self.wan = repo.create_check("WAN", "", "target", 1, 1000, "all", None, "speedtest",
                                     checktypes.merged("speedtest", {}))
        pid = self.probe["probe_id"]
        hops = [{"hop": 1, "ip": "192.168.1.1"}, {"hop": 2, "ip": None}, {"hop": 3, "ip": "1.1.1.1"}]
        ins("INSERT INTO path_runs (probe_id, check_id, first_ts, ts, reason, reached, hops, path_hash, changed) "
            "VALUES (?, ?, ?, ?, '', TRUE, ?, 'x', FALSE)", (pid, self.path, now - 600, now, json.dumps(hops)))
        ins("INSERT INTO bandwidth_runs (probe_id, check_id, ts, kind, direction, peer, protocol, mbps, retransmits, "
            "trigger) VALUES (?, ?, ?, 'speedtest', 'down', 'x', 'http', 240, 0, 'schedule')", (pid, self.wan, now))
        alerts.store_webhook({"alerts": [
            {"status": "firing", "fingerprint": "f1", "startsAt": "2026-10-16T08:00:00Z",
             "labels": {"alertname": "WachtlTargetDown", "severity": "critical", "kind": "target_down",
                        "probe": str(pid), "probe_name": "PC-EMPFANG", "site": "1", "site_name": "Zentrale",
                        "check_id": "1", "target": "8.8.8.8", "role": "target"},
             "annotations": {"summary": "8.8.8.8 von PC-EMPFANG (Zentrale) nicht erreichbar"}},
            {"status": "firing", "fingerprint": "f2", "startsAt": "2026-10-16T08:00:00Z",
             "labels": {"alertname": "WachtlPacketLoss", "severity": "warning", "probe": str(pid)},
             "annotations": {"summary": "Paketverlust"}}]})
        auth = {"Authorization": f"Bearer {self.probe['token']}"}
        for i, (cat, desc) in enumerate((("slow", "Teams-Call ruckelt <b>stark</b>"), ("no_connection", ""))):
            r = self.client.post("/api/probe/v1/report", headers=auth, json={
                "report_id": f"00000000-0000-4000-8000-00000000000{i}", "occurred_at": now - 600 * (i + 1),
                "category": cat, "duration": "minutes", "description": desc, "user": "KUNDE\\mmuster"})
            self.assertEqual(r.status_code, 201, r.get_json())
        self.client.post("/meldungen/2/status", data={"csrf_token": self.session_csrf(), "action": "done",
                                                        "note": "Router neu gestartet"})
        live = {(str(pid), "1"): {"up": 1, "rtt": 0.4, "loss": 0}, (str(pid), "2"): {"up": 0, "rtt": None, "loss": 100}}
        from tests.test_incidents import series
        w0 = now - 700
        raw = dict([series(w0, now - 400, target="192.168.1.1", role="gateway", check_id="1"),
                    series(w0, now - 400, down=[(now - 600, now - 590)], target="8.8.8.8", check_id="2"),
                    series(w0, now - 400, down=[(now - 600, now - 590)], target="8.8.8.8", check_id="3", hop="02")])
        for target, value in (("wachtl.services.vm.live_status", live), ("wachtl.services.vm.hop_table", {}),
                              ("wachtl.services.vm.window_series", raw),
                              ("wachtl.services.vm.loss_lanes", {"target": [(now - 900, 0.05)]})):
            p = mock.patch(target, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def pages(self):
        pid = self.probe["probe_id"]
        now = repo.now()
        return ["/", "/?range=7d", "/zustand", "/stoerungen", f"/stoerungen/1/{now - 600}/{now - 590}",
                f"/stoerungen/1/{now - 600}/0", "/sites/1", f"/probes/{pid}", f"/probes/{pid}/checks/1", f"/probes/{pid}/path/{self.path}",
                f"/probes/{pid}/path/{self.path}/hop/1", f"/probes/{pid}/bandwidth/{self.wan}", "/alerts", "/outages",
                "/admin", "/admin?tab=pcs", "/admin?tab=alarme", "/admin?tab=system", "/verlauf",
                "/verlauf?tag=2020-01-01", "/admin/audit", "/account", "/account/design", "/meldungen", "/meldungen?status=all",
                f"/probes/{pid}/checks/1?at={repo.now() - 600}", "/standorte", "/hinweise"] \
            + [f"/admin/checks/new/{t}" for t in checktypes.TYPES] \
            + [f"/probes?tab={t}" for t in ("probleme", "alle", "bandbreite", "sprache")] \
            + [f"/admin?tab={t}" for t in ("standardpaket", "checks", "messung", "alarme", "benachrichtigungen",
                                           "benutzer")] \
            + [f"/sites/1?tab={t}" for t in ("ereignisse", "meldungen", "messungen")] \
            + [f"/probes/{pid}?tab={t}" for t in ("ping", "bandbreite", "meldungen", "alarme", "details")]

    def test_all_pages_pass_lint(self):
        failures = {}
        for url in self.pages():
            r = self.client.get(url)
            self.assertEqual(r.status_code, 200, url)
            problems = lint(r.get_data(as_text=True))
            if problems:
                failures[url] = problems
        self.client.post("/logout", data={"csrf_token": self.session_csrf()})
        for url in ("/login", "/passwort-vergessen", "/zertifikat"):
            if problems := lint(self.client.get(url).get_data(as_text=True)):
                failures[url] = problems
        self.assertEqual(failures, {}, json.dumps(failures, indent=1, ensure_ascii=False))

    def test_references_are_links(self):
        """Regel „Verweise sind Links“: Steht ein Standort- oder Probe-Name als eigener Wert in Zelle, Karte,
        Navigationspfad oder Untertitel, ist er ein Link. Ausnahmen: <title>, <option>, Text direkt in der h1
        (eigene Seite) und Namen mitten in einem Satz (Alarmtexte, Audit-Details, Statusmeldungen)."""
        pid = self.probe["probe_id"]
        self.make_token(1, token="tok-offen", max_uses=5)
        for obj in ("site:1", f"probe:{pid}", "check:1", "report:1"):
            repo.audit("admin", "test", obj)
        names = {"Zentrale", "PC-EMPFANG"}
        failures = []
        for url in self.pages() + [f"/meldungen?status=all&probe={pid}"]:
            r = self.client.get(url)
            self.assertEqual(r.status_code, 200, url)
            for node in _Tree(r.get_data(as_text=True)).root.walk():
                chain = [node, *node.ancestors()]
                if node.tag == "h1" or any(n.tag in ("a", "title", "option", "select") for n in chain):
                    continue
                for text in node.text:
                    # eigenständiger Wert: ganzer Text oder ein Abschnitt zwischen Trennzeichen (· → ↔ / |)
                    parts = {p.strip() for p in re.split(r"[·→↔/|]", text)}
                    for name in names & parts:
                        failures.append(f"{url}: „{name}“ ohne Link in <{node.tag}>: {' '.join(text.split())[:80]}")
        self.assertEqual(failures, [], "\n".join(failures))
        # Stichproben: Ziel im Ausfall, Audit-Objekt, Zuweisung und Token-Standort sind verlinkt
        self.assertIn(f'href="/probes/{pid}/checks/1" aria-label="8.8.8.8 von PC-EMPFANG"',
                      self.client.get("/outages").get_data(as_text=True))
        self.assertIn('<a href="/admin/checks/1/edit">check:1</a>', self.client.get("/admin/audit").get_data(as_text=True))
        admin = self.client.get("/admin?tab=pcs").get_data(as_text=True)
        self.assertIn('<td><a href="/sites/1">Zentrale</a></td><td>', admin)

    def test_navigation_marks_current_page(self):
        html = self.client.get("/alerts").get_data(as_text=True)
        self.assertRegex(html, r'href="/alerts"[^>]*aria-current="page"')
        self.assertIn('class="skip-link" href="#inhalt"', html)
        self.assertIn('id="inhalt"', html)

    def test_check_form_error_state_is_linked_to_fields(self):
        """Fehler stehen gesammelt oben (role=alert) und am Feld (aria-invalid + aria-describedby)."""
        r = self.client.post("/admin/checks", data={
            "csrf_token": self.session_csrf(), "type": "iperf", "name": "", "peer": "server", "protocol": "tcp",
            "direction": "both", "duration_s": "100", "timeout_s": "60", "weekdays": "189", "schedule_min": "60",
            "offset_min": "-1", "window_start": "00:00", "window_end": "23:59", "scope": "all"})
        self.assertEqual(r.status_code, 400)
        html = r.get_data(as_text=True)
        self.assertEqual(lint(html), [])
        self.assertIn('role="alert"', html)
        for key in ("name", "weekdays", "timeout_s"):
            self.assertRegex(html, rf'id="f-{key}" aria-describedby="[^"]*f-{key}-error" aria-invalid="true"')
            self.assertIn(f'href="#f-{key}"', html)
        # Übersicht folgt der Reihenfolge der Felder
        self.assertLess(html.index('href="#f-name"'), html.index('href="#f-timeout_s"'))
        self.assertLess(html.index('href="#f-timeout_s"'), html.index('href="#f-weekdays"'))

    def test_dependent_fields_hidden_on_server(self):
        """Abhängige Felder sind schon im HTML ausgeblendet (kein Layout-Sprung, CLS)."""
        html = self.client.get("/admin/checks/new/iperf").get_data(as_text=True)
        tree = _Tree(html).root
        by_id = {n.attrs.get("id"): n for n in tree.walk() if n.attrs.get("id")}
        self.assertTrue(by_id["f-udp_mbps"].hidden())        # nur bei UDP
        self.assertFalse(by_id["f-window_kb"].hidden())      # TCP ist Standard
        self.assertTrue(by_id["f-host"].hidden())            # nur bei eigener Gegenstelle

    def test_label_sits_directly_before_its_field(self):
        """Gesetz der Nähe, strukturell: Label, Feld, Hilfe und Fehler stehen im selben .field-Container."""
        html = self.client.get("/admin/checks/new/iperf").get_data(as_text=True)
        tree = _Tree(html).root
        for n in tree.walk():
            if n.tag in CONTROLS and n.attrs.get("type") != "hidden" and n.attrs.get("id", "").startswith("f-"):
                box = next(a for a in n.ancestors() if "field" in (a.attrs.get("class") or "").split())
                inner = {c.attrs.get("id") for c in box.walk()} | {c.attrs.get("for") for c in box.walk()}
                for ref in (n.attrs.get("aria-describedby") or "").split():
                    self.assertIn(ref, inner, f"{ref} liegt nicht im Feld-Container von {n.attrs['id']}")
                self.assertIn(n.attrs["id"], inner)


# -- Farbkontraste der Design-Tokens ----------------------------------------
CSS = os.path.join(os.path.dirname(__file__), "..", "wachtl", "static", "app.css")

# (Vordergrund, Hintergrund, Mindestkontrast) – Text 4,5:1, Bedienelemente/Grafik 3:1
PAIRS = [
    ("--text", "--bg", 4.5), ("--text", "--surface", 4.5), ("--text-muted", "--bg", 4.5),
    ("--text-muted", "--surface", 4.5), ("--accent", "--bg", 4.5), ("--accent", "--surface", 4.5),
    ("--bg", "--accent", 4.5), ("--bar-text", "--bar-bg", 4.5), ("--bar-muted", "--bar-bg", 4.5),
    ("--ok", "--surface", 4.5), ("--warn", "--surface", 4.5), ("--bad", "--surface", 4.5), ("--bad", "--bg", 4.5),
    ("--accent", "--accent-soft", 4.5), ("--text-muted", "--accent-soft", 4.5),
    ("--field-border", "--surface", 3.0), ("--off", "--surface", 3.0), ("--focus", "--bg", 3.0),
    ("--focus", "--surface", 3.0), ("--report", "--surface", 4.5), ("--report", "--bg", 4.5),
    ("--jitter", "--surface", 3.0),
    # Graph: Median je Verlustklasse auf dem dunkleren Rauch-Band (und damit auch auf hellerem Grund) ≥ 3:1
    ("--ok", "--band", 3.0), ("--loss-low", "--band", 3.0), ("--warn", "--band", 3.0), ("--bad", "--band", 3.0),
    ("--loss-low", "--surface", 3.0),
    # Gesundheitsbalken der Übersicht: Flächen ≥ 3:1 auf der Karte (WCAG 1.4.11)
    ("--ok-fill", "--surface", 3.0), ("--warn-fill", "--surface", 3.0), ("--bad-fill", "--surface", 3.0),
    ("--bar-text", "--bar-bg", 4.5), ("--accent", "--surface-2", 4.5),
    # Links in Tabellen sind nicht unterstrichen: Linkfarbe hebt sich ≥ 3:1 vom Text ab (WCAG 1.4.1, G183).
    # Bei „Kontrast erhöht“ sind alle Links unterstrichen, dort gilt das nicht (NORMAL_ONLY).
    ("--accent", "--text", 3.0),
]
NORMAL_ONLY = {("--accent", "--text")}
# Badges: Schrift auf 12 % der eigenen Farbe über --surface (siehe .badge.* in app.css)
BADGES = [("--bad", 0.12), ("--warn", 0.12), ("--report", 0.12), ("--ok", 0.12), ("--text-muted", 0.12)]


def _tokens(block: str, dark: bool = False) -> dict[str, str]:
    """Farb-Tokens eines CSS-Blocks; bei light-dark(hell, dunkel) die gewünschte Seite."""
    out = {}
    for name, value in re.findall(r"(--[\w-]+):\s*([^;]+);", block):
        if m := re.fullmatch(r"light-dark\((#[0-9a-fA-F]{6}),\s*(#[0-9a-fA-F]{6})\)", value.strip()):
            out[name] = m.group(2 if dark else 1)
        elif re.fullmatch(r"#[0-9a-fA-F]{6}", value.strip()):
            out[name] = value.strip()
    return out


def _lum(hex_color: str) -> float:
    rgb = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _mix(fg: str, bg: str, share: float) -> str:
    return "#" + "".join(f"{round(int(fg[i:i + 2], 16) * share + int(bg[i:i + 2], 16) * (1 - share)):02x}"
                         for i in (1, 3, 5))


class ContrastTest(AppTestCase):
    def themes(self) -> dict[str, dict[str, str]]:
        css = open(CSS, encoding="utf-8").read()
        root = re.search(r":root\s*\{(.*?)\}", css, re.S).group(1)
        high = re.search(r':root\[data-contrast="high"\]\s*\{(.*?)\}', css, re.S).group(1)
        themes = {}
        for name, dark in (("hell", False), ("dunkel", True)):
            themes[name] = _tokens(root, dark)
            themes[f"{name}, Kontrast erhöht"] = {**themes[name], **_tokens(high, dark)}
        return themes

    def test_every_color_token_has_dark_value(self):
        """Jede Farbe braucht einen Wert für hell und dunkel (light-dark), sonst bleibt sie im Dunkelmodus hell."""
        css = open(CSS, encoding="utf-8").read()
        root = re.search(r":root\s*\{(.*?)\}", css, re.S).group(1)
        plain = [n for n, v in re.findall(r"(--[\w-]+):\s*(#[0-9a-fA-F]{6})", root)]
        self.assertEqual(plain, [])

    def test_high_contrast_text(self):
        """Kontrast „Erhöht“: Fließtext und gedämpfter Text erreichen 7:1 (WCAG AAA)."""
        for theme, t in self.themes().items():
            if "Kontrast" in theme:
                for fg in ("--text", "--text-muted"):
                    for bg in ("--bg", "--surface"):
                        self.assertGreaterEqual(contrast(t[fg], t[bg]), 7.0, f"{theme}: {fg} auf {bg}")

    def test_token_contrast(self):
        failures = []
        for theme, t in self.themes().items():
            for fg, bg, minimum in PAIRS:
                if (fg, bg) in NORMAL_ONLY and "Kontrast" in theme:
                    continue
                c = contrast(t[fg], t[bg])
                if c < minimum:
                    failures.append(f"{theme}: {fg} auf {bg} = {c:.2f}:1 (mind. {minimum}:1)")
            for fg, share in BADGES:
                c = contrast(t[fg], _mix(t[fg], t["--surface"], share))
                if c < 4.5:
                    failures.append(f"{theme}: Badge {fg} = {c:.2f}:1 (mind. 4.5:1)")
        self.assertEqual(failures, [], "\n".join(failures))

    def test_badge_rule_matches_css(self):
        css = open(CSS, encoding="utf-8").read()
        for fg, share in BADGES:
            self.assertRegex(css, rf"color-mix\(in srgb, var\({fg}\) {int(share * 100)}%, var\(--surface\)\)")
