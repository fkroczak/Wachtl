"""IP-Info (docs/WERKZEUGE.md): Netz, Anbieter, Herkunfts-AS, Land und Kontakte einer Adresse.

Übernommen aus Hop7 (ui/werkzeuge/werkzeuge.py, „IP-Info“) – gleiche Abfrage, gleiche Regeln:
direkt bei der zuständigen Registry (RDAP, ersatzweise WHOIS über Port 43), ohne Dienst eines Dritten,
mit Zwischenspeicher je Netz und höchstens einer Abfrage pro Sekunde. Läuft auf der Server-Probe.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

DRY_RUN = os.environ.get("WACHTL_IPINFO_DRY_RUN") == "1"
# Zwischenspeicher: die Server-Probe setzt ihn in ihr Datenverzeichnis (probe.py)
CACHE_DIR = os.path.join(tempfile.gettempdir(), "wachtl-ipinfo")


# Eigene Abfrage bei den Registries (RDAP, ersatzweise WHOIS über Port 43).
#
# Bewusst ohne Dienst eines Dritten: Die abgefragte Adresse geht nur an die Registry, die den
# Eintrag ohnehin selbst führt (RIPE NCC für Europa, ARIN, APNIC, LACNIC, AFRINIC). Kein
# kommerzieller Anbieter sieht, welche Adressen hier geprüft werden. RDAP ist der offizielle
# Nachfolger von WHOIS (RFC 9082/9083), die Kontaktdaten stecken darin als jCard (RFC 7095).

RDAP_BOOTSTRAP = {4: "https://data.iana.org/rdap/ipv4.json", 6: "https://data.iana.org/rdap/ipv6.json"}
# Nur Server der Registries selbst. Die Liste von der IANA kommt zwar über TLS, aber ein Eintrag
# darf die Abfrage trotzdem nicht auf einen beliebigen Host umlenken.
RDAP_HOST_OK = re.compile(r"(^|\.)(ripe\.net|arin\.net|apnic\.net|lacnic\.net|afrinic\.net|registro\.br|iana\.org)$", re.I)
RDAP_RIRS = (("RIPE NCC", "https://rdap.db.ripe.net/"), ("ARIN", "https://rdap.arin.net/registry/"),
             ("APNIC", "https://rdap.apnic.net/"), ("LACNIC", "https://rdap.lacnic.net/rdap/"),
             ("AFRINIC", "https://rdap.afrinic.net/rdap/"))
BOOTSTRAP_TTL = 14 * 86400          # Zuordnung Adressblock → Registry ändert sich selten
ANBIETER_TTL = 30 * 86400           # Ergebnis je Netz; Einträge der Registry ändern sich selten
RDAP_PAUSE = 1.0                    # Mindestabstand zwischen zwei Abfragen (Rücksicht auf die Registries)
UA = "Wachtl (Netzueberwachung; RDAP-Abfrage aus den Werkzeugen)"
_letzte_abfrage = [0.0]


def _cache_lesen(name, ttl):
    try:
        p = os.path.join(CACHE_DIR, name)
        if time.time() - os.lstat(p).st_mtime > ttl:
            return None
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _cache_schreiben(name, daten):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = os.path.join(CACHE_DIR, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(daten, f)
        os.replace(tmp, os.path.join(CACHE_DIR, name))
    except (OSError, ValueError):
        pass


def _host_ok(url):
    return bool(url.lower().startswith("https://") and RDAP_HOST_OK.search(urllib.parse.urlsplit(url).hostname or ""))


class NurRegistry(urllib.request.HTTPRedirectHandler):
    """Umleitungen nur zu einer Registry und nur über HTTPS.

    Registries leiten bei übertragenen Adressblöcken von einer zur anderen um – das ist normal
    und nötig. Ohne Prüfung könnte eine Antwort die Abfrage aber auf einen beliebigen Host oder
    auf Klartext umbiegen; die Adresse käme dann bei jemand anderem an.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _host_ok(newurl):
            raise urllib.error.HTTPError(newurl, code, "Umleitung außerhalb der Registries", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_oeffner = urllib.request.build_opener(NurRegistry)


def _holen(url, accept="application/rdap+json", timeout=8, limit=512 * 1024):
    """HTTPS-GET mit Größen- und Zeitgrenze. Liefert (Text, Fehler)."""
    if not _host_ok(url):
        return "", "nur HTTPS zu einer Registry erlaubt"
    if DRY_RUN:
        return "", "[Testlauf] keine Abfrage"
    warte = RDAP_PAUSE - (time.time() - _letzte_abfrage[0])
    if warte > 0:
        time.sleep(warte)
    _letzte_abfrage[0] = time.time()
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": UA, "Accept-Encoding": "identity"})
    try:
        with _oeffner.open(req, timeout=timeout) as r:
            return r.read(limit + 1)[:limit].decode("utf-8", "replace"), ""
    except urllib.error.HTTPError as e:
        return "", f"HTTP {e.code}"
    except Exception as e:                      # noqa: BLE001 – Netzfehler dürfen den Dienst nicht beenden
        return "", e.__class__.__name__


def _holen_json(url, **kw):
    text, fehler = _holen(url, **kw)
    if fehler:
        return None, fehler
    try:
        obj = json.loads(text)
    except ValueError:
        return None, "unlesbare Antwort"
    return (obj, "") if isinstance(obj, dict) else (None, "unerwartete Antwort")


def _bootstrap(version):
    """Liste der IANA: welcher Adressblock gehört zu welchem RDAP-Server. Lokal zwischengespeichert."""
    name = f"rdap-ipv{version}.json"
    daten = _cache_lesen(name, BOOTSTRAP_TTL)
    if daten is None:
        daten, _ = _holen_json(RDAP_BOOTSTRAP[version], accept="application/json")
        if daten:
            _cache_schreiben(name, daten)
        else:
            daten = _cache_lesen(name, 10 * 365 * 86400) or {}   # notfalls auch eine alte Liste
    return daten if isinstance(daten, dict) else {}


def _rdap_server(ip):
    """(Basis-URLs, Name der Registry) für eine Adresse – erst laut IANA-Liste, sonst alle Registries der Reihe nach."""
    a = ipaddress.ip_address(ip)
    for dienst in _bootstrap(a.version).get("services", []):
        try:
            netze, urls = dienst[0], dienst[1]
        except (IndexError, TypeError):
            continue
        if not any(a in ipaddress.ip_network(n, strict=False) for n in netze if isinstance(n, str)):
            continue
        gut = [u for u in urls if isinstance(u, str) and u.lower().startswith("https://")
               and RDAP_HOST_OK.search(urllib.parse.urlsplit(u).hostname or "")]
        if gut:
            return gut, ""
    return [u for _, u in RDAP_RIRS], ""


def _flach(x):
    """Verschachtelte Listen (etwa das adr-Feld einer jCard) zu einer flachen Liste."""
    if isinstance(x, list):
        return [v for e in x for v in _flach(e)]
    return [x] if x not in (None, "") else []


def _jcard(ent):
    """vcardArray einer RDAP-Entität (RFC 7095) → {feld: wert}."""
    felder = {}
    arr = ent.get("vcardArray")
    if not isinstance(arr, list) or len(arr) < 2 or not isinstance(arr[1], list):
        return felder
    for e in arr[1]:
        if not isinstance(e, list) or len(e) < 4:
            continue
        name = str(e[0]).lower()
        par = e[1] if isinstance(e[1], dict) else {}
        wert = e[3]
        if name == "adr":
            # Die Anschrift einer jCard hat sieben Teile, der letzte ist das Land (bei ARIN oft die
            # einzige Stelle, an der es steht). Erst merken, dann die Anschrift lesbar zusammensetzen.
            if isinstance(wert, list) and len(wert) == 7 and str(wert[6]).strip():
                felder.setdefault("land", str(wert[6]).strip()[:40])
            wert = par.get("label") or ", ".join(str(v).strip() for v in _flach(wert))
        elif isinstance(wert, list):
            wert = ", ".join(str(v) for v in _flach(wert))
        wert = re.sub(r"\s*\n\s*", ", ", str(wert)).strip()
        if wert and name not in felder:
            felder[name] = wert[:300]
    return felder


def _entitaeten(obj, tiefe=0, raus=None):
    """Alle Kontakte eines RDAP-Objekts nach Rolle; Entitäten dürfen ineinander stecken."""
    raus = {} if raus is None else raus
    if tiefe > 3 or not isinstance(obj, dict):
        return raus
    for ent in obj.get("entities", []) or []:
        if not isinstance(ent, dict):
            continue
        k = _jcard(ent)
        k["handle"] = str(ent.get("handle", ""))[:80]
        for rolle in ent.get("roles", []) or []:
            raus.setdefault(str(rolle).lower(), k)
        _entitaeten(ent, tiefe + 1, raus)
    return raus


def _ereignisse(obj):
    raus = {}
    for e in obj.get("events", []) or []:
        if isinstance(e, dict) and e.get("eventAction"):
            raus[str(e["eventAction"]).lower()] = str(e.get("eventDate", ""))[:10]
    return raus


def _bemerkungen(obj, schluessel="remarks"):
    text = []
    for r in obj.get(schluessel, []) or []:
        if isinstance(r, dict):
            text += [str(z).strip() for z in (r.get("description") or []) if str(z).strip()]
    return text


def _prefix(start, ende, obj):
    """Netz in CIDR-Schreibweise: bevorzugt aus cidr0_cidrs, sonst aus Anfang und Ende errechnet."""
    for c in obj.get("cidr0_cidrs", []) or []:
        if isinstance(c, dict) and c.get("length") is not None:
            v = c.get("v4prefix") or c.get("v6prefix")
            if v:
                return f"{v}/{c['length']}"
    try:
        netze = list(ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(ende)))
        return str(netze[0]) if len(netze) == 1 else ""
    except (ValueError, TypeError):
        return ""


def rdap_ip(ip):
    """RDAP-Eintrag einer Adresse bei der zuständigen Registry. Liefert (Daten, Fehler)."""
    urls, _ = _rdap_server(ip)
    fehler = ""
    for basis in urls:
        obj, fehler = _holen_json(basis.rstrip("/") + "/ip/" + urllib.parse.quote(str(ip)))
        if not obj:
            continue
        start, ende = str(obj.get("startAddress", "")), str(obj.get("endAddress", ""))
        kontakte = _entitaeten(obj)
        d = {
            "quelle": "RDAP " + (urllib.parse.urlsplit(basis).hostname or basis),
            "handle": str(obj.get("handle", ""))[:80],
            "netz": _prefix(start, ende, obj),
            "von": start, "bis": ende,
            "netzname": str(obj.get("name", ""))[:80],
            "art": str(obj.get("type", ""))[:60],
            "land": str(obj.get("country", "") or _land_aus(kontakte))[:2].upper(),
            "status": [str(s) for s in (obj.get("status") or [])][:4],
            "port43": str(obj.get("port43", ""))[:80],
            "eltern": str(obj.get("parentHandle", ""))[:80],
            "kontakte": kontakte,
            "ereignisse": _ereignisse(obj),
            "hinweise": _bemerkungen(obj)[:4],
        }
        d["anbieter"] = _anbieter_aus(d)
        d["basis"] = basis
        return d, ""
    return None, fehler or "kein Eintrag gefunden"


# Rollen in der Reihenfolge, in der sie den Anbieter am besten benennen
ANBIETER_ROLLEN = ("registrant", "administrative", "technical", "abuse", "noc", "reseller")
LAENDER = {"germany": "DE", "deutschland": "DE", "austria": "AT", "switzerland": "CH", "netherlands": "NL",
           "france": "FR", "united kingdom": "GB", "united states": "US", "poland": "PL", "italy": "IT",
           "spain": "ES", "belgium": "BE", "denmark": "DK", "sweden": "SE", "czech republic": "CZ"}


def _land_aus(kontakte):
    """Land aus der Anschrift eines Kontakts – manche Registries führen es nur dort."""
    for rolle in ANBIETER_ROLLEN:
        wert = (kontakte.get(rolle) or {}).get("land", "").strip()
        if not wert:
            continue
        if re.fullmatch(r"[A-Za-z]{2}", wert):
            return wert.upper()
        if LAENDER.get(wert.lower()):
            return LAENDER[wert.lower()]
    return ""


# Registry-Kürzel statt Firmenname: ANEXIA-MNT, DTAG-NIC, EPCAN-MNT, Abuse-C …
HANDLE_RE = re.compile(r"(?i)^[A-Z0-9]+([-_][A-Z0-9]+)+$|[-_](mnt|nic|noc|adm|tech|abuse|ripe|arin|apnic|lacnic|afrinic)$")
ROLLENKONTO_RE = re.compile(r"(?i)^(abuse|noc|host[\s-]*master|admin|tech)[\s-]*c?$")


def _echter_name(name):
    """Sieht das nach einem Firmennamen aus – oder nur nach einem Objektnamen der Registry?"""
    name = (name or "").strip()
    if not name or ROLLENKONTO_RE.match(name):
        return False
    return not (HANDLE_RE.search(name) and " " not in name)


# Namen von Rollen- und Verwaltungsobjekten der Registry: „ANX Group RIPE NCC Role Handle“,
# „… Network Operations Team“, „Host Master Highway“ (A1). Sie stehen oft als Kontakt im Netz- oder
# AS-Objekt, benennen aber keine Firma.
ROLLE_WORT_RE = re.compile(r"(?i)\b(role|handle|contact|team|dept|department|noc|ncc|host\s*master|"
                           r"post\s*master|web\s*master|"
                           r"operations|support|registry|abuse|maintainer|mnt)\b")


def _kandidaten(kontakte):
    """Namen aus den Kontakten, in der Reihenfolge der Rollen, je mit der Art der jCard (org, individual …)."""
    aus = []
    for rolle in ANBIETER_ROLLEN:
        k = kontakte.get(rolle) or {}
        name = (k.get("fn") or k.get("org") or "").strip()[:120]
        if name and not ROLLENKONTO_RE.match(name) and name not in [n for n, _ in aus]:
            aus.append((name, (k.get("kind") or "").lower()))
    return aus


def _bester_name(kontakte, notnagel=""):
    """Firmenname aus den Kontakten. Eine jCard der Art „org“ zählt am meisten, dann ein Name ohne
    Rollenwort, dann einer ohne Registry-Kürzel – erst danach irgendeiner, zuletzt der Notnagel."""
    k = _kandidaten(kontakte)
    return (next((n for n, art in k if art == "org" and _echter_name(n)), "")
            or next((n for n, _ in k if _echter_name(n) and not ROLLE_WORT_RE.search(n)), "")
            or next((n for n, _ in k if _echter_name(n)), "")
            or next((n for n, _ in k), "") or notnagel)


def _anbieter_aus(d):
    return _bester_name(d["kontakte"], d.get("netzname", ""))


def whois43(server, anfrage, timeout=8, limit=128 * 1024):
    """Klassische WHOIS-Abfrage über Port 43. Liefert (Text, Fehler); der Fehler unterscheidet
    „Port nicht erreichbar“ von „nichts eingetragen“ – sonst sieht beides gleich aus."""
    if DRY_RUN or not server:
        return "", "keine Abfrage"
    # Der WHOIS-Name stammt aus der RDAP-Antwort, also von außen. Nur Registries sind erlaubt,
    # damit eine Antwort die Verbindung nicht auf einen Host im eigenen Netz lenken kann.
    if not RDAP_HOST_OK.search(server.strip().lower()):
        return "", f"{server}: kein WHOIS-Server einer Registry"
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall((anfrage + "\r\n").encode("utf-8", "replace"))
            puffer = b""
            while len(puffer) < limit:
                teil = s.recv(8192)
                if not teil:
                    break
                puffer += teil
        return puffer.decode("utf-8", "replace"), ""
    except OSError as e:
        return "", f"{server}:43 nicht erreichbar ({e.__class__.__name__})"


WHOIS_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 /-]{1,30}):\s*(.+?)\s*$")


def whois_felder(text):
    """WHOIS-Text → {feld: [werte]} (Kleinschreibung, Kommentarzeilen übersprungen)."""
    felder = {}
    for zeile in text.splitlines():
        if not zeile or zeile[0] in "%#>":
            continue
        m = WHOIS_RE.match(zeile)
        if m:
            felder.setdefault(m.group(1).strip().lower(), []).append(m.group(2)[:300])
    return felder


def herkunfts_as(netz, port43, ip):
    """Herkunfts-AS aus den Routing-Objekten der Registry (route/route6 bzw. OriginAS bei ARIN).
    Liefert (AS, Grund): Steht kein AS da, sagt der Grund, ob der Port dicht war oder nichts eingetragen ist."""
    if not port43:
        return "", "keine WHOIS-Adresse in der Registry-Antwort"
    if "arin" in port43:
        text, fehler = whois43(port43, f"n + {ip}")
    else:
        # -r: keine Kontaktobjekte (schont das Abfragelimit), -L: auch die größeren Netze
        text, fehler = whois43(port43, f"-r -T route,route6 -L {netz or ip}")
    if fehler:
        return "", fehler
    f = whois_felder(text)
    for schluessel in ("origin", "originas", "origin-as"):
        for wert in f.get(schluessel, []):
            m = re.search(r"AS(\d+)", wert, re.I)
            if m:
                return "AS" + m.group(1), ""
    return "", f"kein route-Objekt bei {port43}"


def _entity_name(basis, handle):
    """Name eines eigenständigen Objekts der Registry. RIPE nennt die Organisation im AS-Objekt
    oft nur mit Kürzel (ORG-NG12-RIPE); der Firmenname steht dann erst im Objekt selbst."""
    if not handle:
        return ""
    obj, _ = _holen_json(basis.rstrip("/") + "/entity/" + urllib.parse.quote(handle))
    if not obj:
        return ""
    f = _jcard(obj)
    name = (f.get("fn") or f.get("org") or "").strip()[:120]
    return name if _echter_name(name) and not ROLLE_WORT_RE.search(name) else ""


def _as_name(roh):
    """Name des AS-Objekts als Notnagel: „NETCUP-AS“ → „NETCUP“. Großschreibung ist hier in Ordnung,
    das ist der offizielle Name des autonomen Systems und kein Verwaltungskürzel."""
    name = re.sub(r"(?i)^as[-_ ]|[-_ ]as$", "", str(roh).strip())[:120]
    return "" if not name or ROLLENKONTO_RE.match(name) or ROLLE_WORT_RE.search(name) else name


# Felder, in denen die Registries den Inhaber eines AS im WHOIS benennen
AS_NAME_FELDER = ("org-name", "orgname", "descr", "owner", "responsible", "as-name")


def _autnum_whois(nummer, port43, basis):
    """Inhaber eines AS über WHOIS. RIPE führt die Organisation bewusst nicht im RDAP-Objekt
    (siehe db-wg), dort steht sie nur als org:-Kürzel im WHOIS – von da aus ist der Firmenname
    dann wieder über RDAP zu holen."""
    if not port43:
        return ""
    anfrage = f"a {nummer}" if "arin" in port43 else f"-r AS{nummer}"
    text, fehler = whois43(port43, anfrage)
    if fehler:
        return ""
    f = whois_felder(text)
    for handle in f.get("org", []):                     # org: ORG-NG12-RIPE → Firmenname im eigenen Objekt
        name = _entity_name(basis, handle.strip())
        if name:
            return name
    for feld in AS_NAME_FELDER:
        for wert in f.get(feld, []):
            name = _as_name(wert) if feld == "as-name" else wert.strip()[:120]
            if name and _echter_name(name) and not ROLLE_WORT_RE.search(name):
                return name
    return ""


def autnum_name(asn, basis="", port43=""):
    """Name des AS-Inhabers – wer das Netz ankündigt, ist der Anbieter (RFC 9083).
    Personen zählen hier nicht: Der admin-c eines AS ist nicht der Anbieter."""
    nummer = re.sub(r"\D", "", str(asn))
    if not nummer:
        return ""
    urls = ([basis] if basis else []) + [u for _, u in RDAP_RIRS if u != basis]
    for b in urls:
        obj, _ = _holen_json(b.rstrip("/") + "/autnum/" + nummer)
        if not obj:
            continue
        kontakte = _entitaeten(obj)
        # Personen und Rollen-Objekte (jCard-Art „group“, etwa „Host Master Highway“ bei A1) sind
        # Ansprechpartner, nicht der Inhaber des AS
        nur_firmen = {r: k for r, k in kontakte.items() if (k.get("kind") or "").lower() not in ("individual", "group")}
        name = _bester_name(nur_firmen)
        if _echter_name(name) and not ROLLE_WORT_RE.search(name):
            return name
        # Organisation steckt nur als Kürzel in der Antwort: eigenes Objekt holen
        for rolle in ANBIETER_ROLLEN:
            handle = (kontakte.get(rolle) or {}).get("handle", "")
            if handle.upper().startswith("ORG-"):
                name = _entity_name(b, handle)
                if name:
                    return name
        name = _autnum_whois(nummer, port43, b) or _as_name(obj.get("name", ""))
        if name:
            return name
        if re.sub(r"\D", "", str(obj.get("handle", ""))) == nummer:
            return ""        # die zuständige Registry hat geantwortet, kennt aber keinen besseren Namen
    return _autnum_whois(nummer, port43, basis)


NETZE_DATEI = "netze.json"
NETZE_MAX = 2000
# Fassung der Auswertung. Wird sie verbessert (anderer Anbietername, neue Felder), zählt diese
# Zahl hoch, und gemerkte Einträge älterer Fassung werden beim nächsten Zugriff neu geholt –
# sonst bliebe ein einmal falsch erkannter Anbieter 30 Tage lang stehen.
NETZ_FORMAT = 5


def _netz_gemerkt(ip):
    """Schon bekannte Auskunft, wenn die Adresse in einem bereits abgefragten Netz liegt.
    So kostet eine ganze Zielliste beim selben Anbieter nur eine einzige Abfrage."""
    alle = _cache_lesen(NETZE_DATEI, ANBIETER_TTL) or {}
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    treffer = None
    for netz, d in alle.items():
        try:
            n = ipaddress.ip_network(netz, strict=False)
        except ValueError:
            continue
        # Das kleinste passende Netz gewinnt (ein Kundennetz schlägt die Zuteilung an den Anbieter)
        if d.get("v") != NETZ_FORMAT:        # vor einer Verbesserung gemerkt: neu holen
            continue
        if a.version == n.version and a in n and (treffer is None or n.prefixlen > treffer[0].prefixlen):
            treffer = (n, d)
    return treffer[1] if treffer else None


def _netz_merken(d, ip):
    alle = _cache_lesen(NETZE_DATEI, ANBIETER_TTL) or {}
    schluessel = d.get("netz") or f"{ip}/{128 if ':' in str(ip) else 32}"
    alle[schluessel] = {**d, "v": NETZ_FORMAT}
    if len(alle) > NETZE_MAX:                       # notfalls von vorn, statt unbegrenzt zu wachsen
        alle = {schluessel: d}
    _cache_schreiben(NETZE_DATEI, alle)


def netz_info(ip, mit_as=True):
    """Vollständige Auskunft zu einer Adresse: RDAP, ersatzweise WHOIS, dazu das Herkunfts-AS.
    Ergebnisse werden je Netz zwischengespeichert, damit die Registries nicht unnötig belastet werden."""
    gemerkt = _netz_gemerkt(ip)
    if gemerkt:
        return gemerkt, ""
    d, fehler = rdap_ip(ip)
    if not d:
        # Ersatzweg: WHOIS bei der Registry, die laut IANA zuständig ist
        d2 = _whois_info(ip)
        if not d2:
            return None, fehler
        d = d2
    if mit_as and not d.get("asn"):
        d["asn"], d["asn_grund"] = herkunfts_as(d.get("netz", ""), d.get("port43", ""), ip)
    # Der Anbieter ist, wer das Netz im Internet ankündigt – das steht im AS-Objekt. Der Kontakt im
    # Netz-Objekt ist oft ein Rollen- oder Verwaltungsobjekt (ANX Group … Role Handle) oder der Kunde
    # selbst; er bleibt als „Netz-Inhaber“ erhalten.
    d["inhaber"] = d.get("anbieter", "")
    if d.get("asn"):
        besser = autnum_name(d["asn"], d.get("basis", ""), d.get("port43", ""))
        if besser:
            d["anbieter"] = besser
    _netz_merken(d, ip)
    return d, ""


WHOIS_SERVER = {"https://rdap.db.ripe.net/": "whois.ripe.net", "https://rdap.arin.net/registry/": "whois.arin.net",
                "https://rdap.apnic.net/": "whois.apnic.net", "https://rdap.lacnic.net/rdap/": "whois.lacnic.net",
                "https://rdap.afrinic.net/rdap/": "whois.afrinic.net"}


def _whois_info(ip):
    """Ersatz für RDAP: klassisches WHOIS, Felder je nach Registry unterschiedlich benannt."""
    urls, _ = _rdap_server(ip)
    for basis in urls:
        server = WHOIS_SERVER.get(basis) or re.sub(r"^rdap[.-]?", "whois.", urllib.parse.urlsplit(basis).hostname or "")
        text, _ = whois43(server, f"-r {ip}" if "arin" not in server else f"n + {ip}")
        f = whois_felder(text)
        bereich = (f.get("inetnum") or f.get("inet6num") or f.get("netrange") or [""])[0]
        if not bereich and not f.get("cidr"):
            continue
        von, _, bis = [t.strip() for t in bereich.partition("-")] if "-" in bereich else (bereich, "", bereich)
        name = (f.get("netname") or f.get("netname:") or [""])[0]
        org = (f.get("org-name") or f.get("orgname") or f.get("descr") or f.get("owner") or [""])[0]
        d = {"quelle": "WHOIS " + server, "handle": (f.get("nethandle") or [""])[0], "netz": (f.get("cidr") or [""])[0],
             "von": von, "bis": bis, "netzname": name, "art": (f.get("status") or f.get("nettype") or [""])[0],
             "land": (f.get("country") or [""])[0][:2].upper(), "status": [], "port43": server, "eltern": "",
             "kontakte": {}, "ereignisse": {}, "hinweise": [], "anbieter": org or name,
             "asn": next((m.group(0) for w in f.get("origin", []) if (m := re.search(r"AS\d+", w, re.I))), "")}
        if not d["netz"] and von and bis:
            d["netz"] = _prefix(von, bis, {})
        return d
    return None


def _kontakt_zeile(k):
    teile = [k.get("fn") or k.get("org") or k.get("handle", "")]
    if k.get("email"):
        teile.append(k["email"])
    return " · ".join(t for t in teile if t)
