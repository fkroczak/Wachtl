// Repräsentative Seiten je Seitentyp. IDs schreibt devtools/seed_demo.py nach .seed.json.
const fs = require("fs");
const path = require("path");

const seedFile = path.join(__dirname, ".seed.json");
const ids = fs.existsSync(seedFile)
  ? JSON.parse(fs.readFileSync(seedFile, "utf8"))
  : { probe: 1, site: 1, ping_check: 2, path_check: 4, wan_check: 5, rtp_check: 6, switch: 2 };

const BASE = process.env.WACHTL_BASE_URL || "http://127.0.0.1:5000";
const PASSWORD = process.env.WACHTL_E2E_PASSWORD || "e2e-admin-passwort";

// [Name, Pfad] – Navigation, Dashboards, Detailseiten, Formulare
const PAGES = [
  ["Übersicht", "/"],
  ["Standorte", "/standorte"],
  ["Probes", "/probes?tab=alle"],
  ["Probes: Bandbreite", "/probes?tab=bandbreite"],
  ["Hinweise", "/hinweise"],
  ["Standort: Alle Messungen", `/sites/${ids.site}?tab=messungen`],
  ["Netzwerk", `/sites/${ids.site}/netzwerk`],
  ["Werkzeuge", "/werkzeuge"],
  ["Topologie: Standorte", "/topologie"],
  ["Topologie: Baum", `/sites/${ids.site}/topologie`],
  ["Topologie: Switches", `/sites/${ids.site}/topologie/switche`],
  ["Topologie: Switch", `/sites/${ids.site}/topologie/switche/${ids.switch}?port=4`],
  ["Topologie: Probleme", `/sites/${ids.site}/topologie/probleme`],
  ["Topologie: Pfad", `/sites/${ids.site}/topologie/pfad?geraet=pc-empfang`],
  ["Topologie: Assistent", `/sites/${ids.site}/topologie/switche/neu`],
  ["Topologie: Zeitleiste", `/sites/${ids.site}/topologie?seite=verlauf&alle=1`],
  ["Topologie: Chronik", `/sites/${ids.site}/topologie/verlauf`],
  ["Probe: Details", `/probes/${ids.probe}?tab=details`],
  ["Verwaltung: Checks", "/admin?tab=checks"],
  ["Verwaltung: Messung", "/admin?tab=messung"],
  ["Standort", `/sites/${ids.site}`],
  ["Probe", `/probes/${ids.probe}`],
  ["Ziel (Graph)", `/probes/${ids.probe}/checks/${ids.ping_check}`],
  ["Pfad", `/probes/${ids.probe}/path/${ids.path_check}`],
  ["Hop", `/probes/${ids.probe}/path/${ids.path_check}/hop/1`],
  ["Bandbreite", `/probes/${ids.probe}/bandwidth/${ids.wan_check}`],
  ["Sprache (RTP)", `/probes/${ids.probe}/rtp/${ids.rtp_check}`],
  ["Alarme", "/alerts"],
  ["Störungen", "/outages"],
  ["Meldungen", "/meldungen?status=all"],
  ["PDF-Bericht", "/bericht"],
  ["Verwaltung", "/admin"],
  ["Probes einrichten", "/admin/einrichtung"],
  ["Check-Formular Ping", "/admin/checks/new/ping"],
  ["Check-Formular iperf3", "/admin/checks/new/iperf"],
  ["Check-Formular WAN", "/admin/checks/new/speedtest"],
  ["Check-Formular Sprache", "/admin/checks/new/rtp"],
  ["Check-Formular Netzwerkscan", "/admin/checks/new/netscan"],
  ["Konto", "/account"],
  ["Design", "/account/design"],
  ["Passwort vergessen", "/passwort-vergessen"],
  ["Audit-Log", "/admin/audit"],
];

module.exports = { BASE, PASSWORD, PAGES, ids };
