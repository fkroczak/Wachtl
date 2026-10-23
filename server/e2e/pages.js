// Repräsentative Seiten je Seitentyp. IDs schreibt devtools/seed_demo.py nach .seed.json.
const fs = require("fs");
const path = require("path");

const seedFile = path.join(__dirname, ".seed.json");
const ids = fs.existsSync(seedFile)
  ? JSON.parse(fs.readFileSync(seedFile, "utf8"))
  : { probe: 1, site: 1, ping_check: 2, path_check: 4, wan_check: 5, rtp_check: 6 };

const BASE = process.env.WACHTL_BASE_URL || "http://127.0.0.1:5000";
const PASSWORD = process.env.WACHTL_E2E_PASSWORD || "e2e-admin-passwort";

// [Name, Pfad] – Navigation, Dashboards, Detailseiten, Formulare
const PAGES = [
  ["Übersicht", "/"],
  ["Übersicht 7 Tage", "/?range=7d"],
  ["Zustand", "/zustand"],
  ["Verlauf (Tag)", "/verlauf"],
  ["Einstellungen PCs", "/admin?tab=pcs"],
  ["Einstellungen Alarme", "/admin?tab=alarme"],
  ["Einstellungen System", "/admin?tab=system"],
  ["Störungen", "/stoerungen"],
  ["Störung (Analyse)", ids.incident ? `/stoerungen/${ids.site}/${ids.incident[0]}/${ids.incident[1]}` : "/stoerungen"],
  ["Standort", `/sites/${ids.site}`],
  ["Probe", `/probes/${ids.probe}`],
  ["Ziel (Graph)", `/probes/${ids.probe}/checks/${ids.ping_check}`],
  ["Pfad", `/probes/${ids.probe}/path/${ids.path_check}`],
  ["Hop", `/probes/${ids.probe}/path/${ids.path_check}/hop/1`],
  ["Bandbreite", `/probes/${ids.probe}/bandwidth/${ids.wan_check}`],
  ["Sprache (RTP)", `/probes/${ids.probe}/rtp/${ids.rtp_check}`],
  ["Alarme", "/alerts"],
  ["Ausfälle", "/outages"],
  ["Meldungen", "/meldungen?status=all"],
  ["Verwaltung", "/admin"],
  ["Probes einrichten", "/admin/einrichtung"],
  ["Check-Formular Ping", "/admin/checks/new/ping"],
  ["Check-Formular iperf3", "/admin/checks/new/iperf"],
  ["Check-Formular WAN", "/admin/checks/new/speedtest"],
  ["Check-Formular Sprache", "/admin/checks/new/rtp"],
  ["Konto", "/account"],
  ["Design", "/account/design"],
  ["Passwort vergessen", "/passwort-vergessen"],
  ["Audit-Log", "/admin/audit"],
];

module.exports = { BASE, PASSWORD, PAGES, ids };
