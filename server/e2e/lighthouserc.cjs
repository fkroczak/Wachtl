// Lighthouse CI für repräsentative Seiten. Grenzwerte und Ausnahmen: docs/quality-guardrails.md
// Baseline (Median aus 3 Läufen, mobil, 2026-10-16): Performance 98–100, LCP 1,07–1,27 s, TBT ≤ 6 ms,
// CLS 0 (Check-Formular vorher 0,083), Seitengewicht 35–91 KB.
const { ids } = require("./pages");

const BASE = process.env.WACHTL_BASE_URL || "http://127.0.0.1:5000";
const cookie = process.env.WACHTL_COOKIE || "";

module.exports = {
  ci: {
    collect: {
      url: [
        "/login", "/", `/sites/${ids.site}`, `/probes/${ids.probe}`, `/probes/${ids.probe}/checks/${ids.ping_check}`,
        "/alerts", "/meldungen?status=all", "/admin", "/admin/checks/new/iperf",
      ].map((p) => BASE + p),
      numberOfRuns: 3,
      ...(process.env.CHROME_PATH ? { chromePath: process.env.CHROME_PATH } : {}),
      settings: {
        // Standard = mobile Emulation mit simulierter Drosselung (strengste Variante)
        extraHeaders: JSON.stringify(cookie ? { Cookie: cookie } : {}),
        chromeFlags: "--no-sandbox --headless=new",
        onlyCategories: ["performance", "accessibility", "best-practices", "seo"],
      },
    },
    assert: {
      assertions: {
        // blockierend
        "categories:accessibility": ["error", { minScore: 1, aggregationMethod: "median" }],
        "categories:best-practices": ["error", { minScore: 1, aggregationMethod: "median" }],
        "categories:performance": ["error", { minScore: 0.9, aggregationMethod: "median" }],
        "largest-contentful-paint": ["error", { maxNumericValue: 2000, aggregationMethod: "median" }],
        "cumulative-layout-shift": ["error", { maxNumericValue: 0.05, aggregationMethod: "median" }],
        "total-blocking-time": ["error", { maxNumericValue: 200, aggregationMethod: "median" }],
        "total-byte-weight": ["error", { maxNumericValue: 170 * 1024, aggregationMethod: "median" }],  // 0.10: Graph-Seite ~161 KB (+8 KB CSS)
        "resource-summary:script:size": ["error", { maxNumericValue: 36 * 1024 }],  // 1.0: Live-Benachrichtigungen (~34 KB)
        "resource-summary:stylesheet:size": ["error", { maxNumericValue: 40 * 1024 }],  // 1.0: Hinweise unten rechts (~38 KB); 0.10: UniFi-Design, Seitenleiste, Reiter, Hamburger-Menü
        "resource-summary:third-party:count": ["error", { maxNumericValue: 0 }],
        // nur Warnung
        "first-contentful-paint": ["warn", { maxNumericValue: 1500, aggregationMethod: "median" }],
        "categories:seo": ["warn", { minScore: 0.9 }],
        // bewusste Ausnahmen (Begründung in docs/quality-guardrails.md)
        "uses-text-compression": "off",
        "unminified-css": "off",
        "unminified-javascript": "off",
        "render-blocking-resources": "off",
        "render-blocking-insight": "off",
        "network-dependency-tree-insight": "off",
        "document-latency-insight": "off",
      },
    },
    upload: { target: "filesystem", outputDir: ".lighthouseci" },
  },
};
