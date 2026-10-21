// Screenshots wichtiger Seiten (Desktop 1280 px, Handy 375 px) für docs/audit/screens/<name>/.
// Aufruf aus server/e2e nach start-server.sh und einem Testlauf (.auth/admin.json): node screens.js vorher
const { chromium } = require("@playwright/test");
const { BASE, PAGES } = require("./pages");
const out = `${__dirname}/../../docs/audit/screens/${process.argv[2] || "neu"}`;
const KEEP = ["Übersicht", "Standort", "Probe", "Ziel (Graph)", "Alarme", "Verwaltung", "Konto"];
(async () => {
  require("fs").mkdirSync(out, { recursive: true });
  const browser = await chromium.launch(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {});
  for (const [w, h, tag] of [[1280, 800, "desktop"], [375, 812, "mobil"]]) {
    const ctx = await browser.newContext({ viewport: { width: w, height: h }, storageState: `${__dirname}/.auth/admin.json`, locale: "de-DE" });
    const page = await ctx.newPage();
    for (const [name, p] of PAGES.filter(([n]) => KEEP.includes(n))) {
      await page.goto(BASE + p);
      await page.screenshot({ path: `${out}/${tag}-${name.replace(/[^\p{L}\d]+/gu, "_")}.jpg`, type: "jpeg", quality: 60 });
    }
    await ctx.close();
  }
  const anon = await browser.newPage({ viewport: { width: 375, height: 812 } });
  await anon.goto(BASE + "/login");
  await anon.screenshot({ path: `${out}/mobil-Login.jpg`, type: "jpeg", quality: 60 });
  await browser.close();
})();
