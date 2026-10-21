// Screenshots wichtiger Seiten (Desktop 1280 px, Handy mit Touch = iPhone 13) für docs/audit/screens/<name>/.
// Aufruf aus server/e2e nach start-server.sh: node screens.js nachher   (Server: WACHTL_BASE_URL)
const { chromium, devices } = require("@playwright/test");
const { BASE, PASSWORD, PAGES } = require("./pages");
const out = `${__dirname}/../../docs/audit/screens/${process.argv[2] || "neu"}`;
const KEEP = ["Übersicht", "Standort", "Probe", "Ziel (Graph)", "Alarme", "Verwaltung", "Konto"];
(async () => {
  require("fs").mkdirSync(out, { recursive: true });
  const browser = await chromium.launch(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {});
  for (const [opts, tag] of [[{ viewport: { width: 1280, height: 800 } }, "desktop"], [devices["iPhone 13"], "mobil"]]) {
    const page = await (await browser.newContext({ ...opts, locale: "de-DE" })).newPage();
    await page.goto(BASE + "/login");
    if (tag === "mobil") await page.screenshot({ path: `${out}/mobil-Login.jpg`, type: "jpeg", quality: 60 });
    await page.getByLabel("Benutzername").fill("admin");
    await page.getByLabel("Passwort").fill(PASSWORD);
    await Promise.all([page.waitForURL(BASE + "/"), page.getByRole("button", { name: "Anmelden" }).click()]);
    for (const [name, p] of PAGES.filter(([n]) => KEEP.includes(n))) {
      await page.goto(BASE + p);
      await page.waitForTimeout(800);   // Graph lädt per fetch
      await page.screenshot({ path: `${out}/${tag}-${name.replace(/[^\p{L}\d]+/gu, "_")}.jpg`, type: "jpeg", quality: 60 });
    }
  }
  await browser.close();
})();
