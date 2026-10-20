// Graphen werden gezeichnet und die Seiten werfen keine JavaScript-Fehler. Blockierend.
const { test, expect } = require("@playwright/test");
const { ids } = require("../pages");

for (const [name, path, host, dots] of [
  ["Bandbreite", `/probes/${ids.probe}/bandwidth/${ids.wan_check}`, "#bw-chart", 2],
  ["Sprache (RTP)", `/probes/${ids.probe}/rtp/${ids.rtp_check}`, "#mos-chart", 1],
]) {
  test(`${name}: Graph mit Messpunkten, keine Skriptfehler`, async ({ page }) => {
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(path);
    const svg = page.locator(`${host} svg[role=img]`);
    await expect(svg).toHaveCount(1);
    await expect(svg).toHaveAttribute("aria-label", /im Zeitverlauf/);
    expect(await page.locator(`${host} circle`).count()).toBeGreaterThanOrEqual(dots);
    expect(errors).toEqual([]);
  });
}
