// axe-core gegen WCAG 2.2 A/AA + Best Practices auf allen Seitentypen, hell und dunkel. Blockierend.
const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;
const { PAGES } = require("../pages");

const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];

function report(violations) {
  return violations.map((v) => `${v.id} (${v.impact}): ${v.help}\n` +
    v.nodes.slice(0, 5).map((n) => `    ${n.target.join(" ")} – ${n.failureSummary.split("\n")[1] || ""}`).join("\n"))
    .join("\n");
}

async function scan(page) {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  return violations;
}

for (const scheme of ["light", "dark"]) {
  test.describe(`axe ${scheme}`, () => {
    test.use({ colorScheme: scheme });

    for (const [name, url] of PAGES) {
      test(`${name} (${url})`, async ({ page }) => {
        await page.goto(url, { waitUntil: "networkidle" });
        const violations = await scan(page);
        expect(violations, report(violations)).toEqual([]);
      });
    }

    test("Anmeldung", async ({ browser }) => {
      const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, colorScheme: scheme });
      const page = await ctx.newPage();
      await page.goto("/login");
      const violations = await scan(page);
      expect(violations, report(violations)).toEqual([]);
      await ctx.close();
    });
  });
}

test("Check-Formular im Fehlerzustand", async ({ page }) => {
  await page.goto("/admin/checks/new/iperf");
  await page.getByLabel("An Wochentagen").fill("189");
  await page.getByRole("button", { name: "Check anlegen" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  const violations = await scan(page);
  expect(violations, report(violations)).toEqual([]);
});
