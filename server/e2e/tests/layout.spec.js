// Reflow, Zoom-Ersatz, Gesetz der Nähe (relativ, keine Pixelvergleiche) und Auto-Refresh. Blockierend.
const { test, expect } = require("@playwright/test");
const { PAGES, ids } = require("../pages");

// 320 CSS-px ≙ 1280 px bei 400 % Zoom (WCAG 1.4.10), 640 px ≙ 200 %, 768/900 px = Tablet (Audit 2026-10-21)
for (const width of [320, 640, 768, 900]) {
  test.describe(`Reflow ${width}px`, () => {
    test.use({ viewport: { width, height: 800 } });
    for (const [name, url] of PAGES) {
      test(`${name}: kein seitliches Scrollen der Seite`, async ({ page }) => {
        await page.goto(url, { waitUntil: "networkidle" });
        const overflow = await page.evaluate(() => {
          const vw = document.documentElement.clientWidth;
          // Tabellen dürfen in ihrem eigenen Container scrollen (zweidimensionale Inhalte, WCAG-Ausnahme)
          const culprits = [...document.querySelectorAll("body *")]
            .filter((el) => el.getBoundingClientRect().right > vw + 1 && !el.closest("table, .scroll, pre, svg"))
            .slice(0, 5).map((el) => `${el.tagName.toLowerCase()}.${el.className}`);
          return { scroll: document.documentElement.scrollWidth, vw, culprits };
        });
        expect(overflow.scroll, `Seite breiter als ${overflow.vw}px: ${overflow.culprits.join(", ")}`)
          .toBeLessThanOrEqual(overflow.vw);
      });
    }
  });
}

// Label liegt näher an seinem eigenen Feld als an jedem anderen Feld – in allen Breiten
const FORMS = ["/admin/checks/new/ping", "/admin/checks/new/iperf", "/admin/checks/new/speedtest", "/admin",
               `/probes/${ids.probe}?tab=details`, "/account", "/outages"];
for (const width of [1280, 768, 320]) {
  test.describe(`Gesetz der Nähe ${width}px`, () => {
    test.use({ viewport: { width, height: 900 } });
    for (const url of FORMS) {
      test(url, async ({ page }) => {
        await page.goto(url);
        const problems = await page.evaluate(() => {
          const gap = (a, b) => Math.hypot(Math.max(0, a.left - b.right, b.left - a.right),
                                           Math.max(0, a.top - b.bottom, b.top - a.bottom));
          const controls = [...document.querySelectorAll("input:not([type=hidden]), select, textarea")]
            .filter((c) => c.offsetParent !== null && !c.closest("table"));
          const out = [];
          for (const c of controls) {
            const label = c.labels && c.labels[0];
            if (!label) continue;                        // fehlende Labels prüft axe
            const text = [...label.childNodes].find((n) => n.nodeType === 3 && n.textContent.trim()) || label;
            const range = document.createRange();
            range.selectNodeContents(text);
            const lr = range.getBoundingClientRect();
            const own = gap(lr, c.getBoundingClientRect());
            for (const other of controls) {
              if (other === c || label.contains(other)) continue;
              const d = gap(lr, other.getBoundingClientRect());
              if (d <= own) out.push(`„${label.textContent.trim().slice(0, 40)}“: eigenes Feld ${own.toFixed(0)}px, ` +
                                     `${other.name} ${d.toFixed(0)}px`);
            }
          }
          return out;
        });
        expect(problems, problems.join("\n")).toEqual([]);
      });
    }
  });
}

test.describe("Auto-Refresh", () => {
  test("lädt die Übersicht neu, wenn niemand tippt", async ({ page }) => {
    await page.clock.install();
    await page.goto("/");
    const reload = page.waitForEvent("load");
    await page.clock.runFor(31_000);
    await reload;
  });

  test("verwirft keine Eingaben auf Seiten mit Formular", async ({ page }) => {
    await page.clock.install();
    await page.goto(`/probes/${ids.probe}?tab=details`);
    const field = page.getByLabel("Adresse für andere Probes");
    await field.fill("10.0.0.99");
    await page.getByRole("heading", { level: 1 }).click();               // Fokus weg, Formular bleibt geändert
    let reloaded = false;
    page.on("load", () => (reloaded = true));
    await page.clock.runFor(95_000);
    expect(reloaded).toBe(false);
    await expect(field).toHaveValue("10.0.0.99");
  });
});

test.describe("Suche auf der Seite Standorte", () => {
  test("filtert Standorte nach Kundennummer und übersteht das Neuladen", async ({ page }) => {
    await page.clock.install();
    await page.goto("/standorte");
    await page.getByLabel("Standort suchen").fill("K-1002");          // Kundennummer der Filiale
    await expect(page.locator("li.site-tile:visible")).toHaveCount(1);
    await expect(page).toHaveURL(/[?&]q=K-1002/);
    await page.getByRole("heading", { level: 1 }).click();
    const reload = page.waitForEvent("load");
    await page.clock.runFor(31_000);                                              // Auto-Refresh läuft weiter
    await reload;
    await expect(page.getByLabel("Standort suchen")).toHaveValue("K-1002");
    await page.getByLabel("Standort suchen").fill("gibt-es-nicht");
    await expect(page.getByText("Kein Standort passt")).toBeVisible();
  });
});
