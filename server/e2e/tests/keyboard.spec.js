// Wesentliche Abläufe nur mit der Tastatur, inklusive Fehlerzuständen. Blockierend.
const { test, expect } = require("@playwright/test");
const { PASSWORD, ids } = require("../pages");

test("Skip-Link ist das erste Element und springt in den Inhalt", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Zum Inhalt springen" });
  await expect(skip).toBeFocused();
  await expect(skip).toBeInViewport();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
});

test("Anmelden nur mit Tastatur, Fehler wird angesagt", async ({ browser }) => {
  const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await ctx.newPage();
  await page.goto("/login");
  await expect(page.getByLabel("Benutzername")).toBeFocused();          // autofocus
  await page.keyboard.type("admin");
  await page.keyboard.press("Tab");
  await page.keyboard.type("falsches-passwort");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("alert")).toContainText("falsch");
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").focus();
  await page.keyboard.type(PASSWORD);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Übersicht" })).toBeVisible();
  await ctx.close();
});

test("Hauptnavigation: aktuelle Seite markiert, per Tastatur erreichbar", async ({ page }) => {
  await page.goto("/alerts");
  const nav = page.getByRole("navigation", { name: "Hauptnavigation" });
  await expect(nav.getByRole("link", { name: "Alarme" })).toHaveAttribute("aria-current", "page");
  await nav.getByRole("link", { name: "Ausfälle" }).focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/outages/);
});

test("Fokus ist auf jedem Bedienelement sichtbar", async ({ page }) => {
  await page.goto("/admin/checks/new/iperf");
  for (let i = 0; i < 25; i++) {
    await page.keyboard.press("Tab");
    const style = await page.evaluate(() => {
      const el = document.activeElement;
      const cs = getComputedStyle(el);
      return { tag: el.tagName, name: el.getAttribute("name") || el.textContent.trim().slice(0, 30),
               outline: cs.outlineStyle, width: parseFloat(cs.outlineWidth), shadow: cs.boxShadow };
    });
    const visible = (style.outline !== "none" && style.width >= 2) || style.shadow !== "none";
    expect(visible, `kein sichtbarer Fokus auf ${style.tag} ${style.name}`).toBe(true);
  }
});

test("Check-Formular: Fehler per Tastatur finden und beheben", async ({ page }) => {
  await page.goto("/admin/checks/new/iperf");
  await page.getByLabel("An Wochentagen").fill("189");
  await page.getByLabel("Name").focus();
  await page.keyboard.press("Enter");                                    // absenden mit Enter

  const summary = page.getByRole("alert");
  await expect(summary).toBeFocused();
  await expect(summary).toContainText("Name fehlt");
  await expect(summary).toContainText("Wochentage");

  // Sprunglink in der Übersicht führt zum Feld; Feld ist als ungültig markiert und beschrieben
  await summary.getByRole("link", { name: /Wochentage/ }).press("Enter");
  const weekdays = page.getByLabel("An Wochentagen");
  await expect(weekdays).toBeFocused();
  await expect(weekdays).toHaveAttribute("aria-invalid", "true");
  await expect(weekdays).toHaveAccessibleDescription(/nur Ziffern 1 bis 7/);
  await expect(weekdays).toHaveValue("189");                               // Eingabe bleibt erhalten

  await weekdays.fill("12345");
  await page.getByLabel("Name").fill("E2E Tastatur-Check");
  await page.getByLabel("Name").press("Enter");
  await expect(page.getByRole("status")).toContainText("E2E Tastatur-Check");
});

test("Abhängige Felder erscheinen beim Umschalten", async ({ page }) => {
  await page.goto("/admin/checks/new/iperf");
  await expect(page.locator("#f-udp_mbps")).toBeHidden();
  await page.getByLabel("Protokoll").selectOption("udp");
  await expect(page.locator("#f-udp_mbps")).toBeVisible();
  await expect(page.locator("#f-window_kb")).toBeHidden();
});

test("Zeitraum-Buttons melden ihren Zustand", async ({ page }) => {
  await page.goto(`/probes/${ids.probe}/checks/${ids.ping_check}`);
  const day = page.getByRole("button", { name: "24h" });
  await expect(day).toHaveAttribute("aria-pressed", "false");
  await day.press("Enter");
  await expect(day).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("button", { name: "1h" })).toHaveAttribute("aria-pressed", "false");
});
