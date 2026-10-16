// Einmal anmelden und die Sitzung für alle Tests speichern.
const { chromium } = require("@playwright/test");
const { BASE, PASSWORD } = require("./pages");

module.exports = async () => {
  const browser = await chromium.launch(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {});
  const page = await browser.newPage();
  await page.goto(BASE + "/login");
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(PASSWORD);
  await Promise.all([page.waitForURL(BASE + "/"), page.getByRole("button", { name: "Anmelden" }).click()]);
  await page.context().storageState({ path: ".auth/admin.json" });
  await browser.close();
};
