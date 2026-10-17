// Browser-Guardrails für das Wachtl-Web-UI. Server vorher starten: e2e/start-server.sh
const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "tests",
  globalSetup: require.resolve("./global-setup.js"),
  fullyParallel: false,
  workers: 1,                       // eine SQLite-DB, Tests teilen sich die Demodaten
  retries: 0,                       // Flakes sollen auffallen, nicht verschwinden
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.WACHTL_BASE_URL || "http://127.0.0.1:5000",
    storageState: ".auth/admin.json",
    locale: "de-DE",
    trace: "retain-on-failure",
    launchOptions: process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {},
  },
});
