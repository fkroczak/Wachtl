// Meldet sich an und gibt den Cookie-Header aus – für Lighthouse CI (Seiten hinter der Anmeldung).
const { BASE, PASSWORD } = require("./pages");

(async () => {
  const first = await fetch(BASE + "/login");
  const jar = (first.headers.getSetCookie() || []).map((c) => c.split(";")[0]);
  const csrf = (await first.text()).match(/name="csrf_token" value="([^"]+)"/)[1];
  const res = await fetch(BASE + "/login", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: jar.join("; ") },
    body: new URLSearchParams({ username: "admin", password: PASSWORD, csrf_token: csrf }),
  });
  const session = (res.headers.getSetCookie() || []).map((c) => c.split(";")[0]);
  if (res.status !== 302 || !session.length) throw new Error(`Anmeldung fehlgeschlagen (HTTP ${res.status})`);
  process.stdout.write(session.join("; "));
})().catch((e) => { console.error(e.message); process.exit(1); });
