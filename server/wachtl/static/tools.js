/* Wachtl – Werkzeuge (docs/WERKZEUGE.md): Einzeltest starten, Fortschritt mit Balken, Ergebnis anzeigen. */
(function () {
  "use strict";

  const form = document.querySelector("[data-tool-form]");
  const box = document.querySelector("[data-tool-result]");
  if (!form || !box) return;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const info = JSON.parse(document.getElementById("tool-info")?.textContent || "{}");
  const bar = box.querySelector("[data-tool-progress]");
  const fill = bar.querySelector("i");
  const track = bar.querySelector(".ptrack");
  const stepEl = box.querySelector("[data-tool-step]");
  const etaEl = box.querySelector("[data-tool-eta]");
  const noteEl = box.querySelector("[data-tool-note]");
  const out = box.querySelector("[data-tool-out]");
  const runBtn = form.querySelector("[data-tool-run]");
  const hostInput = form.elements.host;
  const hostLabel = form.querySelector('label[for="f-host"]');
  const hint = form.querySelector("[data-tool-hint]");
  let polling = null;

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const tool = () => form.querySelector("input[name=tool]:checked")?.value || "ping";
  const val = (n) => (form.elements[n]?.value || "").trim();
  const on = (n) => !!form.elements[n]?.checked;

  function showTool() {
    const t = tool(), [, label, ph, text] = info[t] || [];
    form.querySelectorAll("fieldset[data-tool]").forEach((fs) => { fs.hidden = fs.dataset.tool !== t; });
    if (hostLabel && label) hostLabel.textContent = label;
    if (ph) hostInput.placeholder = ph;
    if (hint && text) hint.textContent = text;
    const url = new URL(window.location.href);
    url.searchParams.set("werkzeug", t);
    url.searchParams.set("probe", val("probe"));
    window.history.replaceState(null, "", url);
  }
  form.querySelectorAll("input[name=tool]").forEach((r) => r.addEventListener("change", showTool));
  form.elements.probe?.addEventListener("change", showTool);

  function payload() {
    const t = tool(), h = val("host"), base = { tool: t, probe: val("probe") };
    return Object.assign(base, {
      ping: { host: h, count: val("p_count"), size: val("p_size"), interval: val("p_interval"), df: on("p_df") },
      mtu: { host: h, min: val("m_min"), max: val("m_max"), tries: val("m_tries") },
      trace: { host: h, count: val("t_count"), max_hops: val("t_hops"), names: on("t_names") },
      dns: { name: h, type: val("d_type"), server: val("d_server") },
      port: { host: h, ports: val("o_ports"), timeout: val("o_timeout") },
      http: { url: h, method: val("h_method"), insecure: on("h_insecure") },
      tls: { host: h, port: val("s_port"), sni: val("s_sni") },
    }[t]);
  }

  // Fortschritt: echte Zwischenstände der Probe (Paket, Hop, Port …), sonst geschätzt aus der erwarteten Dauer
  function progress(job, probeOnline) {
    box.hidden = false;
    bar.hidden = false;
    if (job.status === "queued") {
      bar.classList.add("indet");
      fill.style.width = "";
      track.removeAttribute("aria-valuenow");
      stepEl.textContent = job.ahead > 0 ? `Wartet, ${job.ahead} Test(s) davor …` : "Wartet auf die Probe …";
      etaEl.textContent = "";
      noteEl.textContent = probeOnline === false ? "Die Probe ist gerade offline – der Test startet, sobald sie sich meldet (höchstens 5 Minuten)."
        : "Ein PC holt den Test beim nächsten Kontakt ab (spätestens nach 30 s), der Wachtl-Server sofort.";
      return;
    }
    const el = Math.max(0, (job.now || Date.now() / 1000) - (job.started || job.now));
    const est = job.eta || 5;
    const frac = job.progress != null && job.progress > 0 ? job.progress : Math.min(0.95, el / est);
    const left = job.progress > 0.05 ? el / job.progress - el : est - el;
    const over = !(job.progress > 0) && el > est * 1.1;
    bar.classList.toggle("indet", over);
    const pct = Math.round(Math.min(0.99, Math.max(0.03, frac)) * 100);
    fill.style.width = over ? "" : pct + "%";
    track.setAttribute("aria-valuenow", String(pct));
    stepEl.textContent = job.step || `${job.label} läuft …`;
    etaEl.textContent = over ? `${Math.round(el)} s – dauert länger als erwartet` : `${Math.round(el)} s · noch ca. ${Math.max(1, Math.round(left))} s`;
    noteEl.textContent = "";
    out.innerHTML = job.output ? `<pre class="tool-raw">${esc(job.output)}</pre>` : "";
  }

  function render(job) {
    box.hidden = false;
    bar.hidden = true;
    const r = job.result || {};
    let html = `<p class="muted">${esc(job.label)} zu <strong>${esc(job.target)}</strong></p>`;
    if (job.status === "error") {
      html += `<p class="tool-verdict bad">${esc(job.error || "Test fehlgeschlagen")}</p>`;
    }
    if (r.headline) html += `<p class="tool-verdict ${r.verdict === "bad" ? "bad" : r.verdict === "warn" ? "warn" : "good"}">${esc(r.headline)}</p>`;
    const s = r.stats;
    if (s && s.sent != null) {
      const loss = s.loss ?? 0, lc = loss === 0 ? "good" : loss >= 50 ? "bad" : "warn";
      const fm = (v) => (v == null ? "–" : (+v).toLocaleString("de-DE", { maximumFractionDigits: v < 10 ? 2 : 1 }));
      html += `<div class="tool-stats">
        <div><b class="${lc}">${fm(loss)} %</b><span>Verlust (${s.received}/${s.sent})</span></div>
        <div><b>${fm(s.min)}</b><span>min ms</span></div><div><b>${fm(s.avg)}</b><span>Mittel ms</span></div>
        <div><b>${fm(s.max)}</b><span>max ms</span></div><div><b>${fm(s.mdev)}</b><span>Streuung ms</span></div></div>`;
    }
    if (r.summary && r.summary.length) {
      html += `<dl class="tool-kv">${r.summary.map(([k, v, c]) => `<dt>${esc(k)}</dt><dd class="${esc(c)}">${esc(v)}</dd>`).join("")}</dl>`;
    }
    const t = r.table;
    if (t && t.rows && t.rows.length) {
      html += `<h3>${esc(t.title || "Details")}</h3><div class="scroll"><table class="tool-table"><thead><tr>${t.head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>`
        + t.rows.map((row, i) => `<tr class="${esc((t.classes || [])[i] || "")}">${row.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")
        + "</tbody></table></div>";
    }
    if (job.output) html += `<details${job.status === "error" ? " open" : ""}><summary>Ausgabe</summary><pre class="tool-raw">${esc(job.output)}</pre></details>`;
    out.innerHTML = html;
  }

  async function poll(id, probeOnline) {
    clearTimeout(polling);
    try {
      const r = await fetch(form.dataset.job.replace(/0$/, String(id)), { credentials: "same-origin" });
      const data = await r.json();
      const job = data.job;
      if (job.status === "ok" || job.status === "error") {
        render(job);
        done();
        return;
      }
      progress(job, probeOnline);
    } catch (e) {
      stepEl.textContent = "Verbindung zum Server unterbrochen – versuche es weiter …";
    }
    polling = setTimeout(() => poll(id, probeOnline), 1000);
  }

  function done() {
    if (runBtn) { runBtn.disabled = false; runBtn.textContent = "Test starten"; }
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (!runBtn) return;
    if (!val("host")) { hostInput.focus(); return; }
    runBtn.disabled = true;
    runBtn.textContent = "Läuft …";
    out.innerHTML = "";
    progress({ status: "queued", ahead: 0 });
    try {
      const r = await fetch(form.dataset.start, {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify(payload()),
      });
      const data = await r.json();
      if (!r.ok) {
        bar.hidden = true;
        out.innerHTML = `<p class="tool-verdict bad" role="alert">${esc(data.error || "Test konnte nicht starten.")}</p>`;
        done();
        return;
      }
      progress(data.job, data.online);
      poll(data.job.id, data.online);
    } catch (e) {
      bar.hidden = true;
      out.innerHTML = `<p class="tool-verdict bad" role="alert">Server nicht erreichbar.</p>`;
      done();
    }
  });

  document.addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-tool-show]");
    if (!b) return;
    ev.preventDefault();
    box.hidden = false;
    poll(b.dataset.toolShow);
    box.scrollIntoView({ behavior: "smooth", block: "start" });
  });
})();
