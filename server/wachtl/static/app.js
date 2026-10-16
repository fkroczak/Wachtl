/* Wachtl – Dashboard-Skripte (ohne Inline-Skripte, CSP 'self'). */
(function () {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

  // Sicherheitsabfrage für Buttons mit data-confirm
  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-confirm]");
    if (btn && !window.confirm(btn.dataset.confirm)) ev.preventDefault();
  });

  // Check-Zuweisung: Standort/Probe-Auswahl ein- und ausblenden
  const scopeSelect = document.getElementById("scope-select");
  if (scopeSelect) {
    const update = () => {
      document.querySelectorAll("[data-scope]").forEach((el) => {
        el.hidden = el.dataset.scope !== scopeSelect.value;
      });
    };
    scopeSelect.addEventListener("change", update);
    update();
  }

  // Übersichten automatisch aktualisieren
  const auto = document.querySelector("[data-autorefresh]");
  if (auto) {
    const seconds = parseInt(auto.dataset.autorefresh, 10) || 30;
    setTimeout(() => {
      if (!document.hidden) window.location.reload();
    }, seconds * 1000);
  }

  // Check-Formular: Felder abhängig von Auswahlfeldern ein- und ausblenden
  const checkForm = document.querySelector("[data-check-form]");
  if (checkForm) {
    const deps = checkForm.querySelectorAll("[data-show-if]");
    const value = (name) => {
      const field = checkForm.querySelector(`[name="${name}"]`);
      const label = field?.closest("[data-show-if]");
      if (label && label.hidden) return null;   // abhängige Auswahl, selbst ausgeblendet
      return field ? field.value : null;
    };
    const update = () => {
      // zweimal, damit verschachtelte Abhängigkeiten (Verfahren -> Protokoll -> UDP-Rate) stimmen
      for (let pass = 0; pass < 2; pass++) {
        deps.forEach((label) => {
          const [name, allowed] = label.dataset.showIf.split(":");
          const visible = allowed.split(",").includes(value(name));
          label.hidden = !visible;
          label.querySelectorAll("input, select").forEach((i) => (i.disabled = !visible));
        });
      }
    };
    checkForm.addEventListener("change", update);
    update();
  }

  // Bandbreiten-Seite
  const bwData = document.getElementById("bw-data");
  if (bwData) renderBandwidth(JSON.parse(bwData.textContent), document.getElementById("bw-chart"));

  // Ziel-Detailseite: Graph und Statistik
  const panel = document.getElementById("chart-panel");
  if (!panel) return;

  const fmtMs = (v) => (v === null || v === undefined ? "–" : (v < 10 ? v.toFixed(2) : v.toFixed(1)) + " ms");
  const fmtPct = (v) => (v === null || v === undefined ? "–" : v.toFixed(2) + " %");
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const errorBox = document.getElementById("chart-error");
  const sourceLabel = document.getElementById("chart-source");

  async function getJSON(url) {
    const r = await fetch(url, { headers: { "X-CSRF-Token": csrf }, credentials: "same-origin" });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || "HTTP " + r.status);
    return data;
  }

  // Eigener, schlanker SVG-Graph: keine externe Bibliothek, läuft auch ohne Internet.
  const SVGNS = "http://www.w3.org/2000/svg";
  const chartEl = document.getElementById("chart");
  const tip = document.createElement("div");
  tip.className = "chart-tip";
  tip.hidden = true;
  chartEl.appendChild(tip);
  let lastData = null;

  function el(name, attrs, parent) {
    const node = document.createElementNS(SVGNS, name);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (parent) parent.appendChild(node);
    return node;
  }

  function niceMax(v) {
    if (!(v > 0)) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  function fmtTime(ms, spanMs) {
    const d = new Date(ms);
    const hm = d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
    if (spanMs <= 86400000) return hm;
    return d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" }) + (spanMs <= 3 * 86400000 ? " " + hm : "");
  }

  // Zerlegt eine Reihe an Lücken (null) in zusammenhängende Abschnitte
  function segments(points) {
    const out = [];
    let cur = [];
    for (const p of points) {
      if (p[1] === null || p[2] === null) {
        if (cur.length) out.push(cur);
        cur = [];
      } else cur.push(p);
    }
    if (cur.length) out.push(cur);
    return out;
  }

  function render(data) {
    lastData = data;
    const s = data.series;
    const times = s.avg.map((p) => p[0]);
    chartEl.querySelector("svg")?.remove();
    const W = chartEl.clientWidth || 800;
    const H = chartEl.clientHeight || 420;
    const pad = { l: 52, r: 16, t: 16, b: 28 };
    const lossH = Math.round((H - pad.t - pad.b) * 0.2);
    const latH = H - pad.t - pad.b - lossH - 18;
    const svg = el("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img",
      "aria-label": "Latenz und Paketverlust" });
    chartEl.insertBefore(svg, tip);

    if (!times.length) {
      el("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "c-muted" }, svg).textContent =
        "Keine Messdaten im gewählten Zeitraum";
      sourceLabel.textContent = "";
      return;
    }

    const t0 = times[0], t1 = times[times.length - 1] || t0 + 1;
    const span = Math.max(t1 - t0, 1);
    const x = (t) => pad.l + ((t - t0) / span) * (W - pad.l - pad.r);
    const maxVals = s.max.map((p) => p[1]).filter((v) => v !== null);
    const yMax = niceMax(Math.max(1, ...maxVals) * 1.05);
    const y = (v) => pad.t + latH - (v / yMax) * latH;
    const lossTop = pad.t + latH + 18;
    const lossMaxRaw = Math.max(0, ...s.loss.map((p) => p[1] || 0));
    const lossMax = Math.max(5, niceMax(lossMaxRaw));
    const yl = (v) => lossTop + lossH - (v / lossMax) * lossH;

    // Raster und Achsen
    const grid = el("g", { class: "c-grid" }, svg);
    for (let i = 0; i <= 4; i++) {
      const v = (yMax / 4) * i;
      el("line", { x1: pad.l, x2: W - pad.r, y1: y(v), y2: y(v) }, grid);
      el("text", { x: pad.l - 6, y: y(v) + 4, "text-anchor": "end", class: "c-axis" }, svg).textContent =
        (yMax < 5 ? v.toFixed(1) : Math.round(v)) + (i === 4 ? " ms" : "");
    }
    el("line", { x1: pad.l, x2: W - pad.r, y1: lossTop + lossH, y2: lossTop + lossH }, grid);
    el("text", { x: pad.l - 6, y: lossTop + 8, "text-anchor": "end", class: "c-axis" }, svg).textContent = lossMax + " %";
    el("text", { x: pad.l - 6, y: lossTop + lossH, "text-anchor": "end", class: "c-axis" }, svg).textContent = "0";
    const ticks = Math.max(2, Math.floor((W - pad.l - pad.r) / 110));
    for (let i = 0; i <= ticks; i++) {
      const t = t0 + (span / ticks) * i;
      el("line", { x1: x(t), x2: x(t), y1: pad.t, y2: lossTop + lossH }, grid);
      el("text", { x: x(t), y: H - 8, "text-anchor": i === 0 ? "start" : i === ticks ? "end" : "middle",
        class: "c-axis" }, svg).textContent = fmtTime(t, span);
    }

    // Min-Max-Band und Durchschnitt
    const minMap = new Map(s.min.map((p) => [p[0], p[1]]));
    const band = s.max.map((p) => [p[0], minMap.get(p[0]) ?? null, p[1]]);
    for (const seg of segments(band)) {
      const top = seg.map((p) => `${x(p[0]).toFixed(1)},${y(p[2]).toFixed(1)}`);
      const bottom = seg.slice().reverse().map((p) => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`);
      el("polygon", { points: top.concat(bottom).join(" "), class: "c-band" }, svg);
    }
    for (const seg of segments(s.avg.map((p) => [p[0], p[1], 0]))) {
      el("polyline", { points: seg.map((p) => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join(" "),
        class: "c-avg" }, svg);
    }
    // Jitter als gestrichelte Linie auf derselben ms-Achse
    for (const seg of segments((s.jitter || []).map((p) => [p[0], p[1], 0]))) {
      el("polyline", { points: seg.map((p) => `${x(p[0]).toFixed(1)},${y(Math.min(p[1], yMax)).toFixed(1)}`).join(" "),
        class: "c-jitter" }, svg);
    }

    // Paketverlust als Balken
    const bw = Math.max(1, ((W - pad.l - pad.r) / times.length) * 0.8);
    for (const [t, v] of s.loss) {
      if (v > 0) el("rect", { x: x(t) - bw / 2, y: yl(v), width: bw, height: lossTop + lossH - yl(v), class: "c-loss" }, svg);
    }

    // Tooltip
    const cursor = el("line", { y1: pad.t, y2: lossTop + lossH, class: "c-cursor", visibility: "hidden" }, svg);
    const lookup = (key, t) => s[key].find((p) => p[0] === t)?.[1] ?? null;
    svg.addEventListener("mousemove", (ev) => {
      const rect = svg.getBoundingClientRect();
      const px = ev.clientX - rect.left;
      if (px < pad.l || px > W - pad.r) return;
      const target = t0 + ((px - pad.l) / (W - pad.l - pad.r)) * span;
      let best = times[0];
      for (const t of times) if (Math.abs(t - target) < Math.abs(best - target)) best = t;
      cursor.setAttribute("x1", x(best));
      cursor.setAttribute("x2", x(best));
      cursor.setAttribute("visibility", "visible");
      tip.innerHTML = "";
      const rows = [
        [new Date(best).toLocaleString("de-DE"), ""],
        ["Durchschnitt", fmtMs(lookup("avg", best))],
        ["Min / Max", fmtMs(lookup("min", best)) + " / " + fmtMs(lookup("max", best))],
        ["Jitter", fmtMs(s.jitter ? lookup("jitter", best) : null)],
        ["Verlust", fmtPct(lookup("loss", best))],
      ];
      for (const [k, v] of rows) {
        const row = document.createElement("div");
        row.textContent = v ? `${k}: ${v}` : k;
        tip.appendChild(row);
      }
      tip.hidden = false;
      const left = x(best) + 12;
      tip.style.left = (left + 190 > W ? x(best) - 200 : left) + "px";
      tip.style.top = pad.t + 4 + "px";
    });
    svg.addEventListener("mouseleave", () => {
      tip.hidden = true;
      cursor.setAttribute("visibility", "hidden");
    });

    sourceLabel.textContent =
      (data.source === "agg" ? "1-min-Aggregate" : "Rohdaten") + ", Auflösung " + data.step_s + " s";
  }

  window.addEventListener("resize", () => lastData && render(lastData));


  async function loadSeries(range) {
    errorBox.hidden = true;
    try {
      const url = new URL(panel.dataset.seriesUrl, window.location.href);
      url.searchParams.set("range", range);
      render(await getJSON(url.toString()));
    } catch (e) {
      errorBox.textContent = "Graph konnte nicht geladen werden: " + e.message;
      errorBox.hidden = false;
    }
  }

  async function loadStats() {
    try {
      const stats = await getJSON(panel.dataset.statsUrl);
      document.querySelectorAll("#stats tr[data-window]").forEach((tr) => {
        const row = stats[tr.dataset.window] || {};
        tr.querySelectorAll("td[data-k]").forEach((td) => {
          const v = row[td.dataset.k];
          td.textContent = td.dataset.k === "loss" ? fmtPct(v) : fmtMs(v);
        });
      });
    } catch (e) {
      document.querySelectorAll("#stats td[data-k]").forEach((td) => (td.textContent = "–"));
    }
  }

  let current = "1h";
  panel.querySelectorAll("[data-range]").forEach((btn) =>
    btn.addEventListener("click", () => {
      panel.querySelectorAll("[data-range]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      current = btn.dataset.range;
      loadSeries(current);
    })
  );
  loadSeries(current);
  loadStats();
  setInterval(() => {
    if (document.hidden) return;
    if (current === "1h" || current === "6h") loadSeries(current);
    loadStats();
  }, 30000);

  // Bandbreiten-Graph: Punkte und Linien für Download/Upload, Schwellwerte gestrichelt
  function renderBandwidth(data, host) {
    const NS = "http://www.w3.org/2000/svg";
    const mk = (name, attrs, parent) => {
      const n = document.createElementNS(NS, name);
      for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
      if (parent) parent.appendChild(n);
      return n;
    };
    const draw = () => {
      host.querySelector("svg")?.remove();
      const W = host.clientWidth || 800, H = host.clientHeight || 320;
      const pad = { l: 64, r: 16, t: 16, b: 28 };
      const svg = mk("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Bandbreite" });
      host.appendChild(svg);
      const all = data.down.concat(data.up);
      if (!all.length) {
        mk("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "c-muted" }, svg).textContent =
          "Noch keine Messungen im gewählten Zeitraum";
        return;
      }
      const t0 = data.start, t1 = data.end, span = Math.max(t1 - t0, 1);
      let top = Math.max(...all.map((p) => p[1]), data.min_down || 0, data.min_up || 0) * 1.1;
      const p10 = Math.pow(10, Math.floor(Math.log10(top || 1)));
      top = [1, 2, 2.5, 5, 10].map((m) => m * p10).find((v) => v >= top) || 10 * p10;
      const x = (t) => pad.l + ((t - t0) / span) * (W - pad.l - pad.r);
      const y = (v) => pad.t + (H - pad.t - pad.b) * (1 - v / top);
      const grid = mk("g", { class: "c-grid" }, svg);
      for (let i = 0; i <= 4; i++) {
        const v = (top / 4) * i;
        mk("line", { x1: pad.l, x2: W - pad.r, y1: y(v), y2: y(v) }, grid);
        mk("text", { x: pad.l - 6, y: y(v) + 4, "text-anchor": "end", class: "c-axis" }, svg).textContent =
          (top < 10 ? v.toFixed(1) : Math.round(v)) + (i === 4 ? " Mbit/s" : "");
      }
      const ticks = Math.max(2, Math.floor((W - pad.l - pad.r) / 120));
      for (let i = 0; i <= ticks; i++) {
        const t = t0 + (span / ticks) * i;
        const d = new Date(t);
        mk("text", { x: x(t), y: H - 8, "text-anchor": i === 0 ? "start" : i === ticks ? "end" : "middle", class: "c-axis" }, svg)
          .textContent = d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" }) +
            (span <= 2 * 86400000 ? " " + d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" }) : "");
      }
      for (const [key, min] of [["down", data.min_down], ["up", data.min_up]]) {
        if (min > 0) mk("line", { x1: pad.l, x2: W - pad.r, y1: y(min), y2: y(min), class: `c-thr c-${key}` }, svg);
        const pts = data[key];
        if (pts.length > 1) mk("polyline", { points: pts.map((p) => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join(" "), class: `c-bwline c-${key}` }, svg);
        for (const p of pts) {
          const c = mk("circle", { cx: x(p[0]), cy: y(p[1]), r: 3, class: `c-bwdot c-${key}` }, svg);
          mk("title", {}, c).textContent = `${key === "down" ? "Download" : "Upload"} ${p[1].toFixed(1)} Mbit/s – ${new Date(p[0]).toLocaleString("de-DE")}`;
        }
      }
    };
    draw();
    window.addEventListener("resize", draw);
  }
})();
