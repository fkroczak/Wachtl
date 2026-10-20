/* Wachtl – Dashboard-Skripte (ohne Inline-Skripte, CSP 'self'). */
(function () {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

  // Sicherheitsabfrage für Buttons mit data-confirm
  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-confirm]");
    if (btn && !window.confirm(btn.dataset.confirm)) ev.preventDefault();
  });

  // Benutzermenü: schließt bei Klick daneben und mit Escape (Fokus zurück auf den Namen)
  const userMenu = document.querySelector("[data-usermenu]");
  if (userMenu) {
    document.addEventListener("click", (ev) => {
      if (userMenu.open && !userMenu.contains(ev.target)) userMenu.open = false;
    });
    userMenu.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && userMenu.open) {
        userMenu.open = false;
        userMenu.querySelector("summary").focus();
      }
    });
  }

  // Design-Seite: Auswahl sofort als Vorschau zeigen, gespeichert wird erst mit „Speichern“
  const designForm = document.querySelector("[data-design-form]");
  if (designForm) {
    designForm.addEventListener("change", (ev) => {
      if (ev.target.name === "theme") document.documentElement.dataset.theme = ev.target.value;
      if (ev.target.name === "contrast") document.documentElement.dataset.contrast = ev.target.value;
    });
  }

  // Check-Zuweisung: Standort/Probe-Auswahl ein- und ausblenden
  const scopeSelect = document.querySelector("[data-scope-select]");
  if (scopeSelect) {
    const update = () => {
      document.querySelectorAll("[data-scope]").forEach((el) => {
        el.hidden = el.dataset.scope !== scopeSelect.value;
      });
    };
    scopeSelect.addEventListener("change", update);
    update();
  }

  // Fehlerübersicht nach dem Absenden fokussieren, damit Screenreader sie vorlesen
  document.querySelector("[data-error-summary]")?.focus();

  // Übersichten automatisch aktualisieren – aber nie mitten in einer Eingabe:
  // ein Neuladen würde Eingaben verwerfen und Fokus/Leseposition zurücksetzen.
  const auto = document.querySelector("[data-autorefresh]");
  if (auto) {
    const seconds = parseInt(auto.dataset.autorefresh, 10) || 30;
    let dirty = false;
    document.addEventListener("input", () => (dirty = true));
    document.addEventListener("change", () => (dirty = true));
    const busy = () => {
      const a = document.activeElement;
      return dirty || document.hidden || (a && a.matches("input, select, textarea, [contenteditable]"));
    };
    const tick = () => (busy() ? setTimeout(tick, seconds * 1000) : window.location.reload());
    setTimeout(tick, seconds * 1000);
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

  // Bandbreiten-Graph (Standard) bzw. MOS-Verlauf des Sprachtests: Reihen, Schwellen, Achse
  const BW_CHART = {
    series: [["down", "Download", "min_down"], ["up", "Upload", "min_up"]],
    unit: " Mbit/s", lineClass: "c-bwline", dotClass: "c-bwdot",
    aria: "Graph: Download und Upload im Zeitverlauf. Einzelwerte stehen in der Tabelle Messungen.",
    value: (v) => `${v.toFixed(1)} Mbit/s`,
  };
  const MOS_CHART = {
    series: [["mos", "MOS", "min_mos"]], unit: "", bottom: 1, top: 5, lineClass: "c-bwline", dotClass: "c-bwdot",
    aria: "Graph: Sprachqualität (MOS, 1 bis 5) im Zeitverlauf. Einzelwerte stehen in der Tabelle Tests.",
    value: (v) => `MOS ${v.toFixed(2)}`, tick: (v) => v.toFixed(0),
  };

  // Bandbreiten-Seite und Sprachtest-Seite
  const bwData = document.getElementById("bw-data");
  if (bwData) renderBandwidth(JSON.parse(bwData.textContent), document.getElementById("bw-chart"));
  const mosData = document.getElementById("mos-data");
  if (mosData) renderBandwidth(JSON.parse(mosData.textContent), document.getElementById("mos-chart"), MOS_CHART);

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
  const live = document.getElementById("chart-live");
  let lastData = null, zoom = null;   // zoom: [erster, letzter] Punkt des Ausschnitts

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

  // Smokeping-Darstellung wie HOP7: Rauch p10–p90 und p25–p75, Median nach Paketverlust gefärbt,
  // Latenzschwelle gestrichelt, Zeiten über Schwelle hinterlegt, Verluststreifen unter der Zeitachse.
  function render(data) {
    lastData = data;
    chartEl.querySelector("svg")?.remove();
    chartEl.onkeydown = null;
    tip.hidden = true;
    const s = data.series, thr = data.thr || {}, step = data.step_s;
    // Punkte auf feste Zeitschlitze legen: fehlende Schritte werden Lücken statt Verbindungslinien
    const base = Math.floor(data.start / step), n = Math.floor(data.end / step) - base + 1;
    const slots = (key) => {
      const out = new Array(n).fill(null);
      for (const [t, v] of s[key] || []) {
        const i = Math.round(t / 1000 / step) - base;
        if (i >= 0 && i < n) out[i] = v;
      }
      return out;
    };
    const [p10, p25, med, p75, p90, loss, jit] = ["p10", "p25", "p50", "p75", "p90", "loss", "jitter"].map(slots);
    const W = chartEl.clientWidth || 800;
    const H = chartEl.clientHeight || 420;
    const pad = { l: 52, r: 16, t: 16, b: 44 };
    const PH = H - pad.t - pad.b, bottom = pad.t + PH, PW = W - pad.l - pad.r;
    const svg = el("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img",
      "aria-label": "Graph: Latenz (Median und Streuung), Jitter und Paketverlust im gewählten Zeitraum. Zahlenwerte stehen in der Tabelle Statistik." });
    chartEl.insertBefore(svg, tip);

    if (![med, p90, loss, jit].some((arr) => arr.some((v) => v !== null))) {
      el("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "c-muted" }, svg).textContent =
        "Keine Messdaten im gewählten Zeitraum";
      sourceLabel.textContent = "";
      return;
    }

    const a = zoom ? zoom[0] : 0, b = zoom ? zoom[1] : n - 1, span = Math.max(b - a, 1);
    const x = (i) => pad.l + ((i - a) / span) * PW;
    const tOf = (i) => (base + i) * step * 1000;
    const bw = PW / span;
    const shown = (arr) => arr.slice(a, b + 1).filter((v) => v !== null);
    const vals = shown(p90).concat(shown(med), shown(jit)).sort((u, v) => u - v);
    let top = (vals[Math.floor(vals.length * 0.98)] || 1) * 1.15;   // einzelne Ausreißer kappen statt alles zu stauchen
    const lw = thr.lat_warn_ms, warn = thr.loss_warn_pct, bad = thr.loss_bad_pct;
    if (lw && lw < top * 1.3) top = Math.max(top, lw * 1.08);
    const yMax = niceMax(top);
    const y = (v) => bottom - (Math.min(v, yMax) / yMax) * PH;
    // Verlustklasse: 0 = kein Verlust, 1 = bis Warnschwelle, 2 = bis kritisch, 3 = darüber
    const lossCls = (l) => (l === null ? null : l <= 0 ? 0 : bad != null && l > bad ? 3 : warn != null && l > warn ? 2 : 1);
    // Hinterlegung wie die Alarmregeln: Mittel über deren Fenster (meist 5 min) statt je Punkt.
    // Die Latenzregel mittelt Einzelpings, hier wird der Median gemittelt – für die Anzeige nah genug.
    const roll = (arr, win) => {
      const k = Math.max(1, Math.round((win || step) / step));
      return arr.map((_, i) => {
        const w = arr.slice(Math.max(0, i - k + 1), i + 1).filter((v) => v !== null);
        return w.length ? w.reduce((p, v) => p + v, 0) / w.length : null;
      });
    };
    const lossW = roll(loss, thr.loss_window_s), latW = roll(med, thr.lat_window_s);
    const overLat = (i) => !!lw && latW[i] > lw;
    const level = (i) => (lossCls(lossW[i]) === 3 ? 2 : lossCls(lossW[i]) === 2 || overLat(i) ? 1 : 0);

    // Hinterlegung: Zeiträume über Schwelle gelb bzw. rot, benachbarte Punkte zu einem Balken
    for (let i = a; i <= b; i++) {
      const lv = level(i);
      if (!lv) continue;
      let j = i;
      while (j < b && level(j + 1) === lv) j++;
      const x0 = Math.max(pad.l, x(i) - bw / 2), x1 = Math.min(W - pad.r, x(j) + bw / 2);
      el("rect", { x: x0, y: pad.t, width: Math.max(x1 - x0, 1.5), height: PH, class: lv === 2 ? "c-over-bad" : "c-over-warn" }, svg);
      i = j;
    }

    // Raster und Achsen
    const grid = el("g", { class: "c-grid" }, svg);
    for (let k = 0; k <= 4; k++) {
      const v = (yMax / 4) * k;
      el("line", { x1: pad.l, x2: W - pad.r, y1: y(v), y2: y(v) }, grid);
      el("text", { x: pad.l - 6, y: y(v) + 4, "text-anchor": "end", class: "c-axis" }, svg).textContent =
        (yMax < 5 ? v.toFixed(1) : Math.round(v)) + (k === 4 ? " ms" : "");
    }
    const ticks = Math.max(2, Math.floor(PW / 110));
    for (let k = 0; k <= ticks; k++) {
      const i = a + (span / ticks) * k;
      el("line", { x1: x(i), x2: x(i), y1: pad.t, y2: bottom }, grid);
      el("text", { x: x(i), y: bottom + 15, "text-anchor": k === 0 ? "start" : k === ticks ? "end" : "middle",
        class: "c-axis" }, svg).textContent = fmtTime(tOf(i), tOf(b) - tOf(a));
    }

    // Rauch: 80 % der Pings hell, mittlere 50 % dunkler
    const area = (lo, hi, cls) => {
      let d = "", seg = [];
      const flush = () => {
        if (seg.length > 1) d += "M" + seg.map((i) => `${x(i).toFixed(1)},${y(hi[i]).toFixed(1)}`).join("L") + "L" +
          seg.reverse().map((i) => `${x(i).toFixed(1)},${y(lo[i]).toFixed(1)}`).join("L") + "Z";
        seg = [];
      };
      for (let i = a; i <= b; i++) lo[i] !== null && hi[i] !== null ? seg.push(i) : flush();
      flush();
      if (d) el("path", { d, class: cls }, svg);
    };
    area(p10, p90, "c-smoke-out");
    area(p25, p75, "c-smoke-in");
    if (lw && lw <= yMax) el("line", { x1: pad.l, x2: W - pad.r, y1: y(lw), y2: y(lw), class: "c-thr-lat" }, svg);

    // Median, abschnittsweise in der Farbe der Verlustklasse
    let run = null;
    const flushRun = () => {
      if (run) el("polyline", { points: run.pts.join(" "), class: "c-med c-l" + run.c }, svg);
      run = null;
    };
    const pt = (i) => `${x(i).toFixed(1)},${y(med[i]).toFixed(1)}`;
    for (let i = a + 1; i <= b; i++) {
      if (med[i - 1] === null || med[i] === null) { flushRun(); continue; }
      const c = lossCls(loss[i]) || 0;
      if (!run || run.c !== c) { flushRun(); run = { c, pts: [pt(i - 1)] }; }
      run.pts.push(pt(i));
    }
    flushRun();

    // Jitter: eigene Linie auf derselben ms-Achse, Lücken bleiben Lücken
    let jd = "";
    for (let i = a; i <= b; i++) {
      if (jit[i] === null) continue;
      jd += (i > a && jit[i - 1] !== null ? "L" : "M") + `${x(i).toFixed(1)},${y(jit[i]).toFixed(1)}`;
    }
    if (jd) el("path", { d: jd, class: "c-jitter" }, svg);

    // Verluststreifen unter der Zeitachse: ein Kästchen je Punkt mit Verlust
    for (let i = a; i <= b; i++) {
      const c = lossCls(loss[i]);
      if (c) el("rect", { x: x(i) - bw / 2, y: bottom + 22, width: Math.max(bw, 1.5), height: 8, class: "c-lossbox c-l" + c }, svg);
    }
    el("text", { x: pad.l - 6, y: bottom + 30, "text-anchor": "end", class: "c-axis" }, svg).textContent = "Verlust";

    // Störungsmeldungen: senkrechte Markierung mit Dreieck zum gemeldeten Zeitpunkt
    const marks = [];
    for (const r of data.reports || []) {
      const i = r.ts / step - base;
      if (i < a || i > b) continue;
      drawReportMark(el, el("g", {}, svg), x(i), pad.t, bottom);
      marks.push({ x: x(i), r });
    }
    if (marks.length) svg.setAttribute("aria-label", svg.getAttribute("aria-label") + reportAria(marks.length));

    // Tooltip per Maus, Finger oder Tastatur; Bereich aufziehen vergrößert, Doppelklick zeigt wieder alles
    const sel = el("rect", { x: pad.l, y: pad.t, width: 0, height: PH, class: "c-sel", visibility: "hidden" }, svg);
    const cursor = el("line", { y1: pad.t, y2: bottom, class: "c-cursor", visibility: "hidden" }, svg);
    const hit = el("rect", { x: pad.l, y: pad.t, width: PW, height: PH + 32, class: "c-hit" }, svg);
    const tipLines = (i) => {
      const mins = (w) => ` im ${Math.max(1, Math.round((w || step) / 60))}-min-Mittel`;
      const why = [overLat(i) && "Latenz " + fmtMs(latW[i]) + mins(thr.lat_window_s),
        lossCls(lossW[i]) >= 2 && "Verlust " + fmtPct(lossW[i]) + mins(thr.loss_window_s)];
      const lines = [new Date(tOf(i)).toLocaleString("de-DE"), "Median: " + fmtMs(med[i]),
        `Mittlere 50 %: ${fmtMs(p25[i])} – ${fmtMs(p75[i])}`, `80 %: ${fmtMs(p10[i])} – ${fmtMs(p90[i])}`,
        "Jitter: " + fmtMs(jit[i]), "Verlust: " + fmtPct(loss[i])];
      if (level(i)) lines.push("Über Schwelle: " + why.filter(Boolean).join(", "));
      return lines;
    };
    const showAt = (i) => {
      cursor.setAttribute("x1", x(i));
      cursor.setAttribute("x2", x(i));
      cursor.setAttribute("visibility", "visible");
      tip.innerHTML = "";
      const rows = tipLines(i).map((t) => [t, ""]);
      for (const m of marks.filter((m) => Math.abs(m.x - x(i)) <= Math.max(8, bw / 2))) {
        reportLines(m.r).forEach((t, k) => rows.push([t, k === 0 ? "tip-report" : ""]));
      }
      for (const [t, cls] of rows) {
        const row = document.createElement("div");
        row.textContent = t;
        row.className = cls;
        tip.appendChild(row);
      }
      tip.hidden = false;
      const tw = tip.offsetWidth || 190;
      tip.style.left = Math.max(4, Math.min(x(i) > W * 0.6 ? x(i) - tw - 12 : x(i) + 12, W - tw - 4)) + "px";
      tip.style.top = pad.t + 4 + "px";
      return rows.map((r) => r[0]).join(". ");
    };
    const hide = () => {
      tip.hidden = true;
      cursor.setAttribute("visibility", "hidden");
    };
    const idx = (ev) => {
      const px = ev.clientX - svg.getBoundingClientRect().left;
      return Math.max(a, Math.min(b, Math.round(a + ((px - pad.l) / PW) * span)));
    };
    let drag = null;
    hit.addEventListener("pointermove", (ev) => {
      const i = idx(ev);
      if (drag !== null) {
        sel.setAttribute("x", x(Math.min(drag, i)));
        sel.setAttribute("width", Math.abs(x(i) - x(drag)));
        sel.setAttribute("visibility", "visible");
      }
      if (ev.pointerType === "mouse" || drag !== null) showAt(i);
    });
    hit.addEventListener("pointerleave", (ev) => ev.pointerType === "mouse" && drag === null && hide());
    hit.addEventListener("pointerdown", (ev) => {
      if (ev.button !== 0) return;
      drag = idx(ev);
      hit.setPointerCapture(ev.pointerId);
      if (ev.pointerType === "mouse") ev.preventDefault();
    });
    hit.addEventListener("pointerup", (ev) => {
      if (drag === null) return;
      const i = idx(ev), lo = Math.min(drag, i), hi = Math.max(drag, i);
      drag = null;
      sel.setAttribute("visibility", "hidden");
      // shortcut: Zoom vergrößert nur die geladenen Punkte (Auflösung bleibt), für feinere Punkte from/to an die API geben
      if (x(hi) - x(lo) >= 12) {
        zoom = [lo, hi];
        render(data);
      } else if (ev.pointerType !== "mouse") showAt(i);
    });
    hit.addEventListener("pointercancel", () => {
      drag = null;
      sel.setAttribute("visibility", "hidden");
    });
    hit.addEventListener("dblclick", () => {
      if (!zoom) return;
      zoom = null;
      render(data);
    });
    // Tastatur: Pfeiltasten je Punkt, Bild auf/ab zehn Punkte, Pos1/Ende, Esc blendet aus; Werte gehen an die Live-Region
    let ki = null;
    chartEl.onkeydown = (ev) => {
      if (ev.key === "Escape" && ki !== null) {
        ev.preventDefault();
        ki = null;
        hide();
        return;
      }
      const d = { ArrowLeft: -1, ArrowRight: 1, PageUp: -10, PageDown: 10 }[ev.key];
      if (d === undefined && ev.key !== "Home" && ev.key !== "End") return;
      ev.preventDefault();
      ki = ev.key === "Home" ? a : ev.key === "End" ? b : Math.max(a, Math.min(b, (ki ?? (d > 0 ? a - 1 : b + 1)) + d));
      live.textContent = showAt(ki);
    };
    chartEl.onblur = () => {
      if (ki === null) return;
      ki = null;
      hide();
    };

    sourceLabel.textContent = (data.source === "agg" ? "1-min-Aggregate" : "Rohdaten") + ", Auflösung " + step + " s" +
      (zoom ? " · Ausschnitt, Doppelklick zeigt alles" : "");
  }

  window.addEventListener("resize", () => lastData && render(lastData));


  // ?at=<Unix-Sekunden>: Fenster um eine Störungsmeldung herum statt bis jetzt
  const at = parseInt(panel.dataset.at || "", 10) || null;

  async function loadReports(from, to) {
    if (!panel.dataset.reportsUrl || !from || !to) return [];
    try {
      const url = new URL(panel.dataset.reportsUrl, window.location.href);
      url.searchParams.set("from", from);
      url.searchParams.set("to", to);
      return (await getJSON(url.toString())).reports || [];
    } catch (e) {
      return [];   // Markierungen sind Zusatz – der Graph erscheint auch ohne
    }
  }

  async function loadSeries(range) {
    errorBox.hidden = true;
    try {
      const url = new URL(panel.dataset.seriesUrl, window.location.href);
      url.searchParams.set("range", range);
      if (at) url.searchParams.set("at", at);
      const data = await getJSON(url.toString());   // Fenster (start/end) berechnet der Server
      data.reports = await loadReports(data.start, data.end);
      render(data);
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
      panel.querySelectorAll("[data-range]").forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-pressed", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-pressed", "true");
      current = btn.dataset.range;
      zoom = null;
      loadSeries(current);
    })
  );
  loadSeries(current);
  loadStats();
  setInterval(() => {
    if (document.hidden) return;
    if (!at && !zoom && (current === "1h" || current === "6h")) loadSeries(current);
    loadStats();
  }, 30000);

  function reportAria(n) {
    return ` ${n === 1 ? "Eine Störungsmeldung ist" : n + " Störungsmeldungen sind"} als senkrechte Linie markiert.`;
  }

  // Störungsmeldung als senkrechte, gestrichelte Linie mit Dreieck oben (beide Graph-Arten)
  function drawReportMark(mk, g, xx, top, bottom) {
    mk("line", { x1: xx, x2: xx, y1: top, y2: bottom, class: "c-report" }, g);
    mk("line", { x1: xx, x2: xx, y1: top - 12, y2: bottom, class: "c-report-hit" }, g);
    mk("polygon", { points: `${xx - 5},${top - 12} ${xx + 5},${top - 12} ${xx},${top - 3}`, class: "c-report-mark" }, g);
  }

  // Zeilen für Tooltip bzw. SVG-Titel einer Meldung
  function reportLines(r) {
    const when = new Date(r.ts * 1000).toLocaleString("de-DE");
    const lines = ["Störungsmeldung" + (r.status === "done" ? " (erledigt)" : ""), r.category_label,
      `${r.user || "Benutzer unbekannt"} · ${r.probe}`, when + (r.duration_label ? " · " + r.duration_label : "")];
    if (r.description) lines.push(r.description.length > 160 ? r.description.slice(0, 157) + " …" : r.description);
    return lines;
  }

  // Bandbreiten-Graph: Punkte und Linien für Download/Upload, Schwellwerte gestrichelt
  function renderBandwidth(data, host, opts = BW_CHART) {
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
      const svg = mk("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": opts.aria });
      host.appendChild(svg);
      const all = opts.series.flatMap(([key]) => data[key]);
      if (!all.length) {
        mk("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "c-muted" }, svg).textContent =
          "Noch keine Messungen im gewählten Zeitraum";
        return;
      }
      const t0 = data.start, t1 = data.end, span = Math.max(t1 - t0, 1);
      const bottom = opts.bottom || 0;
      let top = opts.top;
      if (!top) {
        top = Math.max(...all.map((p) => p[1]), ...opts.series.map(([, , thr]) => data[thr] || 0)) * 1.1;
        const p10 = Math.pow(10, Math.floor(Math.log10(top || 1)));
        top = [1, 2, 2.5, 5, 10].map((m) => m * p10).find((v) => v >= top) || 10 * p10;
      }
      const x = (t) => pad.l + ((t - t0) / span) * (W - pad.l - pad.r);
      const y = (v) => pad.t + (H - pad.t - pad.b) * (1 - (Math.max(v, bottom) - bottom) / (top - bottom));
      const grid = mk("g", { class: "c-grid" }, svg);
      for (let i = 0; i <= 4; i++) {
        const v = bottom + ((top - bottom) / 4) * i;
        mk("line", { x1: pad.l, x2: W - pad.r, y1: y(v), y2: y(v) }, grid);
        mk("text", { x: pad.l - 6, y: y(v) + 4, "text-anchor": "end", class: "c-axis" }, svg).textContent =
          (opts.tick ? opts.tick(v) : top < 10 ? v.toFixed(1) : Math.round(v)) + (i === 4 ? opts.unit : "");
      }
      const ticks = Math.max(2, Math.floor((W - pad.l - pad.r) / 120));
      for (let i = 0; i <= ticks; i++) {
        const t = t0 + (span / ticks) * i;
        const d = new Date(t);
        mk("text", { x: x(t), y: H - 8, "text-anchor": i === 0 ? "start" : i === ticks ? "end" : "middle", class: "c-axis" }, svg)
          .textContent = d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" }) +
            (span <= 2 * 86400000 ? " " + d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" }) : "");
      }
      let shown = 0;
      for (const r of data.reports || []) {
        const t = r.ts * 1000;
        if (t < t0 || t > t1) continue;
        const g = mk("g", {}, svg);
        drawReportMark(mk, g, x(t), pad.t, H - pad.b);
        mk("title", {}, g).textContent = reportLines(r).join("\n");
        shown++;
      }
      if (shown) svg.setAttribute("aria-label", svg.getAttribute("aria-label") + reportAria(shown));
      for (const [key, label, thr] of opts.series) {
        const min = data[thr];
        if (min > 0) mk("line", { x1: pad.l, x2: W - pad.r, y1: y(min), y2: y(min), class: `c-thr c-${key}` }, svg);
        const pts = data[key];
        if (pts.length > 1) mk("polyline", { points: pts.map((p) => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join(" "), class: `${opts.lineClass} c-${key}` }, svg);
        for (const p of pts) {
          const c = mk("circle", { cx: x(p[0]), cy: y(p[1]), r: 3, class: `${opts.dotClass} c-${key}` }, svg);
          mk("title", {}, c).textContent = `${label === "MOS" ? "" : label + " "}${opts.value(p[1])} – ${new Date(p[0]).toLocaleString("de-DE")}`;
        }
      }
    };
    draw();
    window.addEventListener("resize", draw);
  }
})();

// Standort-Dashboard: aufgeklappte Detailbereiche über das automatische Neuladen hinweg offen halten
for (const d of document.querySelectorAll("details[id]")) {
  const key = "open:" + location.pathname + "#" + d.id;
  try { if (sessionStorage.getItem(key)) d.open = true; } catch (e) { /* Speicher gesperrt: bleibt zu */ }
  d.addEventListener("toggle", () => {
    try { d.open ? sessionStorage.setItem(key, "1") : sessionStorage.removeItem(key); } catch (e) { /* egal */ }
  });
}
