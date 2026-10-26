/* Wachtl – Tagesansicht (nur /verlauf): Bereich in der Zeitleiste aufziehen → Analyse. CSP: keine Inline-Skripte. */
(function () {
  "use strict";
  // Tag: Bereich aufziehen (Klick = ±15 min) → Analyse; Tastatur: Formular von/bis
  const dz = document.querySelector("[data-zoom]");
  if (dz) {
    const t0 = +dz.dataset.start, span = +dz.dataset.end - t0;
    const sel = dz.appendChild(document.createElement("div"));
    let drag = null;
    sel.className = "tl-sel";
    sel.hidden = true;
    const frac = (ev) => Math.min(1, Math.max(0, (ev.clientX - drag.r.left) / drag.r.width));
    const show = (a, b) => {
      const w = drag.r.width;
      sel.hidden = false;
      sel.style.left = drag.r.left - dz.getBoundingClientRect().left + Math.min(a, b) * w + "px";
      sel.style.width = Math.abs(b - a) * w + "px";
    };
    dz.addEventListener("pointerdown", (ev) => {
      const lane = ev.target.closest(".tl-lane");
      if (!lane || ev.button !== 0 || ev.target.closest("[data-href]")) return;
      drag = { r: lane.getBoundingClientRect(), x: ev.clientX };
      drag.a = frac(ev);
      ev.preventDefault();
    });
    window.addEventListener("pointermove", (ev) => drag && show(drag.a, frac(ev)));
    window.addEventListener("pointerup", (ev) => {
      if (!drag) return;
      const a = drag.a, b = frac(ev), click = Math.abs(ev.clientX - drag.x) < 5;
      drag = null;
      let from = t0 + Math.min(a, b) * span, to = t0 + Math.max(a, b) * span;
      if (click) [from, to] = [from - 900, from + 900];
      window.location.href = dz.dataset.zoom + Math.round(from) + "/" + Math.round(Math.max(to, from + 10));
    });
  }
})();
