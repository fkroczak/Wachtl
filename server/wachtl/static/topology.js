// Topologie-Baum: Zoom (Knöpfe, Strg+Mausrad, Ziehen zum Verschieben) und Startansicht.
// Ohne JavaScript bleibt der Baum in Originalgröße mit Bildlaufleiste – die Liste darunter enthält dasselbe.
(function () {
  const MIN = 0.15, MAX = 2, STEP = 1.25, FAR = 0.55;
  const KEY = "wachtl.topo.zoom:" + location.pathname;

  function load() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function save(v) { try { localStorage.setItem(KEY, v); } catch (e) { /* privat: egal */ } }

  for (const box of document.querySelectorAll(".topo-scroll")) {
    const svg = box.querySelector("svg.topo");
    if (!svg) continue;
    const vb = svg.viewBox.baseVal, W = vb.width, H = vb.height;
    box.classList.add("topo-zoomable");

    // Leiste
    const bar = document.createElement("div");
    bar.className = "topo-zoom";
    bar.setAttribute("role", "toolbar");
    bar.setAttribute("aria-label", "Zoom des Baums");
    bar.innerHTML =
      '<button type="button" class="button" data-z="out" aria-label="Verkleinern">−</button>' +
      '<output aria-live="polite">100 %</output>' +
      '<button type="button" class="button" data-z="in" aria-label="Vergrößern">+</button>' +
      '<button type="button" class="button" data-z="fit">Ganz zeigen</button>' +
      '<button type="button" class="button" data-z="one">100 %</button>' +
      '<span class="hint">Strg + Mausrad zoomt, Ziehen verschiebt</span>';
    box.parentNode.insertBefore(bar, box);
    const out = bar.querySelector("output");

    let z = 1;
    function fitScale() {
      const maxH = parseFloat(getComputedStyle(box).maxHeight) || box.clientHeight;
      const cw = box.clientWidth - 4;
      return Math.max(MIN, Math.min(1, cw / W, (maxH - 12) / H));
    }
    // Zoom setzen; (fx, fy) = Punkt im Kasten, der an seiner Stelle bleibt
    function apply(next, fx, fy) {
      next = Math.max(MIN, Math.min(MAX, next));
      if (fx === undefined) { fx = box.clientWidth / 2; fy = box.clientHeight / 2; }
      const r = box.getBoundingClientRect(), s = svg.getBoundingClientRect();
      // Punkt in Baum-Koordinaten (unabhängig von margin:auto-Zentrierung)
      const px = (r.left + fx - s.left) / z, py = (r.top + fy - s.top) / z;
      z = next;
      svg.setAttribute("width", Math.round(W * z));
      svg.setAttribute("height", Math.round(H * z));
      svg.classList.toggle("topo-far", z < FAR);
      out.textContent = Math.round(z * 100) + " %";
      const s2 = svg.getBoundingClientRect();
      box.scrollLeft += (s2.left + px * z) - (r.left + fx);
      box.scrollTop += (s2.top + py * z) - (r.top + fy);
    }
    function focusNode() {   // gewählten/markierten Knoten, sonst die Wurzel in die Mitte holen
      let node = svg.querySelector(".tn-sel") || svg.querySelector(".tn-hl");
      if (!node) {
        let top = Infinity;
        for (const n of svg.querySelectorAll(".tn")) {
          const y = n.getBoundingClientRect().top;
          if (y < top) { top = y; node = n; }
        }
      }
      if (!node) return;
      const r = node.getBoundingClientRect(), b = box.getBoundingClientRect();
      box.scrollLeft += r.left + r.width / 2 - (b.left + b.width / 2);
      if (box.scrollHeight > box.clientHeight) box.scrollTop += r.top - b.top - 24;
    }

    bar.addEventListener("click", function (e) {
      const k = e.target.closest("button") && e.target.closest("button").dataset.z;
      if (!k) return;
      if (k === "in") apply(z * STEP);
      else if (k === "out") apply(z / STEP);
      else if (k === "one") { apply(1); focusNode(); }
      else if (k === "fit") { apply(fitScale()); box.scrollLeft = 0; box.scrollTop = 0; }
      save(k === "fit" ? "fit" : String(z));
    });

    // Strg/⌘ + Mausrad (auch Zwei-Finger-Zoom am Touchpad) zoomt um den Mauszeiger
    box.addEventListener("wheel", function (e) {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      const r = box.getBoundingClientRect();
      apply(z * Math.exp(-e.deltaY * 0.0025), e.clientX - r.left, e.clientY - r.top);
      save(String(z));
    }, { passive: false });

    // Ziehen mit der Maus verschiebt; ein Klick ohne Bewegung öffnet weiter den Switch
    let drag = null, moved = false;
    box.addEventListener("pointerdown", function (e) {
      if (e.pointerType !== "mouse" || e.button !== 0) return;
      drag = { x: e.clientX, y: e.clientY, l: box.scrollLeft, t: box.scrollTop, id: e.pointerId };
      moved = false;
    });
    box.addEventListener("pointermove", function (e) {
      if (!drag) return;
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (!moved && Math.abs(dx) + Math.abs(dy) < 5) return;
      if (!moved) { moved = true; box.classList.add("panning"); box.setPointerCapture(drag.id); }
      box.scrollLeft = drag.l - dx;
      box.scrollTop = drag.t - dy;
    });
    box.addEventListener("dragstart", function (e) { e.preventDefault(); });   // Links nicht als Link ziehen
    function end() { drag = null; box.classList.remove("panning"); }
    box.addEventListener("pointerup", end);
    box.addEventListener("pointercancel", end);
    box.addEventListener("click", function (e) {
      if (moved) { e.preventDefault(); e.stopPropagation(); moved = false; }
    }, true);

    // Startansicht: gespeicherter Zoom; sonst ganzer Baum, solange er dabei lesbar bleibt
    const saved = load(), fit = fitScale();
    if (saved === "fit") apply(fit);
    else if (saved && !isNaN(parseFloat(saved))) apply(parseFloat(saved));
    else apply(fit >= FAR ? fit : 1);
    if (z > fit + 0.001) focusNode(); else { box.scrollLeft = 0; box.scrollTop = 0; }

    let rt;
    window.addEventListener("resize", function () {
      clearTimeout(rt);
      rt = setTimeout(function () { if (load() === "fit") apply(fitScale()); }, 150);
    });
  }
})();
