// Topologie-Baum: Ist er breiter als die Karte, beim Laden zum gewählten oder markierten Gerät scrollen,
// sonst zur Wurzel (Internet) – statt links mit leerer Fläche oder abgeschnittenen Knoten zu beginnen.
(function () {
  for (const box of document.querySelectorAll(".topo-scroll")) {
    if (box.scrollWidth <= box.clientWidth) continue;
    const svg = box.querySelector("svg.topo");
    if (!svg) continue;
    let node = svg.querySelector(".tn-sel") || svg.querySelector(".tn-hl");
    if (!node) {   // Wurzel = oberster Knoten
      let top = Infinity;
      for (const n of svg.querySelectorAll(".tn")) {
        const y = n.getBoundingClientRect().top;
        if (y < top) { top = y; node = n; }
      }
    }
    if (!node) continue;
    const r = node.getBoundingClientRect(), b = box.getBoundingClientRect();
    box.scrollLeft += r.left + r.width / 2 - (b.left + b.width / 2);
  }
})();
