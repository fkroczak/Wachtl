"""Erzeugt alle Logo-Dateien aus einer Quelle (Wachtel-Umriss).

    python brand/render.py

Ausgabe: brand/out/*.svg|png, wachtl.ico, Wizard-Bitmaps; Kopien nach server/wachtl/static
und windows/assets. Benötigt Playwright (Chromium) und Pillow – nur zum Neuerzeugen, nicht im Betrieb.
"""
from __future__ import annotations

import io
import shutil
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
ROOT = HERE.parent

# Palette (flach, Farben einer Wachtel im Getreidefeld)
INK = "#3B2A1E"       # Umbra – Umriss, Text
BROWN = "#6B4A2E"     # Wachtelbraun – Markenfläche
WHEAT = "#E9D3A6"     # Weizen – Füllung
OCHRE = "#C98B2C"     # Ocker – Ruf/Ping
OCHRE_LIGHT = "#E2B25A"
CREAM = "#F7F4EE"     # Hintergrund

BODY = ("M41 49 C40.5 40 46.5 34.5 54 35 C59 35.3 62 38 64.5 41 C73 36.5 87 35.5 97 41 "
        "C105 45.5 110 53 113 60 L120 64 L112 69 C108 86 94 96 76 96 C56 96 42 86 41 71 "
        "C40.5 64 41 59 41.5 56 L33 52.5 Z")
FLANKS = "M70 64 C82 62 94 64 104 70 M66 74 C78 73 88 75 98 80"
LEGS = "M66 96 L64 108 M60 108 L68 108 M82 95 L84 108 M80 108 L88 108"
CALL = "M25 44 A11 11 0 0 0 25 61 M17 37 A19 19 0 0 0 17 68"


def logo_outline(ink=INK, accent=OCHRE) -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" fill="none" stroke-linecap="round" stroke-linejoin="round">
  <title>Wachtl</title>
  <path d="{BODY}" stroke="{ink}" stroke-width="5"/>
  <path d="{FLANKS}" stroke="{ink}" stroke-width="3.5"/>
  <path d="{LEGS}" stroke="{ink}" stroke-width="4"/>
  <circle cx="50" cy="46" r="2.6" fill="{ink}"/>
  <path d="{CALL}" stroke="{accent}" stroke-width="4.5"/>
</svg>
'''


def logo_filled() -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" fill="none" stroke-linecap="round" stroke-linejoin="round">
  <title>Wachtl</title>
  <path d="{BODY}" fill="{WHEAT}" stroke="{INK}" stroke-width="5"/>
  <path d="{FLANKS}" stroke="{BROWN}" stroke-width="3.5"/>
  <path d="{LEGS}" stroke="{INK}" stroke-width="4"/>
  <circle cx="50" cy="46" r="2.6" fill="{INK}"/>
  <path d="{CALL}" stroke="{OCHRE}" stroke-width="4.5"/>
</svg>
'''


def app_icon(small: bool = False) -> str:
    """Quadratisches Programm-Symbol; klein = dickere Linien, nur ein Bogen."""
    w_body, w_call, eye = (11, 11, 0) if small else (7, 7, 3.4)
    call = "M25 44 A11 11 0 0 0 25 61"
    eye_svg = f'<circle cx="50" cy="46" r="{eye}" fill="{CREAM}"/>' if eye else ""
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" fill="none" stroke-linecap="round" stroke-linejoin="round">
  <title>Wachtl</title>
  <rect width="128" height="128" rx="26" fill="{BROWN}"/>
  <g transform="translate(66 66) scale(1.02) translate(-72 -66)">
    <path d="{BODY}" stroke="{CREAM}" stroke-width="{w_body}"/>
    {eye_svg}
    <path d="{call}" stroke="{OCHRE_LIGHT}" stroke-width="{w_call}"/>
  </g>
</svg>
'''


def wordmark(dark: bool = False) -> str:
    ink, accent = (CREAM, OCHRE_LIGHT) if dark else (INK, OCHRE)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 420 128" fill="none" stroke-linecap="round" stroke-linejoin="round">
  <title>Wachtl</title>
  <path d="{BODY}" stroke="{ink}" stroke-width="5"/>
  <path d="{FLANKS}" stroke="{ink}" stroke-width="3.5"/>
  <path d="{LEGS}" stroke="{ink}" stroke-width="4"/>
  <circle cx="50" cy="46" r="2.6" fill="{ink}"/>
  <path d="{CALL}" stroke="{accent}" stroke-width="4.5"/>
  <text x="136" y="86" font-family="Inter, 'Segoe UI', Arial, sans-serif" font-size="58" font-weight="700" letter-spacing="-1" fill="{ink}" stroke="none">Wachtl</text>
</svg>
'''


def wizard_page(w: int, h: int) -> str:
    """Linkes Bild auf Willkommens- und Abschlussseite des Setups."""
    return f'''<!doctype html><html><head><style>
  html,body{{margin:0;width:{w}px;height:{h}px;overflow:hidden;background:{BROWN};font-family:Inter,'Segoe UI',sans-serif}}
  .wrap{{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:{h*0.03}px}}
  svg{{width:{w*0.8}px;height:{w*0.8}px}}
  .name{{color:{CREAM};font-weight:700;font-size:{w*0.17}px;letter-spacing:-0.02em}}
  .sub{{color:{OCHRE_LIGHT};font-weight:600;font-size:{w*0.058}px;text-transform:uppercase;letter-spacing:.1em}}
  .field{{position:absolute;left:0;right:0;bottom:0;height:{h*0.06}px;background:{OCHRE}}}
</style></head><body><div class="wrap">
<svg viewBox="0 0 128 128" fill="none" stroke-linecap="round" stroke-linejoin="round">
  <path d="{BODY}" fill="{WHEAT}" stroke="{CREAM}" stroke-width="4"/>
  <path d="{FLANKS}" stroke="{BROWN}" stroke-width="3.5"/>
  <path d="{LEGS}" stroke="{CREAM}" stroke-width="4"/>
  <circle cx="50" cy="46" r="2.6" fill="{INK}"/>
  <path d="{CALL}" stroke="{OCHRE_LIGHT}" stroke-width="4.5"/>
</svg>
<div class="name">Wachtl</div><div class="sub">Netzwerk&#8209;Monitoring</div></div><div class="field"></div></body></html>'''


def render(page, html: str, w: int, h: int, scale: float = 1) -> Image.Image:
    page.set_viewport_size({"width": w, "height": h})
    page.set_content(html)
    png = page.screenshot(omit_background=True, clip={"x": 0, "y": 0, "width": w, "height": h})
    return Image.open(io.BytesIO(png)).convert("RGBA")


def svg_page(svg: str, size: int, bg: str = "transparent") -> str:
    return (f"<!doctype html><html><body style='margin:0;background:{bg}'>"
            f"<div style='width:{size}px;height:{size}px'>{svg.replace('<svg ', f'<svg width=\"{size}\" height=\"{size}\" ', 1)}</div></body></html>")


def to_bmp(img: Image.Image, path: Path, bg=(255, 255, 255)) -> None:
    base = Image.new("RGB", img.size, bg)
    base.paste(img, mask=img.split()[3])
    base.save(path, "BMP")


def main() -> None:
    OUT.mkdir(exist_ok=True)
    files = {
        "wachtl-logo.svg": logo_outline(),
        "wachtl-logo-dark.svg": logo_outline(CREAM, OCHRE_LIGHT),
        "wachtl-logo-filled.svg": logo_filled(),
        "wachtl-icon.svg": app_icon(),
        "wachtl-icon-small.svg": app_icon(small=True),
        "wachtl-wordmark.svg": wordmark(),
        "wachtl-wordmark-dark.svg": wordmark(dark=True),
    }
    for name, svg in files.items():
        (OUT / name).write_text(svg, encoding="utf-8")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(device_scale_factor=1)
        # Windows-Symbol (.ico) mit allen üblichen Größen
        frames = []
        for size in (16, 20, 24, 32, 40, 48, 64, 128, 256):
            svg = files["wachtl-icon-small.svg"] if size <= 24 else files["wachtl-icon.svg"]
            frames.append(render(page, svg_page(svg, size), size, size))
        frames[-1].save(OUT / "wachtl.ico", format="ICO", sizes=[f.size for f in frames],
                        append_images=frames[:-1])
        for size in (180, 512):
            render(page, svg_page(files["wachtl-icon.svg"], size), size, size).save(OUT / f"wachtl-icon-{size}.png")
        render(page, svg_page(files["wachtl-logo-filled.svg"], 512), 512, 512).save(OUT / "wachtl-logo-512.png")
        # Setup-Assistent: großes Bild (100/150/200 %) und kleines Bild oben rechts
        for (w, h), tag in (((164, 314), "100"), ((246, 471), "150"), ((328, 628), "200")):
            to_bmp(render(page, wizard_page(w, h), w, h), OUT / f"wizard-{tag}.bmp")
        for size, tag in ((55, "100"), (83, "150"), (110, "200")):
            to_bmp(render(page, svg_page(files["wachtl-icon.svg"], size), size, size), OUT / f"wizard-small-{tag}.bmp")
        browser.close()

    static = ROOT / "server" / "wachtl" / "static"
    for name in ("wachtl-logo.svg", "wachtl-logo-dark.svg", "wachtl-icon.svg", "wachtl-icon-180.png", "wachtl-logo-filled.svg",
                 "wachtl-wordmark.svg", "wachtl-wordmark-dark.svg"):
        shutil.copy2(OUT / name, static / name)
    shutil.copy2(OUT / "wachtl-icon.svg", static / "favicon.svg")
    assets = ROOT / "windows" / "assets"
    assets.mkdir(exist_ok=True)
    for f in OUT.glob("wizard-*.bmp"):
        shutil.copy2(f, assets / f.name)
    shutil.copy2(OUT / "wachtl.ico", assets / "wachtl.ico")
    shutil.copy2(OUT / "wachtl.ico", ROOT / "probe" / "Wachtl.Probe" / "wachtl.ico")
    print("fertig:", ", ".join(sorted(f.name for f in OUT.iterdir())))


if __name__ == "__main__":
    main()
