"""Erzeugt alle Logo-Dateien aus einer Quelle (Wachtel als Tropfen, Muster 05).

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

# Palette = Farben der Weboberfläche (server/wachtl/static/app.css)
BLUE = "#0060e0"       # --accent hell: Markenfläche, Logo auf hellem Grund
BLUE_DARK = "#4689f0"  # --accent dunkel: Logo auf dunklem Grund
BLUE_SOFT = "#d6e4fb"  # Unterzeile auf blauer Fläche
INK = "#15171a"        # --text hell
INK_DARK = "#f1f3f5"   # --text dunkel
WHITE = "#ffffff"

# Wachtel im 64er-Raster: Körper als Tropfen mit ausgespartem Auge, Schnabel, Federschopf
MARK = (
    '<path d="M30 14 C46 14 58 26 60 40 C50 52 40 56 30 56 C18 56 8 47 8 35 C8 23 18 14 30 14Z '
    'M18 29a2.8 2.8 0 1 0 5.6 0a2.8 2.8 0 1 0 -5.6 0Z"/>'
    '<path d="M8.6 30 L2 33.5 L8.4 37Z"/>'
    '<path d="M27 14.5 C26 8.5 22 5 16 5 C19 8 21 11 22 15.5Z"/>'
    '<circle cx="16" cy="6" r="2.6"/>'
)


def mark(color: str, x: float = 0, y: float = 0, scale: float = 1) -> str:
    return f'<g fill="{color}" transform="translate({x:g} {y:g}) scale({scale:g})">{MARK}</g>'


def svg(view: str, body: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}">\n'
            f'  <title>Wachtl</title>\n  {body}\n</svg>\n')


def logo(color: str = BLUE) -> str:
    """Freistehendes Zeichen (Seitenleiste, Dokumente)."""
    return svg("0 0 64 64", mark(color))


def app_icon(small: bool = False) -> str:
    """Quadratisches Programm-Symbol: weiße Wachtel auf blauer Kachel; klein = weniger Rand."""
    s = 1.6 if small else 1.4
    return svg("0 0 128 128", f'<rect width="128" height="128" rx="28" fill="{BLUE}"/>\n  '
               + mark(WHITE, 64 - 31 * s, 64 - 30.5 * s, s))


def wordmark(dark: bool = False) -> str:
    ink, accent = (INK_DARK, BLUE_DARK) if dark else (INK, BLUE)
    return svg("0 0 420 128", mark(accent, 4, 10, 1.75) + "\n  "
               f'<text x="128" y="86" font-family="Inter, \'Segoe UI\', Arial, sans-serif" font-size="58" '
               f'font-weight="700" letter-spacing="-1" fill="{ink}">wachtl</text>')


def wizard_page(w: int, h: int) -> str:
    """Linkes Bild auf Willkommens- und Abschlussseite des Setups."""
    return f'''<!doctype html><html><head><style>
  html,body{{margin:0;width:{w}px;height:{h}px;overflow:hidden;background:{BLUE};font-family:Inter,'Segoe UI',sans-serif}}
  .wrap{{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:{h*0.03}px}}
  svg{{width:{w*0.62}px;height:{w*0.62}px}}
  .name{{color:{WHITE};font-weight:700;font-size:{w*0.17}px;letter-spacing:-0.02em}}
  .sub{{color:{BLUE_SOFT};font-weight:600;font-size:{w*0.058}px;text-transform:uppercase;letter-spacing:.1em}}
</style></head><body><div class="wrap">
<svg viewBox="0 0 64 64">{mark(WHITE)}</svg>
<div class="name">wachtl</div><div class="sub">Netzwerk&#8209;Monitoring</div></div></body></html>'''


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
        "wachtl-logo.svg": logo(),
        "wachtl-logo-dark.svg": logo(BLUE_DARK),
        "wachtl-logo-filled.svg": app_icon(),
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
