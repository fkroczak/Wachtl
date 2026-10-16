"""Lesbarkeit deutscher UI-Texte grob einschätzen (Entwicklungswerkzeug, keine Abhängigkeiten).

Verfahren (beide für Deutsch kalibriert, nicht Flesch-Kincaid):
- Flesch-Lesbarkeitsindex nach Amstad (1978): 180 − ASL − 58,5 · ASW
  ASL = Wörter je Satz, ASW = Silben je Wort. 0–100, höher = leichter; 50–60 ≈ „mittelschwer“.
- Erste Wiener Sachtextformel (Bamberger/Vanecek 1984):
  0,1935·MS + 0,1672·SL + 0,1297·IW − 0,0327·ES − 0,875
  MS = % Wörter mit ≥ 3 Silben, SL = Wörter je Satz, IW = % Wörter mit > 6 Buchstaben,
  ES = % einsilbige Wörter. Ergebnis ≈ Schulstufe 4–15, niedriger = leichter.

Grenzen: Silben werden per Vokalgruppen-Heuristik gezählt (Diphthonge als eine Silbe), Fachbegriffe
wie „iperf3“, „Jitter“ oder IP-Adressen verfälschen die Werte, und kurze UI-Fragmente sind keine
Fließtexte. Die Zahlen sind ein Frühwarnsignal für lange, verschachtelte Sätze – kein Urteil über
Verständlichkeit. Maßgeblich bleibt die manuelle Prüfung (siehe docs/quality-guardrails.md).

Aufruf: python devtools/readability.py datei.html|URL [...]   (oder Text über stdin)
  URLs werden mit dem Cookie aus WACHTL_COOKIE abgerufen. Mit --warn gibt es für Absätze mit
  Wiener Sachtextformel > WSTF_WARN eine GitHub-Annotation (::warning::) – nicht blockierend.
"""
from __future__ import annotations

import os
import re
import sys
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser

VOWELS = "aeiouyäöü"
DIPHTHONGS = ("eau", "ai", "au", "äu", "ei", "eu", "ie", "ey", "oi", "ui")
WORD = re.compile(r"[A-Za-zÄÖÜäöüß][A-Za-zÄÖÜäöüß\-]*")
SENTENCE_END = re.compile(r"(?<!z\.)(?<!B\.)(?<!d\.)(?<!h\.)(?<!ca\.)(?<!bzw\.)[.!?:;](?:\s|$)")
PROSE_TAGS = {"p", "small", "li", "legend", "dd"}
WSTF_WARN = 12.0   # ≈ Schulstufe 12: lange, verschachtelte Sätze – bitte manuell prüfen


def syllables(word: str) -> int:
    w = word.lower().replace("-", "")
    for d in DIPHTHONGS:
        w = w.replace(d, "a")
    groups = re.findall(f"[{VOWELS}]+", w)
    return max(1, len(groups))


@dataclass
class Score:
    sentences: int
    words: int
    amstad: float
    wstf: float

    def __str__(self) -> str:
        return f"Amstad {self.amstad:5.1f}  WSTF {self.wstf:4.1f}  ({self.words} Wörter, {self.sentences} Sätze)"


def score(text: str) -> Score | None:
    words = WORD.findall(text)
    if not words:
        return None
    sentences = max(1, len([s for s in SENTENCE_END.split(text) if WORD.search(s)]))
    syl = [syllables(w) for w in words]
    n = len(words)
    asl = n / sentences
    asw = sum(syl) / n
    ms = 100 * sum(1 for s in syl if s >= 3) / n
    iw = 100 * sum(1 for w in words if len(w) > 6) / n
    es = 100 * sum(1 for s in syl if s == 1) / n
    return Score(sentences, n, 180 - asl - 58.5 * asw, 0.1935 * ms + 0.1672 * asl + 0.1297 * iw - 0.0327 * es - 0.875)


class _Prose(HTMLParser):
    """Sammelt Fließtext-Absätze (p, small, li, legend, dd, Hinweise) aus gerendertem HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.depth = 0
        self.skip = 0
        self.buf: list[str] = []
        self.blocks: list[str] = []

    def handle_starttag(self, tag, attrs):
        cls = dict(attrs).get("class") or ""
        if tag in ("script", "style", "table", "code", "pre"):
            self.skip += 1
        elif tag in PROSE_TAGS or (tag == "div" and "flash" in cls):
            self.depth += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "table", "code", "pre"):
            self.skip = max(0, self.skip - 1)
        elif tag in PROSE_TAGS or (tag == "div" and self.depth):
            self.depth = max(0, self.depth - 1)
            if not self.depth:
                text = " ".join("".join(self.buf).split())
                if len(WORD.findall(text)) >= 6:
                    self.blocks.append(text)
                self.buf = []

    def handle_data(self, data):
        if self.depth and not self.skip:
            self.buf.append(data)


def prose_blocks(html: str) -> list[str]:
    p = _Prose()
    p.feed(html)
    return p.blocks


def _load(src: str) -> str:
    if src.startswith(("http://", "https://")):
        req = urllib.request.Request(src, headers={"Cookie": os.environ.get("WACHTL_COOKIE", "")})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8")
    with open(src, encoding="utf-8") as fh:
        return fh.read()


def main(argv: list[str]) -> int:
    warn = "--warn" in argv
    argv = [a for a in argv if a != "--warn"]
    sources = [(src, _load(src)) for src in argv] or [("stdin", sys.stdin.read())]
    for name, content in sources:
        blocks = prose_blocks(content) if "<" in content else [content]
        total = score(" ".join(b if b.rstrip()[-1:] in ".!?" else b + "." for b in blocks)) if blocks else None
        print(f"== {name}: {total or 'kein Fließtext'}")
        for b in blocks:
            s = score(b)
            if s:
                print(f"   {s}  {b[:90]}")
                if warn and s.words >= 8 and s.wstf > WSTF_WARN:
                    print(f"::warning title=Lesbarkeit {name}::WSTF {s.wstf:.1f} – bitte kürzer/klarer prüfen: {b[:160]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
