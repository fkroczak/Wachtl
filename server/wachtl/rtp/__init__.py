"""RTP-Sprachtest: Probe sendet einen Sprachstrom wie ein Telefonat, ein Reflektor schickt ihn zurück.

Gemeinsames Protokoll für Windows-Probe (Rtp/*.cs), Server-Probe und Reflektor. Jedes Paket ist ein echtes
RTP-Paket (RFC 3550, Version 2) mit der Nutzlastgröße des Codecs; am Anfang der Nutzlast stehen Messfelder:

==========  =====  ==================================================================
Bytes       Feld   Bedeutung
==========  =====  ==================================================================
0–11        RTP    Version 2, Payload-Typ des Codecs, Sequenznummer, Zeitstempel, SSRC
12–15       magic  ``WTL1`` Sprachpaket, ``WTLQ`` Abfrage des Zählers am Ende
16–23       t1     Sendezeit der Probe (µs, monotone Uhr der Probe)
24–31       t2     Empfangszeit am Reflektor (µs, monotone Uhr des Reflektors); 0 = noch nicht reflektiert
32–35       count  Pakete, die der Reflektor von diesem Strom (Absender + SSRC) bisher erhalten hat
==========  =====  ==================================================================

Der Reflektor überschreibt nur t2 und count und schickt das Paket in gleicher Größe zurück (keine Verstärkung).
Daraus ergeben sich je Richtung Verlust und Jitter; die Uhren beider Seiten müssen dafür nicht synchron sein,
weil nur Differenzen der Laufzeiten zählen. Antwortet statt eines Wachtl-Reflektors ein einfacher UDP-Echo-Dienst
(t2 bleibt 0), gibt es nur Werte für Hin- und Rückweg zusammen.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

HEADER = 12
FIELDS = 24
MIN_PACKET = HEADER + FIELDS
MAX_PACKET = 1500
MAGIC_DATA = b"WTL1"
MAGIC_QUERY = b"WTLQ"
DEFAULT_PORT = 5004
_FIELDS = struct.Struct(">4sqqI")
_HEADER = struct.Struct(">BBHII")


@dataclass(frozen=True)
class Codec:
    key: str
    label: str
    payload_type: int
    bytes_per_ms: int       # Nutzdaten je Millisekunde Sprache
    lookahead_ms: int       # algorithmische Verzögerung des Codecs
    ie: float               # Equipment Impairment (ITU-T G.113)
    bpl: float              # Robustheit gegen Paketverlust (ITU-T G.113, mit Verlustverschleierung)

    def payload_bytes(self, ptime_ms: int) -> int:
        return max(FIELDS, self.bytes_per_ms * ptime_ms)


CODECS = {
    "g711": Codec("g711", "G.711 (PCMU, 64 kbit/s)", 0, 8, 0, 0.0, 25.1),
    "g729": Codec("g729", "G.729 (8 kbit/s)", 18, 1, 5, 11.0, 19.0),
}


def build_packet(codec: Codec, ptime_ms: int, seq: int, ssrc: int, t1_us: int, query: bool = False,
                 first: bool = False) -> bytes:
    """Sprachpaket bzw. Abfrage. Der RTP-Zeitstempel zählt Abtastwerte mit 8 kHz."""
    header = _HEADER.pack(0x80, (0x80 if first else 0) | codec.payload_type, seq & 0xFFFF,
                          (seq * ptime_ms * 8) & 0xFFFFFFFF, ssrc & 0xFFFFFFFF)
    fields = _FIELDS.pack(MAGIC_QUERY if query else MAGIC_DATA, t1_us, 0, 0)
    filler = b"\xff" if codec.key == "g711" else b"\x00"     # PCMU-Stille bzw. Nullen
    return header + fields + filler * (codec.payload_bytes(ptime_ms) - FIELDS)


@dataclass(frozen=True)
class Reply:
    seq: int
    ssrc: int
    query: bool
    t1_us: int
    t2_us: int
    count: int


def parse(data: bytes) -> Reply | None:
    """Gültiges Wachtl-RTP-Paket lesen; sonst None."""
    if not MIN_PACKET <= len(data) <= MAX_PACKET or data[0] >> 6 != 2:
        return None
    _, _, seq, _, ssrc = _HEADER.unpack_from(data)
    magic, t1, t2, count = _FIELDS.unpack_from(data, HEADER)
    if magic not in (MAGIC_DATA, MAGIC_QUERY):
        return None
    return Reply(seq, ssrc, magic == MAGIC_QUERY, t1, t2, count)


def reflect(data: bytes, t2_us: int, count: int) -> bytes:
    """Antwort des Reflektors: gleiches Paket, gleiche Größe, mit Empfangszeit und Zähler."""
    magic, t1, _, _ = _FIELDS.unpack_from(data, HEADER)
    return data[:HEADER] + _FIELDS.pack(magic, t1, max(1, t2_us), count & 0xFFFFFFFF) + data[MIN_PACKET:]


# -- Sprachqualität (E-Modell, ITU-T G.107, vereinfacht) ------------------------------------------
def r_factor(one_way_ms: float, jitter_ms: float, loss_pct: float, codec: Codec, ptime_ms: int) -> float:
    """R-Wert: Laufzeit + Jitterpuffer (2 × Jitter) + Paketierung zählen als Verzögerung, Verlust je Codec."""
    ta = max(0.0, one_way_ms) + 2 * max(0.0, jitter_ms) + ptime_ms + codec.lookahead_ms
    delay = 0.024 * ta + (0.11 * (ta - 177.3) if ta > 177.3 else 0.0)
    loss = min(100.0, max(0.0, loss_pct))
    equipment = codec.ie + (95 - codec.ie) * loss / (loss + codec.bpl)
    return 93.2 - delay - equipment


def mos(r: float) -> float:
    """MOS (1–4,5) aus dem R-Wert."""
    if r <= 0:
        return 1.0
    if r >= 100:
        return 4.5
    return 1 + 0.035 * r + 7e-6 * r * (r - 60) * (100 - r)


MOS_LEVELS = ((4.3, "sehr gut"), (4.0, "gut"), (3.6, "ausreichend"), (3.1, "mangelhaft"), (0.0, "schlecht"))


def mos_label(value: float | None) -> str:
    if value is None:
        return "–"
    return next(label for limit, label in MOS_LEVELS if value >= limit)


# -- Auswertung ---------------------------------------------------------------------------------------
def _mean_abs_diff(values: list[float]) -> float | None:
    """Jitter wie beim Dauerping: mittlere Differenz aufeinanderfolgender Laufzeiten."""
    if len(values) < 2:
        return None
    return sum(abs(b - a) for a, b in zip(values, values[1:])) / (len(values) - 1)


def _pct(part: float, whole: float) -> float:
    return round(min(100.0, max(0.0, part * 100 / whole)), 2) if whole > 0 else 0.0


def analyze(sent: int, records: dict[int, tuple[int, int, int, int]], final_count: int | None, codec: Codec,
            ptime_ms: int) -> dict:
    """Ergebnis eines Tests.

    ``records``: Paketnummer -> (t1, t2, count, t4) in µs; t4 = Empfang der Antwort auf der Probe.
    ``final_count``: Zähler des Reflektors aus der Abfrage am Ende (None, wenn sie nicht beantwortet wurde).
    Gleiche Rechnung wie RtpAnalysis.cs.
    """
    result: dict = {"sent": sent, "received": len(records)}
    if not sent:
        result["error"] = "keine Pakete gesendet"
        return result
    if not records:
        result["error"] = "keine Antwort von der Gegenstelle (UDP-Port gesperrt oder Reflektor aus)"
        result["loss_pct"] = 100.0
        return result
    order = sorted(records)
    rtts = [(records[i][3] - records[i][0]) / 1000 for i in order]
    result["rtt_ms"] = round(sum(rtts) / len(rtts), 2)
    result["rtt_max_ms"] = round(max(rtts), 2)
    result["loss_pct"] = _pct(sent - len(records), sent)
    arrival = sorted(order, key=lambda i: records[i][3])
    result["out_of_order"] = sum(1 for a, b in zip(arrival, arrival[1:]) if b < a)
    one_way = result["rtt_ms"] / 2
    reflected = all(records[i][1] for i in order)
    if reflected:
        result["mode"] = "wachtl"
        count = final_count if final_count is not None else max(records[i][2] for i in order)
        count = max(len(records), min(count, sent))
        result["up_loss_pct"] = _pct(sent - count, sent)
        result["down_loss_pct"] = _pct(count - len(records), count)
        up = _mean_abs_diff([(records[i][1] - records[i][0]) / 1000 for i in order])
        down = _mean_abs_diff([(records[i][3] - records[i][1]) / 1000 for i in order])
        result["up_jitter_ms"] = None if up is None else round(up, 2)
        result["down_jitter_ms"] = None if down is None else round(down, 2)
        result["jitter_ms"] = max((v for v in (result["up_jitter_ms"], result["down_jitter_ms"]) if v is not None),
                                  default=None)
        r = min(r_factor(one_way, result[f"{d}_jitter_ms"] or 0, result[f"{d}_loss_pct"], codec, ptime_ms)
                for d in ("up", "down"))
    else:
        # einfacher UDP-Echo-Dienst: nur Hin- und Rückweg zusammen
        result["mode"] = "echo"
        rt = _mean_abs_diff(rtts)
        result["jitter_ms"] = None if rt is None else round(rt, 2)
        r = r_factor(one_way, result["jitter_ms"] or 0, result["loss_pct"], codec, ptime_ms)
    result["r_factor"] = round(r, 1)
    result["mos"] = round(mos(r), 2)
    return result
