"""
Minimal PDF writer.

Produces a real PDF file rather than relying on a browser's print dialogue, so
the tool emits a court-ready document directly.

Two things make this tractable without a library. PDF mandates fourteen base
fonts that every reader already has, so Helvetica needs no embedding - only a
width table for line breaking. And images can be carried as FlateDecode RGB,
which is exactly what zlib produces. Everything else is object bookkeeping.
"""

from __future__ import annotations

import zlib
from typing import Dict, List, Sequence, Tuple

A4 = (595.28, 841.89)          # points

# Adobe's published widths for the base fonts, ASCII 32..126, per 1000 units.
_W_REG = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278,
    278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584,
    584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556,
    833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278,
    278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222,
    500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500,
    500, 334, 260, 334, 584)
_W_BOLD = (
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278,
    278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584,
    584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611,
    833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333,
    278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278,
    556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556,
    500, 389, 280, 389, 584)


def text_width(s: str, size: float, bold: bool = False) -> float:
    table = _W_BOLD if bold else _W_REG
    total = 0
    for ch in s:
        code = ord(ch)
        total += table[code - 32] if 32 <= code <= 126 else 556
    return total * size / 1000.0


def wrap(s: str, size: float, max_w: float, bold: bool = False) -> List[str]:
    """Greedy word wrap against real font metrics."""
    lines, line = [], ""
    for word in str(s).split():
        trial = word if not line else line + " " + word
        if text_width(trial, size, bold) <= max_w:
            line = trial
        else:
            if line:
                lines.append(line)
            while text_width(word, size, bold) > max_w and len(word) > 1:
                cut = len(word)
                while cut > 1 and text_width(word[:cut], size, bold) > max_w:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            line = word
    if line:
        lines.append(line)
    return lines or [""]


#: Characters this document actually uses that live outside ASCII but *do*
#: exist in WinAnsiEncoding, mapped to their WinAnsi byte. Emitting these as
#: octal escapes rather than "?" matters more than it looks: the degree sign
#: appears in every degrees/minutes/seconds coordinate, so without it the PDF
#: rendered `51?28'40.54"N` for a value an examiner may read out in evidence.
_WINANSI = {
    "°": 0o260,   # ° degree
    "±": 0o261,   # ± plus-minus
    "·": 0o267,   # · middle dot
    "×": 0o327,   # × multiplication
    "–": 0o226,   # – en dash
    "—": 0o227,   # — em dash
    "‘": 0o221,   # ' left single quote
    "’": 0o222,   # ' right single quote
    "“": 0o223,   # " left double quote
    "”": 0o224,   # " right double quote
    "…": 0o205,   # … ellipsis
    "•": 0o225,   # • bullet
    "€": 0o200,   # € euro
    "©": 0o251,   # © copyright
    "®": 0o256,   # ® registered
}

#: The redaction mask. WinAnsi has no full block (U+2588), and rendering it as
#: "?" made a redacted PDF look like a rendering fault rather than a deliberate
#: withholding. A run of solid hashes reads unambiguously as redacted text and
#: keeps the same character count as the HTML.
_BLOCK = "█"


def _pdf_escape(s: str) -> str:
    out = []
    for ch in str(s):
        code = ord(ch)
        if ch in "()\\":
            out.append("\\" + ch)
        elif 32 <= code <= 126:
            out.append(ch)
        elif ch == _BLOCK:
            out.append("#")
        elif ch in _WINANSI:
            out.append("\\%03o" % _WINANSI[ch])
        elif code in (9, 10, 13):
            out.append(" ")
        elif 0xA0 <= code <= 0xFF:
            # Latin-1 and WinAnsi agree over this range.
            out.append("\\%03o" % code)
        else:
            # No glyph in this encoding; a marker beats a crash.
            out.append("?")
    return "".join(out)


class Page:
    def __init__(self, width: float, height: float):
        self.w = width
        self.h = height
        self.ops: List[str] = []
        self.images: List[Tuple[str, float, float, float, float]] = []

    def text(self, x: float, y: float, s: str, size: float = 10,
             bold: bool = False, colour: Tuple[float, float, float] = (0, 0, 0)
             ) -> None:
        self.ops.append(
            "BT /%s %.2f Tf %.3f %.3f %.3f rg %.2f %.2f Td (%s) Tj ET"
            % ("HB" if bold else "HR", size, colour[0], colour[1], colour[2],
               x, self.h - y, _pdf_escape(s)))

    def rect(self, x: float, y: float, w: float, h: float,
             colour: Tuple[float, float, float], fill: bool = True) -> None:
        op = "f" if fill else "S"
        prefix = "%.3f %.3f %.3f %s" % (colour[0], colour[1], colour[2],
                                        "rg" if fill else "RG")
        self.ops.append("%s %.2f %.2f %.2f %.2f re %s"
                        % (prefix, x, self.h - y - h, w, h, op))

    def line(self, x0: float, y0: float, x1: float, y1: float,
             colour: Tuple[float, float, float] = (0.8, 0.84, 0.9),
             width: float = 0.6) -> None:
        self.ops.append(
            "%.3f %.3f %.3f RG %.2f w %.2f %.2f m %.2f %.2f l S"
            % (colour[0], colour[1], colour[2], width,
               x0, self.h - y0, x1, self.h - y1))

    def image(self, name: str, x: float, y: float, w: float, h: float) -> None:
        self.ops.append("q %.2f 0 0 %.2f %.2f %.2f cm /%s Do Q"
                        % (w, h, x, self.h - y - h, name))
        self.images.append((name, x, y, w, h))


class PDF:
    def __init__(self, size: Tuple[float, float] = A4,
                 title: str = "", author: str = ""):
        self.size = size
        self.pages: List[Page] = []
        self.title = title
        self.author = author
        self._images: Dict[str, bytes] = {}
        self._image_meta: Dict[str, Tuple[int, int]] = {}

    def add_page(self) -> Page:
        p = Page(*self.size)
        self.pages.append(p)
        return p

    def add_image(self, name: str, width: int, height: int,
                  rgb: Sequence[int]) -> None:
        self._images[name] = zlib.compress(bytes(rgb), 6)
        self._image_meta[name] = (width, height)

    def build(self) -> bytes:
        objects: List[bytes] = []

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)          # 1-based object number

        font_r = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                     b"/Encoding /WinAnsiEncoding >>")
        font_b = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                     b"/Encoding /WinAnsiEncoding >>")

        image_ids: Dict[str, int] = {}
        for name, data in self._images.items():
            w, h = self._image_meta[name]
            header = ("<< /Type /XObject /Subtype /Image /Width %d /Height %d "
                      "/ColorSpace /DeviceRGB /BitsPerComponent 8 "
                      "/Filter /FlateDecode /Length %d >>\nstream\n"
                      % (w, h, len(data)))
            image_ids[name] = add(header.encode("latin-1") + data
                                  + b"\nendstream")

        pages_id = len(objects) + 1 + 2 * len(self.pages) + 1
        page_ids: List[int] = []
        for page in self.pages:
            stream = "\n".join(page.ops).encode("latin-1", "replace")
            packed = zlib.compress(stream, 6)
            content_id = add(b"<< /Filter /FlateDecode /Length %d >>\nstream\n"
                             % len(packed) + packed + b"\nendstream")
            used = {n for n, _x, _y, _w, _h in page.images}
            xobjects = " ".join("/%s %d 0 R" % (n, image_ids[n])
                                for n in used if n in image_ids)
            page_ids.append(add(
                ("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.2f %.2f] "
                 "/Resources << /Font << /HR %d 0 R /HB %d 0 R >>%s >> "
                 "/Contents %d 0 R >>"
                 % (pages_id, page.w, page.h, font_r, font_b,
                    (" /XObject << %s >>" % xobjects) if xobjects else "",
                    content_id)).encode("latin-1")))

        pages_obj = add(("<< /Type /Pages /Count %d /Kids [%s] >>"
                         % (len(page_ids),
                            " ".join("%d 0 R" % i for i in page_ids))
                         ).encode("latin-1"))
        info = add(("<< /Title (%s) /Author (%s) /Producer (WiFi Geolocation Forensics) >>"
                    % (_pdf_escape(self.title), _pdf_escape(self.author))
                    ).encode("latin-1"))
        catalog = add(b"<< /Type /Catalog /Pages %d 0 R >>"
                      % pages_obj)

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for i, body in enumerate(objects, 1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % i + body + b"\nendobj\n"

        xref_at = len(out)
        out += b"xref\n0 %d\n" % (len(objects) + 1)
        out += b"0000000000 65535 f \n"
        for off in offsets[1:]:
            out += b"%010d 00000 n \n" % off
        out += (b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n"
                b"%d\n%%%%EOF\n" % (len(objects) + 1, catalog, info, xref_at))
        return bytes(out)
