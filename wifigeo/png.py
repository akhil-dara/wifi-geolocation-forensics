"""
Pure-Python PNG decode, draw and encode.

Map tiles arrive as PNG, and the exported exhibit must be a PNG. Composing one
from the other normally means an imaging library, which would be this tool's
only third-party dependency. PNG is a simple enough format that it is cheaper
to implement the parts we need: zlib does the compression, and everything else
is a few hundred lines of byte handling.

Supports the colour types tile servers actually emit - greyscale, RGB, palette,
and both with alpha - at bit depths 1/2/4/8/16, non-interlaced. Drawing is
coverage-based, so circles and rings come out anti-aliased rather than jagged.
"""

from __future__ import annotations

import struct
import zlib
from typing import Dict, Sequence, Tuple

PNG_SIG = b"\x89PNG\r\n\x1a\n"


class PngError(ValueError):
    pass


# --------------------------------------------------------------------------
# decode
# --------------------------------------------------------------------------
def decode(data: bytes) -> Tuple[int, int, bytearray]:
    """Decode a PNG to (width, height, RGB bytes)."""
    if not data.startswith(PNG_SIG):
        raise PngError("not a PNG")

    pos = 8
    width = height = 0
    depth = colour = interlace = 0
    palette = b""
    trns = b""
    idat = bytearray()

    while pos + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        pos += 8
        body = data[pos:pos + length]
        pos += length + 4                       # skip CRC
        if ctype == b"IHDR":
            width, height, depth, colour, _comp, _filt, interlace = \
                struct.unpack(">IIBBBBB", body)
        elif ctype == b"PLTE":
            palette = body
        elif ctype == b"tRNS":
            trns = body
        elif ctype == b"IDAT":
            idat += body
        elif ctype == b"IEND":
            break

    if not width or not height:
        raise PngError("missing IHDR")
    if interlace:
        raise PngError("interlaced PNG is not supported")

    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colour)
    if channels is None:
        raise PngError("unsupported colour type %d" % colour)

    raw = zlib.decompress(bytes(idat))
    bpp_bits = channels * depth
    stride = (width * bpp_bits + 7) // 8
    fbpp = max(1, bpp_bits // 8)                # filter unit, in bytes

    # ---- undo per-scanline filtering ----
    out = bytearray(stride * height)
    prev = bytearray(stride)
    src = 0
    for y in range(height):
        ftype = raw[src]
        src += 1
        line = bytearray(raw[src:src + stride])
        src += stride
        if ftype == 1:
            for i in range(fbpp, stride):
                line[i] = (line[i] + line[i - fbpp]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                left = line[i - fbpp] if i >= fbpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                a = line[i - fbpp] if i >= fbpp else 0
                b = prev[i]
                c = prev[i - fbpp] if i >= fbpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pred) & 0xFF
        elif ftype != 0:
            raise PngError("bad filter type %d" % ftype)
        out[y * stride:(y + 1) * stride] = line
        prev = line

    # ---- expand to 8-bit RGB ----
    rgb = bytearray(width * height * 3)

    def sample_rows():
        """Yield each row as a list of per-pixel channel tuples."""
        if depth == 8:
            for y in range(height):
                row = out[y * stride:(y + 1) * stride]
                yield [row[i * channels:(i + 1) * channels] for i in range(width)]
        elif depth == 16:
            for y in range(height):
                row = out[y * stride:(y + 1) * stride]
                yield [[row[(i * channels + c) * 2] for c in range(channels)]
                       for i in range(width)]
        else:                                   # 1, 2 or 4 bit, palette/grey
            mask = (1 << depth) - 1
            per_byte = 8 // depth
            scale = 255 // mask if colour == 0 else 1
            for y in range(height):
                row = out[y * stride:(y + 1) * stride]
                vals = []
                for i in range(width):
                    byte = row[i // per_byte]
                    shift = 8 - depth * (i % per_byte + 1)
                    vals.append([((byte >> shift) & mask) * scale])
                yield vals

    o = 0
    for row in sample_rows():
        for px in row:
            if colour == 3:
                idx = px[0] * 3
                if idx + 2 < len(palette):
                    rgb[o] = palette[idx]
                    rgb[o + 1] = palette[idx + 1]
                    rgb[o + 2] = palette[idx + 2]
            elif colour in (0, 4):
                g = px[0]
                rgb[o] = rgb[o + 1] = rgb[o + 2] = g
            else:                               # 2 or 6
                rgb[o], rgb[o + 1], rgb[o + 2] = px[0], px[1], px[2]
            o += 3
    return width, height, rgb


# --------------------------------------------------------------------------
# encode
# --------------------------------------------------------------------------
def encode(width: int, height: int, rgb: Sequence[int], level: int = 6) -> bytes:
    """Encode 8-bit RGB into a PNG."""
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)                           # filter: none
        raw += bytes(rgb[y * stride:(y + 1) * stride])

    def chunk(tag: bytes, body: bytes) -> bytes:
        return (struct.pack(">I", len(body)) + tag + body
                + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF))

    return (PNG_SIG
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), level))
            + chunk(b"IEND", b""))


# --------------------------------------------------------------------------
# a 5x7 bitmap font, so the exhibit can carry its own caption
# --------------------------------------------------------------------------
_FONT: Dict[str, Tuple[int, ...]] = {
    " ": (0, 0, 0, 0, 0), "!": (0, 0, 0x5F, 0, 0), '"': (0, 7, 0, 7, 0),
    "#": (0x14, 0x7F, 0x14, 0x7F, 0x14), "$": (0x24, 0x2A, 0x7F, 0x2A, 0x12),
    "%": (0x23, 0x13, 0x08, 0x64, 0x62), "&": (0x36, 0x49, 0x55, 0x22, 0x50),
    "'": (0, 0, 7, 0, 0), "(": (0, 0x1C, 0x22, 0x41, 0), ")": (0, 0x41, 0x22, 0x1C, 0),
    "*": (0x14, 0x08, 0x3E, 0x08, 0x14), "+": (0x08, 0x08, 0x3E, 0x08, 0x08),
    ",": (0, 0x50, 0x30, 0, 0), "-": (0x08, 0x08, 0x08, 0x08, 0x08),
    ".": (0, 0x60, 0x60, 0, 0), "/": (0x20, 0x10, 0x08, 0x04, 0x02),
    "0": (0x3E, 0x51, 0x49, 0x45, 0x3E), "1": (0, 0x42, 0x7F, 0x40, 0),
    "2": (0x42, 0x61, 0x51, 0x49, 0x46), "3": (0x21, 0x41, 0x45, 0x4B, 0x31),
    "4": (0x18, 0x14, 0x12, 0x7F, 0x10), "5": (0x27, 0x45, 0x45, 0x45, 0x39),
    "6": (0x3C, 0x4A, 0x49, 0x49, 0x30), "7": (0x01, 0x71, 0x09, 0x05, 0x03),
    "8": (0x36, 0x49, 0x49, 0x49, 0x36), "9": (0x06, 0x49, 0x49, 0x29, 0x1E),
    ":": (0, 0x36, 0x36, 0, 0), ";": (0, 0x56, 0x36, 0, 0),
    "<": (0x08, 0x14, 0x22, 0x41, 0), "=": (0x14, 0x14, 0x14, 0x14, 0x14),
    ">": (0, 0x41, 0x22, 0x14, 0x08), "?": (0x02, 0x01, 0x51, 0x09, 0x06),
    "@": (0x32, 0x49, 0x79, 0x41, 0x3E), "A": (0x7E, 0x11, 0x11, 0x11, 0x7E),
    "B": (0x7F, 0x49, 0x49, 0x49, 0x36), "C": (0x3E, 0x41, 0x41, 0x41, 0x22),
    "D": (0x7F, 0x41, 0x41, 0x22, 0x1C), "E": (0x7F, 0x49, 0x49, 0x49, 0x41),
    "F": (0x7F, 0x09, 0x09, 0x09, 0x01), "G": (0x3E, 0x41, 0x49, 0x49, 0x7A),
    "H": (0x7F, 0x08, 0x08, 0x08, 0x7F), "I": (0, 0x41, 0x7F, 0x41, 0),
    "J": (0x20, 0x40, 0x41, 0x3F, 0x01), "K": (0x7F, 0x08, 0x14, 0x22, 0x41),
    "L": (0x7F, 0x40, 0x40, 0x40, 0x40), "M": (0x7F, 0x02, 0x0C, 0x02, 0x7F),
    "N": (0x7F, 0x04, 0x08, 0x10, 0x7F), "O": (0x3E, 0x41, 0x41, 0x41, 0x3E),
    "P": (0x7F, 0x09, 0x09, 0x09, 0x06), "Q": (0x3E, 0x41, 0x51, 0x21, 0x5E),
    "R": (0x7F, 0x09, 0x19, 0x29, 0x46), "S": (0x46, 0x49, 0x49, 0x49, 0x31),
    "T": (0x01, 0x01, 0x7F, 0x01, 0x01), "U": (0x3F, 0x40, 0x40, 0x40, 0x3F),
    "V": (0x1F, 0x20, 0x40, 0x20, 0x1F), "W": (0x3F, 0x40, 0x38, 0x40, 0x3F),
    "X": (0x63, 0x14, 0x08, 0x14, 0x63), "Y": (0x07, 0x08, 0x70, 0x08, 0x07),
    "Z": (0x61, 0x51, 0x49, 0x45, 0x43), "[": (0, 0x7F, 0x41, 0x41, 0),
    "\\": (0x02, 0x04, 0x08, 0x10, 0x20), "]": (0, 0x41, 0x41, 0x7F, 0),
    "^": (0x04, 0x02, 0x01, 0x02, 0x04), "_": (0x40, 0x40, 0x40, 0x40, 0x40),
    "`": (0, 1, 2, 4, 0),
    "a": (0x20, 0x54, 0x54, 0x54, 0x78), "b": (0x7F, 0x48, 0x44, 0x44, 0x38),
    "c": (0x38, 0x44, 0x44, 0x44, 0x20), "d": (0x38, 0x44, 0x44, 0x48, 0x7F),
    "e": (0x38, 0x54, 0x54, 0x54, 0x18), "f": (0x08, 0x7E, 0x09, 0x01, 0x02),
    "g": (0x0C, 0x52, 0x52, 0x52, 0x3E), "h": (0x7F, 0x08, 0x04, 0x04, 0x78),
    "i": (0, 0x44, 0x7D, 0x40, 0), "j": (0x20, 0x40, 0x44, 0x3D, 0),
    "k": (0x7F, 0x10, 0x28, 0x44, 0), "l": (0, 0x41, 0x7F, 0x40, 0),
    "m": (0x7C, 0x04, 0x18, 0x04, 0x78), "n": (0x7C, 0x08, 0x04, 0x04, 0x78),
    "o": (0x38, 0x44, 0x44, 0x44, 0x38), "p": (0x7C, 0x14, 0x14, 0x14, 0x08),
    "q": (0x08, 0x14, 0x14, 0x18, 0x7C), "r": (0x7C, 0x08, 0x04, 0x04, 0x08),
    "s": (0x48, 0x54, 0x54, 0x54, 0x20), "t": (0x04, 0x3F, 0x44, 0x40, 0x20),
    "u": (0x3C, 0x40, 0x40, 0x20, 0x7C), "v": (0x1C, 0x20, 0x40, 0x20, 0x1C),
    "w": (0x3C, 0x40, 0x30, 0x40, 0x3C), "x": (0x44, 0x28, 0x10, 0x28, 0x44),
    "y": (0x0C, 0x50, 0x50, 0x50, 0x3C), "z": (0x44, 0x64, 0x54, 0x4C, 0x44),
    "|": (0, 0, 0x7F, 0, 0), "~": (0x08, 0x04, 0x08, 0x10, 0x08),
    "°": (0x02, 0x05, 0x02, 0, 0), "±": (0x48, 0x48, 0x7A, 0x48, 0x48),
}


class Canvas:
    """A simple RGB raster with anti-aliased primitives."""

    def __init__(self, width: int, height: int,
                 background: Tuple[int, int, int] = (255, 255, 255)):
        self.w = width
        self.h = height
        self.buf = bytearray(bytes(background) * (width * height))

    # -- pixels --------------------------------------------------------
    def _blend(self, x: int, y: int, colour: Tuple[int, int, int],
               alpha: float) -> None:
        if alpha <= 0 or not (0 <= x < self.w and 0 <= y < self.h):
            return
        if alpha > 1:
            alpha = 1.0
        o = (y * self.w + x) * 3
        inv = 1.0 - alpha
        self.buf[o] = int(self.buf[o] * inv + colour[0] * alpha)
        self.buf[o + 1] = int(self.buf[o + 1] * inv + colour[1] * alpha)
        self.buf[o + 2] = int(self.buf[o + 2] * inv + colour[2] * alpha)

    # -- images --------------------------------------------------------
    def blit(self, x0: int, y0: int, w: int, h: int, rgb: Sequence[int]) -> None:
        """Copy an RGB block, clipped to the canvas. Row-at-a-time."""
        x0, y0 = int(x0), int(y0)
        sx = max(0, -x0)                      # first source column to keep
        ex = min(w, self.w - x0)              # one past the last
        if ex <= sx:
            return
        span = (ex - sx) * 3
        for y in range(max(0, -y0), min(h, self.h - y0)):
            src = (y * w + sx) * 3
            dst = ((y0 + y) * self.w + x0 + sx) * 3
            self.buf[dst:dst + span] = bytes(rgb[src:src + span])

    @staticmethod
    def upscale(w: int, h: int, rgb: Sequence[int], factor: int
                ) -> Tuple[int, int, bytearray]:
        """
        Nearest-neighbour enlargement, built from row slices.

        Nearest-neighbour rather than interpolation on purpose: a smoothed map
        tile invents detail the source never contained, and an exhibit should
        not do that. Working in whole rows keeps this fast enough to be
        practical in pure Python.
        """
        if factor <= 1:
            return w, h, bytearray(rgb)
        out = bytearray()
        for y in range(h):
            row = rgb[y * w * 3:(y + 1) * w * 3]
            wide = bytearray()
            for x in range(w):
                wide += bytes(row[x * 3:x * 3 + 3]) * factor
            out += wide * factor
        return w * factor, h * factor, out

    # -- shapes --------------------------------------------------------
    def rect(self, x0: int, y0: int, w: int, h: int,
             colour: Tuple[int, int, int], alpha: float = 1.0) -> None:
        x0, y0, w, h = int(x0), int(y0), int(w), int(h)
        xs, xe = max(0, x0), min(self.w, x0 + w)
        ys, ye = max(0, y0), min(self.h, y0 + h)
        if xe <= xs or ye <= ys:
            return
        if alpha >= 1.0:                       # opaque: fill whole rows
            row = bytes(colour) * (xe - xs)
            for y in range(ys, ye):
                o = (y * self.w + xs) * 3
                self.buf[o:o + len(row)] = row
            return
        for y in range(ys, ye):
            for x in range(xs, xe):
                self._blend(x, y, colour, alpha)

    def disc(self, cx: float, cy: float, r: float,
             colour: Tuple[int, int, int], alpha: float = 1.0) -> None:
        """Filled circle with coverage-based edge smoothing."""
        for y in range(int(cy - r - 1), int(cy + r + 2)):
            for x in range(int(cx - r - 1), int(cx + r + 2)):
                d = ((x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2) ** 0.5
                cov = min(1.0, max(0.0, r + 0.5 - d))
                if cov > 0:
                    self._blend(x, y, colour, cov * alpha)

    def ring(self, cx: float, cy: float, r: float, thickness: float,
             colour: Tuple[int, int, int], alpha: float = 1.0) -> None:
        outer, inner = r + thickness / 2.0, r - thickness / 2.0
        for y in range(int(cy - outer - 1), int(cy + outer + 2)):
            for x in range(int(cx - outer - 1), int(cx + outer + 2)):
                d = ((x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2) ** 0.5
                cov = min(1.0, max(0.0, outer + 0.5 - d)) * \
                      min(1.0, max(0.0, d - inner + 0.5))
                if cov > 0:
                    self._blend(x, y, colour, cov * alpha)

    def line(self, x0: float, y0: float, x1: float, y1: float,
             colour: Tuple[int, int, int], width: float = 1.0,
             alpha: float = 1.0) -> None:
        steps = int(max(abs(x1 - x0), abs(y1 - y0)) * 2) + 1
        for i in range(steps + 1):
            t = i / steps
            self.disc(x0 + (x1 - x0) * t, y0 + (y1 - y0) * t,
                      width / 2.0, colour, alpha)

    def pin(self, x: float, y: float, size: float,
            colour: Tuple[int, int, int]) -> None:
        """A teardrop marker whose point sits exactly on (x, y)."""
        head_r = size * 0.62
        cy = y - size
        for i in range(int(size * 12)):
            t = i / (size * 12.0)
            self.disc(x, y - t * (size - head_r * 0.2),
                      head_r * (0.30 + 0.70 * t), (255, 255, 255), 1.0)
        for i in range(int(size * 12)):
            t = i / (size * 12.0)
            self.disc(x, y - t * (size - head_r * 0.2),
                      max(0.5, (head_r - 1.6) * (0.30 + 0.70 * t)), colour, 1.0)
        self.disc(x, cy, head_r, (255, 255, 255), 1.0)
        self.disc(x, cy, head_r - 1.6, colour, 1.0)
        self.disc(x, cy, head_r * 0.34, (255, 255, 255), 1.0)

    # -- text ----------------------------------------------------------
    def text(self, x: int, y: int, s: str, colour: Tuple[int, int, int],
             scale: int = 2, alpha: float = 1.0) -> int:
        """Draw `s` with the built-in 5x7 font. Returns the width used."""
        cx = x
        for ch in s:
            glyph = _FONT.get(ch) or _FONT.get(ch.upper()) or _FONT["?"]
            for col in range(5):
                bits = glyph[col]
                for row in range(7):
                    if bits & (1 << row):
                        self.rect(cx + col * scale, y + row * scale,
                                  scale, scale, colour, alpha)
            cx += 6 * scale
        return cx - x

    @staticmethod
    def text_width(s: str, scale: int = 2) -> int:
        return len(s) * 6 * scale

    def to_png(self, level: int = 6) -> bytes:
        return encode(self.w, self.h, self.buf, level)
