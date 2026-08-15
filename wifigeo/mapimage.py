"""
Exportable map image.

Produces a single self-contained SVG: the map tiles are embedded as data URIs
and every annotation is a vector element, so the file has no external
references, renders identically anywhere, scales to any size without
degradation, and drops straight into a statement, a court bundle or a slide.

SVG rather than PNG because composing a raster image would mean decoding the
tile PNGs, which needs an imaging library, which would be the tool's only
third-party dependency. An SVG side-steps that entirely: the tiles are carried
verbatim in the bytes we already have, and the markers, scale bar and caption
are drawn as vectors. Any browser will print it to PDF, and Inkscape,
Illustrator or ImageMagick will rasterise it at whatever DPI is required.
"""

from __future__ import annotations

import html
from typing import Dict, List, Optional

import base64

from . import TOOL_NAME, __version__, png
from .osint import project_onto_map

CAPTION_H = 96
LEGEND_H = 34

INK = (16, 21, 28)
MUTED = (107, 118, 134)
WHITE = (255, 255, 255)
BLUE = (15, 95, 168)
AMBER = (179, 105, 10)
RED = (179, 38, 30)
VIOLET = (124, 58, 237)
PANEL = (247, 249, 252)
LINE = (201, 209, 220)


def render_png(doc: Dict[str, object],
               static_map: Optional[Dict[str, object]] = None,
               scale: int = 2) -> Optional[bytes]:
    """
    Rasterise the annotated map as a PNG exhibit.

    `scale` multiplies the whole canvas, so the annotations are drawn at the
    higher resolution rather than being an upscale of a small image. The tiles
    themselves are nearest-neighbour enlarged, which keeps them crisp and
    honest - a smoothed tile would invent detail the source never had.
    """
    sm = static_map or doc.get("export_map") or doc.get("static_map")
    pos = doc.get("position")
    if not sm or not sm.get("tiles") or not pos:
        return None

    s = max(1, int(scale))
    w, h = int(sm["width"]) * s, int(sm["height"]) * s
    cap_h, leg_h = CAPTION_H * s, LEGEND_H * s
    canvas = png.Canvas(w, h + leg_h + cap_h, WHITE)
    mpp = float(sm.get("metres_per_pixel") or 1.0) / s
    tile_px = int(sm["tile_size"])

    # ---- tiles ----------------------------------------------------------
    for t in sm["tiles"]:
        try:
            raw = base64.b64decode(str(t["data_uri"]).split(",", 1)[1])
            tw, th, rgb = png.decode(raw)
        except Exception:
            continue
        bw, bh, big = png.Canvas.upscale(tw, th, rgb, s)
        canvas.blit(t["left"] * s, t["top"] * s, bw, bh, big)

    def at(lat, lon):
        p = project_onto_map(sm, lat, lon)
        return (p["x"] * s, p["y"] * s) if p else None

    # ---- accuracy circle -------------------------------------------------
    if pos.get("accuracy_m"):
        p = at(pos["latitude"], pos["longitude"])
        r = float(pos["accuracy_m"]) / mpp
        if p and r > 2:
            canvas.disc(p[0], p[1], r, BLUE, 0.10)
            canvas.ring(p[0], p[1], r, 2.0 * s, BLUE, 0.55)

    # ---- neighbours ------------------------------------------------------
    neigh = 0
    for a in (doc.get("apple") or {}).get("access_points", []):
        if not a.get("located") or a.get("queried"):
            continue
        p = at(a["latitude"], a["longitude"])
        if p:
            neigh += 1
            canvas.disc(p[0], p[1], 2.6 * s, BLUE, 0.55)

    # ---- replicate probes ------------------------------------------------
    for rep in ((doc.get("microsoft_replicates") or {}).get("results") or []):
        r = rep.get("result") or {}
        if not r.get("located"):
            continue
        p = at(r["latitude"], r["longitude"])
        if p:
            canvas.disc(p[0], p[1], 5.2 * s, WHITE)
            canvas.disc(p[0], p[1], 3.8 * s, VIOLET)

    # ---- queried access points ------------------------------------------
    for a in (doc.get("apple") or {}).get("queried", []):
        if not a.get("located"):
            continue
        p = at(a["latitude"], a["longitude"])
        if p:
            canvas.disc(p[0], p[1], 7.0 * s, WHITE)
            canvas.disc(p[0], p[1], 5.2 * s, BLUE)

    ms = (doc.get("microsoft") or {}).get("result") or {}
    if ms.get("located"):
        p = at(ms["latitude"], ms["longitude"])
        if p:
            canvas.disc(p[0], p[1], 7.0 * s, WHITE)
            canvas.disc(p[0], p[1], 5.2 * s, AMBER)

    p = at(pos["latitude"], pos["longitude"])
    if p:
        canvas.pin(p[0], p[1], 11.0 * s, RED)

    # ---- scale bar -------------------------------------------------------
    scale_m = 25
    while scale_m / mpp < 70 * s:
        scale_m *= 2
    bar = scale_m / mpp
    bx, by = 14 * s, h - 24 * s
    canvas.rect(bx - 7 * s, by - 11 * s, bar + 62 * s, 23 * s, WHITE, 0.85)
    canvas.line(bx, by, bx + bar, by, INK, 2.5 * s)
    canvas.line(bx, by - 4 * s, bx, by + 4 * s, INK, 2.5 * s)
    canvas.line(bx + bar, by - 4 * s, bx + bar, by + 4 * s, INK, 2.5 * s)
    canvas.text(int(bx + bar + 7 * s), int(by - 3.5 * s), "%d m" % scale_m,
                INK, max(1, s))

    # ---- north arrow -----------------------------------------------------
    nx, ny = w - 28 * s, 28 * s
    canvas.disc(nx, ny, 15 * s, WHITE, 0.88)
    canvas.ring(nx, ny, 15 * s, 1.0 * s, LINE, 0.9)
    canvas.line(nx, ny + 6 * s, nx, ny - 9 * s, INK, 2.4 * s)
    canvas.line(nx, ny - 9 * s, nx - 3.5 * s, ny - 3 * s, INK, 2.2 * s)
    canvas.line(nx, ny - 9 * s, nx + 3.5 * s, ny - 3 * s, INK, 2.2 * s)
    canvas.text(int(nx - 3 * s), int(ny + 7 * s), "N", INK, max(1, s))

    # ---- legend ----------------------------------------------------------
    ly = h + 12 * s
    lx = 14 * s
    items = [("pin", RED, "Reported position"),
             ("dot", BLUE, "Queried access point")]
    if ms.get("located"):
        items.append(("dot", AMBER, "Microsoft fix"))
    if (doc.get("microsoft_replicates") or {}).get("groups_resolved"):
        items.append(("dot", VIOLET, "Replicate probe"))
    if neigh:
        items.append(("sml", BLUE, "Neighbour AP (%d)" % neigh))
    for kind, colour, label in items:
        if kind == "pin":
            canvas.pin(lx + 4 * s, ly + 9 * s, 7.0 * s, colour)
        elif kind == "sml":
            canvas.disc(lx + 4 * s, ly + 5 * s, 2.4 * s, colour, 0.55)
        else:
            canvas.disc(lx + 4 * s, ly + 5 * s, 4.6 * s, colour)
        canvas.text(int(lx + 13 * s), int(ly + 1 * s), label, (57, 66, 79),
                    max(1, s))
        lx += 13 * s + canvas.text_width(label, max(1, s)) + 18 * s

    # ---- caption ---------------------------------------------------------
    cy = h + leg_h
    canvas.rect(0, cy, w, cap_h, PANEL)
    canvas.rect(0, cy, w, max(1, s), LINE)

    coords = doc.get("coordinates") or {}
    val = doc.get("validation") or {}
    tgt = doc.get("target") or {}
    label = tgt.get("ssid") or ", ".join(tgt.get("bssids") or []) or "target"
    ts = max(1, s)
    canvas.text(14 * s, cy + 12 * s, label[:72], INK, ts + 1)
    canvas.text(14 * s, cy + 32 * s,
                "%s  +/- %s m" % (coords.get("decimal_precise", ""),
                                  pos.get("accuracy_m")), (57, 66, 79), ts)
    canvas.text(14 * s, cy + 48 * s,
                "%s | Plus Code %s | MGRS %s"
                % (val.get("verdict", ""), coords.get("plus_code", ""),
                   coords.get("mgrs", "")), MUTED, ts)
    canvas.text(14 * s, cy + 64 * s,
                "Case %s | %s" % (doc.get("case_id"), doc.get("completed_utc")),
                MUTED, ts)
    canvas.text(14 * s, cy + 80 * s,
                "%s | Positions are third-party crowd-sourced records, not "
                "measurements." % sm.get("attribution", ""), MUTED, ts)

    return canvas.to_png()


def _esc(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def render(doc: Dict[str, object], static_map: Optional[Dict[str, object]] = None
           ) -> Optional[str]:
    """Build the SVG. Returns None when there is no map to draw."""
    sm = static_map or doc.get("export_map") or doc.get("static_map")
    pos = doc.get("position")
    if not sm or not sm.get("tiles") or not pos:
        return None

    w = int(sm["width"])
    h = int(sm["height"])
    total_h = h + CAPTION_H + LEGEND_H
    mpp = float(sm.get("metres_per_pixel") or 1.0)

    out: List[str] = []
    add = out.append

    add('<?xml version="1.0" encoding="UTF-8"?>')
    add('<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink" '
        'width="%d" height="%d" viewBox="0 0 %d %d">' % (w, total_h, w, total_h))

    add('<defs>'
        '<filter id="sh" x="-50%%" y="-50%%" width="200%%" height="200%%">'
        '<feDropShadow dx="0" dy="1" stdDeviation="1.5" flood-opacity="0.45"/>'
        '</filter>'
        '<clipPath id="frame"><rect x="0" y="0" width="%d" height="%d"/></clipPath>'
        '</defs>' % (w, h))
    add('<rect width="%d" height="%d" fill="#ffffff"/>' % (w, total_h))

    # ---- tiles -----------------------------------------------------------
    add('<g clip-path="url(#frame)">')
    for t in sm["tiles"]:
        add('<image x="%d" y="%d" width="%d" height="%d" xlink:href="%s" '
            'preserveAspectRatio="none"/>'
            % (t["left"], t["top"], sm["tile_size"], sm["tile_size"],
               t["data_uri"]))

    # ---- accuracy circle -------------------------------------------------
    if pos.get("accuracy_m"):
        p = project_onto_map(sm, pos["latitude"], pos["longitude"])
        r = float(pos["accuracy_m"]) / mpp
        if p and r > 1:
            add('<circle cx="%.1f" cy="%.1f" r="%.1f" fill="#0f5fa8" '
                'fill-opacity="0.11" stroke="#0f5fa8" stroke-opacity="0.55" '
                'stroke-width="1.5"/>' % (p["x"], p["y"], r))

    # ---- neighbouring access points --------------------------------------
    neigh = 0
    for a in (doc.get("apple") or {}).get("access_points", []):
        if not a.get("located") or a.get("queried"):
            continue
        p = project_onto_map(sm, a["latitude"], a["longitude"])
        if p:
            neigh += 1
            add('<circle cx="%.1f" cy="%.1f" r="2.6" fill="#0f5fa8" '
                'fill-opacity="0.5" stroke="#ffffff" stroke-width="0.7" '
                'stroke-opacity="0.8"/>' % (p["x"], p["y"]))

    # ---- Microsoft replicate probes --------------------------------------
    for rep in ((doc.get("microsoft_replicates") or {}).get("results") or []):
        r = rep.get("result") or {}
        if not r.get("located"):
            continue
        p = project_onto_map(sm, r["latitude"], r["longitude"])
        if p:
            add('<rect x="%.1f" y="%.1f" width="9" height="9" fill="#7c3aed" '
                'stroke="#ffffff" stroke-width="1.6" filter="url(#sh)" '
                'transform="rotate(45 %.1f %.1f)"/>'
                % (p["x"] - 4.5, p["y"] - 4.5, p["x"], p["y"]))

    # ---- queried access points -------------------------------------------
    for a in (doc.get("apple") or {}).get("queried", []):
        if not a.get("located"):
            continue
        p = project_onto_map(sm, a["latitude"], a["longitude"])
        if p:
            add('<circle cx="%.1f" cy="%.1f" r="6" fill="#0f5fa8" '
                'stroke="#ffffff" stroke-width="2" filter="url(#sh)"/>'
                % (p["x"], p["y"]))

    # ---- Microsoft observed fix ------------------------------------------
    ms = (doc.get("microsoft") or {}).get("result") or {}
    if ms.get("located"):
        p = project_onto_map(sm, ms["latitude"], ms["longitude"])
        if p:
            add('<circle cx="%.1f" cy="%.1f" r="6" fill="#b3690a" '
                'stroke="#ffffff" stroke-width="2" filter="url(#sh)"/>'
                % (p["x"], p["y"]))

    # ---- the reported position -------------------------------------------
    p = project_onto_map(sm, pos["latitude"], pos["longitude"])
    if p:
        x, y = p["x"], p["y"]
        add('<path d="M %.1f %.1f c 0 -9 -7 -11 -7 -18 a 7 7 0 1 1 14 0 '
            'c 0 7 -7 9 -7 18 z" fill="#b3261e" stroke="#ffffff" '
            'stroke-width="2" filter="url(#sh)"/>' % (x, y))
        add('<circle cx="%.1f" cy="%.1f" r="2.6" fill="#ffffff"/>'
            % (x, y - 18))

    add('</g>')
    add('<rect x="0.5" y="0.5" width="%d" height="%d" fill="none" '
        'stroke="#c9d1dc"/>' % (w - 1, h - 1))

    # ---- scale bar -------------------------------------------------------
    scale_m = 25
    while scale_m / mpp < 70:
        scale_m *= 2
    bar = scale_m / mpp
    add('<g transform="translate(14 %d)">' % (h - 26))
    add('<rect x="-6" y="-13" width="%.0f" height="24" rx="3" fill="#ffffff" '
        'fill-opacity="0.88" stroke="#c9d1dc" stroke-width="0.8"/>'
        % (bar + 56))
    add('<line x1="0" y1="0" x2="%.1f" y2="0" stroke="#10151c" '
        'stroke-width="2.5"/>' % bar)
    add('<line x1="0" y1="-4" x2="0" y2="4" stroke="#10151c" stroke-width="2.5"/>')
    add('<line x1="%.1f" y1="-4" x2="%.1f" y2="4" stroke="#10151c" '
        'stroke-width="2.5"/>' % (bar, bar))
    add('<text x="%.1f" y="4.5" font-family="Helvetica,Arial,sans-serif" '
        'font-size="11" fill="#10151c">%d m</text>' % (bar + 8, scale_m))
    add('</g>')

    # ---- north arrow -----------------------------------------------------
    add('<g transform="translate(%d 26)">' % (w - 30))
    add('<circle cx="0" cy="0" r="15" fill="#ffffff" fill-opacity="0.88" '
        'stroke="#c9d1dc" stroke-width="0.8"/>')
    add('<path d="M 0 -10 L 4.5 6 L 0 3 L -4.5 6 Z" fill="#10151c"/>')
    add('<text x="0" y="-11.5" text-anchor="middle" font-size="8" '
        'font-family="Helvetica,Arial,sans-serif" fill="#10151c">N</text>')
    add('</g>')

    # ---- legend ----------------------------------------------------------
    y = h + 21
    add('<g font-family="Helvetica,Arial,sans-serif" font-size="11" '
        'fill="#39424f">')
    x = 14
    items = [
        ("pin", "#b3261e", "Reported position"),
        ("dot", "#0f5fa8", "Queried access point"),
    ]
    if ms.get("located"):
        items.append(("dot", "#b3690a", "Microsoft fix"))
    if (doc.get("microsoft_replicates") or {}).get("groups_resolved"):
        items.append(("dia", "#7c3aed", "Microsoft replicate probe"))
    if neigh:
        items.append(("sml", "#0f5fa8", "Neighbouring access point (%d)" % neigh))
    if pos.get("accuracy_m"):
        items.append(("ring", "#0f5fa8", "Stated accuracy"))

    for kind, colour, label in items:
        if kind == "pin":
            add('<path d="M %d %d c 0 -4 -3.2 -5 -3.2 -8.2 a 3.2 3.2 0 1 1 6.4 0 '
                'c 0 3.2 -3.2 4.2 -3.2 8.2 z" fill="%s"/>' % (x + 4, y + 3, colour))
        elif kind == "dia":
            add('<rect x="%d" y="%d" width="7" height="7" fill="%s" '
                'transform="rotate(45 %d %d)"/>'
                % (x + 1, y - 4.5, colour, x + 4.5, y - 1))
        elif kind == "ring":
            add('<circle cx="%d" cy="%d" r="4.5" fill="%s" fill-opacity="0.15" '
                'stroke="%s" stroke-opacity="0.6" stroke-width="1.2"/>'
                % (x + 4, y - 1, colour, colour))
        else:
            add('<circle cx="%d" cy="%d" r="%s" fill="%s"%s/>'
                % (x + 4, y - 1, "2.4" if kind == "sml" else "4.2", colour,
                   ' fill-opacity="0.55"' if kind == "sml" else ""))
        add('<text x="%d" y="%d">%s</text>' % (x + 14, y + 3, _esc(label)))
        x += 16 + len(label) * 6 + 18
    add('</g>')

    # ---- caption ---------------------------------------------------------
    cy = h + LEGEND_H
    add('<rect x="0" y="%d" width="%d" height="%d" fill="#f7f9fc"/>'
        % (cy, w, CAPTION_H))
    add('<line x1="0" y1="%d" x2="%d" y2="%d" stroke="#dfe4ec"/>' % (cy, w, cy))

    coords = doc.get("coordinates") or {}
    val = (doc.get("validation") or {})
    tgt = doc.get("target") or {}
    label = tgt.get("ssid") or ", ".join(tgt.get("bssids") or []) or "target"

    add('<g font-family="Helvetica,Arial,sans-serif" fill="#10151c">')
    add('<text x="14" y="%d" font-size="13" font-weight="bold">%s</text>'
        % (cy + 21, _esc(label)))
    add('<text x="14" y="%d" font-size="11" fill="#39424f" '
        'font-family="Consolas,monospace">%s  &#177;%s m</text>'
        % (cy + 39, _esc(coords.get("decimal_precise", "")),
           _esc(pos.get("accuracy_m"))))
    add('<text x="14" y="%d" font-size="10.5" fill="#6b7686">%s</text>'
        % (cy + 56, _esc("%s  |  Plus Code %s  |  MGRS %s"
                         % (val.get("verdict", ""), coords.get("plus_code", ""),
                            coords.get("mgrs", "")))))
    add('<text x="14" y="%d" font-size="9.5" fill="#6b7686">%s</text>'
        % (cy + 73, _esc("Case %s  |  %s  |  %s v%s"
                         % (doc.get("case_id"), doc.get("completed_utc"),
                            TOOL_NAME, __version__))))
    add('<text x="14" y="%d" font-size="9" fill="#8892a2">%s</text>'
        % (cy + 88, _esc("Map data %s. Positions are third-party crowd-sourced "
                         "records, not measurements by this tool."
                         % sm.get("attribution", ""))))
    add('</g>')

    add('</svg>')
    return "\n".join(out)
