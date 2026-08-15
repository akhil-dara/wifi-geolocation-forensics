"""
Self-contained forensic report generator.

The output is a single HTML file with no external references of any kind: the
stylesheet is inline, and the map imagery is embedded as base64 data URIs.
Opened on a machine with no network, ten years from now, it renders exactly as
it did on the day it was produced.  That property is the whole point - a report
that silently loses its map when a tile server retires is not an exhibit.

A print stylesheet turns the same file into a paginated PDF through the
browser's own print dialogue, so no PDF library is needed.
"""

from __future__ import annotations

import html
import re
from typing import Dict, List

from . import TOOL_NAME, __version__
from . import fmt
from .assets import ICON_DATA_URI, MARK_DATA_URI
from .osint import project_onto_map


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _fmt(value, suffix: str = "", dash: str = "&mdash;") -> str:
    """
    Quantities, via the shared formatter, with HTML escaping applied.

    Same contract as `fmt.number`; the only difference is that a non-numeric
    value is escaped before it reaches the markup, and the empty dash is an
    em-dash entity rather than a hyphen.
    """
    if value is None or value == "":
        return dash
    if isinstance(value, float):
        return fmt.number(value, suffix)
    return "%s%s" % (esc(value), suffix)


#: Coordinate precision for the document currently being rendered. Set once by
#: render(); every coordinate in the report is written through _pair/_coord so
#: a redacted document cannot print full precision from some overlooked
#: format string.
_DP = fmt.FULL_PLACES


def _pair(lat, lon, dash="&mdash;"):
    return fmt.pair(lat, lon, _DP, dash=dash)


def _coord(v, dash="&mdash;"):
    return fmt.coord(v, _DP, dash=dash)


STATUS_CLASS = {"pass": "ok", "warn": "warn", "fail": "bad",
                "unavailable": "na", "info": "na"}

VERDICT_CLASS = fmt.VERDICT_CLASS


# ==========================================================================
def render(doc: Dict[str, object], case_meta: Dict[str, object]) -> str:
    """Produce the complete report document."""
    global _DP
    _DP = fmt.places(doc)
    parts: List[str] = [
        _head(doc, case_meta),
        _cover(doc, case_meta),
        _summary(doc),
        _inputs(doc),
        _artefact(doc),
        _places(doc),
        _position(doc),
        _map(doc),
        _confidence(doc),
        _anomalies(doc),
        _sources(doc),
        _cluster(doc),
        _intelligence(doc),
        _survey(doc),
        _custody(doc, case_meta),
        _limitations(),
        _footer(doc, case_meta),
    ]
    html = "\n".join(p for p in parts if p)

    # Number the sections in the order they survived assembly, so that an
    # omitted section (no map, no anomalies) does not leave a gap in the
    # numbering for a reader to wonder about.
    counter = [0]

    def _n(_match):
        counter[0] += 1
        return '<span class="n">%02d</span>' % counter[0]

    html = re.sub(r'<span class="n">##</span>', _n, html)
    banner = ""
    if doc.get("redacted"):
        banner = ('<div class="redacted-banner"><strong>REDACTED COPY</strong>'
                  '<span>%s</span></div>' % esc(doc.get("redaction_note", "")))
    html = html.replace("__REDACTION_BANNER__", banner)
    return html.replace("__MARK__", MARK_DATA_URI).replace("__ICON__", ICON_DATA_URI)


def _inputs(doc: Dict[str, object]) -> str:
    """
    Exactly what the examiner supplied, and exactly what left this machine.

    This section exists because a reader's first question is always "what was
    this actually run against?", and an answer buried across three later
    sections is not an answer.  Every address that was sent is listed in full;
    nothing is summarised as a count alone.
    """
    tgt = doc.get("target") or {}
    survey = doc.get("survey") or {}
    ap = doc.get("apple") or {}
    ms_wrap = doc.get("microsoft") or {}
    ms = ms_wrap.get("result") or {}
    lp = doc.get("microsoft_locality_probe") or {}
    lpr = lp.get("result") or {}
    per = doc.get("microsoft_per_ap") or {}

    def maclist(macs, empty="&mdash;"):
        macs = [m for m in (macs or [])]
        if not macs:
            return empty
        return "<div class=\"maclist\">%s</div>" % "".join(
            "<span>%s</span>" % esc(m) for m in macs)

    kind = {
        "bssid": "a hardware address (BSSID)",
        "ssid": "a network name (SSID), resolved locally by this host's radio",
        "ssid-db": "a network name, resolved via open datasets",
        "imported": ("access point addresses supplied directly &mdash; no "
                     "name lookup or radio scan was involved"),
        "survey": "a general survey of what the radio could see",
        "ssid-unresolvable": "a network name that could not be resolved",
    }.get(tgt.get("kind"), str(tgt.get("kind")))

    asserted = tgt.get("ssid_asserted_by_operator")
    observed = tgt.get("ssid_observed")
    if asserted and not observed:
        name_row = ("%s <em>&mdash; asserted by the examiner; neither service "
                    "returns network names, so this was not derived</em>"
                    % esc(asserted))
    elif observed:
        name_row = ("%s <em>&mdash; observed by this host's radio</em>"
                    % esc(observed))
    else:
        name_row = "&mdash; <em>not known</em>"

    imported = tgt.get("imported_observations") or []
    # Separate what the examiner typed from what came out of an artefact, so
    # the reader can tell an assertion from a recovered record.
    direct = [o for o in imported
              if str(o.get("source") or "").startswith("operator")]
    from_artefacts = [o for o in imported if o not in direct]

    if tgt.get("input"):
        entered = "<span class=\"mono\">%s</span>" % esc(tgt["input"])
    elif direct:
        entered = ("%s <em>&mdash; supplied directly as %d access point "
                   "address(es), not as a search term</em>"
                   % (maclist([o.get("bssid") for o in direct]), len(direct)))
    else:
        entered = "<em>nothing typed; addresses came from imported artefacts</em>"

    supplied = [
        ("Target as entered", entered),
        ("Interpreted as", kind),
        ("Network name", name_row),
        ("Access point addresses queried", maclist(tgt.get("bssids"))),
        ("Recovered from artefacts",
         ("%d address(es) from %s" % (len(from_artefacts), esc(", ".join(
             sorted({str(o.get("source") or "?") for o in from_artefacts})))))
         if from_artefacts else "none &mdash; no artefacts were imported"),
        ("Radio scan",
         ("performed &mdash; %d access points observed"
          % (survey.get("beacon_count") or 0)) if survey.get("active_scan")
         else "not performed &mdash; the radio was not touched"),
    ]

    # ---- what was actually transmitted -----------------------------------
    reqs = []
    if ap:
        reqs.append((
            "Apple Location Services",
            "the %d address(es) above, with a request for up to %s "
            "neighbouring access points"
            % (len(tgt.get("bssids") or []), _fmt(ap.get("neighbours_requested"))),
            maclist(ap.get("requested")),
            "%s access points returned, %s carrying positions"
            % (_fmt(ap.get("total_returned")), _fmt(ap.get("total_located")))))

    if ms_wrap:
        if ms.get("located"):
            outcome = ("position %s &plusmn;%s m"
                       % (_pair(ms["latitude"], ms["longitude"]),
                          _fmt(ms.get("radial_uncertainty_m"))))
        elif ms.get("ip_fallback"):
            outcome = ("<span class=\"bad-t\">no Wi-Fi match &mdash; the service "
                       "returned an IP-derived position (&plusmn;%s m), which was "
                       "discarded</span>" % _fmt(ms.get("radial_uncertainty_m")))
        else:
            outcome = "no position (%s)" % esc(ms.get("fault") or "")
        reqs.append((
            "Microsoft inference &mdash; observed fingerprint",
            "the %s access point(s) actually observed, as a single "
            "co-observation" % _fmt(ms_wrap.get("beacons_submitted")),
            "<span class=\"mono small\">see the request XML preserved in "
            "exhibit %s</span>" % _fmt(ms_wrap.get("exhibit_seq")),
            outcome))

    rp = doc.get("microsoft_replicates") or {}
    if rp and rp.get("results"):
        con = rp.get("consensus") or {}
        outcome = ("%d of %d groups resolved; they agree to within %s m%s"
                   % (rp.get("groups_resolved", 0), rp.get("groups_submitted", 0),
                      _fmt(rp.get("max_separation_m")),
                      (", centred on %s"
                       % _pair(con["latitude"], con["longitude"])) if con else ""))
        allmacs = []
        for g in rp["results"]:
            allmacs.extend(g.get("bssids") or [])
        reqs.append((
            "Microsoft inference &mdash; replicate probes",
            "<strong>not observations.</strong> %d disjoint groups of access "
            "points, each multilaterated separately. Source: %s"
            % (len(rp["results"]), esc(rp.get("origin") or "")),
            maclist(allmacs),
            outcome))

    if per:
        reqs.append((
            "Microsoft inference &mdash; per-access-point",
            "%s separate single-address queries, one per access point"
            % _fmt(per.get("queried")),
            maclist([r.get("bssid") for r in per.get("results") or []]),
            "%s held by both providers; %s answered with an IP-derived "
            "fallback and were discarded"
            % (_fmt(per.get("known_to_microsoft")),
               _fmt(per.get("discarded_ip_fallback")))))

    req_rows = "".join(
        "<tr><td class=\"svc\">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (name, what, macs, outcome) for name, what, macs, outcome in reqs)

    return """
<section class="sec">
  <h2><span class="n">##</span> Inputs and requests</h2>

  <h3>What the examiner supplied</h3>
  <table class="kv">%s</table>

  <h3>What was sent, and to whom</h3>
  <p class="prose">Every address transmitted is listed in full below. The
  complete request and response for each of these, byte for byte, is preserved
  in the evidence package.</p>
  <table class="data reqs">
    <thead><tr><th>Service</th><th>What was asked</th>
    <th>Addresses sent</th><th>Outcome</th></tr></thead>
    <tbody>%s</tbody>
  </table>
  <div class="attrib">Nothing else left this machine except the open-data
  lookups listed in the location intelligence section (address, nearby places,
  elevation, daylight, map imagery), each of which received only the resolved
  coordinate.</div>
</section>""" % (
        "".join("<tr><th>%s</th><td>%s</td></tr>" % (esc(k), v)
                for k, v in supplied),
        req_rows or "<tr><td colspan=4>No requests were made.</td></tr>")




# --------------------------------------------------------------------------
def _head(doc, meta) -> str:
    return """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forensic Report &mdash; %s</title>
<link rel="icon" href="__ICON__">
<style>%s</style>
</head><body>
<div class="sheet">""" % (esc(doc.get("case_id")), CSS)


def _cover(doc, meta) -> str:
    v = doc.get("validation") or {}
    verdict = str(v.get("verdict", "UNRESOLVED"))
    score = v.get("score", 0)
    pos = doc.get("position") or {}
    tgt = doc.get("target") or {}
    coords = doc.get("coordinates") or {}

    ident = (esc(tgt.get("ssid") or tgt.get("input")) or "&mdash;")
    if tgt.get("kind") == "bssid" and not tgt.get("ssid"):
        ident = esc(tgt.get("input"))

    return """
<header class="cover">
  <div class="brand">
    <img class="mark" src="__MARK__" alt="">
    <div>
      <div class="brand-name">WiFi Geolocation Forensics</div>
      <div class="brand-sub">Independent cross-validated positioning</div>
    </div>
    <div class="classification">FOR INVESTIGATIVE USE</div>
  </div>

  <h1>Wireless Access Point<br>Geolocation Report</h1>

  <div class="cover-grid">
    <div><span class="lbl">Case reference</span><span class="val mono">%s</span></div>
    <div><span class="lbl">Examiner</span><span class="val">%s</span></div>
    <div><span class="lbl">Organisation</span><span class="val">%s</span></div>
    <div><span class="lbl">Your reference</span><span class="val">%s</span></div>
    <div><span class="lbl">Target identifier</span><span class="val">%s</span></div>
    <div><span class="lbl">Report generated</span><span class="val mono">%s</span></div>
  </div>

  __REDACTION_BANNER__
  <div class="verdict-card %s">
    <div class="verdict-left">
      <div class="verdict-label">Assessment</div>
      <div class="verdict-name">%s</div>
      <div class="verdict-text">%s</div>
    </div>
    <div class="verdict-right">
      <div class="score-ring" style="--pct:%s">
        <div class="score-num">%s</div>
        <div class="score-den">/100</div>
      </div>
      <div class="coverage">%s%% of checks performed</div>
    </div>
  </div>

  <div class="headline">%s</div>
  <button class="printer no-print" onclick="window.print()">Print / Save as PDF</button>
</header>
""" % (
        esc(doc.get("case_id")),
        esc(meta.get("examiner")) or "&mdash;",
        esc(meta.get("organisation")) or "&mdash;",
        esc(meta.get("reference")) or "&mdash;",
        ident, esc(doc.get("completed_utc")),
        VERDICT_CLASS.get(verdict, "v-none"), esc(verdict),
        esc(v.get("verdict_statement", "")),
        _fmt(score, dash="0"), _fmt(score, dash="0"),
        _fmt(v.get("coverage"), dash="0"),
        _headline(doc, coords, pos),
    )


def _headline(doc, coords, pos) -> str:
    """
    The three figures on the cover.

    A multi-place enquiry has no single position, and the cover used to say so
    with "not established" - directly beside a green CORROBORATED verdict. The
    two together read as a contradiction, when in fact the enquiry succeeded and
    simply answered a different question. Where there are several places, the
    cover states that instead.
    """
    def item(label, value, mono=True):
        return ('<div class="headline-item"><span class="lbl">%s</span>'
                '<span class="big%s">%s</span></div>'
                % (label, " mono" if mono else "", value))

    places = doc.get("places") or []
    if len(places) > 1:
        span = ""
        firsts = [p.get("earliest_seen") for p in places if p.get("earliest_seen")]
        lasts = [p.get("latest_seen") for p in places if p.get("latest_seen")]
        if firsts and lasts:
            span = "%s to %s" % (min(firsts)[:10], max(lasts)[:10])
        return (item("Places identified", "%d" % len(places), mono=False)
                + item("Networks located",
                       "%d" % sum(p["network_count"] for p in places), mono=False)
                + item("Period covered", esc(span) or "&mdash;", mono=False))

    return (item("Position", esc(coords.get("decimal") or "not established"))
            + item("Stated accuracy",
                   ("&plusmn; %s m" % _fmt(pos.get("accuracy_m"))) if pos
                   else "&mdash;", mono=False)
            + item("Plus Code", esc(coords.get("plus_code")) or "&mdash;"))


def _summary(doc) -> str:
    # The sentences themselves live in fmt.summary_lines so that the PDF says
    # exactly the same thing. Escaping happens here, after the text is built,
    # and the `**` markers become emphasis afterwards - so a value containing
    # HTML cannot escape through the emphasis substitution.
    lines = []
    for line in fmt.summary_lines(doc):
        safe = esc(line)
        safe = re.sub(r"\*\*(.+?)\*\*", r"<strong>\g<1></strong>", safe)
        lines.append(safe)
    return """
<section class="sec">
  <h2><span class="n">##</span> Executive summary</h2>
  <div class="prose">%s</div>
</section>""" % "".join("<p>%s</p>" % l for l in lines)



def _artefact(doc) -> str:
    """
    The input side of an artefact-led enquiry, kept separate from the position.

    A single-target enquiry asks "where is this access point". An import asks a
    different question - "where has this machine been" - and answering it from
    the same layout as the first was what made the report hard to follow. When
    an import is what happened, it gets its own section stating what came in
    and what became of it, before any location is discussed.
    """
    places = doc.get("places") or []
    tgt = doc.get("target") or {}
    ap = doc.get("apple") or {}
    if len(places) < 2 and tgt.get("kind") != "imported":
        return ""

    supplied = len(tgt.get("bssids") or []) or len(ap.get("requested") or [])
    resolved = len(ap.get("queried_located") or []) or sum(
        p["network_count"] for p in places)
    unknown = ap.get("unknown_to_apple") or []
    named = sorted({n["ssid"] for p in places for n in p["networks"] if n["ssid"]})

    rows = [
        ("Addresses supplied", "%s" % _fmt(supplied)),
        ("Located by Apple", "%s" % _fmt(resolved)),
        ("Not held by Apple", "%s%s" % (_fmt(len(unknown)),
         " &mdash; no record exists, which is not evidence of absence"
         if unknown else "")),
        ("Distinct places", "%s" % _fmt(len(places))),
    ]
    if named:
        rows.append(("Network names in the artefact",
                     ", ".join(esc(n) for n in named[:24])
                     + (" &hellip;" if len(named) > 24 else "")))

    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (k, v) for k, v in rows)

    return """
<section class="sec">
  <h2><span class="n">##</span> Artefact analysis</h2>
  <div class="prose"><p>The addresses in this enquiry came from an imported
    artefact rather than from a live observation. An artefact of this kind
    records the networks a machine has joined over time, so it is read as a
    history: every address is located independently, and the results are
    grouped into the places they fall in. Network names and dates below are
    the artefact's own &mdash; neither positioning service returns either.</p></div>
  <table class="kv">%s</table>
</section>""" % body


def _timeline(places) -> str:
    """
    The movement history as a time axis: one bar per place, drawn to scale.

    A table of dates tells a reader when each place was used; only a shared
    axis shows the shape - that two places overlap, that one is a single
    afternoon between two long stays, that there is a three-month gap. That
    shape is usually the question being asked of the artefact, and reading it
    out of four date columns is work the report should have done.

    Inline SVG with no script, so it survives being printed, archived inside
    the evidence package, and opened years later with no network.
    """
    import datetime as _dt

    def parse(v):
        try:
            return _dt.datetime.strptime(str(v)[:10], "%Y-%m-%d")
        except (ValueError, TypeError):
            return None

    spans = []
    for pl in places:
        a, b = parse(pl.get("earliest_seen")), parse(pl.get("latest_seen"))
        if a and b:
            spans.append((pl, a, b if b >= a else a))
    if len(spans) < 2:
        return ""                      # nothing to compare against

    lo = min(a for _p, a, _b in spans)
    hi = max(b for _p, _a, b in spans)
    total = max((hi - lo).days, 1)

    row_h, top, left, width = 26, 26, 152, 560
    height = top + row_h * len(spans) + 26
    bars = []
    for i, (pl, a, b) in enumerate(spans):
        y = top + i * row_h
        x0 = left + (a - lo).days / total * width
        w = max((b - a).days / total * width, 3.0)   # a single day is visible
        level = (pl.get("corroboration") or {}).get("level") or ""
        colour = {"strong": "#0f766e", "moderate": "#b45309"}.get(level, "#b91c1c")
        label = esc((pl.get("locality") or "Place %d" % pl["index"])[:22])
        bars.append(
            '<text x="%d" y="%d" class="tl-lbl">%d. %s</text>'
            '<rect x="%.1f" y="%d" width="%.1f" height="11" rx="3" fill="%s"/>'
            '<title>%s to %s</title>'
            % (left - 10, y + 10, pl["index"], label,
               x0, y, w, colour,
               esc(str(pl.get("earliest_seen"))[:10]),
               esc(str(pl.get("latest_seen"))[:10])))

    ticks = []
    for f in (0.0, 0.5, 1.0):
        x = left + f * width
        d = lo + _dt.timedelta(days=int(total * f))
        # The end labels are anchored inwards; centred on the axis ends they
        # overhang the viewBox and the last date is clipped off the page.
        anchor = {0.0: "start", 1.0: "end"}.get(f, "middle")
        ticks.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" class="tl-grid"/>'
                     '<text x="%.1f" y="%d" class="tl-tick" '
                     'text-anchor="%s">%s</text>'
                     % (x, top - 8, x, top + row_h * len(spans),
                        x, height - 8, anchor, d.strftime("%Y-%m-%d")))

    return ('<div class="timeline"><svg viewBox="0 0 %d %d" width="100%%" '
            'role="img" aria-label="When the host was at each place">%s%s</svg>'
            '<p class="attrib">Bars span the first and last connection dates '
            'recorded in the artefact, drawn to scale. Colour shows how well '
            'each place is corroborated. A gap is an absence of records, not '
            'evidence the host was elsewhere.</p></div>'
            % (left + width + 24, height, "".join(ticks), "".join(bars)))



def _places_map(places) -> str:
    """
    Where the places are in relation to each other, drawn to scale.

    Deliberately not a tiled map. Places in a movement history can be a street
    apart or a continent apart, so no single tile grid covers them, and
    fetching one grid per place would mean dozens of round trips for a large
    artefact. What the reader actually needs from an overview is the shape of
    the movement - two sites close together and one far away reads instantly
    here and not at all from a column of coordinates.

    Equirectangular with a cosine correction on longitude, which is accurate
    enough for a relative plot and wrong by nothing a reader would act on. Each
    place keeps its own precise coordinates and map links below.
    """
    import math

    pts = [(p, float(p["latitude"]), float(p["longitude"])) for p in places
           if p.get("latitude") is not None]
    if len(pts) < 2:
        return ""

    lats = [la for _p, la, _lo in pts]
    lons = [lo for _p, _la, lo in pts]
    mid = math.radians(sum(lats) / len(lats))
    # Longitude degrees shrink with latitude; without this a north-south pair
    # looks further apart than an east-west pair of the same distance.
    xs = [lo * math.cos(mid) for lo in lons]
    x0, x1 = min(xs), max(xs)
    y0, y1 = min(lats), max(lats)
    spanx, spany = max(x1 - x0, 1e-6), max(y1 - y0, 1e-6)

    W, H, PAD = 620.0, 300.0, 46.0
    # One scale for both axes, so the picture is not stretched.
    k = min((W - 2 * PAD) / spanx, (H - 2 * PAD) / spany)
    ox = (W - spanx * k) / 2.0
    oy = (H - spany * k) / 2.0

    def place_xy(la, lo):
        return (ox + (lo * math.cos(mid) - x0) * k,
                H - (oy + (la - y0) * k))          # SVG y grows downward

    dots, labels = [], []
    #: Boxes already occupied by a label. Places in one city land on top of
    #: each other at continental scale, and three overlapping names render as
    #: an unreadable smear - worse than no name, because it looks like a fault.
    #: A place whose label will not fit keeps its number, which is what the
    #: list below is keyed on anyway.
    taken = []

    def fits(cx, cy, width):
        box = (cx - width / 2, cy - 7, cx + width / 2, cy + 4)
        for other in taken:
            if not (box[2] < other[0] or box[0] > other[2]
                    or box[3] < other[1] or box[1] > other[3]):
                return False
        taken.append(box)
        return True

    for p, la, lo in pts:
        x, y = place_xy(la, lo)
        level = (p.get("corroboration") or {}).get("level") or ""
        colour = {"strong": "#0f766e", "moderate": "#b45309"}.get(level, "#b91c1c")
        dots.append('<circle cx="%.1f" cy="%.1f" r="9" fill="%s" '
                    'fill-opacity=".85"/><text x="%.1f" y="%.1f" '
                    'class="pm-num">%d</text>' % (x, y, colour, x, y + 3.6,
                                                  p["index"]))
        raw = (p.get("locality") or "Place %d" % p["index"])[:26]
        # 5.4 px per character is close enough for 10.5px Inter at this size.
        if fits(x, y - 14, len(raw) * 5.4):
            labels.append('<text x="%.1f" y="%.1f" class="pm-lbl">%s</text>'
                          % (x, y - 14, esc(raw)))

    # A scale bar covering roughly a quarter of the plot, rounded to something
    # a reader can hold in their head.
    # Imported here rather than at module scope: report.py is otherwise
    # free of the analysis modules, and keeping it that way makes the
    # renderer safe to call on a bare result document.
    from .geo import haversine_m

    span_m = (haversine_m(y0, min(lons), y0, max(lons)) if spanx > spany
              else haversine_m(y0, lons[0], y1, lons[0]))
    target = max(span_m / 4.0, 1.0)
    nice = min([1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
               key=lambda v: abs(v - target / 1000.0)) * 1000.0
    bar_px = (nice / span_m) * (max(spanx, spany) * k) if span_m else 0
    bar = ""
    if 20 < bar_px < W - 2 * PAD:
        bar = ('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" class="pm-bar"/>'
               '<text x="%.1f" y="%.1f" class="pm-tick">%s</text>'
               % (PAD, H - 14, PAD + bar_px, H - 14,
                  PAD, H - 20,
                  "%d km" % (nice / 1000) if nice >= 1000 else "%d m" % nice))

    return ('<div class="placesmap"><svg viewBox="0 0 %d %d" width="100%%" '
            'role="img" aria-label="Where the places are in relation to each '
            'other">%s%s%s</svg>'
            '<p class="attrib">A scale diagram, not a map: it shows how the '
            'places sit relative to one another. Colour is the corroboration '
            'of each. Precise coordinates and map links are with each place '
            'below.</p></div>'
            % (int(W), int(H), bar, "".join(dots), "".join(labels)))



def _places(doc) -> str:
    """
    Where the supplied access points actually are, when there is more than one.

    Omitted for an ordinary single-site enquiry. It appears when an import
    spans several locations, because at that point the honest answer is not a
    coordinate but a history: these networks, in these places, at these times.
    """
    places = doc.get("places") or []
    if len(places) < 2:
        return ""

    blocks = []
    for p in places:
        rows = "".join(
            # esc() around the entity would print it literally, so the dash
            # is chosen after escaping rather than before.
            "<tr><td class=\"mono\">%s</td><td>%s</td><td class=\"mono\">%s</td>"
            "<td>%s</td><td>%s</td></tr>"
            % (esc(n["bssid"]), esc(n["ssid"]) or "&mdash;",
               fmt.pair(n.get("latitude"), n.get("longitude"), _DP),
               esc((n.get("first_seen") or "")[:19]) or "&mdash;",
               esc((n.get("last_seen") or "")[:19]) or "&mdash;")
            for n in p["networks"])
        span = ""
        if p.get("earliest_seen") or p.get("latest_seen"):
            span = (" &middot; connected between %s and %s"
                    % (esc((p.get("earliest_seen") or "?")[:10]),
                       esc((p.get("latest_seen") or "?")[:10])))
        corr = p.get("corroboration") or {}
        level = str(corr.get("level") or "")
        badge = ('<span class="pill %s">%s support</span>'
                 % ({"strong": "v-good", "moderate": "v-mid"}.get(level, "v-low"),
                    esc(level or "unrated"))) if level else ""
        blocks.append("""
  <h3>Place %d &mdash; %s %s</h3>
  <p class="place-addr">%s</p>
  <p class="muted">%s &middot; %d network(s), spread across %s m%s.</p>
  <p class="muted">%s</p>
  %s
  <table class="data">
    <tr><th>Access point</th><th>Network</th><th>Position</th>
        <th>First connected</th><th>Last connected</th></tr>
    %s
  </table>""" % (p["index"],
                 esc(p.get("locality") or "") or fmt.pair(
                     p.get("latitude"), p.get("longitude"), _DP), badge,
                 esc(p.get("address") or "Address not looked up"),
                 fmt.pair(p.get("latitude"), p.get("longitude"), _DP),
                 p["network_count"], _fmt(p.get("spread_m")), span,
                 esc(str(corr.get("statement") or "")),
                 _map_links_compact(p.get("latitude"), p.get("longitude"), _DP),
                 rows))

    return """
<section class="sec">
  <h2><span class="n">##</span> Location history</h2>
  <div class="callout">
    <strong>The supplied access points resolve to %d distinct places.</strong>
    They are reported separately because averaging them would describe nowhere,
    and discarding the outlying ones would throw away the evidence the artefact
    was collected for. Each place is rated on how many of this host's own
    profiled networks Apple independently places there &mdash; two lists built
    without reference to each other, so an overlap between them is support that
    the host was at that location.
  </div>
  %s
  %s
  %s
</section>"""% (len(places), _places_map(places), _timeline(places), "".join(blocks))


def _position(doc) -> str:
    # Where the enquiry found several places, the location history is the
    # answer and this section has nothing left to add. It used to print "No
    # position established" directly beneath four established places, which
    # reads as a failed run rather than a different question answered.
    if len(doc.get("places") or []) > 1:
        return ""

    coords = doc.get("coordinates")
    pos = doc.get("position")
    if not coords or not pos:
        return """
<section class="sec"><h2><span class="n">##</span> Position</h2>
<div class="callout bad"><strong>No position established.</strong>
%s</div></section>""" % esc(doc.get("failure") or
                            "No provider returned a usable position for this target.")

    rows = [
        ("Decimal degrees (WGS84)", coords.get("decimal_precise")),
        ("Degrees / minutes / seconds", coords.get("dms")),
        ("Open Location Code (Plus Code)", coords.get("plus_code")),
        ("Military Grid Reference (MGRS)", coords.get("mgrs")),
        ("Universal Transverse Mercator", coords.get("utm")),
        ("Geohash", coords.get("geohash")),
    ]
    env = (doc.get("enrichment") or {}).get("environment") or {}
    if env.get("elevation_m") is not None:
        rows.append(("Ground elevation", "%s m above sea level"
                     % _fmt(env.get("elevation_m"))))
    if env.get("timezone"):
        rows.append(("Timezone", "%s (%s)" % (env.get("timezone"),
                                              env.get("timezone_abbreviation") or "")))

    anchor_note = doc.get("anchor_note")
    lat, lon = pos["latitude"], pos["longitude"]
    return """
<section class="sec">
  <h2><span class="n">##</span> Position</h2>
  <div class="method-note">%s &mdash; stated accuracy &plusmn;%s m.%s</div>
  <table class="kv">%s</table>
  %s
</section>""" % (
        esc(pos.get("method")), _fmt(pos.get("accuracy_m")),
        (" " + esc(anchor_note)) if anchor_note else "",
        "".join("<tr><th>%s</th><td class=\"mono\">%s</td></tr>"
                % (esc(k), esc(v)) for k, v in rows if v),
        _map_links(lat, lon, _DP),
    )


def _map_links_compact(lat: float, lon: float, dp: int = fmt.FULL_PLACES) -> str:
    """
    One line of map links, for lists of positions.

    The full block prints five services with their URLs spelled out, which is
    right for the single position a report is about - the reader may need to
    copy one into a statement. Repeated once per place it drowns the history:
    four places produced twenty link rows, and a real registry import can hold
    twenty places.
    """
    links = fmt.map_links(lat, lon, dp)
    return ('<p class="maplinks">Open in %s</p>'
            % " &middot; ".join(
                '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>'
                % (esc(url), esc(name)) for name, url in links))



def _map_links(lat: float, lon: float, dp: int = fmt.FULL_PLACES) -> str:
    """
    Clickable links straight to the position in the common mapping services.

    Coordinates are embedded at the precision the report actually holds, so a
    reader can follow the link and land on exactly the point described, and can
    copy the URL into a statement or a disclosure schedule.

    `places` matters in a redacted report. Formatting a value truncated to two
    decimal places as `51.50000000` is not a disclosure - the precision really
    is gone - but it reads as eight-decimal precision, and a reader could
    reasonably conclude the redaction had failed. The link is written at the
    precision that survives.
    """
    links = fmt.map_links(lat, lon, dp)
    return ("<h3>Open this position</h3><ul class=\"links\">%s</ul>"
            "<div class=\"attrib\">Links carry the coordinate at full precision. "
            "Following them sends the position to the operator of that service; "
            "consider whether that is appropriate before doing so from a "
            "sensitive enquiry.</div>"
            % "".join('<li><a href="%s" target="_blank" rel="noopener '
                      'noreferrer">%s</a><span class="mono">%s</span></li>'
                      % (esc(url), esc(name), esc(url)) for name, url in links))


def _map(doc) -> str:
    sm = doc.get("static_map")
    pos = doc.get("position") or {}
    if not sm or not sm.get("tiles"):
        return ""

    imgs = "".join(
        '<img class="tile" src="%s" style="left:%dpx;top:%dpx" alt="" loading="eager">'
        % (t["data_uri"], t["left"], t["top"]) for t in sm["tiles"])

    overlays = []
    mpp = sm.get("metres_per_pixel") or 1.0

    # Neighbouring access points as faint dots.
    for a in (doc.get("apple") or {}).get("access_points", [])[:400]:
        if not a.get("located") or a.get("queried"):
            continue
        p = project_onto_map(sm, a["latitude"], a["longitude"])
        if p:
            overlays.append('<div class="dot neigh" style="left:%.1fpx;top:%.1fpx" '
                            'title="%s"></div>' % (p["x"], p["y"], esc(a["bssid"])))

    # Accuracy circle for the reported position.
    if pos.get("accuracy_m"):
        r = float(pos["accuracy_m"]) / mpp
        p = project_onto_map(sm, pos["latitude"], pos["longitude"])
        if p and r > 2:
            overlays.append(
                '<div class="acc" style="left:%.1fpx;top:%.1fpx;width:%.1fpx;'
                'height:%.1fpx"></div>' % (p["x"] - r, p["y"] - r, r * 2, r * 2))

    # Each queried access point.
    for a in (doc.get("apple") or {}).get("queried", []):
        if not a.get("located"):
            continue
        p = project_onto_map(sm, a["latitude"], a["longitude"])
        if p:
            overlays.append('<div class="dot target" style="left:%.1fpx;top:%.1fpx" '
                            'title="%s"></div>' % (p["x"], p["y"], esc(a["bssid"])))

    # Microsoft's independent position.
    ms = (doc.get("microsoft") or {}).get("result") or {}
    if ms.get("located"):
        p = project_onto_map(sm, ms["latitude"], ms["longitude"])
        if p:
            overlays.append('<div class="dot msft" style="left:%.1fpx;top:%.1fpx" '
                            'title="Microsoft"></div>' % (p["x"], p["y"]))

    # The consensus position, drawn last so it sits on top.
    if pos:
        p = project_onto_map(sm, pos["latitude"], pos["longitude"])
        if p:
            overlays.append('<div class="pin" style="left:%.1fpx;top:%.1fpx"></div>'
                            % (p["x"], p["y"]))

    scale_m = 50
    while scale_m / mpp < 60:
        scale_m *= 2

    return """
<section class="sec page-break">
  <h2><span class="n">##</span> Map</h2>
  <div class="mapwrap">
    <div class="mapview" style="width:%dpx;height:%dpx">%s%s</div>
    <div class="scalebar"><span style="width:%.0fpx"></span><em>%d m</em></div>
  </div>
  <div class="legend">
    <span><i class="k-pin"></i>Reported position</span>
    <span><i class="k-target"></i>Queried access point</span>
    <span><i class="k-msft"></i>Microsoft independent fix</span>
    <span><i class="k-neigh"></i>Neighbouring access point</span>
    <span><i class="k-acc"></i>Stated accuracy</span>
  </div>
  <div class="attrib">Imagery: %s. %s Tiles were retrieved at examination time
  and embedded in this document, so this map renders without network access.</div>
</section>""" % (sm["width"], sm["height"], imgs, "".join(overlays),
                 scale_m / mpp, scale_m,
                 esc(sm.get("layer_name")), esc(sm.get("attribution")))


def _confidence(doc) -> str:
    v = doc.get("validation") or {}
    sigs = v.get("signals") or []
    pens = v.get("penalties") or []
    if not sigs:
        return ""

    def row(s, penalty=False):
        pct = 0 if not s["weight"] else max(0.0, s["awarded"] / s["weight"]) * 100
        cls = STATUS_CLASS.get(s.get("status"), "na")
        bar = ("<div class=\"bar pen\"><span style=\"width:100%%\"></span></div>"
               if penalty else
               "<div class=\"bar %s\"><span style=\"width:%.0f%%\"></span></div>"
               % (cls, pct))
        return ("<tr class=\"%s\"><td class=\"sig\">%s<div class=\"det\">%s</div></td>"
                "<td class=\"barcell\">%s</td><td class=\"num mono\">%s</td></tr>"
                % (cls, esc(s["name"]), esc(s["detail"]), bar,
                   ("%+.1f" % s["awarded"]) if penalty
                   else "%.1f / %.0f" % (s["awarded"], s["weight"])))

    sep = ""
    if v.get("separation_m") is not None:
        b = v.get("separation_bearing") or {}
        sep = ("<div class=\"callout\">The two providers' positions are "
               "<strong>%.0f m</strong> apart, bearing %s&deg; (%s) from the "
               "Apple position to the Microsoft position.</div>"
               % (v["separation_m"], _fmt(b.get("degrees")), esc(b.get("compass"))))

    cov = ""
    if (v.get("coverage") or 100) < 100:
        cov = "<div class=\"callout warn\">%s</div>" % esc(v.get("coverage_note"))

    return """
<section class="sec">
  <h2><span class="n">##</span> Confidence assessment</h2>
  <p class="prose">Each check below was applied independently and contributes a
  fixed maximum to the score. Checks that could not be performed are excluded
  from the calculation rather than counted as failures, and are marked
  <em>unavailable</em>.</p>
  %s%s
  <table class="signals">
    <thead><tr><th>Check</th><th>Result</th><th class="num">Contribution</th></tr></thead>
    <tbody>%s%s</tbody>
    <tfoot><tr><th colspan="2">Assessed score</th>
      <th class="num mono">%s / 100</th></tr></tfoot>
  </table>
</section>""" % (cov, sep,
                 "".join(row(s) for s in sigs),
                 "".join(row(p, True) for p in pens),
                 _fmt(v.get("score"), dash="0"))


def _anomalies(doc) -> str:
    cols = doc.get("collisions") or []
    if not cols:
        return ""
    items = "".join(
        "<li><div class=\"anom-head\"><span class=\"mono\">%s</span>"
        "<span class=\"badge bad\">%s km away</span></div><p>%s</p>"
        "<p class=\"mono small\">Conflicting record: %s</p></li>"
        % (esc(c["bssid"]), _fmt(c["distance_km"]), esc(c["explanation"]),
           _pair(c["latitude"], c["longitude"])) for c in cols)
    return """
<section class="sec">
  <h2><span class="n">##</span> Anomalies and excluded records</h2>
  <div class="callout warn"><strong>%d conflicting database record(s) were
  identified and excluded from positioning.</strong> They are reported here in
  full because their exclusion is an analytical decision that a reviewer is
  entitled to examine and disagree with.</div>
  <ul class="anomalies">%s</ul>
</section>""" % (len(cols), items)


def _sources(doc) -> str:
    ap = doc.get("apple") or {}
    ms_wrap = doc.get("microsoft") or {}
    ms = ms_wrap.get("result") or {}

    def _raw(a):
        r = (a.get("raw") or {}).get("fields") or {}
        return " ".join("%s=%s" % (k, v) for k, v in r.items()) or "&mdash;"

    apple_rows = "".join(
        "<tr><td class=\"mono\">%s</td><td class=\"mono\">%s</td>"
        "<td class=\"mono\">%s</td><td class=\"num\">%s</td>"
        "<td class=\"num\">%s</td><td class=\"num\">%s</td>"
        "<td class=\"mono raw\">%s</td></tr>"
        % (esc(a["bssid"]),
           _coord(a["latitude"]) if a.get("located") else "&mdash;",
           _coord(a["longitude"]) if a.get("located") else "&mdash;",
           _fmt(a.get("accuracy_m")), _fmt(a.get("altitude_m")),
           _fmt(a.get("altitude_accuracy_m")), _raw(a))
        for a in ap.get("queried", []))

    unknown = ap.get("unknown_to_apple") or []
    unknown_html = ""
    if unknown:
        unknown_html = ("<div class=\"callout warn\">Apple holds no record for: "
                        "<span class=\"mono\">%s</span>. An access point absent "
                        "from the database has simply never been reported by a "
                        "contributing device; absence is not evidence that it "
                        "does not exist.</div>"
                        % esc(", ".join(unknown)))

    ms_body = ""
    if ms.get("located"):
        ms_body = """<table class="kv">
        <tr><th>Resolved position</th><td class="mono">%s</td></tr>
        <tr><th>Radial uncertainty</th><td>%s m</td></tr>
        <tr><th>Resolver status</th><td>%s (source: %s)</td></tr>
        <tr><th>Crowd-sourcing level</th><td>%s</td></tr>
        <tr><th>Beacons submitted</th><td>%s</td></tr>
        <tr><th>Server time</th><td class="mono">%s</td></tr>
        <tr><th>Tracking id</th><td class="mono">%s</td></tr></table>""" % (
            _pair(ms["latitude"], ms["longitude"]),
            _fmt(ms.get("radial_uncertainty_m")),
            esc(ms.get("resolver_status")), esc(ms.get("resolver_source")),
            esc(ms.get("crowd_sourcing_level")), _fmt(ms.get("beacons_submitted")),
            esc(ms.get("server_utc")), esc(ms.get("tracking_id")))
    else:
        ms_body = ("<div class=\"callout warn\"><strong>No position obtained.</strong> "
                   "%s</div>" % esc(ms.get("fault") or "The service returned no result."))

    # Per-access-point comparison - the strongest corroboration available.
    pairs = ((doc.get("validation") or {}).get("context") or {}).get("per_ap_pairs") or []
    per_ap = doc.get("microsoft_per_ap") or {}
    per_ap_html = ""
    if pairs:
        rows = "".join(
            "<tr class=\"%s\"><td class=\"mono\">%s</td>"
            "<td class=\"mono\">%s</td><td class=\"num\">%s</td>"
            "<td class=\"mono\">%s</td><td class=\"num\">%s</td>"
            "<td class=\"num\"><strong>%s m</strong></td><td>%s</td></tr>"
            % ("hit" if p["within_uncertainty"] else "",
               esc(p["bssid"]),
               _pair(p["apple"]["latitude"], p["apple"]["longitude"]),
               _fmt(p["apple"]["accuracy_m"]),
               _pair(p["microsoft"]["latitude"], p["microsoft"]["longitude"]),
               _fmt(p["microsoft"]["radial_uncertainty_m"]),
               _fmt(p["separation_m"]),
               "agree" if p["within_uncertainty"] else "outside uncertainty")
            for p in pairs)
        per_ap_html = """
  <h3>Device-level cross-check</h3>
  <div class="method-note">Each access point below was put to both providers
  individually, so the two independent databases were asked the identical
  question about the identical physical device. This is stronger evidence than
  comparing two aggregate positions, which can coincide for unrelated reasons.
  %s</div>
  <table class="data">
    <thead><tr><th>BSSID</th><th>Apple position</th><th class="num">Acc m</th>
    <th>Microsoft position</th><th class="num">Unc m</th>
    <th class="num">Separation</th><th>Assessment</th></tr></thead>
    <tbody>%s</tbody>
  </table>""" % (
            ("%d of %d queried access points were absent from Microsoft's "
             "database; the service answered those with an IP-derived fallback "
             "position, which was detected and discarded."
             % (per_ap.get("discarded_ip_fallback", 0), per_ap.get("queried", 0))
             ) if per_ap.get("discarded_ip_fallback") else "",
            rows)

    # Replicated independent multilateration.
    rep = doc.get("microsoft_replicates") or {}
    lp_html = ""
    if rep and rep.get("results"):
        rows = "".join(
            "<tr class=\"%s\"><td class=\"num\">%d</td><td class=\"num\">%d</td>"
            "<td class=\"mono\">%s</td><td class=\"num\">%s</td>"
            "<td class=\"mono raw\">%s</td></tr>"
            % ("hit" if (g.get("result") or {}).get("located") else "",
               g["group"], g["size"],
               _pair((g.get("result") or {}).get("latitude"),
                     (g.get("result") or {}).get("longitude"),
                     dash="no position"),
               _fmt((g.get("result") or {}).get("radial_uncertainty_m")),
               esc(" ".join(g.get("bssids") or [])))
            for g in rep["results"])
        con = rep.get("consensus") or {}
        summary = ""
        if rep.get("groups_resolved", 0) >= 2:
            summary = ("<div class=\"callout\">All %d resolved groups fall "
                       "within <strong>%s m</strong> of one another"
                       "%s. Since the groups share no access points, that "
                       "agreement cannot be produced by any single database "
                       "record.</div>"
                       % (rep["groups_resolved"],
                          _fmt(rep.get("max_separation_m")),
                          (", centred on %s"
                           % _pair(con["latitude"], con["longitude"])) if con else ""))
        lp_html = """
  <h3>Replicated independent multilateration</h3>
  <div class="callout warn"><strong>These are probes, not observations.</strong>
  No device belonging to this examination observed these access points, and
  none of the results below may be described as a device sighting. What they
  establish is narrower and still valuable: the access points Apple reports
  nearest the target were divided into <strong>disjoint</strong> groups, and
  each group was put to Microsoft's multilateration engine separately. Each
  group is therefore independent evidence, computed by a database built from a
  different contributing population than Apple's. Because the sets were drawn
  from Apple's own response, this check is discounted in the confidence score
  rather than counted as two independent observations.</div>
  <div class="method-note">Groups were dealt round-robin from the access points
  ordered by distance from the target, so every group spans the same area
  rather than forming concentric rings. Source set: %s.</div>
  %s
  <table class="data">
    <thead><tr><th class="num">Group</th><th class="num">APs</th>
    <th>Position Microsoft computed</th><th class="num">Unc m</th>
    <th>Access points in this group</th></tr></thead>
    <tbody>%s</tbody>
  </table>""" % (esc(rep.get("origin") or "Apple's response"), summary, rows)

    ip_warn = ""
    if ms.get("ip_fallback"):
        ip_warn = ("<div class=\"callout bad\"><strong>IP fallback detected and "
                   "discarded.</strong> %s</div>" % esc(ms.get("fault")))

    return """
<section class="sec page-break">
  <h2><span class="n">##</span> Source detail</h2>

  <h3>Apple Location Services</h3>
  <div class="method-note">Endpoint <span class="mono">%s</span>. Credential-free
  crowd-sourced database. %s access point record(s) returned across %s request
  batch(es), %s of them carrying positions.</div>
  <div class="callout"><strong>Apple is never told the network name.</strong>
  Its service accepts hardware addresses only, and its response contains no
  network-name field of any kind &mdash; the only text it returns is the BSSID
  itself. Where this enquiry started from an SSID, that name was resolved to
  hardware addresses locally, by this host's own radio. Consequently the
  neighbouring access points below are positions without names.</div>
  %s
  <table class="data">
    <thead><tr><th>Queried BSSID</th><th>Latitude</th><th>Longitude</th>
    <th class="num">Accuracy&nbsp;m</th><th class="num">Altitude&nbsp;m</th>
    <th class="num">Alt&nbsp;acc&nbsp;m</th>
    <th>Uninterpreted fields</th></tr></thead>
    <tbody>%s</tbody>
  </table>
  <div class="attrib">Coordinates are shown at the full precision returned by
  the service (8 decimal places, as transmitted). "Uninterpreted fields" are
  numeric fields present in every record whose meaning is not established;
  they are preserved verbatim rather than guessed at. Fields numbered 1000 and
  above are access-point-level; the remainder are position-level.</div>

  <h3>Microsoft Location Inference Service</h3>
  <div class="method-note">Endpoint <span class="mono">%s</span>. Independent
  crowd-sourced database, queried with the observed beacon fingerprint. This
  provider multilaterates a single device position rather than reporting per
  access point, which is what makes it a genuine cross-check rather than a
  restatement of the first source.</div>
  %s%s
  %s%s
</section>""" % (
        esc(ap.get("endpoint")), _fmt(ap.get("total_returned")),
        len(ap.get("batches") or []), _fmt(ap.get("total_located")),
        unknown_html, apple_rows or "<tr><td colspan=7>No records.</td></tr>",
        (esc(ms_wrap.get("endpoint")) or "&mdash;"), ip_warn, ms_body,
        lp_html, per_ap_html)


def _cluster(doc) -> str:
    c = doc.get("cluster") or {}
    if not c.get("kept_count"):
        return ""
    bb = c.get("bounding_box") or {}
    return """
<section class="sec">
  <h2><span class="n">##</span> Neighbouring access-point analysis</h2>
  <p class="prose">Apple returns access points geographically adjacent to the
  target. Their distribution is an independent check on the target's own record:
  a tight cluster around the reported position corroborates it, while a diffuse
  or bimodal spread suggests a stale or mistaken entry.</p>
  <div class="stats">
    <div><span class="s-num">%s</span><span class="s-lbl">supporting points</span></div>
    <div><span class="s-num">%s</span><span class="s-lbl">excluded outliers</span></div>
    <div><span class="s-num">%s m</span><span class="s-lbl">median deviation</span></div>
    <div><span class="s-num">%s m</span><span class="s-lbl">95th percentile radius</span></div>
    <div><span class="s-num">%s m</span><span class="s-lbl">maximum radius</span></div>
  </div>
  <table class="kv">
    <tr><th>Cluster centroid</th><td class="mono">%s</td></tr>
    <tr><th>Bounding box</th><td class="mono">N %s &nbsp; S %s &nbsp; E %s &nbsp; W %s</td></tr>
  </table>
</section>""" % (
        _fmt(c.get("kept_count")), _fmt(c.get("rejected_count")),
        _fmt(c.get("mad_m")), _fmt(c.get("radius_p95_m")),
        _fmt(c.get("radius_max_m")),
        _pair(c["centroid"]["latitude"], c["centroid"]["longitude"]),
        _coord(bb.get("north")), _coord(bb.get("south")),
        _coord(bb.get("east")), _coord(bb.get("west")))


def _intelligence(doc) -> str:
    enr = doc.get("enrichment") or {}
    addr = enr.get("address") or {}
    places = (enr.get("places") or {}).get("places") or []
    day = enr.get("daylight") or {}
    vendors = doc.get("vendors") or {}
    if not (addr or places or day or vendors):
        return ""

    addr_rows = "".join(
        "<tr><th>%s</th><td>%s</td></tr>" % (esc(k), esc(v))
        for k, v in [
            ("Full address", addr.get("display_name")),
            ("Building / feature", addr.get("name")),
            ("House number", addr.get("house_number")),
            ("Road", addr.get("road")),
            ("Neighbourhood", addr.get("neighbourhood")),
            ("City / town", addr.get("city")),
            ("District", addr.get("district")),
            ("State / region", addr.get("state")),
            ("Postcode", addr.get("postcode")),
            ("Country", "%s (%s)" % (addr.get("country"), addr.get("country_code"))
             if addr.get("country") else None),
            ("OSM reference", "%s/%s" % (addr.get("osm_type"), addr.get("osm_id"))
             if addr.get("osm_id") else None),
        ] if v)

    place_rows = "".join(
        "<tr><td>%s</td><td class=\"kind\">%s</td><td class=\"kind\">%s</td>"
        "<td class=\"num\">%s m</td><td>%s</td><td>%s</td></tr>"
        % (esc(p["name"]), esc(p.get("category") or ""), esc(p["kind"]),
           _fmt(p["distance_m"], dash="0"), esc(p["bearing"]),
           esc(p.get("address") or ""))
        for p in places[:40])

    day_rows = "".join(
        "<tr><th>%s</th><td class=\"mono\">%s</td></tr>" % (esc(k), esc(v))
        for k, v in [
            ("Sunrise (UTC)", day.get("sunrise")),
            ("Solar noon (UTC)", day.get("solar_noon")),
            ("Sunset (UTC)", day.get("sunset")),
            ("Day length", day.get("day_length")),
            ("Civil twilight begins", day.get("civil_twilight_begin")),
            ("Civil twilight ends", day.get("civil_twilight_end")),
        ] if v)

    vend_rows = "".join(
        "<tr><td class=\"mono\">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (esc(mac), esc(v.get("vendor") or "not attributed"),
           (esc(v.get("vendor_source")) or "&mdash;"),
           "Locally administered" if v.get("locally_administered")
           else "Universally administered")
        for mac, v in vendors.items())

    blocks = []
    if addr_rows:
        blocks.append("<h3>Address</h3><table class=\"kv\">%s</table>" % addr_rows)
    pl = enr.get("places") or {}
    landmarks = pl.get("landmarks") or []

    if pl.get("error"):
        blocks.append(
            "<h3>Nearby places</h3><div class=\"callout warn\">"
            "<strong>The place-name lookup did not complete.</strong> %s "
            "Providers attempted: %s.</div>"
            % (esc(pl["error"]), esc(", ".join(pl.get("providers_attempted") or []))))
    elif pl.get("source") and places:
        blocks.append(
            "<div class=\"attrib\">Place names resolved via %s. Providers "
            "attempted in order: %s.</div>"
            % (esc(pl["source"]),
               esc(", ".join(pl.get("providers_attempted") or []))))

    if landmarks:
        lm_rows = "".join(
            "<tr class=\"%s\"><td><strong>%s</strong>%s</td><td class=\"kind\">%s</td>"
            "<td class=\"kind\">%s</td><td class=\"num\">%s m</td><td>%s</td></tr>"
            % ("hit" if p.get("notable") else "", esc(p["name"]),
               " <span class=\"badge note\">notable</span>" if p.get("notable") else "",
               esc(p["category"]), esc(p["kind"]),
               _fmt(p["distance_m"], dash="0"), esc(p["bearing"]))
            for p in landmarks[:30])
        blocks.append(
            "<h3>Recognisable places within %s m</h3>"
            "<p class=\"prose small\">What identifies this location to a reader "
            "is often not the building it sits in but the landmark beside it. "
            "These are ranked by prominence rather than distance; those marked "
            "<em>notable</em> carry a Wikidata or Wikipedia reference in "
            "OpenStreetMap.%s</p>"
            "<table class=\"data\"><thead><tr><th>Name</th><th>Category</th>"
            "<th>Type</th><th class=\"num\">Distance</th><th>Bearing</th>"
            "</tr></thead><tbody>%s</tbody></table>"
            % (_fmt(pl.get("landmark_radius_m")),
               (" " + esc(pl.get("landmark_note"))) if pl.get("landmark_note") else "",
               lm_rows))
    elif pl.get("landmark_error"):
        blocks.append(
            "<h3>Recognisable places nearby</h3>"
            "<div class=\"callout warn\">The wider landmark sweep did not "
            "return. This is a failed lookup, not a finding: it does not mean "
            "there are no landmarks nearby. %s</div>"
            % esc(pl.get("landmark_error")))

    if place_rows:
        cats = pl.get("by_category") or {}
        summary = ""
        if cats:
            summary = ("<div class=\"chips\">%s</div>" % "".join(
                "<span><b>%d</b> %s</span>" % (n, esc(c))
                for c, n in cats.items()))
        blocks.append(
            "<h3>Everything within %s m</h3>"
            "<p class=\"prose small\">%s feature(s) were found and classified; "
            "the nearest %d are listed.</p>%s"
            "<table class=\"data\"><thead><tr><th>Name</th><th>Category</th>"
            "<th>Type</th><th class=\"num\">Distance</th><th>Bearing</th>"
            "<th>Address</th></tr></thead><tbody>%s</tbody></table>"
            % (_fmt(pl.get("radius_m")), _fmt(pl.get("total_found"), dash="0"),
               min(40, len(places)), summary, place_rows))
    if vend_rows:
        blocks.append(
            "<h3>Hardware attribution</h3><table class=\"data\"><thead><tr>"
            "<th>BSSID</th><th>Vendor</th><th>Source</th><th>Address type</th>"
            "</tr></thead><tbody>%s</tbody></table>" % vend_rows)
    if day_rows:
        blocks.append(
            "<h3>Daylight at this position</h3>"
            "<p class=\"prose small\">Relevant when correlating a wireless "
            "observation against imagery, CCTV or witness accounts of light "
            "conditions.</p><table class=\"kv\">%s</table>" % day_rows)

    return """
<section class="sec page-break">
  <h2><span class="n">##</span> Location intelligence</h2>
  %s
</section>""" % "".join(blocks)


def _survey(doc) -> str:
    survey = doc.get("survey") or {}
    beacons = survey.get("beacons") or []
    if not beacons:
        return ""
    targets = set((doc.get("target") or {}).get("bssids") or [])
    rows = "".join(
        "<tr class=\"%s\"><td class=\"mono\">%s</td><td>%s</td>"
        "<td class=\"num\">%s</td><td class=\"num\">%s</td><td>%s</td>"
        "<td>%s</td><td>%s</td></tr>"
        % ("hit" if b["bssid"] in targets else "",
           esc(b["bssid"]),
           "<em>hidden</em>" if b.get("hidden") else esc(b["ssid"]),
           _fmt(b.get("rssi_dbm")), _fmt(b.get("channel")),
           esc(b.get("band")), esc(b.get("phy")),
           "yes" if b.get("privacy") else ("no" if b.get("privacy") is False else "&mdash;"))
        for b in beacons)

    warn = ""
    if survey.get("warnings"):
        warn = "<div class=\"callout warn\">%s</div>" % "<br>".join(
            esc(w) for w in survey["warnings"])

    return """
<section class="sec page-break">
  <h2><span class="n">##</span> Radio survey</h2>
  <div class="method-note">Collection method: %s. Active scan: %s. Rows matching
  the target are highlighted.</div>
  %s
  <table class="data">
    <thead><tr><th>BSSID</th><th>SSID</th><th class="num">RSSI dBm</th>
    <th class="num">Ch</th><th>Band</th><th>PHY</th><th>Encrypted</th></tr></thead>
    <tbody>%s</tbody>
  </table>
</section>""" % (esc(survey.get("method")),
                 "yes" if survey.get("active_scan") else "no (cached list)",
                 warn, rows)


def _custody(doc, meta) -> str:
    ev = doc.get("evidence") or {}
    exchanges = meta.get("exchanges") or []
    rows = "".join(
        "<tr><td class=\"num mono\">%04d</td><td>%s</td><td class=\"mono url\">%s</td>"
        "<td class=\"num\">%s</td><td class=\"num\">%s</td>"
        "<td class=\"mono hash\">%s</td></tr>"
        % (e.get("seq", 0), esc(e.get("label")), esc(e.get("url")),
           _fmt(e.get("status")), _fmt(e.get("response_bytes_wire")),
           esc(e.get("response_sha256_wire") or ""))
        for e in exchanges)

    return """
<section class="sec page-break">
  <h2><span class="n">##</span> Chain of custody</h2>
  <p class="prose">Every network transaction performed during this examination
  was captured in full &mdash; request headers, request body, response headers
  and the response body exactly as received on the wire &mdash; and written to
  the evidence package before analysis. The table lists each transaction with a
  truncated SHA-256 of its response; full-length hashes for every file are in
  <span class="mono">manifest.json</span>.</p>
  <table class="kv">
    <tr><th>Evidence package</th><td class="mono">%s</td></tr>
    <tr><th>Package size</th><td>%s bytes</td></tr>
    <tr><th>Package SHA-256</th><td class="mono hash">%s</td></tr>
    <tr><th>Manifest root hash</th><td class="mono hash">%s</td></tr>
    <tr><th>Files covered</th><td>%s</td></tr>
    <tr><th>Verification</th><td>Inside the extracted case directory run
        <span class="mono">python3 verify_evidence.py</span> on Linux or macOS,
        or <span class="mono">py verify_evidence.py</span> on Windows.</td></tr>
  </table>
  <table class="data small">
    <thead><tr><th class="num">Seq</th><th>Transaction</th><th>Endpoint</th>
    <th class="num">HTTP</th><th class="num">Bytes</th>
    <th>Response SHA-256 (truncated)</th></tr></thead>
    <tbody>%s</tbody>
  </table>
</section>""" % (
        esc((ev.get("zip_path") or "").split("\\")[-1].split("/")[-1]),
        _fmt(ev.get("zip_bytes")), esc(ev.get("zip_sha256")),
        esc(ev.get("root_hash")), _fmt(ev.get("file_count")), rows)


def _limitations() -> str:
    return """
<section class="sec">
  <h2><span class="n">##</span> Limitations and caveats</h2>
  <ol class="caveats">
    <li><strong>These positions are not measurements made by this tool.</strong>
      They are records held in third-party crowd-sourced databases, describing
      where contributing devices observed an access point at some earlier,
      unstated time.</li>
    <li><strong>Access points move.</strong> A router carried to a new address,
      a mobile hotspot, or a device in a vehicle will continue to return its
      previously recorded position until the database is updated. There is no
      timestamp in either provider's response to detect this.</li>
    <li><strong>Randomised and locally administered addresses are not unique.</strong>
      Two unrelated devices can present the same address, and a database record
      may therefore describe a different device entirely. Any such address is
      flagged in this report and excluded from anchoring where alternatives
      exist.</li>
    <li><strong>Absence is not proof of absence.</strong> An access point with
      no database record has simply never been reported by a contributing
      device.</li>
    <li><strong>BSSIDs can be forged.</strong> Nothing prevents an access point
      from advertising an arbitrary address, so a hit can be induced
      deliberately.</li>
    <li><strong>Stated accuracy is the provider's own claim</strong> and is not
      independently validated. It generally describes the spread of contributing
      observations, not a guaranteed error bound.</li>
    <li><strong>Corroboration between providers is not proof.</strong> Both
      draw on overlapping populations of contributing devices; agreement raises
      confidence but does not establish ground truth.</li>
    <li>Findings here are investigative leads. They should be corroborated by
      independent means before being relied upon.</li>
  </ol>
</section>"""


def _footer(doc, meta) -> str:
    env = meta.get("environment") or {}
    return """
<footer class="foot">
  <div class="foot-grid">
    <div><span class="lbl">Tool</span>%s v%s</div>
    <div><span class="lbl">Runtime</span>Python %s on %s</div>
    <div><span class="lbl">Host</span>%s</div>
    <div><span class="lbl">Operator</span>%s</div>
    <div><span class="lbl">Case opened (UTC)</span><span class="mono">%s</span></div>
    <div><span class="lbl">Case sealed (UTC)</span><span class="mono">%s</span></div>
  </div>
  <p class="fine">This report was generated automatically from the data in the
  accompanying evidence package. Every figure in it can be re-derived from the
  raw exhibits. Produced using only credential-free public services and
  OpenStreetMap open data.</p>
</footer>
</div></body></html>""" % (
        esc(TOOL_NAME), esc(__version__), esc(env.get("python")),
        esc(env.get("os")), esc(env.get("hostname")), esc(env.get("user")),
        esc(meta.get("opened_utc")), esc(meta.get("sealed_utc")))


# ==========================================================================
CSS = """
:root{
  --ink:#10151c; --ink-2:#39424f; --ink-3:#6b7686; --line:#dfe4ec;
  --bg:#f4f6fa; --card:#ffffff; --accent:#0f5fa8; --accent-2:#0a4278;
  --ok:#12805c; --warn:#b3690a; --bad:#b3261e; --na:#8892a2;
  --mono:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:14px;line-height:1.62;-webkit-font-smoothing:antialiased}
.sheet{max-width:1080px;margin:0 auto;background:var(--card);
  box-shadow:0 1px 3px rgba(16,21,28,.08),0 12px 40px rgba(16,21,28,.06)}
.mono{font-family:var(--mono);font-size:.93em;font-variant-ligatures:none}
.small{font-size:12.5px}
.num{text-align:right;font-variant-numeric:tabular-nums}

/* ---------- cover ---------- */
.cover{padding:44px 56px 36px;background:
  linear-gradient(160deg,#0d1b2a 0%,#132b45 48%,#0f5fa8 140%);color:#fff}
.brand{display:flex;align-items:center;gap:14px;margin-bottom:38px}
.mark{width:44px;height:44px;flex:none;display:block}
.brand-name{font-size:19px;font-weight:680;letter-spacing:.16em}
.brand-sub{font-size:11.5px;color:#a9c4de;letter-spacing:.05em}
.classification{margin-left:auto;font-size:10.5px;letter-spacing:.14em;
  border:1px solid rgba(255,255,255,.34);padding:5px 11px;border-radius:3px;
  color:#cfe1f2}
.cover h1{font-size:38px;line-height:1.14;margin:0 0 30px;font-weight:640;
  letter-spacing:-.022em}
.cover-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px 26px;
  padding-bottom:26px;border-bottom:1px solid rgba(255,255,255,.16)}
.cover-grid .lbl,.headline .lbl,.foot .lbl{display:block;font-size:10.5px;
  text-transform:uppercase;letter-spacing:.1em;color:#8fb0cf;margin-bottom:3px}
.cover-grid .val{font-size:14px;color:#eaf2f9}

.redacted-banner{margin:22px 0 0;padding:13px 17px;border-radius:7px;
  background:rgba(255,193,7,.16);border:1px solid rgba(255,193,7,.45);
  display:flex;flex-direction:column;gap:5px}
.redacted-banner strong{font-size:12px;letter-spacing:.14em;color:#ffd54f}
.redacted-banner span{font-size:12px;color:#e8eef5;line-height:1.55}
.verdict-card{margin:26px 0 22px;padding:20px 24px;border-radius:8px;
  display:flex;align-items:center;gap:26px;
  background:rgba(255,255,255,.07);border-left:4px solid var(--na)}
.verdict-card.v-strong{border-left-color:#2ecc8f}
.verdict-card.v-good{border-left-color:#6fd08c}
.verdict-card.v-mid{border-left-color:#e8b53d}
.verdict-card.v-low{border-left-color:#e88b3d}
.verdict-card.v-none{border-left-color:#e05a52}
.verdict-left{flex:1}
.verdict-label{font-size:10.5px;text-transform:uppercase;letter-spacing:.1em;
  color:#8fb0cf}
.verdict-name{font-size:25px;font-weight:660;letter-spacing:-.01em;margin:2px 0 5px}
.verdict-text{font-size:13px;color:#cfe1f2;max-width:56ch}
.verdict-right{text-align:center;flex:none}
.score-ring{width:82px;height:82px;border-radius:50%;display:flex;
  flex-direction:column;align-items:center;justify-content:center;
  background:conic-gradient(#6fb4f2 calc(var(--pct)*1%),rgba(255,255,255,.14) 0);
  position:relative}
.score-ring::before{content:"";position:absolute;inset:6px;border-radius:50%;
  background:#122438}
.score-num{position:relative;font-size:25px;font-weight:680;line-height:1}
.score-den{position:relative;font-size:10.5px;color:#9fc0dd}
.coverage{font-size:10.5px;color:#8fb0cf;margin-top:7px}

.headline{display:grid;grid-template-columns:2fr 1fr 1fr;gap:22px;
  padding-top:20px;border-top:1px solid rgba(255,255,255,.16)}
.headline .big{font-size:17px;font-weight:600;color:#fff}
.printer{margin-top:24px;background:#6fb4f2;color:#0d1b2a;border:0;
  padding:9px 17px;border-radius:5px;font-size:13px;font-weight:600;
  cursor:pointer;font-family:inherit}
.printer:hover{background:#8cc5f7}

/* ---------- sections ---------- */
.sec{padding:34px 56px;border-bottom:1px solid var(--line)}
.sec h2{font-size:12.5px;text-transform:uppercase;letter-spacing:.13em;
  color:var(--accent-2);margin:0 0 18px;display:flex;align-items:center;gap:11px}
.sec h2 .n{background:var(--accent);color:#fff;width:24px;height:24px;
  border-radius:4px;display:inline-flex;align-items:center;justify-content:center;
  font-size:11px;letter-spacing:0}
.sec h3{font-size:15px;margin:26px 0 11px;font-weight:640;color:var(--ink)}
.sec h3:first-of-type{margin-top:4px}
.prose p{margin:0 0 11px;max-width:78ch;color:var(--ink-2)}
.method-note{font-size:12.5px;color:var(--ink-3);margin-bottom:14px;max-width:82ch}

.callout{background:#eef4fb;border-left:3px solid var(--accent);
  padding:11px 15px;margin:0 0 16px;font-size:13px;color:var(--ink-2);
  border-radius:0 4px 4px 0}
.callout.warn{background:#fdf5e8;border-left-color:var(--warn)}
.callout.bad{background:#fdeeed;border-left-color:var(--bad)}

/* ---------- tables ---------- */
table{width:100%;border-collapse:collapse;font-size:13px}
.kv th{text-align:left;font-weight:560;color:var(--ink-3);width:36%;
  padding:7px 14px 7px 0;vertical-align:top;border-bottom:1px solid var(--line);
  font-size:12.5px}
.kv td{padding:7px 0;border-bottom:1px solid var(--line);vertical-align:top}
.kv tr:last-child th,.kv tr:last-child td{border-bottom:0}

.data thead th{text-align:left;font-size:10.5px;text-transform:uppercase;
  letter-spacing:.07em;color:var(--ink-3);padding:0 10px 7px 0;
  border-bottom:1.5px solid var(--line);font-weight:600}
.data td{padding:6px 10px 6px 0;border-bottom:1px solid #eef1f6}
.data tbody tr:hover{background:#f7f9fc}
.data tr.hit{background:#eef6ff}
.data tr.hit td:first-child{box-shadow:inset 3px 0 0 var(--accent)}
.data .kind{color:var(--ink-3);text-transform:capitalize}
.url{word-break:break-all;font-size:11px;color:var(--ink-3);max-width:240px}
.hash{font-size:10px;color:var(--ink-3);word-break:break-all;max-width:300px}
.raw{font-size:10.5px;color:var(--ink-3);word-break:break-all;max-width:220px}

/* ---------- signals ---------- */
.signals thead th{text-align:left;font-size:10.5px;text-transform:uppercase;
  letter-spacing:.07em;color:var(--ink-3);padding-bottom:8px;
  border-bottom:1.5px solid var(--line)}
.signals td{padding:11px 0;border-bottom:1px solid #eef1f6;vertical-align:top}
.signals .sig{font-weight:560;padding-right:22px}
.signals .det{font-weight:400;color:var(--ink-3);font-size:12.5px;
  margin-top:3px;max-width:60ch}
.barcell{width:150px;padding-right:18px!important}
.bar{height:6px;border-radius:3px;background:#e8ecf3;overflow:hidden;margin-top:5px}
.bar span{display:block;height:100%;border-radius:3px;background:var(--na)}
.bar.ok span{background:var(--ok)} .bar.warn span{background:var(--warn)}
.bar.bad span{background:var(--bad)} .bar.na span{background:#c8cfda}
.bar.pen span{background:var(--bad)}
.signals tr.na .sig{color:var(--ink-3)}
.signals tfoot th{padding-top:12px;font-size:13px;text-align:left}
.signals tfoot th.num{text-align:right;font-size:15px}

/* ---------- stats ---------- */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:18px}
.stats>div{background:#f7f9fc;border:1px solid var(--line);border-radius:6px;
  padding:13px 14px}
.s-num{display:block;font-size:20px;font-weight:660;letter-spacing:-.01em}
.s-lbl{display:block;font-size:11px;color:var(--ink-3);margin-top:2px}

/* ---------- map ---------- */
.mapwrap{position:relative;display:inline-block;border:1px solid var(--line);
  border-radius:8px;overflow:hidden;background:#e8eaed;max-width:100%}
.mapview{position:relative;overflow:hidden}
.tile{position:absolute;width:256px;height:256px;display:block}
.dot{position:absolute;border-radius:50%;transform:translate(-50%,-50%);
  box-shadow:0 0 0 1.5px rgba(255,255,255,.9)}
.dot.neigh{width:5px;height:5px;background:rgba(15,95,168,.5)}
.dot.target{width:11px;height:11px;background:#0f5fa8;
  box-shadow:0 0 0 2px #fff,0 1px 3px rgba(0,0,0,.4)}
.dot.msft{width:11px;height:11px;background:#b3690a;
  box-shadow:0 0 0 2px #fff,0 1px 3px rgba(0,0,0,.4)}
.acc{position:absolute;border-radius:50%;background:rgba(15,95,168,.12);
  border:1.5px solid rgba(15,95,168,.5)}
.pin{position:absolute;width:17px;height:17px;border-radius:50% 50% 50% 0;
  background:#b3261e;transform:translate(-50%,-100%) rotate(-45deg);
  box-shadow:0 0 0 2.5px #fff,0 2px 5px rgba(0,0,0,.45)}
.scalebar{position:absolute;left:12px;bottom:12px;background:rgba(255,255,255,.9);
  padding:4px 8px;border-radius:3px;font-size:10.5px;display:flex;
  align-items:center;gap:7px;color:var(--ink-2)}
.scalebar span{display:block;height:3px;background:var(--ink);border-radius:1px}
.scalebar em{font-style:normal}
.legend{display:flex;flex-wrap:wrap;gap:18px;margin-top:13px;font-size:12px;
  color:var(--ink-2)}
.legend span{display:flex;align-items:center;gap:6px}
.legend i{width:11px;height:11px;border-radius:50%;display:block;flex:none}
.k-pin{background:#b3261e;border-radius:50% 50% 50% 0!important;
  transform:rotate(-45deg)}
.k-target{background:#0f5fa8}.k-msft{background:#b3690a}
.k-neigh{background:rgba(15,95,168,.5);width:6px!important;height:6px!important}
.k-acc{background:rgba(15,95,168,.14);border:1.5px solid rgba(15,95,168,.5)}
.attrib{font-size:11px;color:var(--ink-3);margin-top:11px;max-width:80ch}

/* ---------- anomalies ---------- */
.anomalies{list-style:none;padding:0;margin:0}
.anomalies li{border:1px solid #f0d9d7;background:#fdf7f6;border-radius:6px;
  padding:14px 17px;margin-bottom:11px}
.anom-head{display:flex;align-items:center;gap:12px;margin-bottom:7px}
.anomalies p{margin:0 0 6px;font-size:13px;color:var(--ink-2);max-width:78ch}
.badge{font-size:11px;padding:2px 9px;border-radius:11px;font-weight:600}
.badge.bad{background:#fbe3e1;color:var(--bad)}
.badge.note{background:#e6f0fb;color:var(--accent);font-weight:600}
.chips{display:flex;flex-wrap:wrap;gap:7px;margin:0 0 13px}
.chips span{font-size:11.5px;background:#f2f5f9;border:1px solid var(--line);
  border-radius:20px;padding:3px 11px;color:var(--ink-2)}
.chips b{color:var(--ink);font-weight:660}

/* ---------- inputs & requests ---------- */
.maclist{display:flex;flex-wrap:wrap;gap:4px}
.maclist span{font-family:var(--mono);font-size:10.5px;background:#f2f5f9;
  border:1px solid var(--line);border-radius:3px;padding:1px 5px;
  color:var(--ink-2);white-space:nowrap}
.reqs td{vertical-align:top;padding-top:10px;padding-bottom:10px}
.reqs .svc{font-weight:600;padding-right:18px;min-width:150px}
.reqs td:nth-child(2){max-width:250px;color:var(--ink-2)}
.reqs td:nth-child(3){max-width:290px}
.reqs td:nth-child(4){max-width:190px}
.kv td em{color:var(--ink-3);font-style:italic;font-size:12px}

.place-addr{font-size:13.5px;color:var(--ink,#0f172a);margin:2px 0 4px}
  .placesmap{margin:14px 0 6px}.placesmap svg{max-width:100%;height:auto;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px}.pm-num{font:600 9.5px var(--sans);fill:#fff;text-anchor:middle}.pm-lbl{font:500 10.5px var(--sans);fill:#334155;text-anchor:middle}.pm-bar{stroke:#94a3b8;stroke-width:2}.pm-tick{font:9.5px var(--mono);fill:#94a3b8}
  .timeline{margin:14px 0 18px}.timeline svg{max-width:100%;height:auto}.tl-lbl{font:500 11px var(--sans);fill:#334155;text-anchor:end}.tl-tick{font:10px var(--mono);fill:#94a3b8;text-anchor:middle}.tl-grid{stroke:#e2e8f0;stroke-width:1}
  .maplinks{font-size:12px;color:var(--muted);margin:6px 0 10px}.maplinks a{color:var(--accent);text-decoration:none}.maplinks a:hover{text-decoration:underline}
  .links{list-style:none;padding:0;margin:0 0 10px}
.links li{display:flex;align-items:baseline;gap:12px;padding:6px 0;
  border-bottom:1px solid #eef1f6;flex-wrap:wrap}
.links a{color:var(--accent);font-weight:560;text-decoration:none;
  white-space:nowrap}
.links a:hover{text-decoration:underline}
.links span{font-size:10.5px;color:var(--ink-3);word-break:break-all}

.caveats{margin:0;padding-left:20px;max-width:80ch}
.caveats li{margin-bottom:9px;color:var(--ink-2)}
.caveats strong{color:var(--ink)}

/* ---------- footer ---------- */
.foot{padding:26px 56px 34px;background:#f7f9fc}
.foot-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:13px 26px;
  font-size:12.5px;color:var(--ink-2)}
.foot .lbl{color:var(--ink-3)}
.fine{margin:20px 0 0;font-size:11.5px;color:var(--ink-3);max-width:84ch}

/* ---------- print ---------- */
@media print{
  @page{size:A4;margin:13mm 12mm}
  body{background:#fff;font-size:10.5pt}
  .sheet{max-width:none;box-shadow:none}
  .no-print{display:none!important}
  .cover{padding:0 0 18px;background:#fff!important;color:var(--ink)!important;
    -webkit-print-color-adjust:exact;print-color-adjust:exact}
  .cover h1{font-size:26pt;color:var(--ink)}
  .brand-name,.headline .big{color:var(--ink)}
  .brand-sub,.cover-grid .lbl,.headline .lbl,.verdict-label,.coverage,
  .verdict-text{color:#5a6675!important}
  .cover-grid .val{color:var(--ink)}
  .classification{color:var(--ink);border-color:#b9c2cf}
  .cover-grid,.headline{border-color:var(--line)}
  .verdict-card{background:#f4f6fa!important;color:var(--ink)}
  .score-ring::before{background:#f4f6fa}
  .sec,.foot{padding-left:0;padding-right:0}
  .page-break{break-before:page}
  .sec,.stats>div,.anomalies li,table{break-inside:avoid}
  tr{break-inside:avoid}
  .mapwrap{border-color:#c9d1dc}
  a{color:inherit;text-decoration:none}
}
@media (max-width:820px){
  .cover,.sec,.foot{padding-left:22px;padding-right:22px}
  .cover-grid,.headline,.foot-grid{grid-template-columns:1fr 1fr}
  .stats{grid-template-columns:repeat(2,1fr)}
  .verdict-card{flex-direction:column;align-items:flex-start}
}
"""
