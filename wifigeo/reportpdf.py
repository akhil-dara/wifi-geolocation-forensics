"""
The forensic report as a real PDF.

The HTML report remains the richer document; this is the version that goes into
a bundle, an exhibit list or an email without depending on anyone's browser
print settings.
"""

from __future__ import annotations

from typing import Dict, Optional, Sequence, Tuple

from . import TOOL_NAME, __version__, fmt, mapimage, pdf, png

M = 46.0                       # page margin, points
INK = (0.06, 0.08, 0.11)
BODY = (0.22, 0.26, 0.31)
MUTED = (0.42, 0.46, 0.52)
ACCENT = (0.06, 0.37, 0.66)
OK = (0.07, 0.50, 0.36)
WARN = (0.70, 0.41, 0.04)
BAD = (0.70, 0.15, 0.12)
RULE = (0.87, 0.89, 0.93)
PANEL = (0.968, 0.976, 0.988)


class Writer:
    """A page cursor that knows how to break pages."""

    def __init__(self, doc: pdf.PDF, footer: str):
        self.doc = doc
        self.footer = footer
        self.page: Optional[pdf.Page] = None
        self.y = 0.0
        self.n = 0
        self.new_page()

    @property
    def width(self) -> float:
        return self.doc.size[0] - 2 * M

    def new_page(self) -> None:
        self.page = self.doc.add_page()
        self.n += 1
        self.y = M
        h = self.doc.size[1]
        self.page.line(M, h - 30, self.doc.size[0] - M, h - 30, RULE, 0.5)
        self.page.text(M, h - 20, self.footer, 7.5, colour=MUTED)
        self.page.text(self.doc.size[0] - M - 40, h - 20, "Page %d" % self.n,
                       7.5, colour=MUTED)

    def need(self, space: float) -> None:
        if self.y + space > self.doc.size[1] - 52:
            self.new_page()

    def gap(self, h: float) -> None:
        self.y += h

    def heading(self, s: str, size: float = 13.5) -> None:
        self.need(size + 22)
        self.gap(10)
        self.page.text(M, self.y + size, s, size, bold=True, colour=INK)
        self.y += size + 6
        self.page.line(M, self.y, M + self.width, self.y, RULE, 0.8)
        self.y += 10

    def sub(self, s: str) -> None:
        self.need(24)
        self.gap(8)
        self.page.text(M, self.y + 9.5, s, 9.5, bold=True, colour=ACCENT)
        self.y += 17

    def para(self, s: str, size: float = 9, colour=BODY,
             indent: float = 0.0) -> None:
        for line in pdf.wrap(s, size, self.width - indent):
            self.need(size + 4)
            self.page.text(M + indent, self.y + size, line, size, colour=colour)
            self.y += size + 3.4
        self.y += 3

    def kv(self, rows: Sequence[Tuple[str, str]], key_w: float = 150.0,
           size: float = 9) -> None:
        for key, value in rows:
            if value in (None, ""):
                continue
            lines = pdf.wrap(str(value), size, self.width - key_w - 8)
            self.need(len(lines) * (size + 3) + 6)
            self.page.text(M, self.y + size, str(key), size, colour=MUTED)
            for i, line in enumerate(lines):
                if i:
                    self.need(size + 3)
                self.page.text(M + key_w, self.y + size, line, size, colour=INK)
                self.y += size + 3
            self.y += 2.5

    def table(self, headers: Sequence[str], widths: Sequence[float],
              rows: Sequence[Sequence[str]], size: float = 7.8,
              highlight: Optional[Sequence[bool]] = None) -> None:
        self.need(26)
        x = M
        for head, w in zip(headers, widths):
            self.page.text(x, self.y + size, str(head), size, bold=True,
                           colour=MUTED)
            x += w
        self.y += size + 4
        self.page.line(M, self.y, M + sum(widths), self.y, RULE, 0.8)
        self.y += 5

        for i, row in enumerate(rows):
            cells = [pdf.wrap(str(c), size, w - 6) for c, w in zip(row, widths)]
            height = max(len(c) for c in cells) * (size + 2.4) + 3
            self.need(height + 2)
            if highlight and i < len(highlight) and highlight[i]:
                self.page.rect(M - 3, self.y - 2, sum(widths) + 6, height,
                               (0.93, 0.96, 1.0))
            x = M
            for cell, w in zip(cells, widths):
                yy = self.y
                for line in cell:
                    self.page.text(x, yy + size, line, size, colour=INK)
                    yy += size + 2.4
                x += w
            self.y += height
            self.page.line(M, self.y - 1, M + sum(widths), self.y - 1,
                           (0.94, 0.95, 0.97), 0.4)
        self.y += 6


def _fmt(value, dash: str = "-") -> str:
    """
    Quantities, via the shared formatter.

    This is a wrapper rather than a plain alias because `fmt.number` takes a
    suffix before the dash, while every call site here passes the dash second.
    Aliasing the two directly turned a score of 97.8 into "97.80" - the dash
    was being appended as a suffix.
    """
    return fmt.number(value, dash=dash)


def render(doc: Dict[str, object], meta: Dict[str, object]) -> bytes:
    case_id = str(doc.get("case_id", ""))
    # Coordinates are written at the precision this document actually holds.
    # A redacted report keeps two decimal places; padding that out to eight
    # discloses nothing but reads as full precision.
    cdp = fmt.places(doc)
    out = pdf.PDF(title="WiFi Geolocation Forensics report %s" % case_id,
                  author=str(meta.get("examiner") or ""))
    w = Writer(out, "WiFi Geolocation Forensics  |  %s  |  %s"
               % (case_id, doc.get("completed_utc")))
    page_w = out.size[0]

    val = doc.get("validation") or {}
    pos = doc.get("position")
    co = doc.get("coordinates") or {}
    tgt = doc.get("target") or {}

    # ---------------- cover ----------------
    p = w.page
    p.rect(0, 0, page_w, 118, (0.05, 0.11, 0.17))
    p.text(M, 46, "WiFi Geolocation Forensics", 17, bold=True, colour=(1, 1, 1))
    p.text(M, 62, "Independent cross-validated positioning", 9,
           colour=(0.66, 0.77, 0.87))
    p.text(M, 88, "Access Point Geolocation Report", 15, bold=True,
           colour=(1, 1, 1))
    p.text(M, 106, "FOR INVESTIGATIVE USE", 8, colour=(0.66, 0.77, 0.87))
    w.y = 148

    verdict = str(val.get("verdict") or "UNRESOLVED")
    vcol = fmt.verdict_rgb(verdict)
    w.page.rect(M, w.y, w.width, 46, PANEL)
    w.page.rect(M, w.y, 3.5, 46, vcol)
    w.page.text(M + 14, w.y + 18, verdict, 15, bold=True, colour=vcol)
    w.page.text(M + 14, w.y + 34, "%s / 100   |   %s%% of checks performed"
                % (_fmt(val.get("score"), "0"), _fmt(val.get("coverage"), "0")),
                8.5, colour=MUTED)
    w.y += 58
    w.para(str(val.get("verdict_statement") or ""), 9)

    # A redacted copy must say so on its own face, before anything else it
    # asserts. This is the document that leaves the investigation, and a reader
    # who does not know the coordinates were truncated will read them as
    # precise - and may quote them as such. The HTML has carried this banner
    # from the start; the PDF silently did not, which is worse than either,
    # because the two claim to be the same report.
    if doc.get("redacted"):
        note = str(doc.get("redaction_note") or "This report has been redacted.")
        lines = pdf.wrap(note, 8, w.width - 28)
        height = 22 + 11 * len(lines)
        w.need(height + 10)
        w.page.rect(M, w.y, w.width, height, (1.0, 0.97, 0.86))
        w.page.rect(M, w.y, 3.5, height, (0.85, 0.62, 0.11))
        w.page.text(M + 14, w.y + 15, "REDACTED COPY", 9.5, bold=True,
                    colour=(0.55, 0.38, 0.03))
        for i, line in enumerate(lines):
            w.page.text(M + 14, w.y + 28 + 11 * i, line, 8,
                        colour=(0.35, 0.26, 0.05))
        w.y += height + 12

    w.kv([
        ("Case reference", case_id),
        ("Examiner", meta.get("examiner")),
        ("Organisation", meta.get("organisation")),
        ("Your reference", meta.get("reference")),
        ("Target", tgt.get("ssid") or tgt.get("input")),
        ("Report generated (UTC)", doc.get("completed_utc")),
    ])

    # ---------------- executive summary ----------------
    # Shared with the HTML renderer rather than written twice: this is the part
    # of the report most likely to be read alone and quoted, so the two must not
    # be able to say different things. The PDF cannot set bold mid-line, so the
    # emphasis markers are stripped.
    w.heading("Executive summary")
    for line in fmt.summary_lines(doc):
        w.para(fmt.strip_emphasis(line), 9)

    # ---------------- position ----------------
    if pos:
        w.heading("Position")
        w.para("%s. Stated accuracy plus or minus %s metres."
               % (pos.get("method"), _fmt(pos.get("accuracy_m"))))
        w.kv([
            ("Decimal degrees", co.get("decimal_precise")),
            ("Deg / min / sec", co.get("dms")),
            ("Plus Code", co.get("plus_code")),
            ("MGRS", co.get("mgrs")),
            ("UTM", co.get("utm")),
            ("Geohash", co.get("geohash")),
        ])
        addr = (doc.get("enrichment") or {}).get("address") or {}
        if addr.get("display_name"):
            w.kv([("Address", addr["display_name"])])
        lat, lon = pos["latitude"], pos["longitude"]
        # Write the link at the precision the document actually holds. In a
        # redacted report the value is truncated to two decimal places;
        # printing it as 51.50000000 discloses nothing but reads as
        # eight-decimal precision, which invites the reader to conclude the
        # redaction failed.
        w.sub("Open this position")
        for name, url in fmt.map_links(lat, lon, cdp):
            w.para("%s  %s" % (name, url), 8, MUTED)
    else:
        w.heading("Position")
        w.para("No position was established. %s" % (doc.get("failure") or ""))

    # ---------------- map ----------------
    src_map = doc.get("export_map") or doc.get("static_map")
    if src_map and pos:
        try:
            raster = mapimage.render_png(doc, src_map, scale=1)
            iw, ih, rgb = png.decode(raster)
            w.new_page()
            w.heading("Map")
            avail_w = w.width
            avail_h = out.size[1] - w.y - 70
            ratio = min(avail_w / iw, avail_h / ih)
            w.page.image("MAP", M, w.y, iw * ratio, ih * ratio)
            out.add_image("MAP", iw, ih, rgb)
            w.y += ih * ratio + 10
            w.para("Imagery: %s. Tiles were retrieved at examination time."
                   % src_map.get("attribution", ""), 7.5, MUTED)
        except Exception:
            pass

    # ---------------- inputs ----------------
    w.heading("Inputs and requests")
    w.kv([
        ("Target as entered", tgt.get("input") or "(supplied as addresses)"),
        ("Network name", tgt.get("ssid") or "not known"),
        ("Addresses queried", ", ".join(tgt.get("bssids") or [])),
        ("Radio scan", "performed" if (doc.get("survey") or {}).get("active_scan")
         else "not performed - the radio was not touched"),
    ])

    ap = doc.get("apple") or {}
    ms = (doc.get("microsoft") or {}).get("result") or {}
    rep = doc.get("microsoft_replicates") or {}
    per = doc.get("microsoft_per_ap") or {}
    rows = []
    if ap:
        rows.append(["Apple Location Services",
                     "%s address(es), up to %s neighbours"
                     % (len(tgt.get("bssids") or []),
                        _fmt(ap.get("neighbours_requested"))),
                     "%s returned, %s positioned"
                     % (_fmt(ap.get("total_returned")),
                        _fmt(ap.get("total_located")))])
    if ms:
        outcome = ("%s +/-%s m" % (fmt.pair(ms["latitude"], ms["longitude"], cdp),
                                   _fmt(ms.get("radial_uncertainty_m")))
                   if ms.get("located") else
                   "no Wi-Fi match; IP-derived answer discarded"
                   if ms.get("ip_fallback") else "no position")
        rows.append(["Microsoft - observed fingerprint",
                     "the access points actually observed", outcome])
    if rep:
        rows.append(["Microsoft - replicate probes",
                     "%d disjoint groups (not observations)"
                     % rep.get("groups_submitted", 0),
                     "%d resolved, agreeing within %s m"
                     % (rep.get("groups_resolved", 0),
                        _fmt(rep.get("max_separation_m")))])
    if per:
        rows.append(["Microsoft - per access point",
                     "%s single-address queries" % _fmt(per.get("queried")),
                     "%s held by both; %s IP-fallbacks discarded"
                     % (_fmt(per.get("known_to_microsoft")),
                        _fmt(per.get("discarded_ip_fallback")))])
    if rows:
        w.sub("What was sent, and to whom")
        w.table(["Service", "What was asked", "Outcome"],
                [150, 175, 178], rows)

    # ---------------- confidence ----------------
    w.heading("Confidence assessment")
    w.para("Each check below was applied independently. Checks that could not "
           "be performed are excluded from the calculation rather than counted "
           "as failures.")
    sig_rows, hl = [], []
    for s in val.get("signals") or []:
        sig_rows.append([s["name"],
                         "not run" if s.get("available") is False
                         else "%.1f / %.0f" % (s["awarded"], s["weight"]),
                         s["detail"]])
        hl.append(s.get("status") == "pass")
    for s in val.get("penalties") or []:
        sig_rows.append([s["name"], "%+.1f" % s["awarded"], s["detail"]])
        hl.append(False)
    if sig_rows:
        w.table(["Check", "Contribution", "Result"], [150, 62, 291], sig_rows,
                highlight=hl)

    # ---------------- anomalies ----------------
    cols = doc.get("collisions") or []
    if cols:
        w.heading("Anomalies and excluded records")
        for c in cols:
            w.sub("%s - excluded, %s km away" % (c["bssid"],
                                                 _fmt(c["distance_km"])))
            w.para(c["explanation"])

    # ---------------- intelligence ----------------
    enr = doc.get("enrichment") or {}
    places = enr.get("places") or {}
    lms = places.get("landmarks") or []
    if lms:
        w.heading("Location intelligence")
        w.para("Recognisable places near this position, ranked by prominence "
               "and spread across categories.")
        w.table(["Name", "Category", "Distance", "Bearing"],
                [250, 130, 60, 63],
                [[p["name"], p["category"], "%s m" % _fmt(p["distance_m"], "0"),
                  p["bearing"]] for p in lms[:22]])

    # ---------------- source detail ----------------
    # What each provider actually said, and the caveat that governs it. The PDF
    # printed the fused position without ever showing the two answers it came
    # from, which invites the reader to treat a single figure as if it were a
    # measurement.
    ap = doc.get("apple") or {}
    msr = (doc.get("microsoft") or {}).get("result") or {}
    if ap or msr:
        w.heading("Source detail")
        w.para("The two services are independent in both data and method. "
               "Apple is asked where a given access point is, and answers per "
               "access point. Microsoft is asked where a device that can see "
               "all of these access points would be, and answers with a single "
               "multilaterated position. Agreement between them is therefore "
               "corroboration rather than a restatement of one source.")
        if ap:
            w.sub("Apple Location Services")
            anchor = doc.get("anchor") or {}
            w.kv([
                ("Records returned", _fmt(ap.get("total_returned"))),
                ("Carrying positions", _fmt(ap.get("total_located"))),
                ("Queried addresses located", _fmt(ap.get("queried_located"))),
                ("Anchor position",
                 fmt.pair(anchor.get("latitude"), anchor.get("longitude"), cdp)
                 if anchor.get("latitude") is not None else "-"),
                ("Stated accuracy", "%s m" % _fmt(anchor.get("accuracy_m"))
                 if anchor.get("accuracy_m") is not None else "-"),
            ])
            if doc.get("anchor_note"):
                w.para(str(doc["anchor_note"]), 8, colour=MUTED)
        if msr:
            w.sub("Microsoft location inference")
            w.kv([
                ("Response status", msr.get("response_status")),
                ("Resolver status", msr.get("resolver_status")),
                ("Resolver source", msr.get("resolver_source")),
                ("Position",
                 fmt.pair(msr.get("latitude"), msr.get("longitude"), cdp)
                 if msr.get("latitude") is not None else "-"),
                ("Radial uncertainty", "%s m"
                 % _fmt(msr.get("radial_uncertainty_m"))),
                ("Crowd-sourcing level", msr.get("crowd_sourcing_level")),
                ("Beacons submitted", _fmt(msr.get("beacons_submitted"))),
                ("TrackingId echoed back",
                 "verified" if msr.get("tracking_id_verified")
                 else ("MISMATCH" if msr.get("tracking_id_verified") is False
                       else "not checked")),
                ("Usable as a position",
                 "yes" if msr.get("located") else "no"),
            ])
            if msr.get("ip_fallback"):
                # This caveat is the whole reason the figure above is not being
                # used. Printing the coordinates without it would be misleading.
                w.para("This answer was derived from the examining host's own "
                       "internet connection, not from the submitted beacons - "
                       "the service reports Source=\"IP\" and a radial "
                       "uncertainty far larger than any Wi-Fi fix. It describes "
                       "this connection rather than the target, and has been "
                       "excluded from the position and from the score.",
                       8.5, colour=(0.70, 0.15, 0.12))

    # ---------------- neighbouring access points ----------------
    cluster = doc.get("cluster") or {}
    if cluster.get("count"):
        w.heading("Neighbouring access-point analysis")
        w.para("Apple returns the access points it holds near the one queried. "
               "These were not observed together by this tool and are not "
               "treated as an observation; they describe the density and "
               "spread of the area around the target.")
        w.kv([
            ("Access points in the cloud", _fmt(cluster.get("count"))),
            ("Median distance from target", "%s m"
             % _fmt(cluster.get("median_distance_m"))),
            ("Spread (bounding box)", "%s m x %s m"
             % (_fmt(cluster.get("extent_ns_m")),
                _fmt(cluster.get("extent_ew_m")))),
            ("Density", "%s per km²" % _fmt(cluster.get("density_per_km2"))),
            ("Environment", cluster.get("environment_hint")),
        ])

    # ---------------- custody ----------------
    ev = doc.get("evidence") or {}
    w.heading("Chain of custody")
    w.para("Every network transaction was captured in full - request headers, "
           "request body, response headers and the response body exactly as "
           "received - and written to the evidence package before analysis.")
    w.kv([
        ("Evidence package",
         str(ev.get("zip_path", "")).replace("\\", "/").split("/")[-1]),
        ("Package size", "%s bytes" % _fmt(ev.get("zip_bytes"))),
        ("Package SHA-256", ev.get("zip_sha256")),
        ("Manifest root hash", ev.get("root_hash")),
        ("Files sealed", _fmt(ev.get("file_count"))),
        ("Verify with", "python3 verify_evidence.py  (py on Windows)"),
    ], key_w=118)

    # The transaction list itself. Without it the section asserted that every
    # exchange was captured and then showed none of them - the reader had to
    # take the claim on trust, which is precisely what a chain of custody is
    # supposed to remove. Hashes are printed in full: a truncated hash cannot
    # be checked against anything.
    exchanges = meta.get("exchanges") or []
    if exchanges:
        w.sub("Transactions captured (%d)" % len(exchanges))
        # The hash column is sized so a full SHA-256 sits on one line at 6.4pt
        # (227.7pt wide, measured). Wrapping a hash across two lines leaves it
        # complete but makes it materially harder to compare against another
        # copy by eye, which is the one thing it is printed for.
        widths = [22, 104, 30, 30, 42, 234]
        w.table(["#", "Exhibit", "Method", "Status", "Bytes", "Response SHA-256"],
                widths,
                [[str(x.get("seq")),
                  str(x.get("label") or "")[:26],
                  str(x.get("method") or ""),
                  str(x.get("status") or x.get("error") or "-")[:10],
                  _fmt(x.get("response_bytes_wire")),
                  str(x.get("response_sha256_wire") or "")]
                 for x in exchanges],
                size=6.4)
        w.para("Each exhibit directory holds the request headers and body, the "
               "response headers, and the response body exactly as it arrived "
               "on the wire, together with the SHA-256 of both directions. "
               "Hashes are shown in full so they can be checked.",
               8, colour=MUTED)

    # ---------------- limitations ----------------
    w.heading("Limitations and caveats")
    for i, text in enumerate([
        "These positions are not measurements made by this tool. They are "
        "records held in third-party crowd-sourced databases, describing where "
        "contributing devices observed an access point at some earlier, "
        "unstated time.",
        "Access points move. A relocated router or a mobile hotspot continues "
        "to return its previously recorded position until the database updates.",
        "Randomised and locally administered addresses are not unique. Two "
        "unrelated devices can present the same address, so a database record "
        "may describe a different device entirely.",
        "Absence is not proof of absence. An access point with no record has "
        "simply never been reported by a contributing device.",
        "BSSIDs can be forged, so a hit can be induced deliberately.",
        "Stated accuracy is the provider's own claim and is not independently "
        "validated.",
        "Corroboration between providers raises confidence but does not "
        "establish ground truth.",
        "Findings here are investigative leads and should be corroborated by "
        "independent means before being relied upon.",
    ], 1):
        w.para("%d.  %s" % (i, text), 8.5)

    env = meta.get("environment") or {}
    w.gap(8)
    w.para("Produced by %s v%s on Python %s, %s. Case opened %s, sealed %s. "
           "Only credential-free public services and OpenStreetMap open data "
           "were used."
           % (TOOL_NAME, __version__, env.get("python"), env.get("os"),
              meta.get("opened_utc"), meta.get("sealed_utc")), 7.5, MUTED)

    return out.build()
