"""
Formatting shared by the HTML and PDF reports.

The two renderers are deliberately separate - one emits markup, the other lays
out a page - but they present the same facts, and every fact they format the
same way should be formatted in one place.

This module exists because it was not. Coordinate precision was hard-coded as
`%.8f` in nine separate expressions across the two files. When a redacted
report needed two decimal places instead, the change had to be made in every
one of them, and three consecutive rounds of fixes each missed some. A redacted
report went out reading `51.50000000` - disclosing nothing, since the precision
really was gone, but looking exactly like a redaction that had failed.

Anything below is used by both renderers. Adding a third output format should
mean using these, not copying them.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

#: Decimal places for a coordinate in an ordinary report. Eight is what the
#: providers return, so it is what is reproduced.
FULL_PLACES = 8

#: Decimal places once redacted. Two is roughly a kilometre: it names a
#: district without naming a building.
REDACTED_PLACES = 2


def places(doc: Dict[str, object]) -> int:
    """How many decimal places this document is entitled to print."""
    return REDACTED_PLACES if doc.get("redacted") else FULL_PLACES


def coord(value: Optional[float], dp: int = FULL_PLACES,
          dash: str = "-") -> str:
    """One coordinate at the given precision."""
    if value is None:
        return dash
    return ("%%.%df" % dp) % float(value)


def pair(lat: Optional[float], lon: Optional[float], dp: int = FULL_PLACES,
         dash: str = "-", sep: str = ", ") -> str:
    """A latitude/longitude pair at the given precision."""
    if lat is None or lon is None:
        return dash
    return coord(lat, dp) + sep + coord(lon, dp)


def number(value, suffix: str = "", dash: str = "-") -> str:
    """
    A quantity that is not a coordinate: metres, counts, scores.

    Trailing zeros are stripped, because "45 m" reads better than "45.00 m"
    and the extra digits imply a precision the value does not have.
    """
    if value is None or value == "":
        return dash
    if isinstance(value, float):
        return "%s%s" % (("%.2f" % value).rstrip("0").rstrip("."), suffix)
    return "%s%s" % (value, suffix)


def map_links(lat: float, lon: float, dp: int = FULL_PLACES
              ) -> List[Tuple[str, str]]:
    """
    Links to the position in the common mapping services.

    Written at the precision the document holds, and at a zoom level that
    matches it - offering street-level zoom on a coordinate truncated to a
    kilometre would misrepresent what is known.
    """
    lat_s, lon_s = coord(lat, dp), coord(lon, dp)
    both = lat_s + "," + lon_s
    zoom = 19 if dp >= 5 else 13
    return [
        ("Google Maps",
         "https://www.google.com/maps/search/?api=1&query=%s" % both),
        ("Google Maps satellite",
         "https://www.google.com/maps/@%s,%dz/data=!3m1!1e3" % (both, zoom)),
        ("Google Street View",
         "https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=%s"
         % both),
        ("OpenStreetMap",
         "https://www.openstreetmap.org/?mlat=%s&mlon=%s#map=%d/%s/%s"
         % (lat_s, lon_s, zoom, lat_s, lon_s)),
        ("Bing Maps",
         "https://www.bing.com/maps?cp=%s~%s&lvl=%d&style=a"
         % (lat_s, lon_s, zoom)),
    ]


#: Verdict -> stylesheet class, for the HTML report.
VERDICT_CLASS = {
    "CORROBORATED": "v-strong",
    "SUPPORTED": "v-good",
    "SINGLE-SOURCE": "v-mid",
    "INDICATIVE": "v-mid",
    "SINGLE-SOURCE (WEAK)": "v-low",
    "WEAK": "v-low",
    "UNRESOLVED": "v-none",
}

#: Verdict -> RGB, for the PDF. Kept beside the class map so the two cannot
#: drift into disagreeing about what a verdict looks like.
VERDICT_RGB = {
    "v-strong": (0.07, 0.50, 0.36),
    "v-good": (0.07, 0.50, 0.36),
    "v-mid": (0.70, 0.41, 0.04),
    "v-low": (0.70, 0.41, 0.04),
    "v-none": (0.70, 0.15, 0.12),
}


def verdict_class(verdict: Optional[str]) -> str:
    return VERDICT_CLASS.get(str(verdict or ""), "v-none")


def verdict_rgb(verdict: Optional[str]) -> Tuple[float, float, float]:
    return VERDICT_RGB[verdict_class(verdict)]


# --------------------------------------------------------------------------
# executive summary
# --------------------------------------------------------------------------
#: The summary is the part of the report most likely to be read on its own and
#: quoted, so the two renderers must not be able to disagree about it. It is
#: built once here as plain sentences; `**emphasis**` marks the terms the HTML
#: sets in bold, and the PDF simply strips the markers.
def summary_lines(doc: Dict[str, object]) -> List[str]:
    tgt = doc.get("target") or {}
    ap = doc.get("apple") or {}
    ms = (doc.get("microsoft") or {}).get("result") or {}
    pos = doc.get("position") or {}
    val = doc.get("validation") or {}
    survey = doc.get("survey") or {}
    addr = (doc.get("enrichment") or {}).get("address") or {}
    ctx = val.get("context") or {}

    kind = tgt.get("kind")
    name = tgt.get("ssid") or tgt.get("input")
    if kind == "imported" and not name:
        # There is no single identifier to name in an import, and saying
        # "the identifier (unnamed)" reads as though something was missing.
        out: List[str] = [
            "This enquiry was conducted against **%d access point address(es)** "
            "recovered from an imported artefact."
            % len(tgt.get("bssids") or tgt.get("imported_observations") or []),
        ]
    else:
        out = ["A wireless positioning enquiry was conducted against the "
               "identifier **%s**." % (name or "(unnamed)")]
    if kind == "ssid":
        out.append(
            "The identifier was supplied as a network name (SSID). Neither "
            "positioning service accepts a network name, so the name was "
            "resolved to hardware addresses locally, by this host's own radio, "
            "which observed **%d** access point(s) broadcasting it. Only those "
            "hardware addresses were sent to the positioning services."
            % len(tgt.get("bssids") or []))
    elif kind == "ssid-db":
        out.append("The network name was not observable from the examination "
                   "host, so candidate access points were obtained from open "
                   "wireless datasets.")
    elif kind == "bssid":
        out.append("The identifier was supplied directly as a hardware "
                   "address (BSSID).")
    elif kind == "imported" and name:
        # Only when the opening sentence named a target instead; otherwise it
        # has already said the addresses came from an artefact.
        out.append("The access point address(es) were imported from artefacts "
                   "rather than observed by this host.")

    if survey.get("beacon_count"):
        out.append("The survey recorded **%d** access points in radio range "
                   "using %s." % (survey["beacon_count"],
                                  survey.get("method") or "the local radio"))
    if ap:
        out.append("Apple Location Services returned **%s** access point "
                   "records, of which **%s** carried positions."
                   % (number(ap.get("total_returned")),
                      number(ap.get("total_located"))))
    if ms.get("located"):
        out.append("The Microsoft location inference service independently "
                   "returned a position with a stated radial uncertainty of "
                   "**%s m**." % number(ms.get("radial_uncertainty_m")))
    elif ctx.get("microsoft_unreachable"):
        out.append("The Microsoft location inference service could not be "
                   "reached (%s), so no independent cross-check was obtained. "
                   "This is recorded as a limitation of collection rather than "
                   "as evidence against the position."
                   % (ctx.get("microsoft_unreachable_reason") or "no reason given"))

    # A multi-place enquiry has no single position, and the summary must lead
    # with the finding it does have. Left to the generic wording below, the
    # summary of a four-place movement history said nothing whatsoever about
    # the places - the one thing the reader needed.
    places = doc.get("places") or []
    if len(places) > 1:
        firsts = [p.get("earliest_seen") for p in places if p.get("earliest_seen")]
        lasts = [p.get("latest_seen") for p in places if p.get("latest_seen")]
        when = (" The artefact covers the period **%s to %s**."
                % (min(firsts)[:10], max(lasts)[:10])) if firsts and lasts else ""
        out.append(
            "The supplied addresses resolve to **%d distinct places**, so this "
            "enquiry reports a location history rather than a single position."
            "%s Each place, the networks found there and the dates recorded in "
            "the artefact are set out below." % (len(places), when))
        strong = [p for p in places
                  if (p.get("corroboration") or {}).get("level") == "strong"]
        weak = [p for p in places
                if (p.get("corroboration") or {}).get("level") == "weak"]
        if strong or weak:
            out.append(
                "Of those, **%d** are supported both by more than one supplied "
                "network and by other access points Apple independently holds "
                "at the same spot; **%d** rest on a single record with little "
                "around it and should be treated as leads rather than "
                "established locations." % (len(strong), len(weak)))

    if pos and len(places) <= 1:
        out.append("The reported position was derived by %s and is stated to "
                   "\u00b1%s metres." % (pos.get("method") or "fusion",
                                         number(pos.get("accuracy_m"))))
    if addr.get("display_name"):
        out.append("Reverse geocoding places this position at **%s**."
                   % addr["display_name"])

    out.append("The overall assessment is **%s**. %s"
               % (val.get("verdict") or "UNRESOLVED",
                  val.get("verdict_statement") or ""))
    return out


def strip_emphasis(text: str) -> str:
    """Drop the `**` markers, for renderers that cannot set bold mid-line."""
    return text.replace("**", "")
