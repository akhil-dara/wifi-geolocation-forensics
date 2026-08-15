"""
Redaction for reports that leave the investigation.

A finished report names a place and the hardware at it. That is the point of
it, and it is also why a copy cannot simply be pasted into a briefing deck, a
bug report, a conference slide or a public repository.

Redaction happens at render time and never touches the evidence package. The
sealed exhibits, the manifest and the root hash are always the unredacted
truth; what is produced here is a derived document that deliberately says less.
A redacted report states plainly, on its face, that it is redacted and that the
evidence package is not - so nobody mistakes one for the other.

What is removed, and why:

  Hardware addresses   The vendor prefix is public and stays; the device half
                       identifies one specific unit and goes.
  Coordinates          Truncated, not scrambled. Truncation keeps the result
                       honest - the reader can see the precision was reduced -
                       whereas a fake coordinate would be a false statement.
  Street address       House number and street go; locality and country stay,
                       because those are what make the report legible.
  Host and examiner    The examining machine and operator are not the subject.

What is kept: case identifiers, hashes, verdicts, scores, timings, provider
behaviour and every methodological statement. Redaction is meant to remove
identifying detail, not to hide how the conclusion was reached.
"""

from __future__ import annotations

import copy
import math
import re
from typing import Any, Dict, List, Optional

#: Degrees of latitude/longitude to keep. Two places is roughly 1 km, which
#: locates a district without locating a building.
COORD_PLACES = 2

MASK = "█" * 4          # a solid block, so redaction is visible as such


def _mac(value: str) -> str:
    """`00:00:5e:00:53:a6` -> `00:00:5e:xx:xx:xx`, keeping the vendor prefix."""
    parts = str(value).split(":")
    if len(parts) != 6:
        return str(value)
    return ":".join(parts[:3] + ["xx", "xx", "xx"])


def _coord(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    factor = 10 ** COORD_PLACES
    return math.floor(float(value) * factor) / factor


_MAC_ANY = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")


def _walk(node: Any, mac_keys, coord_keys, drop_keys) -> Any:
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            # Some maps are keyed BY the address - vendor attributions, for one.
            # Masking only values would leave every address on display in the
            # keys, which is exactly the mistake this catches.
            safe_key = _mac(key) if (isinstance(key, str)
                                     and _MAC_ANY.match(key)) else key
            lower = key.lower() if isinstance(key, str) else ""
            if lower in drop_keys:
                out[safe_key] = MASK
            elif lower in mac_keys and isinstance(value, str):
                out[safe_key] = _mac(value)
            elif lower in coord_keys and isinstance(value, (int, float)):
                out[safe_key] = _coord(value)
            else:
                out[safe_key] = _walk(value, mac_keys, coord_keys, drop_keys)
        return out
    if isinstance(node, list):
        return [_walk(v, mac_keys, coord_keys, drop_keys) for v in node]
    if isinstance(node, str):
        # Catch identifiers written into free text - a request XML body, an
        # exhibit URL, a narrative sentence - which the key-based rules above
        # cannot see. The chain-of-custody table renders request URLs verbatim,
        # and those carry both the queried address and, for the geocoding
        # lookups, the resolved coordinate.
        text = re.sub(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b",
                      lambda m: _mac(m.group(1)), node)
        text = re.sub(r"\b([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b",
                      lambda m: _mac(m.group(1).replace("-", ":")).replace(":", "-"),
                      text)
        # Five or more decimal places is coordinate-grade precision; ordinary
        # numbers in this document (versions, counts, metres) never carry it.
        text = re.sub(r"(-?\d{1,3})\.(\d{5,})",
                      lambda m: "%s.%s" % (m.group(1),
                                           m.group(2)[:COORD_PLACES]), text)
        return text
    return node


MAC_KEYS = {"bssid", "bssid_as_returned", "mac", "normalised", "nic",
            "local_macs", "defaultgatewaymac"}
#: The compass keys are the corners of a bounding box. They are coordinates
#: with different names, and leaving them out let full precision through.
COORD_KEYS = {"latitude", "longitude", "lat", "lon",
              "north", "south", "east", "west"}
#: Keys whose value is replaced outright.
#:
#: `address` is deliberately absent: the generic walk would replace the whole
#: dictionary, and the locality inside it is what makes a redacted report
#: readable at all. It is handled specifically in `apply`, which keeps the city
#: and country and discards the rest.
#:
#: Every filesystem path is dropped, not just some. A path on the examining
#: machine carries the operator's account name in it - `C:\Users\<name>\...` -
#: so a single missed path key undoes the withholding of the examiner. They are
#: listed exhaustively rather than by suffix because a silent miss here is
#: invisible in the rendered output until someone else is reading it.
DROP_KEYS = {"hostname", "user", "cwd", "executable", "case_dir",
             "zip_path", "report_path", "report_pdf_path",
             "report_redacted_path", "report_redacted_pdf_path",
             "evidence_root", "path", "house_number", "road", "display_name",
             "postcode"}


def apply_meta(meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact the case metadata that the report renders alongside the findings.

    This is a separate entry point because the metadata is passed to the
    renderer separately from the findings, and redacting only the findings left
    every queried address on display in the chain-of-custody table - the
    request URLs contain them.
    """
    red = _walk(copy.deepcopy(meta), MAC_KEYS, COORD_KEYS, DROP_KEYS)
    red["examiner"] = MASK
    red["organisation"] = MASK
    env = red.get("environment")
    if isinstance(env, dict):
        for key in ("hostname", "user", "cwd", "executable"):
            if key in env:
                env[key] = MASK
    return red


def apply(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Return a redacted copy of a result document. The original is untouched."""
    red = _walk(copy.deepcopy(doc), MAC_KEYS, COORD_KEYS, DROP_KEYS)

    # Derived coordinate strings are rebuilt rather than pattern-matched, so a
    # full-precision value cannot survive in a format we did not anticipate.
    co = red.get("coordinates")
    pos = red.get("position")
    if isinstance(co, dict) and isinstance(pos, dict):
        lat, lon = pos.get("latitude"), pos.get("longitude")
        if lat is not None and lon is not None:
            fmt = "%%.%df" % COORD_PLACES
            pair = (fmt % lat) + ", " + (fmt % lon)
            co["decimal"] = pair
            co["decimal_precise"] = pair + "  (redacted to %d decimal places)" % COORD_PLACES
            for key in ("dms", "utm", "mgrs", "geohash", "plus_code"):
                if co.get(key):
                    co[key] = MASK
    elif isinstance(co, dict):
        for key in list(co):
            co[key] = MASK

    # Enrichment describes the place in detail; keep only the coarse locality.
    enr = red.get("enrichment")
    if isinstance(enr, dict):
        addr = enr.get("address")
        if isinstance(addr, dict):
            enr["address"] = {
                "city": addr.get("city"),
                "state": addr.get("state"),
                "country": addr.get("country"),
                "country_code": addr.get("country_code"),
                "display_name": MASK,
                "redacted": True,
            }
        for key in ("places", "daylight"):
            if key in enr:
                enr[key] = {"redacted": True}

    # The map is a picture of the address. There is no safe way to blur it, so
    # it is removed outright rather than degraded.
    for key in ("static_map", "export_map", "map_image"):
        red.pop(key, None)

    red["redacted"] = True
    red["redaction_note"] = (
        "This report has been redacted for distribution. Hardware addresses "
        "show the manufacturer prefix only, coordinates are truncated to %d "
        "decimal places, the street address and map have been removed, and the "
        "examining host and operator are withheld. Case identifiers, hashes, "
        "scores and methodology are unchanged. The sealed evidence package is "
        "NOT redacted and remains the authoritative record."
        % COORD_PLACES)
    return red
