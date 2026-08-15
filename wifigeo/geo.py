"""
Geospatial mathematics, coordinate systems and the cross-validation engine.

Everything here is deterministic and offline.  The coordinate conversions
(Plus Code, geohash, UTM, MGRS) matter in a DFIR context because different
agencies standardise on different grids, and a report that only carries
decimal degrees forces the reader to convert by hand.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

EARTH_RADIUS_M = 6371008.8          # IUGG mean radius
WGS84_A = 6378137.0
WGS84_F = 1 / 298.257223563
WGS84_E2 = WGS84_F * (2 - WGS84_F)


# --------------------------------------------------------------------------
# distance / bearing
# --------------------------------------------------------------------------
def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in metres."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


def bearing_deg(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Initial true bearing from point 1 to point 2, degrees clockwise from N."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


def compass_point(bearing: float) -> str:
    names = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
             "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"]
    return names[int((bearing + 11.25) % 360 / 22.5)]


# --------------------------------------------------------------------------
# aggregation
# --------------------------------------------------------------------------
def centroid(points: Sequence[Tuple[float, float]],
             weights: Optional[Sequence[float]] = None) -> Tuple[float, float]:
    """
    Weighted centroid computed in 3-D Cartesian space.

    Averaging degrees directly is wrong across the antimeridian and near the
    poles; projecting to unit vectors and back is correct everywhere.
    """
    if not points:
        raise ValueError("no points")
    if weights is None:
        weights = [1.0] * len(points)
    x = y = z = 0.0
    total = 0.0
    for (lat, lon), w in zip(points, weights):
        if w <= 0:
            continue
        p, l = math.radians(lat), math.radians(lon)
        x += math.cos(p) * math.cos(l) * w
        y += math.cos(p) * math.sin(l) * w
        z += math.sin(p) * w
        total += w
    if total == 0:
        return points[0]
    x, y, z = x / total, y / total, z / total
    hyp = math.sqrt(x * x + y * y)
    if hyp < 1e-12 and abs(z) < 1e-12:
        return points[0]
    return math.degrees(math.atan2(z, hyp)), math.degrees(math.atan2(y, x))


def median(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("no values")
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def mad(values: Sequence[float]) -> float:
    """Median absolute deviation - robust to the outliers we expect."""
    if not values:
        return 0.0
    m = median(values)
    return median([abs(v - m) for v in values])


def reject_outliers(points: Sequence[Tuple[float, float]],
                    threshold: float = 3.5
                    ) -> Tuple[List[int], List[int], Dict[str, float]]:
    """
    Split points into (kept, rejected) by modified Z-score on distance from the
    geometric median-ish centre.

    Apple's neighbour cloud regularly contains a handful of access points that
    have physically moved (a hotspot in a vehicle, a relocated router) and sit
    hundreds of kilometres from the rest.  Including them would drag the
    centroid off; silently dropping them without saying so would be worse.  We
    return both lists so the report can state exactly what was excluded.
    """
    if len(points) < 4:
        return list(range(len(points))), [], {}
    lat0, lon0 = centroid(points)
    dists = [haversine_m(lat0, lon0, la, lo) for la, lo in points]
    m = median(dists)
    d = mad(dists)
    if d <= 0:
        # Degenerate spread: fall back to a plain distance cap.
        kept = [i for i, x in enumerate(dists) if x <= max(500.0, m * 3)]
        rejected = [i for i in range(len(points)) if i not in set(kept)]
        return kept, rejected, {"median_distance_m": m, "mad_m": 0.0}
    kept, rejected = [], []
    for i, x in enumerate(dists):
        z = 0.6745 * (x - m) / d
        (kept if z <= threshold else rejected).append(i)
    return kept, rejected, {"median_distance_m": m, "mad_m": d}


def bounding_box(points: Sequence[Tuple[float, float]]) -> Dict[str, float]:
    lats = [p[0] for p in points]
    lons = [p[1] for p in points]
    return {"north": max(lats), "south": min(lats),
            "east": max(lons), "west": min(lons)}


def convex_hull(points: Sequence[Tuple[float, float]]
                ) -> List[Tuple[float, float]]:
    """Andrew's monotone chain, in (lat, lon)."""
    pts = sorted(set(points), key=lambda p: (p[1], p[0]))
    if len(pts) < 3:
        return list(pts)

    def cross(o, a, b):
        return ((a[1] - o[1]) * (b[0] - o[0])) - ((a[0] - o[0]) * (b[1] - o[1]))

    lower: List[Tuple[float, float]] = []
    for p in pts:
        while len(lower) >= 2 and cross(lower[-2], lower[-1], p) <= 0:
            lower.pop()
        lower.append(p)
    upper: List[Tuple[float, float]] = []
    for p in reversed(pts):
        while len(upper) >= 2 and cross(upper[-2], upper[-1], p) <= 0:
            upper.pop()
        upper.append(p)
    return lower[:-1] + upper[:-1]


# --------------------------------------------------------------------------
# coordinate formats
# --------------------------------------------------------------------------
def to_dms(lat: float, lon: float) -> str:
    def one(v: float, pos: str, neg: str) -> str:
        hemi = pos if v >= 0 else neg
        v = abs(v)
        d = int(v)
        m = int((v - d) * 60)
        s = (v - d - m / 60) * 3600
        return "%d°%02d'%05.2f\"%s" % (d, m, s, hemi)
    return "%s %s" % (one(lat, "N", "S"), one(lon, "E", "W"))


_OLC_ALPHABET = "23456789CFGHJMPQRVWX"


def plus_code(lat: float, lon: float, length: int = 11) -> str:
    """Open Location Code (Plus Code).  Length 11 is roughly 3.5 m."""
    length = max(2, min(15, length - (length % 2) if length <= 10 else length))
    lat = max(-90.0, min(90.0, lat))
    if lat == 90.0:
        lat = 89.999999
    lon = ((lon + 180.0) % 360.0) - 180.0

    code = ""
    lat_v = lat + 90.0
    lon_v = lon + 180.0
    lat_res, lon_res = 20.0, 20.0
    pair_len = min(length, 10)
    for i in range(pair_len // 2):
        if i:
            lat_res /= 20.0
            lon_res /= 20.0
        li = int(lat_v / lat_res)
        lat_v -= li * lat_res
        oi = int(lon_v / lon_res)
        lon_v -= oi * lon_res
        code += _OLC_ALPHABET[min(li, 19)] + _OLC_ALPHABET[min(oi, 19)]

    if length > 10:
        lat_g, lon_g = lat_res / 5.0, lon_res / 4.0
        for _ in range(length - 10):
            r = min(int(lat_v / lat_g), 4)
            c = min(int(lon_v / lon_g), 3)
            code += _OLC_ALPHABET[r * 4 + c]
            lat_v -= r * lat_g
            lon_v -= c * lon_g
            lat_g /= 5.0
            lon_g /= 4.0

    if len(code) < 8:
        code += "0" * (8 - len(code))
    return code[:8] + "+" + code[8:]


_GEOHASH_B32 = "0123456789bcdefghjkmnpqrstuvwxyz"


def geohash(lat: float, lon: float, precision: int = 10) -> str:
    lat_r, lon_r = [-90.0, 90.0], [-180.0, 180.0]
    out, bit, ch, even = [], 0, 0, True
    while len(out) < precision:
        # The comparison is >=, not >. A value sitting exactly on a cell
        # boundary belongs to the upper cell by convention, and every other
        # geohash implementation agrees: with > instead, (0, 0) encodes as
        # "7zzzzzzz" - the diagonally adjacent cell - rather than "s0000000".
        if even:
            mid = sum(lon_r) / 2
            if lon >= mid:
                ch |= 1 << (4 - bit)
                lon_r[0] = mid
            else:
                lon_r[1] = mid
        else:
            mid = sum(lat_r) / 2
            if lat >= mid:
                ch |= 1 << (4 - bit)
                lat_r[0] = mid
            else:
                lat_r[1] = mid
        even = not even
        if bit < 4:
            bit += 1
        else:
            out.append(_GEOHASH_B32[ch])
            bit, ch = 0, 0
    return "".join(out)


def to_utm(lat: float, lon: float) -> Dict[str, object]:
    """WGS84 latitude/longitude to UTM."""
    zone = int((lon + 180) / 6) + 1
    # Norway/Svalbard exceptions.
    if 56.0 <= lat < 64.0 and 3.0 <= lon < 12.0:
        zone = 32
    elif 72.0 <= lat < 84.0:
        if 0.0 <= lon < 9.0:
            zone = 31
        elif 9.0 <= lon < 21.0:
            zone = 33
        elif 21.0 <= lon < 33.0:
            zone = 35
        elif 33.0 <= lon < 42.0:
            zone = 37

    lon0 = math.radians((zone - 1) * 6 - 180 + 3)
    p, l = math.radians(lat), math.radians(lon)
    k0 = 0.9996
    ep2 = WGS84_E2 / (1 - WGS84_E2)
    N = WGS84_A / math.sqrt(1 - WGS84_E2 * math.sin(p) ** 2)
    T = math.tan(p) ** 2
    C = ep2 * math.cos(p) ** 2
    A = math.cos(p) * (l - lon0)
    e2, e4, e6 = WGS84_E2, WGS84_E2 ** 2, WGS84_E2 ** 3
    M = WGS84_A * (
        (1 - e2 / 4 - 3 * e4 / 64 - 5 * e6 / 256) * p
        - (3 * e2 / 8 + 3 * e4 / 32 + 45 * e6 / 1024) * math.sin(2 * p)
        + (15 * e4 / 256 + 45 * e6 / 1024) * math.sin(4 * p)
        - (35 * e6 / 3072) * math.sin(6 * p))
    easting = k0 * N * (A + (1 - T + C) * A ** 3 / 6
                        + (5 - 18 * T + T * T + 72 * C - 58 * ep2) * A ** 5 / 120) + 500000.0
    northing = k0 * (M + N * math.tan(p) * (
        A ** 2 / 2 + (5 - T + 9 * C + 4 * C * C) * A ** 4 / 24
        + (61 - 58 * T + T * T + 600 * C - 330 * ep2) * A ** 6 / 720))
    hemisphere = "N"
    if lat < 0:
        northing += 10000000.0
        hemisphere = "S"
    band = _lat_band(lat)
    return {"zone": zone, "band": band, "hemisphere": hemisphere,
            "easting": easting, "northing": northing,
            "text": "%d%s %.0fmE %.0fmN" % (zone, band, easting, northing)}


_BANDS = "CDEFGHJKLMNPQRSTUVWX"


def _lat_band(lat: float) -> str:
    if lat < -80 or lat > 84:
        return "Z"
    idx = int((lat + 80) / 8)
    return _BANDS[min(idx, len(_BANDS) - 1)]


def to_mgrs(lat: float, lon: float, digits: int = 5) -> str:
    """WGS84 latitude/longitude to MGRS using the standard AA lettering."""
    u = to_utm(lat, lon)
    zone, band = int(u["zone"]), str(u["band"])
    e, n = float(u["easting"]), float(u["northing"])

    col_sets = ["ABCDEFGH", "JKLMNPQR", "STUVWXYZ"]
    col_letters = col_sets[(zone - 1) % 3]
    col = col_letters[min(int(e / 100000) - 1, 7)]

    row_letters = "ABCDEFGHJKLMNPQRSTUV"
    row_index = int(n / 100000) % 20
    if zone % 2 == 0:
        row_index = (row_index + 5) % 20
    row = row_letters[row_index]

    div = 10 ** (5 - digits)
    e_str = str(int((e % 100000) / div)).zfill(digits)
    n_str = str(int((n % 100000) / div)).zfill(digits)
    return "%d%s %s%s %s %s" % (zone, band, col, row, e_str, n_str)


def coordinate_formats(lat: float, lon: float) -> Dict[str, object]:
    """Every representation the report offers, in one place."""
    return {
        "decimal": "%.6f, %.6f" % (lat, lon),
        "decimal_precise": "%.8f, %.8f" % (lat, lon),
        "dms": to_dms(lat, lon),
        "plus_code": plus_code(lat, lon),
        "geohash": geohash(lat, lon),
        "utm": to_utm(lat, lon)["text"],
        "mgrs": to_mgrs(lat, lon),
    }


# --------------------------------------------------------------------------
# cross-source validation
# --------------------------------------------------------------------------
@dataclass
class Signal:
    """
    One named, weighted contribution to the confidence score.

    `available` distinguishes "we tested this and it failed" from "we could not
    test this at all".  The difference matters: if a provider is unreachable
    because its edge blocked us, that says nothing about the position, and
    scoring it as a failure would understate evidence that is otherwise sound.
    Unavailable signals are removed from the denominator rather than scored
    zero - see `cross_validate`.
    """

    name: str
    weight: float
    awarded: float
    detail: str
    status: str = "info"     # pass | warn | fail | info | unavailable
    available: bool = True

    def to_dict(self) -> Dict[str, object]:
        return {"name": self.name, "weight": self.weight,
                "awarded": round(self.awarded, 2), "detail": self.detail,
                "status": self.status, "available": self.available}


VERDICTS = [
    (85, "CORROBORATED", "Two independent providers agree within their stated uncertainty."),
    (70, "SUPPORTED", "Position is well supported, with a minor reservation."),
    (50, "INDICATIVE", "A plausible position, but corroboration is incomplete."),
    (30, "WEAK", "Insufficient corroboration. Treat as a lead only."),
    (0, "UNRESOLVED", "The evidence does not support a position."),
]


def verdict_for(score: float, corroborated: bool = True) -> Tuple[str, str]:
    """
    Map a score to a verdict.

    `corroborated` gates the top band.  "CORROBORATED" asserts that two
    independent providers agreed; if the second provider never answered, that
    assertion is false no matter how well the remaining checks scored, so the
    label is capped and renamed to say exactly what happened.  Overstating the
    strength of a single-source result is the most damaging mistake this tool
    could make.
    """
    if not corroborated:
        if score >= 70:
            return ("SINGLE-SOURCE",
                    "Internally consistent and well supported, but resting on "
                    "one provider only. No independent cross-check was "
                    "obtained, so this must not be presented as corroborated.")
        if score >= 50:
            return ("SINGLE-SOURCE (WEAK)",
                    "One provider only, with reservations. Treat as an "
                    "investigative lead requiring corroboration.")
        return ("UNRESOLVED",
                "One provider only and the supporting checks were poor. The "
                "evidence does not support a position.")
    for threshold, label, text in VERDICTS:
        if score >= threshold:
            return label, text
    return "UNRESOLVED", VERDICTS[-1][2]


def cross_validate(apple_anchor: Optional[Dict[str, object]],
                   msft: Optional[Dict[str, object]],
                   cluster: Optional[Dict[str, object]],
                   context: Optional[Dict[str, object]] = None
                   ) -> Dict[str, object]:
    """
    Score the agreement between the two providers.

    The score is the sum of explicitly named, individually weighted signals,
    each of which is reported alongside its contribution.  An analyst can see
    precisely why a position scored what it did and can disagree with any single
    line rather than with an opaque number.
    """
    ctx = context or {}
    signals: List[Signal] = []

    a_lat = apple_anchor.get("latitude") if apple_anchor else None
    a_lon = apple_anchor.get("longitude") if apple_anchor else None
    a_acc = (apple_anchor or {}).get("accuracy_m")
    m_lat = msft.get("latitude") if msft else None
    m_lon = msft.get("longitude") if msft else None
    m_acc = (msft or {}).get("radial_uncertainty_m")

    have_apple = a_lat is not None and a_lon is not None
    # An IP-fallback answer has coordinates but is not a positioning result.
    # The caller should already have withheld it; re-check rather than assume.
    have_msft = (m_lat is not None and m_lon is not None
                 and (msft or {}).get("located", True)
                 and not (msft or {}).get("ip_fallback", False))

    # Did Microsoft actually get to answer, or was the question refused?
    # A 403 from the Azure edge, a timeout or a DNS failure are all "we never
    # asked successfully"; only a well-formed response with no position is a
    # genuine negative.
    msft_unreachable = bool(ctx.get("microsoft_unreachable"))
    msft_reason = str(ctx.get("microsoft_unreachable_reason") or "")

    # 1. Apple resolved the queried access point.                    (20)
    signals.append(Signal(
        "Apple Location Services resolved the target", 20.0,
        20.0 if have_apple else 0.0,
        ("Apple returned a position for the queried BSSID."
         if have_apple else
         "Apple has no record of the queried BSSID."),
        "pass" if have_apple else "fail"))

    # 2. Microsoft independently resolved a position.                (15)
    if msft_unreachable:
        signals.append(Signal(
            "Microsoft inference service resolved a position", 15.0, 0.0,
            "The Microsoft service could not be reached, so no independent "
            "check was possible (%s). This is a limitation of the collection, "
            "not evidence against the position; the weighting has been "
            "redistributed across the checks that did run." % msft_reason,
            "unavailable", available=False))
    else:
        signals.append(Signal(
            "Microsoft inference service resolved a position", 15.0,
            15.0 if have_msft else 0.0,
            ("Microsoft multilaterated a position from the beacon fingerprint."
             if have_msft else
             "Microsoft answered but returned no position for the submitted "
             "fingerprint."),
            "pass" if have_msft else "fail"))

    # 3. The two providers agree.                                    (25)
    separation = None
    if have_apple and have_msft:
        separation = haversine_m(a_lat, a_lon, m_lat, m_lon)
        budget = max(50.0, (a_acc or 0) + (m_acc or 0))
        ratio = separation / budget
        if ratio <= 1.0:
            award, status = 25.0, "pass"
            detail = ("Separation %.0f m is within the combined stated "
                      "uncertainty of %.0f m." % (separation, budget))
        elif ratio <= 2.0:
            award, status = 25.0 * (2.0 - ratio), "warn"
            detail = ("Separation %.0f m exceeds the combined uncertainty of "
                      "%.0f m but remains the same locality." % (separation, budget))
        elif separation <= 5000:
            award, status = 5.0, "warn"
            detail = ("Separation %.0f m is well beyond stated uncertainty; the "
                      "providers disagree on the precise location."
                      % separation)
        else:
            award, status = 0.0, "fail"
            detail = ("Separation %.1f km. The two providers describe different "
                      "places. Do not rely on either without further work."
                      % (separation / 1000.0))
        if ctx.get("microsoft_is_derived_probe"):
            # The Microsoft position here came from putting Apple's nearest
            # neighbours to Microsoft's engine, not from anything the tool
            # observed.  The two databases remain independent, so agreement is
            # real - but the question was framed using Apple's own output, so
            # it is not as strong as two independent observations and is
            # discounted and labelled accordingly.
            award *= 0.7
            detail = ("Derived locality probe, not an observation: %s Because "
                      "the access point set was taken from Apple's own "
                      "response, this check is discounted." % detail)
        signals.append(Signal("Cross-provider agreement", 25.0, award, detail, status))
    elif msft_unreachable:
        signals.append(Signal(
            "Cross-provider agreement", 25.0, 0.0,
            "No cross-check could be performed because the second provider was "
            "unreachable. Re-run this query when the service is available to "
            "obtain independent corroboration.",
            "unavailable", available=False))
    else:
        signals.append(Signal(
            "Cross-provider agreement", 25.0, 0.0,
            "Only one provider returned a position, so the result is "
            "uncorroborated.", "fail"))

    # 3b. Per-access-point agreement between the providers.          (20)
    #
    # The strongest check available: both databases were asked about the same
    # physical device, so agreement is about that device rather than about two
    # aggregate estimates happening to land near each other.
    pairs = ctx.get("per_ap_pairs") or []
    if pairs:
        agree = int(ctx.get("per_ap_agree") or 0)
        total = int(ctx.get("per_ap_total") or len(pairs))
        med = ctx.get("per_ap_median_separation_m")
        ratio = agree / total if total else 0.0
        award = 20.0 * ratio
        status = "pass" if ratio >= 0.75 else ("warn" if ratio > 0 else "fail")
        signals.append(Signal(
            "Per-access-point agreement between providers", 20.0, award,
            "%d of %d access point(s) held by both providers agree within their "
            "combined stated uncertainty (median separation %s m)."
            % (agree, total, med if med is not None else "n/a"), status))
    elif msft_unreachable:
        signals.append(Signal(
            "Per-access-point agreement between providers", 20.0, 0.0,
            "Not assessed: the second provider was unreachable.",
            "unavailable", available=False))
    else:
        signals.append(Signal(
            "Per-access-point agreement between providers", 20.0, 0.0,
            "No access point was held by both providers, so no device-level "
            "comparison was possible. This is common - the two databases are "
            "built from different contributing populations - and is treated as "
            "an absence of evidence rather than evidence of conflict.",
            "unavailable", available=False))

    # 3c. Replicated independent multilateration.                    (15)
    #
    # Microsoft was asked to compute a position several times over, each time
    # from a disjoint set of access points. Convergence across sets that share
    # no members cannot be produced by a single bad database record, which is
    # what makes this a replication rather than a repetition.
    reps = int(ctx.get("replicate_resolved") or 0)
    rep_total = int(ctx.get("replicate_groups") or 0)
    if reps >= 2:
        spread = float(ctx.get("replicate_spread_m") or 0.0)
        if spread <= 150:
            award, status, word = 15.0, "pass", "tightly"
        elif spread <= 500:
            award, status, word = 11.0, "pass", "closely"
        elif spread <= 2000:
            award, status, word = 5.0, "warn", "loosely"
        else:
            award, status, word = 0.0, "fail", "not at all"
        signals.append(Signal(
            "Replicated independent multilateration", 15.0, award,
            "%d of %d disjoint access-point groups resolved, and they agree %s "
            "(maximum separation %.0f m). Each group shares no members with the "
            "others, so agreement is not attributable to any single record."
            % (reps, rep_total, word, spread), status))
    elif rep_total:
        signals.append(Signal(
            "Replicated independent multilateration", 15.0, 0.0,
            "Only %d of %d groups resolved, so no replication could be "
            "assessed." % (reps, rep_total), "unavailable", available=False))

    # 4. Neighbour cluster support.                                  (15)
    n_support = int((cluster or {}).get("kept_count", 0) or 0)
    if n_support >= 50:
        award, status = 15.0, "pass"
    elif n_support >= 15:
        award, status = 11.0, "pass"
    elif n_support >= 5:
        award, status = 7.0, "warn"
    elif n_support >= 1:
        award, status = 3.0, "warn"
    else:
        award, status = 0.0, "fail"
    signals.append(Signal(
        "Neighbouring access-point support", 15.0, award,
        "%d neighbouring access points from Apple's database corroborate this "
        "locality." % n_support, status))

    # 5. Cluster tightness.                                          (10)
    spread = (cluster or {}).get("mad_m")
    if spread is None:
        signals.append(Signal("Neighbour cluster coherence", 10.0, 0.0,
                              "Not enough neighbours to assess spread.", "warn"))
    else:
        spread = float(spread)
        if spread <= 150:
            award, status, word = 10.0, "pass", "tight"
        elif spread <= 500:
            award, status, word = 7.0, "pass", "coherent"
        elif spread <= 2000:
            award, status, word = 4.0, "warn", "loose"
        else:
            award, status, word = 1.0, "warn", "dispersed"
        signals.append(Signal(
            "Neighbour cluster coherence", 10.0, award,
            "Cluster is %s: median absolute deviation %.0f m." % (word, spread),
            status))

    # 6. Quality of the stated uncertainties.                        (10)
    accs = [x for x in (a_acc, m_acc) if x]
    if accs:
        worst = max(accs)
        if worst <= 100:
            award, status = 10.0, "pass"
        elif worst <= 500:
            award, status = 7.0, "pass"
        elif worst <= 2000:
            award, status = 3.0, "warn"
        else:
            award, status = 0.0, "warn"
        signals.append(Signal(
            "Reported positional accuracy", 10.0, award,
            "Worst-case stated accuracy across providers is %.0f m." % worst,
            status))
    else:
        signals.append(Signal("Reported positional accuracy", 10.0, 0.0,
                              "Neither provider stated an accuracy.", "warn"))

    # 7. Multiple radios of the same network agree.                  (5)
    multi = ctx.get("consistent_radios") or 0
    span = ctx.get("radio_span_m")
    if multi >= 2 and span is not None and span <= 250:
        signals.append(Signal(
            "Multi-radio consistency", 5.0, 5.0,
            "%d access points advertising this SSID resolve within %.0f m of "
            "each other." % (multi, span), "pass"))
    elif multi >= 2:
        signals.append(Signal(
            "Multi-radio consistency", 5.0, 1.5,
            "%d access points advertise this SSID but they resolve %.0f m "
            "apart." % (multi, span or 0), "warn"))
    else:
        signals.append(Signal(
            "Multi-radio consistency", 5.0, 0.0,
            "Only one access point resolved, so no internal consistency check "
            "was possible.", "info"))

    # Score over the checks that could actually be performed.  Weight from
    # unavailable checks is redistributed proportionally rather than counted
    # as zero, so an unreachable provider lowers *certainty* (recorded in
    # `coverage`) without manufacturing evidence against the position.
    available = [s for s in signals if s.available]
    available_weight = sum(s.weight for s in available) or 1.0
    score = 100.0 * sum(s.awarded for s in available) / available_weight
    coverage = available_weight / sum(s.weight for s in signals)

    # ---- penalties -------------------------------------------------------
    penalties: List[Signal] = []
    if ctx.get("randomised_mac"):
        penalties.append(Signal(
            "Locally administered (randomised) MAC", -15.0, -15.0,
            "The access point this position is anchored on has the "
            "locally-administered bit set. It is likely a randomised or virtual "
            "address, so a database record for it may belong to an entirely "
            "different device.", "fail"))
    if ctx.get("mac_collision"):
        penalties.append(Signal(
            "Randomised-MAC database collision detected", -8.0, -8.0,
            str(ctx.get("mac_collision")), "warn"))
    if ctx.get("stale_scan"):
        penalties.append(Signal(
            "Cached scan data", -10.0, -10.0,
            "An active scan could not be performed; the beacon list came from "
            "the operating system cache and may not reflect the present "
            "environment.", "warn"))
    if ctx.get("approximated_rssi"):
        penalties.append(Signal(
            "Approximated signal strength", -5.0, -5.0,
            "Signal strengths were derived from percentages rather than "
            "measured in dBm, which degrades the Microsoft multilateration.",
            "warn"))
    # A hidden SSID used to be penalised here. It is not scored, for two
    # reasons. It says nothing about positional accuracy - the position is
    # derived from the BSSID, and whether the network advertises a name is
    # irrelevant to that. And it can only be known at all if a radio scan
    # actually observed the beacon; where the enquiry began from an address,
    # nothing was ever listened for, so calling the network "hidden" would
    # assert a fact not in evidence.

    score = max(0.0, min(100.0, score + sum(p.awarded for p in penalties)))

    # The top verdict band asserts independent corroboration.  Only award it
    # when a cross-provider check actually ran AND actually agreed - either the
    # aggregate comparison or the stronger per-device one.
    named = {s.name: s for s in signals}
    cross = named.get("Cross-provider agreement")
    per_ap = named.get("Per-access-point agreement between providers")
    corroborated = any(s and s.available and s.awarded > 0 for s in (cross, per_ap))
    label, statement = verdict_for(score, corroborated)

    return {
        "score": round(score, 1),
        "verdict": label,
        "verdict_statement": statement,
        "coverage": round(coverage * 100, 1),
        "coverage_note": (
            "All planned checks ran." if coverage >= 0.999 else
            "Only %.0f%% of the planned checks could be performed; the score is "
            "computed over those and should be read with correspondingly lower "
            "certainty." % (coverage * 100)),
        "signals": [s.to_dict() for s in signals],
        "penalties": [p.to_dict() for p in penalties],
        "separation_m": round(separation, 1) if separation is not None else None,
        "separation_bearing": (
            {"degrees": round(bearing_deg(a_lat, a_lon, m_lat, m_lon), 1),
             "compass": compass_point(bearing_deg(a_lat, a_lon, m_lat, m_lon))}
            if separation is not None else None),
        "max_possible": 100.0,
    }


def analyse_cluster(points: Sequence[Tuple[float, float]],
                    weights: Optional[Sequence[float]] = None) -> Dict[str, object]:
    """Summarise Apple's neighbour cloud: centre, spread, extent, outliers."""
    if not points:
        return {"kept_count": 0, "rejected_count": 0}
    kept_i, rejected_i, stats = reject_outliers(points)
    kept = [points[i] for i in kept_i]
    if not kept:
        kept, kept_i = list(points), list(range(len(points)))
    w = [weights[i] for i in kept_i] if weights else None
    lat, lon = centroid(kept, w)
    dists = [haversine_m(lat, lon, la, lo) for la, lo in kept]
    hull = convex_hull(kept)
    return {
        "centroid": {"latitude": lat, "longitude": lon},
        "kept_count": len(kept),
        "rejected_count": len(rejected_i),
        "rejected_indices": rejected_i,
        "median_distance_m": round(stats.get("median_distance_m", 0.0), 1),
        "mad_m": round(stats.get("mad_m", 0.0), 1),
        "radius_p50_m": round(median(dists), 1) if dists else 0.0,
        "radius_p95_m": round(sorted(dists)[int(len(dists) * 0.95)], 1) if dists else 0.0,
        "radius_max_m": round(max(dists), 1) if dists else 0.0,
        "bounding_box": bounding_box(kept),
        "hull": [{"latitude": la, "longitude": lo} for la, lo in hull],
    }


#: Two access points further apart than this are treated as different places.
#:
#: Sized to a site, not to a city. An earlier value of 25 km - borrowed from the
#: threshold used to spot a randomised-address collision - collapsed a person's
#: home, office and airport into a single "place" merely because all three were
#: in the same conurbation, which is precisely the distinction a movement
#: history exists to draw. Those are different questions and they get different
#: constants: 25 km still answers "is this record irreconcilable with the rest",
#: while this answers "is this somewhere else".
#:
#: 500 m comfortably contains a building or a campus - and single-linkage means
#: a chain of nearby buildings still groups - while two addresses half a
#: kilometre apart are, to an investigator, two addresses.
PLACE_RADIUS_M = 500.0


def group_places(points: Sequence[Tuple[float, float]],
                 radius_m: float = PLACE_RADIUS_M) -> List[List[int]]:
    """
    Partition positions into distinct places, returning indices per place.

    Single-linkage: a point joins a place if it is within `radius_m` of *any*
    member, so a chain of nearby sites stays one place while a genuinely
    separate location forms its own.

    This exists because an artefact import is not one observation. A registry
    NetworkList holds every network a machine has ever joined, which may be
    hundreds of networks in dozens of towns. Averaging those into one position
    describes nowhere, and discarding the distant ones as anomalies throws away
    the very evidence the artefact was collected for.
    """
    n = len(points)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        a, b = find(i), find(j)
        if a != b:
            parent[b] = a

    for i in range(n):
        for j in range(i + 1, n):
            if haversine_m(points[i][0], points[i][1],
                           points[j][0], points[j][1]) <= radius_m:
                union(i, j)

    groups: Dict[int, List[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)
    # Largest first: the place with the most evidence leads the report.
    return sorted(groups.values(), key=len, reverse=True)
