"""
Open-source geospatial enrichment and corroborating positioning sources.

Everything here is credential-free.  Two categories:

Corroboration
    Additional wireless-positioning databases queried for a third opinion on a
    BSSID.  These are weaker and patchier than Apple or Microsoft, so they
    inform the narrative but do not feed the confidence score - a source that
    is silent most of the time cannot be allowed to move a number.

Enrichment
    Once a position is established, describe it: street address, what is
    there, elevation, timezone, daylight at the time of the observation, and
    the map imagery itself.

Map tiles are fetched and embedded in the report as data URIs.  A report that
depends on a live tile server stops working the day that server changes; an
evidence exhibit must still render years later, offline.
"""

from __future__ import annotations

import base64
import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from .net import Transport

# --------------------------------------------------------------------------
# corroborating positioning sources
# --------------------------------------------------------------------------
def mylnikov(transport: Transport, bssid: str) -> Dict[str, object]:
    """
    api.mylnikov.org - a free, open Wi-Fi geolocation dataset.

    Coverage is thin outside Europe and it frequently returns "not found";
    that is expected and is reported as such rather than treated as an error.
    """
    url = ("https://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid=%s"
           % bssid)
    ex = transport.fetch(url, label="mylnikov.%s" % bssid.replace(":", ""))
    out: Dict[str, object] = {"source": "mylnikov", "exhibit_seq": ex.seq,
                              "status": ex.status, "located": False}
    if not ex.ok or not ex.response_body:
        out["error"] = ex.error or "HTTP %s" % ex.status
        return out
    try:
        doc = json.loads(ex.response_body.decode("utf-8", "replace"))
    except ValueError as e:
        out["error"] = "invalid JSON: %s" % e
        return out
    out["result_code"] = doc.get("result")
    if doc.get("result") == 200 and isinstance(doc.get("data"), dict):
        d = doc["data"]
        try:
            out.update({"located": True,
                        "latitude": float(d["lat"]),
                        "longitude": float(d["lon"]),
                        "accuracy_m": d.get("range")})
        except (KeyError, TypeError, ValueError):
            out["error"] = "unexpected data shape"
    else:
        out["note"] = doc.get("desc") or "not present in the mylnikov dataset"
    return out


def wifidb_ssid(transport: Transport, ssid: str) -> Dict[str, object]:
    """wifidb.net public GeoJSON search - keyless, SSID-searchable."""
    from urllib.parse import quote
    ex = transport.fetch(
        "https://wifidb.net/wifidb/api/geojson.php?func=exp_search&ssid=%s"
        % quote(ssid), label="wifidb.search")
    out: Dict[str, object] = {"source": "wifidb", "exhibit_seq": ex.seq,
                              "matches": []}
    if not ex.ok or not ex.response_body:
        out["error"] = ex.error or "HTTP %s" % ex.status
        return out
    try:
        doc = json.loads(ex.response_body.decode("utf-8", "replace"))
    except ValueError as e:
        out["error"] = "invalid or empty response: %s" % e
        return out
    for feat in (doc.get("features") or [])[:50]:
        geom = feat.get("geometry") or {}
        props = feat.get("properties") or {}
        coords = geom.get("coordinates") or []
        if len(coords) >= 2:
            out["matches"].append({
                "ssid": props.get("ssid"), "bssid": props.get("mac"),
                "latitude": coords[1], "longitude": coords[0],
                "channel": props.get("chan"), "security": props.get("capabilities"),
            })
    return out


# --------------------------------------------------------------------------
# location enrichment
# --------------------------------------------------------------------------
def reverse_geocode(transport: Transport, lat: float, lon: float) -> Dict[str, object]:
    """OpenStreetMap Nominatim.  Requires a descriptive User-Agent."""
    url = ("https://nominatim.openstreetmap.org/reverse?format=jsonv2"
           "&lat=%.7f&lon=%.7f&zoom=18&addressdetails=1&extratags=1"
           "&namedetails=1" % (lat, lon))
    ex = transport.fetch(url, label="nominatim.reverse",
                         headers={"Accept": "application/json",
                                  "Accept-Language": "en"})
    out: Dict[str, object] = {"source": "OpenStreetMap Nominatim",
                              "exhibit_seq": ex.seq}
    if not ex.ok or not ex.response_body:
        out["error"] = ex.error or "HTTP %s" % ex.status
        return out
    try:
        doc = json.loads(ex.response_body.decode("utf-8", "replace"))
    except ValueError as e:
        out["error"] = "invalid JSON: %s" % e
        return out
    addr = doc.get("address") or {}
    out.update({
        "display_name": doc.get("display_name"),
        "osm_type": doc.get("osm_type"),
        "osm_id": doc.get("osm_id"),
        "category": doc.get("category"),
        "type": doc.get("type"),
        "name": doc.get("name") or (doc.get("namedetails") or {}).get("name"),
        "address": addr,
        "house_number": addr.get("house_number"),
        "road": addr.get("road"),
        "neighbourhood": addr.get("neighbourhood") or addr.get("suburb"),
        "city": (addr.get("city") or addr.get("town") or addr.get("village")
                 or addr.get("municipality")),
        "district": addr.get("state_district") or addr.get("county"),
        "state": addr.get("state"),
        "postcode": addr.get("postcode"),
        "country": addr.get("country"),
        "country_code": (addr.get("country_code") or "").upper(),
        "boundingbox": doc.get("boundingbox"),
    })
    return out


#: Overpass query for what is physically at a position.
#:
#: `nwr` matches nodes, ways AND relations. The earlier version of this query
#: asked only for nodes plus a narrow slice of ways, which made it structurally
#: blind to exactly the places an investigator most wants named: shopping
#: centres, hospitals, campuses, stations, airports and civic buildings are
#: almost always mapped as large ways or as relations, never as a single point.
_POI_QUERY = """[out:json][timeout:50];
(
  nwr(around:{r},{lat},{lon})["amenity"]["name"];
  nwr(around:{r},{lat},{lon})["shop"]["name"];
  nwr(around:{r},{lat},{lon})["office"]["name"];
  nwr(around:{r},{lat},{lon})["tourism"]["name"];
  nwr(around:{r},{lat},{lon})["leisure"]["name"];
  nwr(around:{r},{lat},{lon})["historic"]["name"];
  nwr(around:{r},{lat},{lon})["healthcare"]["name"];
  nwr(around:{r},{lat},{lon})["craft"]["name"];
  nwr(around:{r},{lat},{lon})["government"]["name"];
  nwr(around:{r},{lat},{lon})["military"]["name"];
  nwr(around:{r},{lat},{lon})["club"]["name"];
  nwr(around:{r},{lat},{lon})["railway"~"^(station|halt|tram_stop|subway_entrance)$"]["name"];
  nwr(around:{r},{lat},{lon})["public_transport"~"^(station|stop_position|platform)$"]["name"];
  nwr(around:{r},{lat},{lon})["aeroway"~"^(terminal|aerodrome|helipad)$"]["name"];
  nwr(around:{r},{lat},{lon})["man_made"~"^(tower|works|water_tower|communications_tower|bridge)$"]["name"];
  nwr(around:{r},{lat},{lon})["building"~"^(commercial|retail|office|hospital|school|university|college|hotel|public|civic|government|train_station|mall|industrial|warehouse|apartments|residential|dormitory|church|mosque|temple|stadium)$"]["name"];
  nwr(around:{r},{lat},{lon})["landuse"~"^(retail|commercial|industrial|education|military|residential)$"]["name"];
  nwr(around:{r},{lat},{lon})["place"~"^(neighbourhood|suburb|quarter|city_block|square)$"]["name"];
  nwr(around:{r},{lat},{lon})["natural"~"^(water|beach|peak)$"]["name"];
);
out center tags {limit};"""

#: A second, wider sweep for places of genuine prominence.
#:
#: A 200 m radius answers "what is this building", but an investigator also
#: needs "where is this, in terms anyone would recognise" - and the landmark
#: that identifies a location to a human being is routinely several hundred
#: metres away.
#:
#: Every clause here keys off an indexed tag. An earlier version opened with
#: `nwr["wikidata"]`, reasoning that a wikidata tag is a decent proxy for public
#: notability. It is - but the key is not indexed, so Overpass had to scan the
#: whole radius, and the request died after 60 seconds with the connection
#: dropped, silently returning no landmarks at all. Notability is now read from
#: the tags of features found by type, which costs nothing.
_LANDMARK_QUERY = """[out:json][timeout:90];
(
  nwr(around:{r},{lat},{lon})["amenity"~"^(university|college|hospital|townhall|courthouse|police|prison|embassy|theatre|arts_centre|conference_centre|stadium|bus_station|marketplace)$"]["name"];
  nwr(around:{r},{lat},{lon})["tourism"~"^(attraction|museum|zoo|theme_park|viewpoint|gallery)$"]["name"];
  nwr(around:{r},{lat},{lon})["historic"~"^(monument|memorial|castle|fort|ruins|archaeological_site)$"]["name"];
  nwr(around:{r},{lat},{lon})["shop"~"^(mall|department_store)$"]["name"];
  nwr(around:{r},{lat},{lon})["leisure"~"^(stadium|sports_centre|park|nature_reserve|water_park)$"]["name"];
  nwr(around:{r},{lat},{lon})["railway"~"^(station|halt)$"]["name"];
  nwr(around:{r},{lat},{lon})["public_transport"="station"]["name"];
  nwr(around:{r},{lat},{lon})["aeroway"="aerodrome"]["name"];
  nwr(around:{r},{lat},{lon})["office"="government"]["name"];
  nwr(around:{r},{lat},{lon})["building"~"^(mall|stadium|hospital|university|train_station)$"]["name"];
  nwr(around:{r},{lat},{lon})["place"~"^(suburb|neighbourhood|quarter)$"]["name"];
);
out center tags {limit};"""


#: Tag value -> (category, human label).  Ordered: the first tag key present on
#: a feature decides its category, so the more specific keys come first.
_CATEGORY_RULES = [
    ("aeroway", {"aerodrome": "Transport", "terminal": "Transport",
                 "helipad": "Transport"}),
    ("railway", {"station": "Transport", "halt": "Transport",
                 "tram_stop": "Transport", "subway_entrance": "Transport"}),
    ("public_transport", {"*": "Transport"}),
    ("healthcare", {"*": "Healthcare"}),
    ("military", {"*": "Military"}),
    ("government", {"*": "Government"}),
    ("historic", {"*": "Landmark & heritage"}),
    ("tourism", {"hotel": "Accommodation", "motel": "Accommodation",
                 "guest_house": "Accommodation", "hostel": "Accommodation",
                 "apartment": "Accommodation", "*": "Landmark & heritage"}),
    ("amenity", {
        "restaurant": "Food & drink", "cafe": "Food & drink",
        "fast_food": "Food & drink", "bar": "Food & drink", "pub": "Food & drink",
        "food_court": "Food & drink", "ice_cream": "Food & drink",
        "school": "Education", "college": "Education", "university": "Education",
        "kindergarten": "Education", "library": "Education",
        "hospital": "Healthcare", "clinic": "Healthcare", "doctors": "Healthcare",
        "pharmacy": "Healthcare", "dentist": "Healthcare",
        "bank": "Financial", "atm": "Financial", "bureau_de_change": "Financial",
        "police": "Government", "fire_station": "Government",
        "townhall": "Government", "courthouse": "Government",
        "prison": "Government", "embassy": "Government", "post_office": "Government",
        "place_of_worship": "Worship",
        "fuel": "Transport", "parking": "Transport", "bus_station": "Transport",
        "charging_station": "Transport", "taxi": "Transport",
        "theatre": "Leisure & culture", "cinema": "Leisure & culture",
        "arts_centre": "Leisure & culture", "community_centre": "Leisure & culture",
        "*": "Amenity"}),
    ("shop", {"mall": "Retail", "supermarket": "Retail", "*": "Retail"}),
    ("office", {"government": "Government", "*": "Commercial & offices"}),
    ("craft", {"*": "Commercial & offices"}),
    ("leisure", {"*": "Leisure & culture"}),
    ("club", {"*": "Leisure & culture"}),
    ("man_made", {"*": "Infrastructure"}),
    ("natural", {"*": "Natural feature"}),
    ("landuse", {"residential": "Residential", "education": "Education",
                 "military": "Military", "industrial": "Industrial",
                 "*": "Commercial & offices"}),
    ("building", {
        "hospital": "Healthcare", "school": "Education", "university": "Education",
        "college": "Education", "hotel": "Accommodation", "mall": "Retail",
        "retail": "Retail", "commercial": "Commercial & offices",
        "office": "Commercial & offices", "government": "Government",
        "civic": "Government", "public": "Government",
        "train_station": "Transport", "industrial": "Industrial",
        "warehouse": "Industrial", "stadium": "Leisure & culture",
        "church": "Worship", "mosque": "Worship", "temple": "Worship",
        "apartments": "Residential", "residential": "Residential",
        "dormitory": "Residential", "*": "Building"}),
    ("place", {"*": "Locality"}),
]


def classify(tags: Dict[str, str]) -> Tuple[str, str]:
    """Map OSM tags to (category, specific type)."""
    for key, mapping in _CATEGORY_RULES:
        value = tags.get(key)
        if not value:
            continue
        category = mapping.get(value) or mapping.get("*")
        if category:
            return category, value.replace("_", " ")
    return "Other", "place"


def _prominence(tags: Dict[str, str], category: str) -> int:
    """
    A crude notability score, used only for ordering.

    Nothing here is presented as fact in the report; it decides which of a
    hundred nearby features are worth listing first.
    """
    score = 0
    if tags.get("wikidata"):
        score += 40
    if tags.get("wikipedia"):
        score += 25
    if tags.get("brand") or tags.get("operator"):
        score += 6
    if tags.get("website") or tags.get("contact:website"):
        score += 4
    score += {
        "Transport": 22, "Healthcare": 20, "Education": 18, "Government": 18,
        "Military": 18, "Landmark & heritage": 16, "Retail": 10,
        "Leisure & culture": 10, "Accommodation": 8, "Worship": 8,
    }.get(category, 0)
    if tags.get("shop") == "mall" or tags.get("building") == "mall":
        score += 20
    if tags.get("amenity") in ("university", "hospital", "airport"):
        score += 15
    return score


#: Overpass mirrors, tried in order.
#:
#: The main instance is popular and frequently answers 429 or 504 at busy
#: times. Falling back through the community mirrors is the difference between
#: a report that names the landmarks around a position and one that silently
#: says there are none - which a reader would reasonably take as a finding
#: rather than as a failed lookup.
#: Ordered by observed responsiveness, not by prominence. The reference
#: instance is listed last because it is the busiest and, in testing, spent
#: 60 seconds timing out before a mirror answered in two.
OVERPASS_MIRRORS = [
    "https://overpass.kumi.systems/api/interpreter",
    "https://overpass.private.coffee/api/interpreter",
    "https://overpass-api.de/api/interpreter",
    "https://overpass.osm.jp/api/interpreter",
]

#: Seconds to wait for one mirror before also trying the next.
HEDGE_DELAY = 6.0
#: Hard ceiling on any single mirror.
OVERPASS_TIMEOUT = 35.0


def _run_overpass(transport: Transport, query: str, label: str,
                  lat: float, lon: float) -> Tuple[List[Dict[str, object]], Dict]:
    """Execute one Overpass query against the first mirror that answers."""
    from .geo import bearing_deg, compass_point, haversine_m

    # Hedged requests. Mirrors were previously tried strictly one after
    # another, so a slow instance cost its full timeout before the next was
    # attempted - measured at 155 seconds for a single landmark sweep, which
    # was the overwhelming majority of an entire investigation's runtime.
    # Instead, start the first mirror and bring in the next only if it has not
    # answered within HEDGE_DELAY. The first usable response wins. This keeps
    # load on these free services close to one request in the common case,
    # while a stalled instance costs seconds rather than a minute.
    meta: Dict[str, object] = {}
    attempts: List[str] = []
    winner: Dict[str, object] = {}
    done = threading.Event()
    lock = threading.Lock()

    def attempt(index: int, endpoint: str) -> None:
        if done.is_set():
            return
        ex = transport.fetch(
            endpoint, label="%s.m%d" % (label, index + 1),
            method="POST", body=query.encode("utf-8"),
            headers={"Content-Type": "text/plain; charset=utf-8"},
            timeout=OVERPASS_TIMEOUT, retries=0)
        if ex.ok and ex.response_body and not done.is_set():
            try:
                parsed = json.loads(ex.response_body.decode("utf-8", "replace"))
            except ValueError as e:
                with lock:
                    attempts.append("%s: invalid JSON (%s)" % (endpoint, e))
                return
            with lock:
                if not winner:
                    winner["doc"] = parsed
                    winner["meta"] = {"exhibit_seq": ex.seq, "status": ex.status,
                                      "mirror_used": endpoint,
                                      "mirrors_started": index + 1}
                    done.set()
        else:
            with lock:
                attempts.append("%s: %s"
                                % (endpoint, ex.error or "HTTP %s" % ex.status))

    threads: List[threading.Thread] = []
    for i, endpoint in enumerate(OVERPASS_MIRRORS):
        t = threading.Thread(target=attempt, args=(i, endpoint), daemon=True)
        t.start()
        threads.append(t)
        if done.wait(HEDGE_DELAY):
            break
    for t in threads:
        t.join(timeout=OVERPASS_TIMEOUT + 5)

    doc = winner.get("doc")
    if doc is None:
        meta["error"] = "; ".join(attempts) or "no mirror answered"
        return [], meta
    meta = winner["meta"]

    seen = set()
    places: List[Dict[str, object]] = []
    for el in doc.get("elements") or []:
        tags = el.get("tags") or {}
        name = tags.get("name")
        if not name:
            continue
        if el.get("type") == "node":
            p_lat, p_lon = el.get("lat"), el.get("lon")
        else:
            centre = el.get("center") or {}
            p_lat, p_lon = centre.get("lat"), centre.get("lon")
        if p_lat is None or p_lon is None:
            continue
        key = (name, round(p_lat, 5), round(p_lon, 5))
        if key in seen:
            continue
        seen.add(key)

        category, kind = classify(tags)
        dist = haversine_m(lat, lon, p_lat, p_lon)
        brg = bearing_deg(lat, lon, p_lat, p_lon)
        places.append({
            "name": name,
            "category": category,
            "kind": kind,
            "latitude": p_lat, "longitude": p_lon,
            "distance_m": round(dist, 1),
            "bearing": compass_point(brg),
            "bearing_deg": round(brg, 1),
            "osm_type": el.get("type"), "osm_id": el.get("id"),
            "prominence": _prominence(tags, category),
            "notable": bool(tags.get("wikidata") or tags.get("wikipedia")),
            "wikidata": tags.get("wikidata"),
            "address": " ".join(x for x in [
                tags.get("addr:housenumber"), tags.get("addr:street")] if x) or None,
            "phone": tags.get("phone") or tags.get("contact:phone"),
            "website": tags.get("website") or tags.get("contact:website"),
            "operator": tags.get("operator") or tags.get("brand"),
        })
    return places, meta


PHOTON = "https://photon.komoot.io/reverse"
NOMINATIM_REVERSE = "https://nominatim.openstreetmap.org/reverse"


def _nominatim_at(transport: Transport, lat: float, lon: float, ref_lat: float,
                  ref_lon: float, label: str
                  ) -> Tuple[List[Dict[str, object]], Optional[str]]:
    """
    One Nominatim reverse lookup, normalised like the Photon results.

    Nominatim returns a single nearest feature rather than a list, so this is
    far thinner than Photon. It exists as the last tier of the fallback chain:
    thin coverage from a service that is up beats nothing from two that are
    down.
    """
    from .geo import bearing_deg, compass_point, haversine_m

    url = ("%s?format=jsonv2&lat=%.7f&lon=%.7f&zoom=18&addressdetails=1"
           % (NOMINATIM_REVERSE, lat, lon))
    ex = transport.fetch(url, label=label, timeout=20, retries=0,
                         headers={"Accept": "application/json",
                                  "Accept-Language": "en"})
    if not ex.ok or not ex.response_body:
        return [], ex.error or "HTTP %s" % ex.status
    try:
        doc = json.loads(ex.response_body.decode("utf-8", "replace"))
    except ValueError as e:
        return [], "invalid JSON: %s" % e

    name = doc.get("name") or (doc.get("address") or {}).get("amenity")
    if not name:
        return [], None
    try:
        p_lat, p_lon = float(doc["lat"]), float(doc["lon"])
    except (KeyError, TypeError, ValueError):
        return [], None
    key = doc.get("category") or ""
    value = doc.get("type") or ""
    category, kind = classify({key: value})
    d = haversine_m(ref_lat, ref_lon, p_lat, p_lon)
    b = bearing_deg(ref_lat, ref_lon, p_lat, p_lon)
    return [{
        "name": name, "category": category, "kind": kind or value,
        "latitude": p_lat, "longitude": p_lon,
        "distance_m": round(d, 1), "bearing": compass_point(b),
        "bearing_deg": round(b, 1),
        "osm_type": doc.get("osm_type"), "osm_id": doc.get("osm_id"),
        "prominence": _prominence({key: value}, category),
        "notable": False,
        "address": None, "phone": None, "website": None, "operator": None,
    }], None


def _photon_at(transport: Transport, lat: float, lon: float, ref_lat: float,
               ref_lon: float, limit: int, label: str
               ) -> Tuple[List[Dict[str, object]], Optional[str]]:
    """One Photon reverse lookup, normalised and measured from the target."""
    from .geo import bearing_deg, compass_point, haversine_m

    url = "%s?lat=%.7f&lon=%.7f&limit=%d" % (PHOTON, lat, lon, limit)
    # Fail fast. This is the first tier of a fallback chain, so a slow refusal
    # here just delays the provider that is actually going to answer.
    ex = transport.fetch(url, label=label, headers={"Accept": "application/json"},
                         timeout=7, retries=0)
    if not ex.ok or not ex.response_body:
        return [], ex.error or "HTTP %s" % ex.status
    try:
        doc = json.loads(ex.response_body.decode("utf-8", "replace"))
    except ValueError as e:
        return [], "invalid JSON: %s" % e

    out: List[Dict[str, object]] = []
    for feat in doc.get("features") or []:
        p = feat.get("properties") or {}
        name = p.get("name")
        if not name:
            continue
        coords = (feat.get("geometry") or {}).get("coordinates") or []
        if len(coords) < 2:
            continue
        p_lon, p_lat = coords[0], coords[1]
        key, value = p.get("osm_key") or "", p.get("osm_value") or ""
        if key in ("highway", "boundary", "waterway", "barrier", "route"):
            continue                       # roads and admin edges are not places
        category, kind = classify({key: value})
        d = haversine_m(ref_lat, ref_lon, p_lat, p_lon)
        b = bearing_deg(ref_lat, ref_lon, p_lat, p_lon)
        out.append({
            "name": name, "category": category, "kind": kind or value,
            "latitude": p_lat, "longitude": p_lon,
            "distance_m": round(d, 1), "bearing": compass_point(b),
            "bearing_deg": round(b, 1),
            "osm_type": p.get("osm_type"), "osm_id": p.get("osm_id"),
            "prominence": _prominence({key: value}, category),
            "notable": False,
            "address": " ".join(x for x in [p.get("housenumber"),
                                            p.get("street")] if x) or None,
            "phone": None, "website": None,
            "operator": p.get("city") or p.get("district"),
        })
    return out, None


def _ring(lat: float, lon: float, radius_m: float, count: int
          ) -> List[Tuple[float, float]]:
    """Evenly spaced sample points on a circle around a position."""
    pts = []
    for i in range(count):
        brg = math.radians(360.0 * i / count)
        dlat = (radius_m * math.cos(brg)) / 111320.0
        dlon = ((radius_m * math.sin(brg))
                / (111320.0 * max(0.05, math.cos(math.radians(lat)))))
        pts.append((lat + dlat, lon + dlon))
    return pts


def nearby_places(transport: Transport, lat: float, lon: float,
                  radius_m: int = 200, limit: int = 120,
                  landmark_radius_m: int = 1400,
                  deep: bool = False) -> Dict[str, object]:
    """
    What is at this position, and what recognisable places surround it.

    Photon does the work. It is a geocoder built on the same OpenStreetMap
    data as Overpass but purpose-built for point lookups, and it answers in
    about a second where Overpass - which is a general query engine being asked
    to scan an area - took over two minutes and frequently timed out entirely.
    Same underlying data, a hundredth of the time.

    Photon's reverse lookup only reaches a few hundred metres, so wider
    coverage comes from sampling a ring of points around the target and merging
    the results. Those calls are independent and run together, so the whole
    sweep costs about as long as the slowest one.
    """
    out: Dict[str, object] = {
        "source": "Photon (OpenStreetMap)",
        "radius_m": radius_m,
        "landmark_radius_m": landmark_radius_m,
        "places": [], "landmarks": [], "by_category": {},
    }

    # Provider chain. Photon is first because it is by far the fastest, but
    # it is one host and it does go down - observed unreachable while Overpass
    # was also timing out, which left the earlier single-provider design with
    # nothing to report and only a buried error to show for it. Each tier is
    # tried until one actually yields places, and the report records which one
    # answered so a reader knows the provenance.
    merged: Dict[Tuple, Dict[str, object]] = {}
    errors: List[str] = []
    attempts: List[str] = []
    provider = None

    def keep(rows):
        for p in rows:
            key = (p["osm_type"], p["osm_id"]) if p.get("osm_id") else                   (p["name"], round(p["latitude"], 5), round(p["longitude"], 5))
            prev = merged.get(key)
            if prev is None or p["distance_m"] < prev["distance_m"]:
                merged[key] = p

    # --- tier 1: Photon, ring-sampled -----------------------------------
    jobs = [(lat, lon, 120, "photon.centre")]
    for i, (rlat, rlon) in enumerate(_ring(lat, lon, landmark_radius_m * 0.55, 6)):
        jobs.append((rlat, rlon, 60, "photon.ring1.%d" % (i + 1)))
    for i, (rlat, rlon) in enumerate(_ring(lat, lon, landmark_radius_m, 8)):
        jobs.append((rlat, rlon, 60, "photon.ring2.%d" % (i + 1)))

    with ThreadPoolExecutor(max_workers=8) as pool:
        for got, err in pool.map(
                lambda j: _photon_at(transport, j[0], j[1], lat, lon, j[2], j[3]),
                jobs):
            if err:
                errors.append("photon: %s" % err)
            keep(got)
    attempts.append("Photon (%d results)" % len(merged))
    if merged:
        provider = "Photon (OpenStreetMap)"

    # --- tier 2: Overpass, if Photon gave nothing -----------------------
    if not merged:
        deep_res = _overpass_sweep(transport, lat, lon, radius_m,
                                   landmark_radius_m)
        keep(deep_res.get("places") or [])
        keep(deep_res.get("landmarks") or [])
        attempts.append("Overpass (%d results)" % len(merged))
        if deep_res.get("error"):
            errors.append("overpass: %s" % deep_res["error"])
        if merged:
            provider = "OpenStreetMap Overpass"

    # --- tier 3: Nominatim, ring-sampled, rate limited -------------------
    if not merged:
        points = [(lat, lon)] + _ring(lat, lon, radius_m, 4)                              + _ring(lat, lon, landmark_radius_m * 0.6, 6)
        for i, (rlat, rlon) in enumerate(points):
            got, err = _nominatim_at(transport, rlat, rlon, lat, lon,
                                     "nominatim.poi.%d" % (i + 1))
            if err:
                errors.append("nominatim: %s" % err)
            keep(got)
            time.sleep(1.05)      # Nominatim asks for no more than 1 req/sec
        attempts.append("Nominatim (%d results)" % len(merged))
        if merged:
            provider = "OpenStreetMap Nominatim (fallback)"

    out["source"] = provider or "none - every provider failed"
    out["providers_attempted"] = attempts
    if not merged:
        out["error"] = ("No place-name provider could be reached. This is a "
                        "failed lookup, not a finding: it does not mean there "
                        "is nothing at this position. " +
                        "; ".join(sorted(set(errors))[:3]))

    everything = sorted(merged.values(), key=lambda p: p["distance_m"])
    out["total_found"] = len(everything)

    close = [p for p in everything if p["distance_m"] <= radius_m]
    out["places"] = close[:limit]

    # Landmarks: what a reader would recognise, ranked by prominence rather
    # than proximity, and excluding anything already listed close by.
    close_keys = {(p["osm_type"], p["osm_id"]) for p in out["places"]}
    ranked = [p for p in everything
              if (p["osm_type"], p["osm_id"]) not in close_keys
              and p["prominence"] >= 8]
    ranked.sort(key=lambda p: (-p["prominence"], p["distance_m"]))

    # Diversify across categories. Prominence is partly category-weighted, so a
    # straight sort produces eleven hospitals and no transport, retail or
    # education - which is a worse answer to "where is this" even though every
    # entry is individually correct. Dealing round-robin across categories
    # keeps the strongest of each kind near the top.
    buckets: Dict[str, List[Dict[str, object]]] = {}
    for p in ranked:
        buckets.setdefault(p["category"], []).append(p)
    order = sorted(buckets, key=lambda c: -buckets[c][0]["prominence"])
    diverse: List[Dict[str, object]] = []
    depth = 0
    while len(diverse) < 40 and depth < 12:
        added = False
        for cat in order:
            if depth < len(buckets[cat]):
                diverse.append(buckets[cat][depth])
                added = True
                if len(diverse) >= 40:
                    break
        if not added:
            break
        depth += 1

    out["landmarks"] = diverse
    out["total_landmarks_found"] = len(ranked)
    out["landmark_categories"] = {c: len(v) for c, v in
                                  sorted(buckets.items(), key=lambda kv: -len(kv[1]))}

    grouped: Dict[str, int] = {}
    for p in out["places"]:
        grouped[p["category"]] = grouped.get(p["category"], 0) + 1
    out["by_category"] = dict(sorted(grouped.items(), key=lambda kv: -kv[1]))

    if deep:
        out["deep"] = _overpass_sweep(transport, lat, lon, radius_m,
                                      landmark_radius_m)
    return out


def _overpass_sweep(transport: Transport, lat: float, lon: float,
                    radius_m: int, landmark_radius_m: int,
                    limit: int = 120) -> Dict[str, object]:
    """
    What is at this position, and what recognisable places are around it.

    Two sweeps. The close sweep answers "what is this building"; the wide sweep
    answers "where is this, in terms a reader would recognise" - which the close
    sweep cannot do, because a landmark 800 m away is still the thing that
    identifies a location to a human being.

    Results are classified into categories and ordered by category then
    distance, so a reader can find the transport links or the schools without
    reading a hundred undifferentiated rows.
    """
    """Optional deep Overpass sweep. Slow; off unless explicitly requested."""
    out: Dict[str, object] = {
        "source": "OpenStreetMap Overpass",
        "radius_m": radius_m,
        "landmark_radius_m": landmark_radius_m,
        "places": [], "landmarks": [], "by_category": {},
    }

    near, meta = _run_overpass(
        transport,
        _POI_QUERY.format(r=radius_m, lat="%.7f" % lat, lon="%.7f" % lon,
                          limit=400),
        "overpass.nearby", lat, lon)
    out["exhibit_seq"] = meta.get("exhibit_seq")
    if meta.get("error"):
        out["error"] = meta["error"]

    # A wide sweep can still exceed the server's budget in a dense city.
    # Halve the radius and try once more rather than reporting no landmarks,
    # which would read as "there are none nearby" instead of "we did not get
    # an answer".
    far, meta2 = _run_overpass(
        transport,
        _LANDMARK_QUERY.format(r=landmark_radius_m, lat="%.7f" % lat,
                               lon="%.7f" % lon, limit=300),
        "overpass.landmarks", lat, lon)
    out["landmark_exhibit_seq"] = meta2.get("exhibit_seq")
    if meta2.get("error") and landmark_radius_m > 800:
        retry_r = landmark_radius_m // 2
        far, meta3 = _run_overpass(
            transport,
            _LANDMARK_QUERY.format(r=retry_r, lat="%.7f" % lat,
                                   lon="%.7f" % lon, limit=200),
            "overpass.landmarks.retry", lat, lon)
        out["landmark_retry_exhibit_seq"] = meta3.get("exhibit_seq")
        if meta3.get("error"):
            out["landmark_error"] = ("first attempt at %d m: %s; retry at %d m: %s"
                                     % (landmark_radius_m, meta2["error"],
                                        retry_r, meta3["error"]))
        else:
            out["landmark_radius_m"] = retry_r
            out["landmark_note"] = (
                "The %d m sweep exceeded the service's time budget; the "
                "landmarks below are from a %d m sweep."
                % (landmark_radius_m, retry_r))
    elif meta2.get("error"):
        out["landmark_error"] = meta2["error"]

    near.sort(key=lambda p: (p["distance_m"], -p["prominence"]))
    out["places"] = near[:limit]

    # Landmarks: prominence first, then proximity. Anything already listed in
    # the close sweep is dropped so the two lists do not repeat each other.
    close_keys = {(p["osm_type"], p["osm_id"]) for p in out["places"]}
    ranked = [p for p in far if (p["osm_type"], p["osm_id"]) not in close_keys]
    ranked.sort(key=lambda p: (-(p["prominence"]), p["distance_m"]))
    out["landmarks"] = ranked[:40]

    grouped: Dict[str, int] = {}
    for p in out["places"]:
        grouped[p["category"]] = grouped.get(p["category"], 0) + 1
    out["by_category"] = dict(sorted(grouped.items(), key=lambda kv: -kv[1]))
    out["total_found"] = len(near)
    out["total_landmarks_found"] = len(far)
    return out


def environment(transport: Transport, lat: float, lon: float) -> Dict[str, object]:
    """Elevation and IANA timezone from Open-Meteo (keyless)."""
    url = ("https://api.open-meteo.com/v1/forecast?latitude=%.6f&longitude=%.6f"
           "&timezone=auto&current=temperature_2m" % (lat, lon))
    ex = transport.fetch(url, label="openmeteo.environment",
                         headers={"Accept": "application/json"})
    out: Dict[str, object] = {"source": "Open-Meteo", "exhibit_seq": ex.seq}
    if not ex.ok or not ex.response_body:
        out["error"] = ex.error or "HTTP %s" % ex.status
        return out
    try:
        doc = json.loads(ex.response_body.decode("utf-8", "replace"))
    except ValueError as e:
        out["error"] = "invalid JSON: %s" % e
        return out
    out.update({
        "elevation_m": doc.get("elevation"),
        "timezone": doc.get("timezone"),
        "timezone_abbreviation": doc.get("timezone_abbreviation"),
        "utc_offset_seconds": doc.get("utc_offset_seconds"),
    })
    return out


def daylight(transport: Transport, lat: float, lon: float,
             date: Optional[str] = None) -> Dict[str, object]:
    """
    Sunrise / sunset / twilight for the observation date.

    Relevant when correlating a wireless observation against CCTV, imagery or
    witness accounts of light conditions.
    """
    url = ("https://api.sunrise-sunset.org/json?lat=%.6f&lng=%.6f&formatted=0"
           % (lat, lon))
    if date:
        url += "&date=%s" % date
    ex = transport.fetch(url, label="sunrisesunset.daylight",
                         headers={"Accept": "application/json"})
    out: Dict[str, object] = {"source": "sunrise-sunset.org",
                              "exhibit_seq": ex.seq}
    if not ex.ok or not ex.response_body:
        out["error"] = ex.error or "HTTP %s" % ex.status
        return out
    try:
        doc = json.loads(ex.response_body.decode("utf-8", "replace"))
    except ValueError as e:
        out["error"] = "invalid JSON: %s" % e
        return out
    r = doc.get("results") or {}
    out.update({k: r.get(k) for k in (
        "sunrise", "sunset", "solar_noon", "day_length",
        "civil_twilight_begin", "civil_twilight_end",
        "nautical_twilight_begin", "nautical_twilight_end")})
    return out


# --------------------------------------------------------------------------
# map tiles
# --------------------------------------------------------------------------
def _deg2tile(lat: float, lon: float, z: int) -> Tuple[float, float]:
    lat_r = math.radians(max(-85.05112878, min(85.05112878, lat)))
    n = 2.0 ** z
    x = (lon + 180.0) / 360.0 * n
    y = (1.0 - math.asinh(math.tan(lat_r)) / math.pi) / 2.0 * n
    return x, y


#: Tile servers we may use.  OpenStreetMap's own server has a usage policy that
#: forbids bulk downloading; a report needs at most a few dozen tiles, which is
#: well inside acceptable use, and we identify ourselves properly.
TILE_LAYERS = {
    "osm": {
        "url": "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
        "name": "OpenStreetMap Standard",
        "attribution": "© OpenStreetMap contributors (ODbL)",
    },
    "topo": {
        "url": "https://tile.opentopomap.org/{z}/{x}/{y}.png",
        "name": "OpenTopoMap",
        "attribution": "© OpenStreetMap contributors, SRTM | OpenTopoMap (CC-BY-SA)",
    },
}


def fetch_static_map(transport: Transport, lat: float, lon: float,
                     zoom: int = 17, grid: int = 3,
                     layer: str = "osm") -> Dict[str, object]:
    """
    Download a tile grid centred on a position and return it as data URIs.

    The result is everything the report needs to draw a map with no network
    access whatsoever: the tiles themselves, their pixel offsets, and the
    projection parameters needed to place a marker on top of them.
    """
    spec = TILE_LAYERS.get(layer, TILE_LAYERS["osm"])
    fx, fy = _deg2tile(lat, lon, zoom)
    cx, cy = int(fx), int(fy)
    half = grid // 2
    size = 256
    tiles: List[Dict[str, object]] = []
    total_bytes = 0

    wanted = []
    n = 2 ** zoom
    for dy in range(-half, half + 1):
        for dx in range(-half, half + 1):
            tx, ty = cx + dx, cy + dy
            if not (0 <= ty < n):
                continue
            wanted.append((tx % n, ty, (dx + half) * size, (dy + half) * size))

    def grab(job):
        tx, ty, left, top = job
        url = spec["url"].format(z=zoom, x=tx, y=ty)
        ex = transport.fetch(url, label="tile.%s.%d_%d_%d" % (layer, zoom, tx, ty),
                             headers={"Accept": "image/png,image/*"},
                             timeout=20, retries=1)
        if not ex.ok or not ex.response_body:
            return None
        return {
            "x": tx, "y": ty, "z": zoom, "left": left, "top": top,
            "data_uri": "data:image/png;base64," + base64.b64encode(
                ex.response_body).decode("ascii"),
            "bytes": len(ex.response_body),
            "exhibit_seq": ex.seq,
        }

    # Fetched a few at a time: a tile grid is dozens of small requests and
    # doing them strictly in series wastes most of the time waiting. The cap
    # keeps us well inside the tile server's usage policy.
    with ThreadPoolExecutor(max_workers=6) as pool:
        for got in pool.map(grab, wanted):
            if got:
                total_bytes += got.pop("bytes")
                tiles.append(got)
    tiles.sort(key=lambda t: (t["top"], t["left"]))

    width = height = (2 * half + 1) * size
    # Position of the target within the composed image, in pixels.
    marker_x = (fx - (cx - half)) * size
    marker_y = (fy - (cy - half)) * size
    origin_x, origin_y = cx - half, cy - half

    return {
        "layer": layer,
        "layer_name": spec["name"],
        "attribution": spec["attribution"],
        "zoom": zoom,
        "grid": grid,
        "tile_size": size,
        "width": width,
        "height": height,
        "tiles": tiles,
        "tile_count": len(tiles),
        "bytes": total_bytes,
        "centre": {"latitude": lat, "longitude": lon},
        "marker": {"x": marker_x, "y": marker_y},
        "origin_tile": {"x": origin_x, "y": origin_y},
        "metres_per_pixel": (156543.03392 * math.cos(math.radians(lat))
                             / (2 ** zoom)),
    }


def project_onto_map(static_map: Dict[str, object], lat: float,
                     lon: float) -> Optional[Dict[str, float]]:
    """Pixel coordinates of a point within a previously fetched static map."""
    if not static_map:
        return None
    z = int(static_map["zoom"])
    size = int(static_map["tile_size"])
    origin = static_map["origin_tile"]
    fx, fy = _deg2tile(lat, lon, z)
    x = (fx - origin["x"]) * size
    y = (fy - origin["y"]) * size
    if not (-size <= x <= static_map["width"] + size):
        return None
    if not (-size <= y <= static_map["height"] + size):
        return None
    return {"x": x, "y": y}
