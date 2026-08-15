"""
Microsoft Location Inference Service client - credential-free.

Endpoint
--------
    POST https://inference.location.live.net/inferenceservice/v22/pox/GetLocationUsingFingerprint

This is the "plain old XML" (POX) transport used by the Windows Location
Provider.  The request body is gzip-compressed XML; the response is plain XML.
The service answers without any Authorization header - the response even says
so explicitly::

    Authorization-Result: Failure
    Authorization-Debug: Authorization Header not present

...while still returning a resolved position.  The request format below is
reproduced from live captures. ``tests/test_protocol.py`` pins the exact
shape with a sanitised sample.

Why this matters forensically
-----------------------------
Apple and Microsoft maintain *separate*, independently crowd-sourced
databases, and they answer fundamentally different questions:

  * Apple is asked "where is this access point?" and answers per access point.
  * Microsoft is asked "where is the device that can see all of these access
    points?" and answers with a single multilaterated position plus a radial
    uncertainty.

Because the two are independent in both data and method, agreement between
them is meaningful corroboration rather than a restatement of one source.
That is the entire basis of the confidence scoring.
"""

from __future__ import annotations

import datetime as dt
import gzip
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .net import Transport

ENDPOINT = ("https://inference.location.live.net/inferenceservice/v22/pox/"
            "GetLocationUsingFingerprint")

#: The ApplicationId the Windows Location Provider presents.  It is a fixed
#: public constant, not a secret and not per-user.
#:
#: It is also a gate rather than a free field.  Tested against the live
#: service:
#:
#:     this value                  -> 200 and a position
#:     any other valid GUID        -> 403
#:     element removed entirely    -> 403
#:     empty or not a GUID         -> 500
#:
#: So there is no scope for an examiner to substitute their own identifier,
#: and the tool does not offer one by default.
APPLICATION_ID = "e1e71f6b-2149-45f3-a298-a20682ab5017"

#: TrackingId, by contrast, is entirely ours.  Tested against the live service:
#:
#:     any valid GUID              -> 200, braces optional, case-insensitive
#:     the same GUID reused        -> 200, the server does not deduplicate
#:     element removed entirely    -> 200
#:     empty or not a GUID         -> 500
#:
#: The service echoes the value back verbatim in the response.  That makes it
#: worth setting carefully: a fresh GUID per request means every response in
#: the evidence package can be tied to exactly one request, which is why this
#: tool never reuses one.  `verify_tracking_id` below turns that echo into an
#: actual check rather than a decoration.

NS = "http://inference.location.live.com"

#: These headers are not cosmetic.  The service sits behind an Azure
#: Application Gateway that rejects the request with HTTP 403 before it ever
#: reaches the positioning service unless BOTH the unusual compound
#: Content-Type and the Windows-Location-Framework User-Agent are present.
#: Verified by ablation against the live service: removing either one produces
#: 403; removing Accept or Accept-Encoding does not.  Values are taken from a
#: capture of the genuine Windows location stack.
_HEADERS = {
    "Accept-Encoding": "identity",
    "Content-Type": "application/x-gzip-compressed; application/xml; charset=utf-8",
    "Content-Encoding": "gzip",
    "Accept": "application/xml",
    "User-Agent": "Windows-Location-Framework/4.2",
    "Connection": "close",
}

#: Uncertainty at or above this is the service telling us it fell back to a
#: coarse method rather than actually positioning the fingerprint.
IP_FALLBACK_UNCERTAINTY_M = 50000.0


@dataclass
class InferenceResult:
    """A parsed GetLocationUsingFingerprint response."""

    response_status: str = ""
    resolver_status: str = ""
    resolver_source: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    radial_uncertainty_m: Optional[float] = None
    crowd_sourcing_level: str = ""
    server_utc: str = ""
    tracking_id: str = ""
    fault: Optional[str] = None
    beacons_submitted: int = 0
    #: Set once the echoed TrackingId has been compared with the one sent.
    #: None means the check was not performed.
    tracking_id_verified: Optional[bool] = None

    @property
    def has_coordinates(self) -> bool:
        return (
            self.latitude is not None
            and self.longitude is not None
            and -90.0 <= self.latitude <= 90.0
            and -180.0 <= self.longitude <= 180.0
            and not (self.latitude == 0.0 and self.longitude == 0.0)
        )

    @property
    def ip_fallback(self) -> bool:
        """
        True when the service geolocated *us* instead of the fingerprint.

        When Microsoft cannot position the submitted beacons it does not say
        so - it silently answers with an IP-derived position, flagged only by
        ``ResolverStatus Source="IP"`` and a huge RadialUncertainty (100 km
        observed).  Verified with a control: the nonexistent BSSID
        00:00:00:00:00:01 returns exactly this, at the examiner's own city.

        This is the single most dangerous failure mode in the whole tool. Such
        a result looks entirely plausible - correct city, sensible-looking
        coordinates - and would appear to independently corroborate the Apple
        position while actually describing the examiner's internet connection.
        It must never be treated as a positioning result.
        """
        if (self.resolver_source or "").strip().upper() == "IP":
            return True
        return (self.radial_uncertainty_m or 0) >= IP_FALLBACK_UNCERTAINTY_M

    @property
    def located(self) -> bool:
        """A usable, Wi-Fi-derived position."""
        return self.has_coordinates and not self.ip_fallback

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": "microsoft",
            "ip_fallback": self.ip_fallback,
            "has_coordinates": self.has_coordinates,
            "response_status": self.response_status,
            "resolver_status": self.resolver_status,
            "resolver_source": self.resolver_source,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "radial_uncertainty_m": self.radial_uncertainty_m,
            "crowd_sourcing_level": self.crowd_sourcing_level,
            "server_utc": self.server_utc,
            "tracking_id": self.tracking_id,
            "tracking_id_verified": self.tracking_id_verified,
            "fault": self.fault,
            "beacons_submitted": self.beacons_submitted,
            "located": self.located,
        }


def verify_tracking_id(result: "InferenceResult", sent: str) -> bool:
    """
    Confirm the response belongs to the request that was sent.

    The service echoes the TrackingId back. Comparing it is cheap and it is the
    only thing in the exchange that ties a particular answer to a particular
    question. Without the check, a response served from a cache, crossed over
    by a proxy, or replayed from an earlier run would be accepted silently -
    and in an evidential context "this position came from that request" is
    precisely the claim being made.

    Sets `tracking_id_verified` on the result and returns it. A mismatch also
    records a fault, because a position that cannot be tied to its request is
    not safe to rely on.
    """
    got = (result.tracking_id or "").strip().strip("{}").lower()
    want = (sent or "").strip().strip("{}").lower()
    if not got or not want:
        result.tracking_id_verified = None
        return False
    ok = got == want
    result.tracking_id_verified = ok
    if not ok:
        result.fault = (
            "Response TrackingId %r does not match the request TrackingId %r. "
            "This response cannot be tied to this request and has been "
            "rejected." % (got, want))
    return ok


def _msft_mac(mac: str) -> str:
    """
    Microsoft wants dash-separated lowercase: 00-00-5e-00-53-a6.

    Normalisation itself lives in one place - apple.canonical_bssid - so that
    every entry point accepts exactly the same set of notations. Three
    near-identical parsers is how one of them ends up rejecting an address the
    others accept.
    """
    from .apple import canonical_bssid
    return canonical_bssid(mac).replace(":", "-")


def _xml_attr(value) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _ts() -> str:
    """The exact timestamp shape the service expects: ...+00:00, not Z."""
    now = dt.datetime.now(dt.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % (now.microsecond // 1000) + "+00:00"


#: The service advertises `api-supported-versions: 2.1, 2.2`, and both answer.
#: v2.2 is the current path used by Windows; v2.1 is the older one and is kept
#: available because a service can withdraw a version without notice.
API_VERSIONS = {
    "v22": ("https://inference.location.live.net/inferenceservice/v22/pox/"
            "GetLocationUsingFingerprint"),
    "v21": ("https://inference.location.live.net/inferenceservice/v21/Pox/"
            "GetLocationUsingFingerprint"),
}


def build_request(beacons: Sequence[Tuple[str, Optional[int]]],
                  timestamp: Optional[str] = None,
                  tracking_id: Optional[str] = None,
                  application_id: Optional[str] = None,
                  device_profile: Optional[Dict[str, str]] = None
                  ) -> Tuple[bytes, bytes, str]:
    """
    Build the fingerprint request.

    `beacons` is a sequence of (bssid, rssi_dbm).  A missing RSSI is omitted
    rather than guessed - inventing a signal strength would be fabricating
    evidence, and the service tolerates the attribute being absent.

    `timestamp` is the time the beacons were *observed*, not the time of the
    query. They are the same thing for a live scan, but not when positioning an
    access point recovered from a registry hive or an event log months later.
    The service does not appear to use it, but stating the observation time
    truthfully costs nothing and misstating it in an evidential request is not
    defensible.

    `device_profile` emits the optional `<DeviceProfile>` element that the
    Windows location stack sends (ClientGuid, Platform, DeviceType, OSVersion,
    LFVersion, ExtendedDeviceInfo). It is omitted by default: it identifies the
    querying machine, and there is no reason to hand that to a third party
    during an investigation unless an examiner deliberately chooses to.

    Returns (xml_bytes, gzipped_bytes, tracking_id).
    """
    ts = timestamp or _ts()
    tid = tracking_id or str(uuid.uuid4())

    header = [
        "    <Timestamp>%s</Timestamp>" % ts,
        "    <ApplicationId>%s</ApplicationId>" % (application_id or APPLICATION_ID),
        "    <TrackingId>{%s}</TrackingId>" % tid,
    ]
    if device_profile:
        attrs = " ".join('%s="%s"' % (k, _xml_attr(v))
                         for k, v in device_profile.items() if v is not None)
        header.append("    <DeviceProfile %s />" % attrs)

    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<GetLocationUsingFingerprint xmlns="%s">' % NS,
        "  <RequestHeader>",
    ] + header + [
        "  </RequestHeader>",
        "  <BeaconFingerprint>",
        "    <Timestamp>%s</Timestamp>" % ts,
        "    <Detections>",
    ]
    for mac, rssi in beacons:
        bss = _msft_mac(mac)
        if rssi is None:
            lines.append('      <Wifi7 BssId="%s" />' % bss)
        else:
            lines.append('      <Wifi7 BssId="%s" rssi="%d" />' % (bss, int(rssi)))
    lines += [
        "    </Detections>",
        "  </BeaconFingerprint>",
        "</GetLocationUsingFingerprint>",
        "",
    ]
    xml = "\n".join(lines).encode("utf-8")
    # mtime=0 so the same fingerprint always produces byte-identical gzip,
    # which makes the request hash reproducible for verification.
    packed = gzip.compress(xml, compresslevel=9, mtime=0)
    return xml, packed, tid


def parse_response(body: bytes) -> InferenceResult:
    """Parse the POX response.  Tolerates faults and partial documents."""
    res = InferenceResult()
    text = body.decode("utf-8", "replace").lstrip("﻿")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        res.fault = "XML parse error: %s" % e
        snippet = re.sub(r"\s+", " ", text)[:400]
        if snippet:
            res.fault += " | body starts: %s" % snippet
        return res

    def find(tag: str):
        return root.find(".//{%s}%s" % (NS, tag)) if root is not None else None

    node = find("ResponseStatus")
    if node is not None and node.text:
        res.response_status = node.text.strip()

    node = find("ResolverStatus")
    if node is not None:
        res.resolver_status = node.get("Status", "")
        res.resolver_source = node.get("Source", "")

    node = find("ResolvedPosition")
    if node is not None:
        for attr, key in (("Latitude", "latitude"), ("Longitude", "longitude"),
                          ("Altitude", "altitude")):
            raw = node.get(attr)
            if raw not in (None, ""):
                try:
                    setattr(res, key, float(raw))
                except ValueError:
                    pass

    node = find("RadialUncertainty")
    if node is not None and node.text:
        try:
            res.radial_uncertainty_m = float(node.text.strip())
        except ValueError:
            pass

    node = find("ExtendedV21Result")
    if node is not None:
        res.crowd_sourcing_level = node.get("CrowdSourcingLevel", "")
        res.server_utc = node.get("ServerUtcTime", "")

    node = find("TrackingId")
    if node is not None and node.text:
        res.tracking_id = node.text.strip()

    if res.ip_fallback and res.has_coordinates:
        res.fault = (
            "The service did not position the submitted beacons. It returned an "
            "IP-derived location (ResolverStatus Source=%r, radial uncertainty "
            "%s m), which describes the internet connection this query was sent "
            "from, not the target. Discarded."
            % (res.resolver_source or "IP", res.radial_uncertainty_m))
        return res

    if not res.located and res.fault is None:
        # Surface whatever the service actually said instead of a bare "no".
        parts = []
        if res.response_status:
            parts.append("ResponseStatus=%s" % res.response_status)
        if res.resolver_status:
            parts.append("ResolverStatus=%s" % res.resolver_status)
        for tag in ("faultstring", "Message", "ErrorCode", "Error"):
            n = root.find(".//{*}%s" % tag)
            if n is not None and n.text:
                parts.append("%s=%s" % (tag, n.text.strip()))
        if parts:
            res.fault = "; ".join(parts)
        elif not res.response_status:
            res.fault = "no position in response"
    return res


#: The service degrades on very large fingerprints; the Windows provider itself
#: submits a few dozen beacons.  Keep to the observed working envelope.
MAX_BEACONS = 60


def query(transport: Transport,
          beacons: Iterable[Tuple[str, Optional[int]]],
          endpoint: Optional[str] = None,
          observed_at: Optional[str] = None,
          application_id: Optional[str] = None,
          device_profile: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    """
    Submit a beacon fingerprint and return the inferred position.

    Beacons are ordered by descending signal strength before truncation, so if
    we must drop some we drop the weakest and least informative first.
    """
    items: List[Tuple[str, Optional[int]]] = []
    invalid: List[str] = []
    seen = set()
    for mac, rssi in beacons:
        try:
            norm = _msft_mac(mac)
        except ValueError:
            invalid.append(mac)
            continue
        if norm in seen:
            continue
        seen.add(norm)
        items.append((norm, rssi))

    items.sort(key=lambda b: (b[1] is None, -(b[1] if b[1] is not None else -999)))
    truncated = max(0, len(items) - MAX_BEACONS)
    items = items[:MAX_BEACONS]

    url = endpoint or ENDPOINT
    out: Dict[str, object] = {
        "source": "microsoft",
        "endpoint": url,
        "observed_at": observed_at,
        "beacons_submitted": len(items),
        "beacons_truncated": truncated,
        "invalid_input": invalid,
    }

    if not items:
        out["result"] = InferenceResult(fault="no valid beacons to submit")
        return out

    xml, packed, tid = build_request(items, timestamp=observed_at,
                                     application_id=application_id,
                                     device_profile=device_profile)
    ex = transport.fetch(url, label="microsoft.inference", method="POST",
                         body=packed, headers=_HEADERS)

    out.update({
        "exhibit_seq": ex.seq,
        "status": ex.status,
        "error": ex.error,
        "tracking_id": tid,
        "request_xml_bytes": len(xml),
        "request_gzip_bytes": len(packed),
        "request_xml": xml.decode("utf-8", "replace"),
        "authorization_result": ex.response_headers.get("Authorization-Result", ""),
        "api_supported_versions": ex.response_headers.get("api-supported-versions", ""),
    })

    if ex.ok and ex.response_body:
        res = parse_response(ex.response_body)
        verify_tracking_id(res, tid)
    else:
        res = InferenceResult(fault=ex.error or "HTTP %s" % ex.status)
    res.beacons_submitted = len(items)
    out["result"] = res
    return out


def probe_replicates(transport: Transport, groups: Sequence[Sequence[str]],
                     origin: str = "Apple neighbour cloud") -> Dict[str, object]:
    """
    Run several locality probes over *disjoint* access point sets.

    A single probe tells you where Microsoft computes for one set of access
    points.  Repeating it with sets that share no members turns that into a
    replication test: each group is different evidence, multilaterated
    independently, so convergence is not an artefact of one lucky record and
    cannot be explained by a single mistaken database entry.

    This is materially stronger than querying access points one at a time.
    Individual queries establish that two databases hold similar coordinates
    for the same devices; replicates establish that Microsoft's own
    multilateration lands in the same place from several independent starting
    points.  A wide spread across the groups is a warning that the neighbour
    cloud is not describing one locality at all.
    """
    from .geo import centroid, haversine_m

    def one(indexed):
        i, group = indexed
        items, seen = [], set()
        for mac in group:
            try:
                norm = _msft_mac(mac)
            except ValueError:
                continue
            if norm not in seen:
                seen.add(norm)
                items.append((norm, None))
        items = items[:MAX_BEACONS]
        if not items:
            return None
        xml, packed, tid = build_request(items)
        ex = transport.fetch(ENDPOINT, label="microsoft.replicate%02d" % i,
                             method="POST", body=packed, headers=_HEADERS,
                             timeout=30)
        if ex.ok and ex.response_body:
            res = parse_response(ex.response_body)
            verify_tracking_id(res, tid)
        else:
            res = InferenceResult(fault=ex.error or "HTTP %s" % ex.status)
        res.beacons_submitted = len(items)
        return {"group": i, "bssids": [m for m, _r in items],
                "size": len(items), "exhibit_seq": ex.seq,
                "tracking_id": tid, "result": res.to_dict()}

    # The groups are independent by construction, so they are asked together.
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [r for r in pool.map(one, enumerate(groups, 1)) if r]
    results.sort(key=lambda r: r["group"])

    located = [r for r in results if r["result"]["located"]]
    pts = [(r["result"]["latitude"], r["result"]["longitude"]) for r in located]

    spread = 0.0
    if len(pts) >= 2:
        spread = max(haversine_m(pts[i][0], pts[i][1], pts[j][0], pts[j][1])
                     for i in range(len(pts)) for j in range(i + 1, len(pts)))
    consensus = None
    if pts:
        lat, lon = centroid(pts)
        consensus = {"latitude": lat, "longitude": lon}

    return {
        "source": "microsoft-replicate-probes",
        "is_observation": False,
        "origin": origin,
        "groups_submitted": len(results),
        "groups_resolved": len(located),
        "max_separation_m": round(spread, 1),
        "consensus": consensus,
        "disjoint": True,
        "caveat": ("Derived probes, not observations. Each group is a disjoint "
                   "subset of %s; no device belonging to this examination "
                   "observed any of them together. Agreement between groups "
                   "shows that Microsoft's independent database resolves the "
                   "same locality from several non-overlapping sets of access "
                   "points." % origin),
        "results": results,
    }


def corroborate_each(transport: Transport, bssids: Sequence[str],
                     limit: int = 8) -> Dict[str, object]:
    """
    Ask Microsoft about each access point individually.

    The service accepts a single-beacon fingerprint, so each BSSID can be put
    to it on its own.  Where Microsoft holds a record, this yields a genuine
    per-access-point cross-check against Apple's per-access-point answer -
    substantially stronger than comparing one fused position to another,
    because the two providers are being asked the identical question about the
    identical device.

    Where Microsoft holds no record it falls back to IP geolocation, which is
    detected and discarded rather than being mistaken for agreement.
    """
    jobs = []
    for mac in list(bssids)[:limit]:
        try:
            jobs.append((mac, _msft_mac(mac)))
        except ValueError:
            continue

    def ask(job):
        mac, norm = job
        _xml, packed, tid = build_request([(norm, None)])
        ex = transport.fetch(
            ENDPOINT, label="microsoft.single.%s" % norm.replace("-", ""),
            method="POST", body=packed, headers=_HEADERS, timeout=25)
        if ex.ok and ex.response_body:
            res = parse_response(ex.response_body)
            verify_tracking_id(res, tid)
        else:
            res = InferenceResult(fault=ex.error or "HTTP %s" % ex.status)
        res.beacons_submitted = 1
        return {"bssid": mac, "exhibit_seq": ex.seq, "status": ex.status,
                "tracking_id": tid, "result": res.to_dict()}

    # Each of these is an independent question, so they are asked a few at a
    # time rather than one after another. Modest concurrency: this is a free
    # service and twenty simultaneous connections would be discourteous.
    with ThreadPoolExecutor(max_workers=5) as pool:
        results: List[Dict[str, object]] = [r for r in pool.map(ask, jobs) if r]
    results.sort(key=lambda r: r["exhibit_seq"])
    known = [r for r in results if r["result"]["located"]]
    return {
        "source": "microsoft-per-bssid",
        "queried": len(results),
        "known_to_microsoft": len(known),
        "discarded_ip_fallback": sum(
            1 for r in results if r["result"]["ip_fallback"]),
        "results": results,
    }
