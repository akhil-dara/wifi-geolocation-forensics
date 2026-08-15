"""
Apple Location Services (WLoc) client - credential-free.

Endpoint
--------
    POST https://gs-loc.apple.com/clls/wloc

Wire format
-----------
The body is a small binary envelope wrapping a Protocol Buffers message::

    00 01                      envelope version
    00 05  "en_US"             locale,      uint16-BE length prefixed
    00 13  "com.apple.locationd"  bundle id, uint16-BE length prefixed
    00 0A  "8.1.12B411"        client version, uint16-BE length prefixed
    00 00 00 01                request kind
    <uint32-BE>                length of the protobuf payload
    <protobuf>

Every public implementation of this protocol hard-codes the payload length as a
single byte, because they all copied a snippet that only ever sends one BSSID
and therefore never exceeds 255 bytes.  Live testing against the service
confirms the length is in fact a 4-byte big-endian integer whose top three
bytes were being mistaken for padding.  Using the full width lets us submit an
entire scan in one request: 44 BSSIDs in a single call returns 443 access
points.

Request protobuf::

    message Query {
        repeated AP  aps          = 2;   // AP { string bssid = 1; }
        optional int64 unknown    = 3;
        optional int64 neighbours = 4;   // see below
    }

Field 4 is the number of *neighbouring* access points to return.  This was
determined empirically:

    field 4 = 1    ->   2 results      <- what every public tool sends
    field 4 = 100  -> 101 results
    field 4 = 255  -> 256 results
    field 4 = 400  -> 401 results      (server-side maximum)
    field 4 = 0    -> 401 results
    field 4 omitted-> 401 results      (default)

So the widely-copied `\\x18\\x00\\x20\\x01` suffix silently throttles the
neighbour harvest to a single access point.  This client defaults to 400.

Response protobuf (after a 10-byte envelope)::

    message Result {
        repeated AP aps = 2;
    }
    message AP {
        string   bssid    = 1;
        Location location = 2;
        int64    unknown  = 21;     // present on every record; meaning unsettled
        int64    unknown  = 22;     // present on every record; meaning unsettled
    }
    message Location {
        int64 latitude       = 1;   // degrees * 1e8, int64 (NOT zigzag)
        int64 longitude      = 2;   // degrees * 1e8, int64 (NOT zigzag)
        int64 accuracy_m     = 3;   // horizontal accuracy, metres
        int64 unknown        = 4;
        int64 altitude_m     = 5;
        int64 altitude_acc_m = 6;
        int64 unknown        = 11;
        int64 unknown        = 12;
    }

Published schemas for this protocol commonly show a `channel` field on the AP
message.  Against the live service in 2026 no such field is returned: the only
AP-level fields present are 1, 2, 21 and 22, and 21/22 are variously described
elsewhere as "channel" and "course accuracy".  Rather than print a channel
number that may be neither, the tool reports the radio channel from its own
scan and preserves 21/22 verbatim as uninterpreted values.

An access point Apple has never seen comes back with latitude and longitude
both equal to -180.0 exactly.  That is a sentinel, not a coordinate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from . import proto
from .net import Transport

ENDPOINT = "https://gs-loc.apple.com/clls/wloc"

# Apple's location daemon as shipped in iOS 8.1.  The service still honours it
# and it is what every published capture uses, so we keep it for fidelity.
_LOCALE = "en_US"
_BUNDLE = "com.apple.locationd"
_CLIENT_VERSION = "8.1.12B411"

_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "*/*",
    "Accept-Charset": "utf-8",
    "Accept-Language": "en-us",
    "Accept-Encoding": "gzip",
    "User-Agent": "locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0",
}

#: Apple returns this for a BSSID it has no record of.
SENTINEL = -180.0

#: Server-side cap on neighbours per request.
MAX_NEIGHBOURS = 400

_MAC_RE = re.compile(r"^[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}$")


@dataclass
class AccessPoint:
    """One access point as reported by Apple."""

    bssid: str                       # canonical, zero-padded, lowercase
    bssid_as_returned: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_m: Optional[int] = None
    altitude_m: Optional[int] = None
    altitude_accuracy_m: Optional[int] = None
    is_queried: bool = False         # did we explicitly ask about this one
    #: Every numeric field Apple sent that we do not claim to understand,
    #: preserved so nothing is discarded and nothing is misrepresented.
    #: AP-level fields are offset by 1000 to keep them distinct from the
    #: Location-level ones.
    raw_fields: Dict[int, int] = field(default_factory=dict)

    @property
    def located(self) -> bool:
        return (
            self.latitude is not None
            and self.longitude is not None
            and not (self.latitude == SENTINEL and self.longitude == SENTINEL)
            and -90.0 <= self.latitude <= 90.0
            and -180.0 <= self.longitude <= 180.0
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "bssid": self.bssid,
            "bssid_as_returned": self.bssid_as_returned,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "accuracy_m": self.accuracy_m,
            "altitude_m": self.altitude_m,
            "altitude_accuracy_m": self.altitude_accuracy_m,
            "queried": self.is_queried,
            "located": self.located,
            # Exactly what came back, unrounded and uninterpreted.
            "raw": {
                "latitude_e8": (int(round(self.latitude * 1e8))
                                if self.latitude is not None else None),
                "longitude_e8": (int(round(self.longitude * 1e8))
                                 if self.longitude is not None else None),
                "fields": {str(k): v for k, v in sorted(self.raw_fields.items())},
            },
        }


# --------------------------------------------------------------------------
# BSSID normalisation
# --------------------------------------------------------------------------
#: Every separator seen in the wild: colons (IEEE/Linux), hyphens (Windows and
#: Microsoft's own API), dots (Cisco's 4-4-4 grouping), spaces (copied out of
#: spreadsheets and log viewers), and nothing at all.
_MAC_SEPARATORS = ":-. \t _"


def canonical_bssid(mac: str) -> str:
    """
    Normalise any commonly used MAC notation to `aa:bb:cc:dd:ee:ff`.

    Investigators paste addresses out of whatever tool produced them, and the
    notations are not interchangeable between vendors:

        00:1a:2b:03:04:05   IEEE / Linux / Apple
        00-1A-2B-03-04-05   Windows, and Microsoft's positioning API
        001a.2b03.0405      Cisco, grouped in fours
        00 1a 2b 03 04 05   pasted from a spreadsheet or a log viewer
        001a2b030405        bare
        0:1a:2b:3:4:5       zero-padding dropped, as Apple returns them

    All of these name the same access point, so all of them are accepted.
    Rejecting a valid address because of its punctuation would send an
    investigator hunting for a fault that is not there.
    """
    text = str(mac).strip().lower()
    if not text:
        raise ValueError("not a MAC address: %r" % mac)

    # Structured first: split on any known separator and keep the groups. This
    # correctly handles the Cisco form, where the groups are four hex digits
    # rather than two.
    parts = [p for p in re.split("[%s]" % re.escape(_MAC_SEPARATORS), text) if p]
    if len(parts) == 6 and all(re.fullmatch(r"[0-9a-f]{1,2}", p) for p in parts):
        return ":".join(p.zfill(2) for p in parts)
    if len(parts) == 3 and all(re.fullmatch(r"[0-9a-f]{4}", p) for p in parts):
        flat = "".join(parts)
        return ":".join(flat[i:i + 2] for i in range(0, 12, 2))

    # Otherwise fall back to the hex digits alone, which covers the bare form
    # and any mixed punctuation.
    flat = re.sub(r"[^0-9a-f]", "", text)
    if len(flat) == 12 and len(re.sub(r"[0-9a-f%s]" % re.escape(_MAC_SEPARATORS),
                                      "", text)) == 0:
        return ":".join(flat[i:i + 2] for i in range(0, 12, 2))

    raise ValueError(
        "not a MAC address: %r (expected 12 hex digits, optionally separated "
        "by colons, hyphens, dots or spaces)" % mac)


def is_bssid(text: str) -> bool:
    try:
        canonical_bssid(text)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# request construction
# --------------------------------------------------------------------------
def _lp16(text: str) -> bytes:
    raw = text.encode("utf-8")
    return len(raw).to_bytes(2, "big") + raw


def build_request(bssids: Iterable[str], neighbours: int = MAX_NEIGHBOURS) -> bytes:
    """Build the complete request body for one or more BSSIDs."""
    macs = [canonical_bssid(b) for b in bssids]
    if not macs:
        raise ValueError("at least one BSSID is required")

    payload = b""
    for mac in macs:
        ap = proto.field_string(1, mac)
        payload += proto.field_bytes(2, ap)
    payload += proto.field_varint(3, 0)
    # 0 and "omitted" both mean "give me the maximum"; anything in 1..400 is a
    # literal cap.  Clamp so a caller cannot accidentally ask for 1.
    n = 0 if neighbours >= MAX_NEIGHBOURS else max(0, int(neighbours))
    payload += proto.field_varint(4, n)

    envelope = (
        b"\x00\x01"
        + _lp16(_LOCALE)
        + _lp16(_BUNDLE)
        + _lp16(_CLIENT_VERSION)
        + b"\x00\x00\x00\x01"
        + len(payload).to_bytes(4, "big")
    )
    return envelope + payload


# --------------------------------------------------------------------------
# response parsing
# --------------------------------------------------------------------------
def _parse_location(buf: bytes) -> Tuple[Dict[str, Optional[float]], Dict[int, int]]:
    vals: Dict[int, int] = {}
    for fnum, wire, value in proto.iter_fields(buf):
        if wire == proto.WIRE_VARINT:
            vals[fnum] = proto.as_signed64(value)
    out = {
        "latitude": vals[1] / 1e8 if 1 in vals else None,
        "longitude": vals[2] / 1e8 if 2 in vals else None,
        "accuracy_m": vals.get(3),
        "altitude_m": vals.get(5),
        "altitude_accuracy_m": vals.get(6),
    }
    return out, vals


def _find_payload_offset(body: bytes) -> int:
    """
    Locate where the protobuf begins in the response.

    The response carries a 10-byte envelope.  Rather than trusting that
    constant blindly - a server-side change would turn every result into
    garbage - we verify that the message parses from that offset, and if it
    does not we scan a small window for an offset that does.
    """
    candidates = [10] + [i for i in range(0, 24) if i != 10]
    for off in candidates:
        if off >= len(body):
            continue
        try:
            fields = list(proto.iter_fields(body[off:]))
        except proto.ProtoError:
            continue
        # A valid result is dominated by field 2 (repeated AP) records.
        if fields and sum(1 for f, w, _ in fields if f == 2 and w == proto.WIRE_LEN):
            return off
    return 10


def parse_response(body: bytes, queried: Optional[Iterable[str]] = None
                   ) -> Tuple[List[AccessPoint], int]:
    """Decode a WLoc response.  Returns (access_points, payload_offset)."""
    asked = {canonical_bssid(b) for b in (queried or [])}
    offset = _find_payload_offset(body)
    aps: List[AccessPoint] = []

    for fnum, wire, value in proto.iter_fields(body[offset:]):
        if fnum != 2 or wire != proto.WIRE_LEN:
            continue
        mac_raw = ""
        loc: Dict[str, Optional[float]] = {}
        raw_fields: Dict[int, int] = {}
        ap_extra: Dict[int, int] = {}
        for sub_f, sub_w, sub_v in proto.iter_fields(value):  # type: ignore[arg-type]
            if sub_f == 1 and sub_w == proto.WIRE_LEN:
                mac_raw = bytes(sub_v).decode("utf-8", "replace")
            elif sub_f == 2 and sub_w == proto.WIRE_LEN:
                loc, raw_fields = _parse_location(bytes(sub_v))
            elif sub_w == proto.WIRE_VARINT:
                # Fields 21 and 22 are present on every record but their meaning
                # is not settled - published schemas variously call field 21
                # "channel" and "course accuracy".  Rather than pick one and
                # print a possibly wrong channel number, both are preserved
                # verbatim and reported as uninterpreted.
                ap_extra[sub_f] = proto.as_signed64(int(sub_v))
        raw_fields = {**{1000 + k: v for k, v in ap_extra.items()}, **raw_fields}
        if not mac_raw:
            continue
        try:
            mac = canonical_bssid(mac_raw)
        except ValueError:
            mac = mac_raw.lower()
        aps.append(AccessPoint(
            bssid=mac,
            bssid_as_returned=mac_raw,
            latitude=loc.get("latitude"),
            longitude=loc.get("longitude"),
            accuracy_m=loc.get("accuracy_m"),
            altitude_m=loc.get("altitude_m"),
            altitude_accuracy_m=loc.get("altitude_accuracy_m"),
            is_queried=mac in asked,
            raw_fields=raw_fields,
        ))
    return aps, offset


# --------------------------------------------------------------------------
# high level
# --------------------------------------------------------------------------
#: Apple accepts a bounded number of BSSIDs per request; keep batches modest so
#: one failure does not cost the whole scan.
BATCH_SIZE = 25


def query(transport: Transport, bssids: Iterable[str],
          neighbours: int = MAX_NEIGHBOURS) -> Dict[str, object]:
    """
    Resolve one or more BSSIDs.

    Returns a dict with the deduplicated access points, the ones we explicitly
    asked about, and per-batch diagnostics.  Never raises on network failure.
    """
    macs: List[str] = []
    invalid: List[str] = []
    for b in bssids:
        try:
            mac = canonical_bssid(b)
        except ValueError:
            invalid.append(b)
            continue
        if mac not in macs:
            macs.append(mac)

    merged: Dict[str, AccessPoint] = {}
    batches: List[Dict[str, object]] = []

    for start in range(0, len(macs), BATCH_SIZE):
        chunk = macs[start:start + BATCH_SIZE]
        body = build_request(chunk, neighbours)
        ex = transport.fetch(
            ENDPOINT, label="apple.wloc.batch%02d" % (start // BATCH_SIZE + 1),
            method="POST", body=body, headers=_HEADERS,
        )
        info: Dict[str, object] = {
            "batch": start // BATCH_SIZE + 1,
            "requested": chunk,
            "exhibit_seq": ex.seq,
            "status": ex.status,
            "error": ex.error,
            "request_bytes": len(body),
            "response_bytes": len(ex.response_body),
        }
        if ex.ok and ex.response_body:
            try:
                aps, offset = parse_response(ex.response_body, chunk)
                info["payload_offset"] = offset
                info["access_points"] = len(aps)
                for ap in aps:
                    prev = merged.get(ap.bssid)
                    if prev is None or (ap.located and not prev.located):
                        ap.is_queried = ap.is_queried or (prev.is_queried if prev else False)
                        merged[ap.bssid] = ap
                    elif ap.is_queried:
                        prev.is_queried = True
            except proto.ProtoError as e:
                info["parse_error"] = str(e)
        batches.append(info)

    all_aps = list(merged.values())
    queried_aps = [a for a in all_aps if a.is_queried]
    located = [a for a in all_aps if a.located]

    return {
        "source": "apple",
        "endpoint": ENDPOINT,
        "requested": macs,
        "invalid_input": invalid,
        "neighbours_requested": neighbours,
        "access_points": all_aps,
        "queried_access_points": queried_aps,
        "queried_located": [a for a in queried_aps if a.located],
        "unknown_to_apple": [a.bssid for a in queried_aps if not a.located],
        "never_returned": [m for m in macs if m not in merged],
        "total_returned": len(all_aps),
        "total_located": len(located),
        "batches": batches,
    }
