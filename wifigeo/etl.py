"""
BSSID recovery from Windows wireless event traces (`.etl`).

Windows runs an autologger called `WiFiSession` on every boot, writing to
``C:\\Windows\\System32\\LogFiles\\WMI\\Wifi.etl``.  It records the results of
each radio scan, so it holds the BSSIDs of access points that were audible to
the machine, with their channel and signal strength - including ones that are
no longer on the air.

Two important limits, both measured rather than assumed:

* The file is a **circular** buffer (default 8 MB).  It wraps continuously, so
  a busy machine retains only a few hours.  It is a record of where a machine
  was recently, not a history.
* Roughly three quarters of the events are WPP traces from ``WdiWiFi.sys``
  which carry no format information.  Decoding those needs TMF files Microsoft
  does not ship.  The BSSIDs live in the decodable remainder.

Reading it
----------
`netsh trace convert` applies the installed manifests and renders scan results
as a tab-delimited table, which is the most complete result - but it only
exists on Windows, and an analyst working a disk image usually is not on
Windows.  So this module reads the container directly, with no dependencies
and no OS requirement, and `parse_rendered` handles converted output when it
is available.

Nothing here decodes the full ETL event stream.  It recovers the two record
shapes that carry a BSSID and validates every candidate before returning it,
because a naive MAC-shaped regex over 8 MB of binary returns tens of thousands
of false hits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

__all__ = ["EtlBeacon", "EtlResult", "parse_etl", "parse_rendered", "looks_like_etl"]

#: `WMI_BUFFER_HEADER` begins each buffer; the first word is the buffer size.
_ETL_BUFFER_SIZES = {0x8000, 0x10000, 0x14000, 0x20000}

#: Legal 802.11 channel centre frequencies, 2.4 GHz and 5/6 GHz.
_FREQ_24 = {2412 + 5 * n for n in range(0, 12)} | {2484}
_FREQ_5 = {5000 + 5 * n for n in range(0, 400)}
_FREQ_6 = {5950 + 5 * n for n in range(0, 500)}
_VALID_FREQ = _FREQ_24 | _FREQ_5 | _FREQ_6

#: Receive levels a real scan reports.  Anything outside is a decode error.
_RSSI_RANGE = (-100, -20)

_MAC_TEXT = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")

#: A rendered scan row: name, name-as-hex, BSSID, frequency, quality, RSSI.
_RENDERED_ROW = re.compile(
    r"^(?P<ssid>[^\t]{0,32})\t(?P<hex>[0-9A-Fa-f]*)\t"
    r"(?P<bssid>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\t"
    r"(?P<freq>\d{3,5})\t(?P<qual>\d{1,3})\t(?P<rssi>-?\d{1,3})",
    re.MULTILINE,
)

#: Field names whose value is this machine's own radio, never an access point.
_HOST_FIELDS = ("LocalMac", "LocalAddr", "pSupplicantAddress", "Local MAC Address")

#: The scan record tags each BSS with whether the sweep had seen it before.
#: The tag sits immediately in front of the address, which is what separates a
#: real record from six bytes that merely look like one.
_BSS_STATE_MARKERS = (b"EXISTING\x00", b"NEW\x00")

#: An adapter's own MAC follows its description string.  Matching the vendor
#: name is what keeps this machine's radio out of the access point list when
#: the caller has not supplied it.
_ADAPTER_VENDORS = (
    "Intel(R)", "Realtek", "Qualcomm", "Broadcom", "MediaTek", "Marvell",
    "Atheros", "Ralink", "Killer", "Wi-Fi Direct Virtual", "Network Adapter",
)


def _norm(mac: str) -> str:
    return mac.lower().replace("-", ":")


def _is_broadcastish(mac: str) -> bool:
    h = mac.replace(":", "")
    if h in ("000000000000", "ffffffffffff"):
        return True
    if h.startswith(("01005e", "3333", "0180c2")):
        return True
    return int(h[0:2], 16) & 0x01 == 1        # group bit: never a BSSID


@dataclass
class EtlBeacon:
    """One access point recovered from a trace."""

    bssid: str
    ssid: Optional[str] = None
    rssi_dbm: Optional[int] = None
    freq_mhz: Optional[int] = None
    #: How this was recovered, for the evidence trail.
    methods: Set[str] = field(default_factory=set)
    #: Byte offsets it was seen at, so a reviewer can go and look.
    offsets: List[int] = field(default_factory=list)
    occurrences: int = 0

    @property
    def locally_administered(self) -> bool:
        return bool(int(self.bssid[0:2], 16) & 0x02)

    @property
    def band(self) -> Optional[str]:
        if self.freq_mhz is None:
            return None
        if self.freq_mhz < 2500:
            return "2.4 GHz"
        return "6 GHz" if self.freq_mhz >= 5950 else "5 GHz"

    @property
    def corroboration(self) -> int:
        """How many independent record shapes produced this address."""
        return len(self.methods)


@dataclass
class EtlResult:
    beacons: List[EtlBeacon]
    #: MACs identified as the host's own radio and deliberately excluded.
    host_macs: Set[str] = field(default_factory=set)
    #: Populated when the container does not look like an ETL at all.
    warnings: List[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.beacons)

    def confident(self) -> List[EtlBeacon]:
        """Beacons recovered by more than one record shape.

        Measured against an independently verified set from a live 8 MB
        trace, every multiply-corroborated address was genuine, while the
        few false hits appeared in exactly one shape.  `beacons` is the right
        list to look up - a wrong address simply fails to resolve - and this
        is the right list to put in a report.
        """
        return [b for b in self.beacons
                if b.corroboration > 1 or b.rssi_dbm is not None]


def looks_like_etl(blob: bytes) -> bool:
    if len(blob) < 0x40:
        return False
    return int.from_bytes(blob[0:4], "little") in _ETL_BUFFER_SIZES


# --------------------------------------------------------------------------
# record shape 1: length-prefixed SSID following the address
# --------------------------------------------------------------------------

def _read_record(blob: bytes, off: int) -> Optional[Tuple[str, str]]:
    """Decode ``[BSSID:6][len:u16 LE][SSID]`` at `off`, or return None."""
    if off < 0 or off + 8 > len(blob):
        return None
    ln = int.from_bytes(blob[off + 6:off + 8], "little")
    if not 1 <= ln <= 32:
        return None
    ssid_bytes = blob[off + 8:off + 8 + ln]
    if len(ssid_bytes) != ln or not all(0x20 <= c < 0x7F for c in ssid_bytes):
        return None
    mac = blob[off:off + 6]
    if mac[0] & 0x01 or mac[:3] == b"\0\0\0" or mac == b"\xff" * 6:
        return None
    try:
        ssid = ssid_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not ssid.strip():
        return None
    return ":".join("%02x" % b for b in mac), ssid


def _scan_prefixed_records(blob: bytes, *, anchored_only: bool = True
                           ) -> Iterable[Tuple[str, str, int, bool]]:
    """Yield (bssid, ssid, offset, anchored) for scan records.

    An anchored record is one preceded by a `NEW`/`EXISTING` state tag, which
    is how the scan writes them.  Measured on a live 8 MB trace, requiring the
    tag keeps every genuine access point and discards 77 of 77 false hits, so
    it is the default.  `anchored_only=False` falls back to searching on the
    length field alone, which finds records on a build that tags them
    differently at the cost of a great deal of noise; those are flagged so a
    caller can weigh them separately.
    """
    seen_offsets = set()
    for marker in _BSS_STATE_MARKERS:
        start = 0
        while True:
            i = blob.find(marker, start)
            if i < 0:
                break
            start = i + 1
            off = i + len(marker)
            rec = _read_record(blob, off)
            if rec is not None:
                seen_offsets.add(off)
                yield rec[0], rec[1], off, True

    if anchored_only:
        return

    for lm in re.finditer(rb"[\x01-\x20]\x00", blob):
        off = lm.start() - 6
        if off in seen_offsets:
            continue
        rec = _read_record(blob, off)
        if rec is not None:
            yield rec[0], rec[1], off, False


# --------------------------------------------------------------------------
# record shape 2: the address rendered as text inside the payload
# --------------------------------------------------------------------------

def _scan_text_macs(blob: bytes) -> Iterable[Tuple[str, int, str, str]]:
    """Yield (bssid, offset, encoding, context) for MACs written as text."""
    for encoding, step in (("ascii", 1), ("utf-16le", 2)):
        try:
            text = blob.decode("latin-1" if encoding == "ascii" else "utf-16-le",
                               "replace")
        except Exception:                       # pragma: no cover - defensive
            continue
        for m in _MAC_TEXT.finditer(text):
            mac = _norm(m.group(0))
            if _is_broadcastish(mac):
                continue
            context = text[max(0, m.start() - 60):m.start()]
            yield mac, m.start() * step, encoding, context


def parse_etl(path: str, *, host_macs: Optional[Sequence[str]] = None,
              deep: bool = False) -> EtlResult:
    """Recover access point BSSIDs from a `.etl` wireless trace.

    `host_macs` are this machine's own adapters, which are excluded; they are
    also detected from the trace where possible.  `deep` additionally reports
    unanchored records, trading precision for recall.
    """
    with open(path, "rb") as fh:
        blob = fh.read()

    result = EtlResult(beacons=[])
    if not looks_like_etl(blob):
        result.warnings.append(
            "First four bytes are not a known ETL buffer size; parsing anyway."
        )

    found: Dict[str, EtlBeacon] = {}
    excluded = {_norm(m) for m in (host_macs or [])}

    def note(mac: str, method: str, offset: int) -> EtlBeacon:
        b = found.get(mac)
        if b is None:
            b = found[mac] = EtlBeacon(bssid=mac)
        b.methods.add(method)
        b.occurrences += 1
        if len(b.offsets) < 8:
            b.offsets.append(offset)
        return b

    in_scan_record: Set[str] = set()
    for mac, ssid, off, anchored in _scan_prefixed_records(blob,
                                                           anchored_only=not deep):
        beacon = note(mac, "scan record" if anchored else "unanchored record", off)
        if beacon.ssid is None:
            beacon.ssid = ssid
        if anchored:
            in_scan_record.add(mac)

    # An address is the host radio if it is printed after a field name meaning
    # "this machine", or straight after an adapter's own description.  Both
    # cues also fire near genuine access points, so the deciding test is that
    # the host radio never turns up in a scan record - it does the scanning.
    host_context: Dict[str, int] = {}
    other_context: Dict[str, int] = {}
    for mac, off, encoding, context in _scan_text_macs(blob):
        low = context.lower()
        looks_host = any(h.lower() in low for h in _HOST_FIELDS) or \
            any(v.lower() in low for v in _ADAPTER_VENDORS)
        if looks_host:
            host_context[mac] = host_context.get(mac, 0) + 1
        else:
            other_context[mac] = other_context.get(mac, 0) + 1
        note(mac, "text/%s" % encoding, off)

    for mac, hits in host_context.items():
        if mac in in_scan_record:
            continue
        if hits >= other_context.get(mac, 0):
            excluded.add(mac)

    for mac in excluded:
        found.pop(mac, None)

    result.host_macs = excluded
    result.beacons = sorted(found.values(),
                            key=lambda b: (-b.corroboration, -b.occurrences, b.bssid))
    return result


def parse_rendered(text: str) -> List[EtlBeacon]:
    """Parse `netsh trace convert` output, which renders scan results fully.

    Each row is ``SSID, SSID-as-hex, BSSID, frequency, quality, RSSI``.  A row
    is accepted only when the frequency is a real channel centre and the RSSI
    is a plausible receive level - a constraint that random hex cannot meet.
    """
    out: Dict[str, EtlBeacon] = {}
    for m in _RENDERED_ROW.finditer(text):
        freq = int(m.group("freq"))
        rssi = int(m.group("rssi"))
        if freq not in _VALID_FREQ:
            continue
        if not _RSSI_RANGE[0] <= rssi <= _RSSI_RANGE[1]:
            continue
        mac = _norm(m.group("bssid"))
        if _is_broadcastish(mac):
            continue
        b = out.get(mac)
        if b is None:
            b = out[mac] = EtlBeacon(bssid=mac)
        b.methods.add("rendered scan row")
        b.occurrences += 1
        b.ssid = b.ssid or (m.group("ssid").strip() or None)
        if b.rssi_dbm is None or rssi > b.rssi_dbm:
            b.rssi_dbm = rssi
            b.freq_mhz = freq
    return sorted(out.values(), key=lambda b: (b.rssi_dbm or -999), reverse=True)
