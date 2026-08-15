"""
Observation ingestion from operator input and from host forensic artefacts.

A live radio scan tells you where a machine is now.  Where it has *been* is
the more useful question, and Windows answers it only partly - which is worth
stating plainly, because two widely repeated claims about it are wrong.

What a Windows host actually keeps, measured rather than assumed:

Windows registry - NetworkList
    `Signatures\\Unmanaged\\*` holds `DefaultGatewayMac`.  That is the
    gateway's MAC, **not** the BSSID.  On a router that serves both, the two
    addresses sit one or two apart, so the value points at the right device
    and still resolves to nothing.  The key also needs elevation to read.
    Its `DateCreated` and `DateLastConnected` are genuinely useful, and are
    all it offers: a dated list of network names, without positions.

Windows event log - WLAN-AutoConfig
    Events 8000-8011 and 11000-11010 carry `SSID`, `ProfileName` and
    `LocalMac` - this machine's own radio.  None of them carries a peer
    address, so the operational log yields no BSSIDs at all.

Wireless trace - Wifi.etl
    The `WiFiSession` autologger does record scanned BSSIDs, with channel and
    signal strength, and needs no elevation.  It is a circular buffer, so it
    holds hours rather than months.  See `wifigeo.etl`.

Sources understood here
-----------------------
Operator input
    A pasted list of BSSIDs in any common notation.  Networks routinely
    advertise separate radios for 2.4 GHz and 5 GHz under one name, and an
    investigator often knows several - each is an independent lookup and they
    corroborate one another.

Other
    `netsh wlan show networks mode=bssid` output, Kismet/WiGLE CSV, generic
    CSV, and arbitrary SIEM/Sentinel exports, from
    which MAC-shaped tokens are extracted with their surrounding context.

Everything produced here is an `Observation` carrying its provenance, so the
report can always state where a given BSSID came from.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .apple import canonical_bssid

#: Matches every notation in common use, longest first so that a punctuated
#: form is never partially consumed by the bare-hex pattern.
#:
#: The boundaries matter more than they look. A GUID is 8-4-4-4-12 hex digits
#: separated by hyphens, and registry exports and event logs are full of them.
#: With a hyphen allowed as a separator, the Cisco 4-4-4 pattern happily
#: matched `2222-3333-4444` out of the middle of one, and the bare 12-hex
#: pattern matched the trailing `555555555555` - both of which were then
#: submitted for geolocation as if they were access points.
#:
#: So: the Cisco form takes dots only, which is the only way it is actually
#: written, and both it and the bare form must not be flanked by a hex digit
#: or a hyphen.
_HEX_EDGE = r"(?![0-9a-fA-F-])"
_HEX_START = r"(?<![0-9a-fA-F-])"
_MAC_PATTERNS = [
    re.compile(r"\b([0-9a-fA-F]{2}(?:[:\-_][0-9a-fA-F]{2}){5})" + _HEX_EDGE),
    re.compile(_HEX_START + r"([0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2})" + _HEX_EDGE),
    re.compile(r"\b([0-9a-fA-F]{2}(?: [0-9a-fA-F]{2}){5})\b"),
    re.compile(_HEX_START + r"([0-9a-fA-F]{12})" + _HEX_EDGE),
]

#: A GUID, so that text known to contain one can be cleared before the MAC
#: patterns run. Belt and braces alongside the boundaries above.
_GUID_RE = re.compile(
    r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?")

#: A signal strength written alongside an address, e.g. "-65" or "-65 dBm".
#: The lookbehind rejects a hyphen attached to a preceding word, so a label
#: like "AP-45" or "Block-70" is not mistaken for a measurement.
_RSSI_RE = re.compile(r"(?<![\w-])(-\d{2,3})\s*(?:dbm)?(?![\w-])", re.I)

#: MACs that are structurally valid but never identify an access point.
_JUNK = {
    "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
    "01:00:5e:00:00:01", "33:33:00:00:00:01",
}


@dataclass
class Observation:
    """One BSSID, with where it came from and when it was seen."""

    bssid: str
    ssid: str = ""
    rssi_dbm: Optional[int] = None
    source: str = "manual"
    source_detail: str = ""
    first_seen: str = ""
    last_seen: str = ""
    context: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "bssid": self.bssid, "ssid": self.ssid, "rssi_dbm": self.rssi_dbm,
            "source": self.source, "source_detail": self.source_detail,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "context": self.context,
        }


def _clean(mac: str) -> Optional[str]:
    """Normalise any notation to canonical form, rejecting non-AP addresses."""
    try:
        norm = canonical_bssid(mac)
    except ValueError:
        return None
    if norm in _JUNK:
        return None
    first = int(norm[:2], 16)
    if first & 0x01:          # group/multicast bit - never an infrastructure BSS
        return None
    if norm.startswith("00:00:00"):
        return None
    return norm


def _dedupe(obs: Iterable[Observation]) -> List[Observation]:
    """Merge duplicate BSSIDs, preferring the richest record."""
    best: Dict[str, Observation] = {}
    for o in obs:
        prev = best.get(o.bssid)
        if prev is None:
            best[o.bssid] = o
            continue
        if not prev.ssid and o.ssid:
            prev.ssid = o.ssid
        if prev.rssi_dbm is None and o.rssi_dbm is not None:
            prev.rssi_dbm = o.rssi_dbm
        if o.last_seen and o.last_seen > (prev.last_seen or ""):
            prev.last_seen = o.last_seen
        if o.first_seen and (not prev.first_seen or o.first_seen < prev.first_seen):
            prev.first_seen = o.first_seen
        if o.source not in prev.source:
            prev.source = "%s + %s" % (prev.source, o.source)
    return list(best.values())


# ==========================================================================
# operator input
# ==========================================================================
def parse_manual(text: str) -> List[Observation]:
    """
    Parse a pasted list of BSSIDs.

    Accepts any separator (newline, comma, semicolon, whitespace) and any MAC
    notation.  An optional label may follow a MAC on the same line, separated
    by whitespace, a comma or an equals sign - so `aa:bb:.. Office-5G` works
    and keeps the operator's own annotation as the SSID.
    """
    out: List[Observation] = []
    for line in re.split(r"[\r\n;]+", text or ""):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        found = None
        for pat in _MAC_PATTERNS:
            m = pat.search(line)
            if m:
                found = m
                break
        if not found:
            continue
        mac = _clean(found.group(1))
        if not mac:
            continue
        rest = (line[:found.start()] + " " + line[found.end():]).strip(" ,=\t|")

        # A signal strength may follow the address. It is worth accepting
        # because Microsoft multilaterates from RSSI, so an examiner working
        # from a Kismet capture or a survey sheet can supply real measurements
        # instead of leaving the service to position from addresses alone.
        # Only plausible dBm values are taken, so a label like "AP-45" is not
        # mistaken for a measurement.
        rssi = None
        m = _RSSI_RE.search(rest)
        if m:
            value = int(m.group(1))
            if -100 <= value <= -10:
                rssi = value
                rest = (rest[:m.start()] + " " + rest[m.end():]).strip(" ,=\t|")

        out.append(Observation(bssid=mac, ssid=rest[:64], rssi_dbm=rssi,
                               source="operator input",
                               source_detail="pasted by the examiner"))
    return _dedupe(out)


# ==========================================================================
# Windows registry - NetworkList
# ==========================================================================
def _filetime_from_systemtime(blob: bytes) -> str:
    """Decode the 16-byte SYSTEMTIME the NetworkList profiles use."""
    if len(blob) < 16:
        return ""
    import struct
    y, mo, _dow, d, h, mi, s, ms = struct.unpack("<8H", blob[:16])
    try:
        return dt.datetime(y, mo, d, h, mi, s, ms * 1000,
                           tzinfo=dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return ""


def read_registry_networklist() -> Dict[str, object]:
    """
    Read every network this machine has joined, from the live registry.

    Requires only read access to HKLM; no elevation is needed for these keys.
    """
    result: Dict[str, object] = {"source": "registry NetworkList",
                                 "observations": [], "profiles": [],
                                 "warnings": []}
    if sys.platform != "win32":
        result["warnings"].append("Registry ingestion requires Windows.")
        return result
    try:
        import winreg
    except ImportError:                                    # pragma: no cover
        result["warnings"].append("winreg is unavailable.")
        return result

    base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList"

    # -- profiles: name + dates, keyed by GUID --------------------------
    profiles: Dict[str, Dict[str, object]] = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + r"\Profiles") as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                guid = winreg.EnumKey(k, i)
                try:
                    with winreg.OpenKey(k, guid) as pk:
                        entry: Dict[str, object] = {"guid": guid}
                        for name in ("ProfileName", "Description", "NameType",
                                     "Managed", "Category"):
                            try:
                                entry[name] = winreg.QueryValueEx(pk, name)[0]
                            except OSError:
                                pass
                        for name, key in (("DateCreated", "created"),
                                          ("DateLastConnected", "last_connected")):
                            try:
                                raw = winreg.QueryValueEx(pk, name)[0]
                                entry[key] = _filetime_from_systemtime(bytes(raw))
                            except OSError:
                                pass
                        profiles[guid] = entry
                except OSError:
                    continue
    except PermissionError:
        result["warnings"].append(
            "Access denied reading NetworkList. These keys are restricted to "
            "Administrators on current Windows builds, so the tool must be run "
            "elevated to read them from a live host. For an acquired image, "
            "export the key to a .reg file and import that instead: "
            "reg export \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
            "CurrentVersion\\NetworkList\" networklist.reg")
        result["access_denied"] = True
        return result
    except OSError as e:
        result["warnings"].append("Could not read NetworkList\\Profiles: %s" % e)

    result["profiles"] = list(profiles.values())

    # -- signatures: the gateway MAC, which for Wi-Fi is the BSSID -------
    obs: List[Observation] = []
    for scope in ("Unmanaged", "Managed"):
        path = base + r"\Signatures\%s" % scope
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
                for i in range(winreg.QueryInfoKey(k)[0]):
                    sig = winreg.EnumKey(k, i)
                    try:
                        with winreg.OpenKey(k, sig) as sk:
                            def val(name):
                                try:
                                    return winreg.QueryValueEx(sk, name)[0]
                                except OSError:
                                    return None

                            mac_raw = val("DefaultGatewayMac")
                            desc = val("Description") or val("FirstNetwork") or ""
                            guid = val("ProfileGuid") or ""
                            if not mac_raw:
                                continue
                            mac = _clean(bytes(mac_raw)[:6].hex()) if isinstance(
                                mac_raw, (bytes, bytearray)) else _clean(str(mac_raw))
                            if not mac:
                                continue
                            prof = profiles.get(str(guid), {})
                            obs.append(Observation(
                                bssid=mac, ssid=str(desc),
                                source="registry NetworkList",
                                source_detail=("HKLM\\...\\NetworkList\\Signatures\\"
                                               "%s\\%s (DefaultGatewayMac)"
                                               % (scope, sig[:16])),
                                first_seen=str(prof.get("created") or ""),
                                last_seen=str(prof.get("last_connected") or ""),
                                context=("Network previously joined by this host. "
                                         "The stored gateway MAC is the access "
                                         "point's BSSID.")))
                    except OSError:
                        continue
        except OSError:
            continue

    result["observations"] = obs
    if not obs and not result["warnings"]:
        result["warnings"].append(
            "No wireless networks with a recorded gateway MAC were found. Wired "
            "networks also appear here but their gateway MAC belongs to a "
            "router, not an access point, and is not geolocatable.")
    return result


_REG_SECTION = re.compile(r"^\[(.+)\]\s*$")
_REG_HEX = re.compile(r'^"([^"]+)"=hex(?:\(\w+\))?:(.*)$', re.I)
_REG_STR = re.compile(r'^"([^"]+)"="(.*)"$')
_REG_DWORD = re.compile(r'^"([^"]+)"=dword:([0-9a-fA-F]+)$')


def parse_reg_export(text: str) -> Dict[str, object]:
    """
    Parse a `reg export` / regedit .reg file of the NetworkList key.

    This is the practical route for examining an acquired image: the examiner
    mounts or loads the SOFTWARE hive, exports the key, and brings the text
    here.  It needs no elevation, no hive parser and no third-party library,
    and it preserves an artefact that is itself hashable evidence.
    """
    result: Dict[str, object] = {"source": "registry export (.reg)",
                                 "observations": [], "profiles": [],
                                 "warnings": []}
    sections: Dict[str, Dict[str, object]] = {}
    current: Optional[str] = None
    pending_key: Optional[str] = None
    pending_hex: List[str] = []

    def flush():
        nonlocal pending_key, pending_hex
        if current and pending_key:
            blob = "".join(pending_hex).replace("\\", "").replace(" ", "")
            try:
                sections[current][pending_key] = bytes.fromhex(
                    "".join(c for c in blob if c in "0123456789abcdefABCDEF"))
            except ValueError:
                pass
        pending_key, pending_hex = None, []

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        sec = _REG_SECTION.match(line)
        if sec:
            flush()
            current = sec.group(1)
            sections.setdefault(current, {})
            continue
        if current is None:
            continue
        if pending_key:
            pending_hex.append(line.rstrip("\\"))
            if not raw.rstrip().endswith("\\"):
                flush()
            continue
        m = _REG_HEX.match(line)
        if m:
            pending_key = m.group(1)
            pending_hex = [m.group(2).rstrip("\\")]
            if not raw.rstrip().endswith("\\"):
                flush()
            continue
        m = _REG_STR.match(line)
        if m:
            sections[current][m.group(1)] = m.group(2).encode().decode(
                "unicode_escape")
            continue
        m = _REG_DWORD.match(line)
        if m:
            sections[current][m.group(1)] = int(m.group(2), 16)
    flush()

    profiles: Dict[str, Dict[str, object]] = {}
    for path, values in sections.items():
        if "\\Profiles\\" not in path:
            continue
        guid = path.rsplit("\\", 1)[-1]
        entry: Dict[str, object] = {"guid": guid,
                                    "ProfileName": values.get("ProfileName")}
        for name, key in (("DateCreated", "created"),
                          ("DateLastConnected", "last_connected")):
            blob = values.get(name)
            if isinstance(blob, (bytes, bytearray)):
                entry[key] = _filetime_from_systemtime(bytes(blob))
        profiles[guid] = entry
    result["profiles"] = list(profiles.values())

    obs: List[Observation] = []
    for path, values in sections.items():
        if "\\Signatures\\" not in path:
            continue
        raw_mac = values.get("DefaultGatewayMac")
        if not isinstance(raw_mac, (bytes, bytearray)) or len(raw_mac) < 6:
            continue
        mac = _clean(bytes(raw_mac)[:6].hex())
        if not mac:
            continue
        guid = str(values.get("ProfileGuid") or "")
        prof = profiles.get(guid, {})
        obs.append(Observation(
            bssid=mac,
            ssid=str(values.get("Description") or values.get("FirstNetwork")
                     or prof.get("ProfileName") or ""),
            source="registry export (.reg)",
            source_detail=path.rsplit("\\", 2)[-2:][0][:40],
            first_seen=str(prof.get("created") or ""),
            last_seen=str(prof.get("last_connected") or ""),
            context=("Network previously joined by the examined host. The "
                     "stored gateway MAC is the access point's BSSID.")))

    result["observations"] = _dedupe(obs)
    if not obs:
        result["warnings"].append(
            "No DefaultGatewayMac values were found in this export. Confirm the "
            "export covers HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
            "CurrentVersion\\NetworkList and its subkeys.")
    return result


# ==========================================================================
# Windows event log - WLAN-AutoConfig
# ==========================================================================
WLAN_CHANNEL = "Microsoft-Windows-WLAN-AutoConfig/Operational"

#: Fields that hold the ACCESS POINT's address.
#: Verified empirically against a live Windows 11 log: of every Data field in
#: this channel, only `PeerMac` carries a BSSID.
_AP_MAC_FIELDS = ("PeerMac", "BSSID", "APMac", "TargetMac", "RemoteMac")

#: Fields that hold THIS MACHINE's own wireless adapter address.
#:
#: This distinction is safety-critical.  `LocalMac` appears in far more events
#: than `PeerMac` does (161 occurrences against 1 in a sample of 600), so a
#: parser that simply hunts for MAC-shaped strings in the event log will
#: overwhelmingly harvest the examined machine's own adapter and then submit it
#: for geolocation.  That is both wrong and actively misleading, since a client
#: adapter is not an access point and any database hit on it is spurious.
_LOCAL_MAC_FIELDS = ("LocalMac", "InterfaceMac", "AdapterMac")


def read_wlan_events(max_events: int = 2000) -> Dict[str, object]:
    """
    Extract association history from Microsoft-Windows-WLAN-AutoConfig.

    Uses `wevtutil` rather than a third-party EVTX parser so that no dependency
    is introduced.  The whole channel is read and filtered here rather than
    server-side, because the events that carry an access point address are a
    small minority and vary between Windows builds.
    """
    out: Dict[str, object] = {"source": "WLAN-AutoConfig event log",
                              "channel": WLAN_CHANNEL,
                              "observations": [], "local_macs": [],
                              "warnings": []}
    if sys.platform != "win32":
        out["warnings"].append("Event log ingestion requires Windows.")
        return out

    try:
        proc = subprocess.run(
            ["wevtutil", "qe", WLAN_CHANNEL,
             "/c:%d" % max_events, "/rd:true", "/f:xml"],
            capture_output=True, timeout=180,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except FileNotFoundError:
        out["warnings"].append("wevtutil was not found on this system.")
        return out
    except Exception as e:
        out["warnings"].append("wevtutil failed: %s" % e)
        return out

    text = proc.stdout.decode("utf-8", "replace")
    if not text.strip():
        err = proc.stderr.decode("utf-8", "replace").strip()
        out["warnings"].append(
            "No events were returned. %s" % (err or "The channel may be empty, "
            "or reading it may require an elevated process."))
        return out

    obs, locals_seen, scanned = _parse_wlan_event_xml(text)
    out["observations"] = obs
    out["local_macs"] = sorted(locals_seen)
    out["events_scanned"] = scanned
    if not obs:
        out["warnings"].append(
            "%d events were read but none recorded an access point address. "
            "Windows logs the associated access point only in a minority of "
            "events (field 'PeerMac'); the common connect event 8001 records "
            "the network name but not the access point. Association history "
            "may still be recoverable from the registry NetworkList."
            % scanned)
    if locals_seen:
        out["warnings"].append(
            "This host's own wireless adapter address(es) %s were seen in the "
            "log and deliberately excluded - a client adapter is not an access "
            "point and must not be geolocated."
            % ", ".join(sorted(locals_seen)))
    return out


def parse_wlan_event_export(text: str) -> List[Observation]:
    """Parse a wevtutil / Event Viewer XML export captured elsewhere."""
    return _parse_wlan_event_xml(text)[0]


_EV_TIME = re.compile(r'SystemTime=[\'"]([^\'"]+)[\'"]')
_EV_ID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
_EV_DATA = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]>(.*?)</Data>",
                      re.S | re.I)


def _parse_wlan_event_xml(text: str) -> Tuple[List[Observation], set, int]:
    """
    Turn event XML into access-point observations.

    Only named fields are trusted.  There is deliberately no "look for anything
    MAC-shaped" fallback here: the dominant MAC in this log is the examined
    machine's own adapter, so a loose parser produces confident nonsense.
    """
    obs: List[Observation] = []
    local_macs: set = set()
    scanned = 0

    for chunk in re.split(r"(?=<Event\b)", text):
        if "<Event" not in chunk:
            continue
        scanned += 1
        fields = {m.group(1): m.group(2).strip()
                  for m in _EV_DATA.finditer(chunk)}
        if not fields:
            continue

        for key in _LOCAL_MAC_FIELDS:
            if fields.get(key):
                got = _clean(fields[key])
                if got:
                    local_macs.add(got)

        mac = None
        via = ""
        for key in _AP_MAC_FIELDS:
            if fields.get(key):
                got = _clean(fields[key])
                if got:
                    mac, via = got, key
                    break
        if not mac:
            continue

        eid = _EV_ID.search(chunk)
        eid = eid.group(1) if eid else "?"
        when = ""
        tm = _EV_TIME.search(chunk)
        if tm:
            when = tm.group(1)

        rssi = None
        if fields.get("RSSI"):
            try:
                rssi = int(float(fields["RSSI"]))
                if rssi > 0:
                    rssi = -rssi
            except ValueError:
                rssi = None

        ssid = fields.get("SSID") or fields.get("ProfileName") or ""
        obs.append(Observation(
            bssid=mac, ssid=ssid, rssi_dbm=rssi,
            source="WLAN-AutoConfig event log",
            source_detail="event %s, field %s" % (eid, via),
            first_seen=when, last_seen=when,
            context=("This host was associated with this access point at the "
                     "recorded time.")))

    # Guard against a build that puts the adapter address in an AP field.
    obs = [o for o in obs if o.bssid not in local_macs]
    return _dedupe(obs), local_macs, scanned


# ==========================================================================
# text and tabular formats
# ==========================================================================
#: `netsh wlan show networks mode=bssid` prints one "SSID <n> : <name>" header
#: per network, then indented properties, then "BSSID <n> : <address>" entries.
#: Anchored at the start of the line so "BSSID 1 :" cannot match.
_NETSH_SSID_RE = re.compile(r"^\s*SSID\s+\d+\s*:(.*)$", re.I)

#: netsh reports link quality as a percentage rather than dBm.
_NETSH_SIGNAL_RE = re.compile(r"^\s*Signal\s*:\s*(\d{1,3})\s*%", re.I)


def _percent_to_dbm(percent: int) -> int:
    """
    Convert netsh's link-quality percentage to an approximate dBm.

    Windows derives the percentage from RSSI with a linear map over -100..-50
    dBm, so this inverts it. It is an approximation and is only ever used to
    weight a multilateration - Microsoft treats signal strength as a hint about
    relative distance, and a roughly right value is far better than none, which
    is what the parser used to supply.
    """
    return max(-100, min(-50, (max(0, min(100, percent)) // 2) - 100))


def parse_netsh(text: str) -> List[Observation]:
    """Parse `netsh wlan show networks mode=bssid` captured from any host."""
    obs: List[Observation] = []
    ssid = ""
    for line in text.splitlines():
        if not line.strip():
            continue
        hit = _MAC_PATTERNS[0].search(line)
        if hit:
            mac = _clean(hit.group(1))
            if mac:
                obs.append(Observation(bssid=mac, ssid=ssid, source="netsh output",
                                       source_detail="netsh wlan show networks"))
            continue
        # Signal belongs to the access point named just above it. Dropping it
        # cost real accuracy: Microsoft multilaterates on relative signal
        # strength, so a fingerprint with no strengths is a weaker question
        # than the same one with them.
        sig = _NETSH_SIGNAL_RE.match(line)
        if sig and obs:
            obs[-1].rssi_dbm = _percent_to_dbm(int(sig.group(1)))
            continue
        # Only an actual "SSID <n> :" header names a network. Treating every
        # "key : value" line as the name meant the last property before a BSSID
        # won: an access point under "Authentication : WPA2-Personal" was
        # recorded as being on a network called WPA2-Personal, and one after
        # "Channel : 6" as being on a network called 6. A wrong network name in
        # a report is a misattribution, not a cosmetic defect.
        #
        # "BSSID 1 :" cannot match because the pattern is anchored at the start
        # of the line, and BSSID lines have already been consumed above.
        header = _NETSH_SSID_RE.match(line)
        if header:
            # An empty value is a hidden network: it has no name, and carrying
            # the previous block's name forward would invent one.
            ssid = header.group(1).strip()
    return _dedupe(obs)


#: Ordered by specificity: an explicit access-point column is chosen ahead of a
#: generic "mac". `peermac` is what the Windows WLAN-AutoConfig event log calls
#: the access point, and it reaches this parser whenever those events have been
#: exported to CSV by a SIEM.
_CSV_BSSID_KEYS = ("bssid", "peermac", "apmac", "ap_mac", "targetmac",
                   "remotemac", "wifi_bssid", "bssid_hex",
                   "destinationmacaddress", "mac", "macaddress", "mac_address",
                   "sourcemacaddress", "devicemac",
                   "defaultgatewaymac", "gatewaymac")

#: Columns that hold the *examining or subject host's own* adapter address.
#: These must never be geolocated: a client radio is not an access point, and
#: positioning one answers a question nobody asked. A Sentinel export commonly
#: carries a local and a peer address on the same row, and picking the wrong one
#: silently places the wrong device.
_CSV_LOCAL_KEYS = ("localmac", "interfacemac", "adaptermac", "clientmac",
                   "stationmac", "hostmac", "nicmac")
_CSV_SSID_KEYS = ("ssid", "network", "networkname", "essid", "profilename",
                  "description", "wifi_ssid")
_CSV_RSSI_KEYS = ("rssi", "signal", "signal_dbm", "rssi_dbm", "dbm", "level")
_CSV_TIME_KEYS = ("time", "timestamp", "timegenerated", "lastseen", "last_seen",
                  "firstseen", "datelastconnected", "eventtime", "utc")


def parse_table(text: str, source: str = "imported table") -> List[Observation]:
    """
    Parse CSV/TSV where a column holds a MAC address.

    Column names are matched case- and punctuation-insensitively against a
    list that covers Kismet, WiGLE, netsh exports and the usual SIEM field
    names, including Microsoft Sentinel's DestinationMacAddress.
    """
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        return []

    def norm(name):
        return re.sub(r"[^a-z0-9]", "", (name or "").lower())

    cols = {norm(f): f for f in reader.fieldnames}
    mac_col = next((cols[k] for k in _CSV_BSSID_KEYS if k in cols), None)
    #: Resolved once, so the row-scan fallback below can skip them too.
    local_cols = {cols[k] for k in _CSV_LOCAL_KEYS if k in cols}
    ssid_col = next((cols[k] for k in _CSV_SSID_KEYS if k in cols), None)
    rssi_col = next((cols[k] for k in _CSV_RSSI_KEYS if k in cols), None)
    time_col = next((cols[k] for k in _CSV_TIME_KEYS if k in cols), None)

    obs: List[Observation] = []
    for row in reader:
        raw = row.get(mac_col) if mac_col else None
        if not raw:
            # No recognised column - scan the row, but never the columns known
            # to hold a local adapter address. Without the exclusion this takes
            # whichever address appears leftmost, so a "LocalMac,PeerMac" export
            # geolocates the host instead of the access point it was talking to.
            joined = " ".join(str(v) for k, v in row.items()
                              if v and k not in local_cols)
            m = _MAC_PATTERNS[0].search(joined)
            raw = m.group(1) if m else None
        if not raw:
            continue
        mac = _clean(str(raw))
        if not mac:
            continue
        rssi = None
        if rssi_col and row.get(rssi_col):
            try:
                rssi = int(float(str(row[rssi_col]).replace("dBm", "").strip()))
                if rssi > 0:
                    rssi = -rssi
            except ValueError:
                rssi = None
        when = str(row.get(time_col) or "") if time_col else ""
        obs.append(Observation(
            bssid=mac, ssid=str(row.get(ssid_col) or "") if ssid_col else "",
            rssi_dbm=rssi, source=source,
            source_detail="column %r" % (mac_col or "auto-detected"),
            first_seen=when, last_seen=when))
    return _dedupe(obs)


def sniff_any(text: str, source: str = "imported text") -> List[Observation]:
    """
    Last resort: pull every MAC-shaped token out of arbitrary text.

    Used for SIEM exports, incident notes, pasted log fragments and anything
    else with no recognisable structure.  Each hit keeps a slice of its
    surrounding line so a reviewer can see the context it came from.
    """
    obs: List[Observation] = []
    for raw_line in text.splitlines():
        # GUIDs are hex and hyphens and appear all over registry and event
        # data; blank them so they cannot be mistaken for hardware addresses.
        line = _GUID_RE.sub(" ", raw_line)
        for pat in _MAC_PATTERNS[:2]:
            for m in pat.finditer(line):
                mac = _clean(m.group(1))
                if mac:
                    snippet = raw_line.strip()
                    obs.append(Observation(
                        bssid=mac, source=source,
                        source_detail="extracted from unstructured text",
                        context=snippet[:180]))
    return _dedupe(obs)


# ==========================================================================
# collector bundles
# ==========================================================================
def parse_collection(doc: Dict[str, object]) -> Dict[str, object]:
    """Load a bundle produced by the standalone collector."""
    obs: List[Observation] = []
    for b in doc.get("scan", {}).get("beacons", []) or []:
        mac = _clean(str(b.get("bssid", "")))
        if mac:
            obs.append(Observation(
                bssid=mac, ssid=b.get("ssid") or "",
                rssi_dbm=b.get("rssi_dbm"),
                source="collector radio scan",
                source_detail="collected on %s" % doc.get("host", "?"),
                first_seen=doc.get("collected_utc", ""),
                last_seen=doc.get("collected_utc", "")))
    for row in doc.get("registry", {}).get("observations", []) or []:
        mac = _clean(str(row.get("bssid", "")))
        if mac:
            obs.append(Observation(
                bssid=mac, ssid=row.get("ssid") or "",
                source="collector registry NetworkList",
                source_detail=row.get("source_detail", ""),
                first_seen=row.get("first_seen", ""),
                last_seen=row.get("last_seen", ""),
                context=row.get("context", "")))
    for row in doc.get("events", {}).get("observations", []) or []:
        mac = _clean(str(row.get("bssid", "")))
        if mac:
            obs.append(Observation(
                bssid=mac, ssid=row.get("ssid") or "",
                source="collector WLAN event log",
                source_detail=row.get("source_detail", ""),
                first_seen=row.get("first_seen", ""),
                last_seen=row.get("last_seen", ""),
                context=row.get("context", "")))
    return {
        "source": "collection bundle",
        "collector_host": doc.get("host"),
        "collected_utc": doc.get("collected_utc"),
        "collector_version": doc.get("collector_version"),
        "integrity": doc.get("integrity"),
        "observations": _dedupe(obs),
    }


# ==========================================================================
# front door
# ==========================================================================
def ingest(payload: str, filename: str = "") -> Dict[str, object]:
    """
    Work out what a blob of pasted or uploaded data is, and parse it.

    Returns the observations plus a description of how the data was
    interpreted, which goes into the report so the reader knows the provenance
    of every BSSID.
    """
    text = payload if isinstance(payload, str) else payload.decode("utf-8", "replace")
    stripped = text.strip()
    ext = os.path.splitext(filename or "")[1].lower()

    if not stripped:
        return {"format": "empty", "observations": [], "note": "nothing to parse"}

    # collection bundle / any JSON
    if stripped[:1] in "{[" or ext == ".json":
        try:
            doc = json.loads(stripped)
        except ValueError:
            doc = None
        if isinstance(doc, dict) and doc.get("wgf_collection"):
            parsed = parse_collection(doc)
            return {"format": "collection bundle",
                    "note": ("Collected on %s at %s by collector %s."
                             % (parsed.get("collector_host"),
                                parsed.get("collected_utc"),
                                parsed.get("collector_version"))),
                    **parsed}
        if doc is not None:
            obs = sniff_any(json.dumps(doc), "imported JSON")
            return {"format": "generic JSON",
                    "note": ("MAC-shaped values were extracted from the JSON. "
                            "Review the context column before relying on them."),
                    "observations": obs}

    # Registry export
    if ext == ".reg" or stripped[:64].lstrip().lower().startswith(
            "windows registry editor"):
        parsed = parse_reg_export(stripped)
        obs = parsed.get("observations") or []
        return {"format": "registry export (.reg)",
                "note": ("Parsed as a NetworkList registry export. %d network "
                         "profile(s) read." % len(parsed.get("profiles") or [])),
                "observations": obs,
                "profiles": parsed.get("profiles"),
                "warnings": parsed.get("warnings")}

    # Event log XML
    if "<Event" in stripped[:4000] and "WLAN" in stripped[:8000].upper():
        obs = parse_wlan_event_export(stripped)
        return {"format": "WLAN-AutoConfig event XML",
                "note": "Association events parsed from an event log export.",
                "observations": obs}

    # netsh
    if "SSID" in stripped[:3000] and "BSSID" in stripped[:4000] \
            and "%" in stripped[:6000]:
        obs = parse_netsh(stripped)
        if obs:
            return {"format": "netsh wlan output",
                    "note": "Parsed from netsh wlan show networks output.",
                    "observations": obs}

    # Tabular
    first = stripped.splitlines()[0]
    if ext in (".csv", ".tsv") or first.count(",") >= 2 or first.count("\t") >= 2:
        obs = parse_table(stripped)
        if obs:
            return {"format": "delimited table",
                    "note": "Parsed as a table; a MAC-bearing column was located.",
                    "observations": obs}

    # Plain list
    obs = parse_manual(stripped)
    if obs:
        return {"format": "BSSID list",
                "note": "Parsed as a list of access point addresses.",
                "observations": obs}

    obs = sniff_any(stripped)
    return {"format": "unstructured text",
            "note": ("No recognised structure; MAC-shaped tokens were extracted "
                     "with their surrounding context."),
            "observations": obs}


def ingest_file(path: str) -> Dict[str, object]:
    # The collector ships a ZIP holding the parsed bundle plus the raw
    # artefacts it was derived from.  Prefer the bundle; fall back to any
    # readable member so a partially-built package is still usable.
    if path.lower().endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            for want in ("bundle.json",):
                match = next((n for n in names if n.endswith(want)), None)
                if match:
                    got = ingest(zf.read(match).decode("utf-8", "replace"), want)
                    got["package"] = os.path.basename(path)
                    got["package_members"] = names
                    return got
            merged: List[Observation] = []
            for n in names:
                if n.endswith("/"):
                    continue
                try:
                    part = ingest(zf.read(n).decode("utf-8", "replace"), n)
                except Exception:
                    continue
                merged.extend(part.get("observations") or [])
            return {"format": "collection package (no bundle.json)",
                    "note": "Assembled from the raw members of the package.",
                    "observations": _dedupe(merged), "package_members": names}

    with open(path, "rb") as fh:
        raw = fh.read()
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return ingest(raw.decode(enc), os.path.basename(path))
        except UnicodeDecodeError:
            continue
    return ingest(raw.decode("utf-8", "replace"), os.path.basename(path))


def collect_host_artefacts(use_registry: bool = False) -> Dict[str, object]:
    """
    Gather what this machine can say about the access points it has used.

    The registry is off by default and should stay that way: NetworkList holds
    the default gateway's address, not the BSSID, so its addresses cannot be
    positioned. Only the event log's `PeerMac` is genuinely an access point.
    """
    registry = (read_registry_networklist() if use_registry
                else {"observations": [], "warnings": []})
    events = read_wlan_events()
    obs = list(registry.get("observations") or []) + \
        list(events.get("observations") or [])
    return {
        "registry": {**registry,
                     "observations": [o.to_dict() for o in registry.get("observations") or []]},
        "events": {**events,
                   "observations": [o.to_dict() for o in events.get("observations") or []]},
        "observations": _dedupe(obs),
        "warnings": list(registry.get("warnings") or []) +
                    list(events.get("warnings") or []),
    }
