"""
Native Windows Wi-Fi scanner via wlanapi.dll (ctypes, no dependencies).

This is how an SSID is turned into BSSIDs.  There is no credential-free
service that maps an arbitrary SSID to its access points, so the authoritative
answer comes from the radio in this machine: scan, then read the BSS list,
which gives SSID, BSSID, true RSSI in dBm, channel, band and PHY.

Why not `netsh wlan show networks mode=bssid`?
  * It reports signal as a percentage, not dBm.  Microsoft's positioning
    service wants dBm, and converting back from a percentage is lossy
    guesswork - unacceptable when the number ends up in a report.
  * Its output is localised, so parsing breaks on non-English Windows.
It is retained purely as a last-resort fallback and is clearly labelled as
approximated wherever its numbers are used.

Note on Windows scan throttling: since Windows 10 1709 an unelevated process
may trigger only a limited number of scans in a rolling window.  When the
request is throttled we still read the cached BSS list and record that the
data may be stale, rather than failing the investigation.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"

DOT11_BSS_TYPE_INFRASTRUCTURE = 1
DOT11_BSS_TYPE_ANY = 3

PHY_NAMES = {
    0: "unknown", 1: "fhss", 2: "dsss", 3: "irbaseband", 4: "ofdm(11a/g)",
    5: "hrdsss(11b)", 6: "erp(11g)", 7: "ht(11n)", 8: "vht(11ac)",
    9: "dmg(11ad)", 10: "he(11ax)", 11: "eht(11be)",
}


@dataclass
class Beacon:
    """One observed BSS."""

    bssid: str
    ssid: str = ""
    rssi_dbm: Optional[int] = None
    signal_pct: Optional[int] = None
    channel: Optional[int] = None
    frequency_khz: Optional[int] = None
    band: str = ""
    phy: str = ""
    beacon_period_ms: Optional[int] = None
    link_quality: Optional[int] = None
    capabilities: Optional[int] = None
    rssi_approximated: bool = False

    @property
    def privacy(self) -> Optional[bool]:
        if self.capabilities is None:
            return None
        return bool(self.capabilities & 0x0010)   # IEEE 802.11 Privacy bit

    def to_dict(self) -> Dict[str, object]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "hidden": self.ssid == "",
            "rssi_dbm": self.rssi_dbm,
            "signal_pct": self.signal_pct,
            "channel": self.channel,
            "frequency_khz": self.frequency_khz,
            "band": self.band,
            "phy": self.phy,
            "beacon_period_ms": self.beacon_period_ms,
            "link_quality": self.link_quality,
            "privacy": self.privacy,
            "rssi_approximated": self.rssi_approximated,
        }


# --------------------------------------------------------------------------
# ctypes structures
# --------------------------------------------------------------------------
class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

    def __str__(self) -> str:
        return "{%08X-%04X-%04X-%s-%s}" % (
            self.Data1, self.Data2, self.Data3,
            "".join("%02X" % b for b in self.Data4[:2]),
            "".join("%02X" % b for b in self.Data4[2:]),
        )


class DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", ctypes.c_ulong), ("ucSSID", ctypes.c_ubyte * 32)]

    def value(self) -> str:
        n = min(int(self.uSSIDLength), 32)
        raw = bytes(self.ucSSID[:n])
        # SSIDs are octet strings, not text.  UTF-8 first, then the common
        # legacy encodings, then a lossless-but-visible fallback.
        for enc in ("utf-8", "cp1252", "shift_jis"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", "backslashreplace")


class WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [("uRateSetLength", ctypes.c_ulong),
                ("usRateSet", ctypes.c_ushort * 126)]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", ctypes.c_ulong),
        ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11BssType", ctypes.c_int),
        ("dot11BssPhyType", ctypes.c_int),
        ("lRssi", ctypes.c_long),
        ("uLinkQuality", ctypes.c_ulong),
        ("bInRegDomain", ctypes.c_ubyte),
        ("usBeaconPeriod", ctypes.c_ushort),
        ("ullTimestamp", ctypes.c_ulonglong),
        ("ullHostTimestamp", ctypes.c_ulonglong),
        ("usCapabilityInformation", ctypes.c_ushort),
        ("ulChCenterFrequency", ctypes.c_ulong),
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", ctypes.c_ulong),
        ("ulIeSize", ctypes.c_ulong),
    ]


class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [("dwTotalSize", wt.DWORD), ("dwNumberOfItems", wt.DWORD),
                ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", GUID),
                ("strInterfaceDescription", ctypes.c_wchar * 256),
                ("isState", ctypes.c_int)]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wt.DWORD), ("dwIndex", wt.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


INTERFACE_STATES = {
    0: "not_ready", 1: "connected", 2: "ad_hoc_network_formed",
    3: "disconnecting", 4: "disconnected", 5: "associating",
    6: "discovering", 7: "authenticating",
}


def _channel_from_khz(khz: int) -> Tuple[Optional[int], str]:
    """Map a centre frequency in kHz to (channel, band label)."""
    mhz = khz / 1000.0
    if 2412 <= mhz <= 2472:
        return int(round((mhz - 2412) / 5)) + 1, "2.4 GHz"
    if abs(mhz - 2484) < 1:
        return 14, "2.4 GHz"
    if 5150 <= mhz <= 5895:
        return int(round((mhz - 5000) / 5)), "5 GHz"
    if 5925 <= mhz <= 7125:
        return int(round((mhz - 5950) / 5)), "6 GHz"
    return None, "unknown"


def _mac(raw) -> str:
    return ":".join("%02x" % b for b in raw)


def _pct_to_dbm(pct: int) -> int:
    """
    Windows' documented inverse of its own dBm->percentage mapping.

    Only used for the netsh fallback.  Every beacon produced this way is
    flagged `rssi_approximated=True` so it is never silently presented as a
    measurement.
    """
    pct = max(0, min(100, int(pct)))
    return int(round(pct / 2.0)) - 100


# --------------------------------------------------------------------------
# native scan
# --------------------------------------------------------------------------
class WlanScanner:
    """Thin RAII wrapper around the wlanapi handle."""

    def __init__(self) -> None:
        if not IS_WINDOWS:
            raise OSError("wlanapi is only available on Windows")
        self.dll = ctypes.windll.LoadLibrary("wlanapi.dll")
        self.handle = wt.HANDLE()
        negotiated = wt.DWORD()
        rc = self.dll.WlanOpenHandle(2, None, ctypes.byref(negotiated),
                                     ctypes.byref(self.handle))
        if rc != 0:
            raise OSError("WlanOpenHandle failed (code %d). Is the WLAN "
                          "AutoConfig service running?" % rc)
        self.negotiated_version = negotiated.value

    def close(self) -> None:
        if self.handle:
            self.dll.WlanCloseHandle(self.handle, None)
            self.handle = wt.HANDLE()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- interfaces --------------------------------------------------------
    def interfaces(self) -> List[Dict[str, object]]:
        ptr = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        rc = self.dll.WlanEnumInterfaces(self.handle, None, ctypes.byref(ptr))
        if rc != 0:
            raise OSError("WlanEnumInterfaces failed (code %d)" % rc)
        try:
            lst = ptr.contents
            n = lst.dwNumberOfItems
            arr = ctypes.cast(
                ctypes.byref(lst.InterfaceInfo),
                ctypes.POINTER(WLAN_INTERFACE_INFO * n)).contents
            return [{
                "guid": str(item.InterfaceGuid),
                "_guid_struct": GUID.from_buffer_copy(item.InterfaceGuid),
                "description": item.strInterfaceDescription,
                "state": INTERFACE_STATES.get(item.isState, "state_%d" % item.isState),
                "state_code": item.isState,
            } for item in arr]
        finally:
            self.dll.WlanFreeMemory(ptr)

    # -- scan --------------------------------------------------------------
    def trigger_scan(self, guid: GUID) -> Tuple[bool, str]:
        rc = self.dll.WlanScan(self.handle, ctypes.byref(guid), None, None, None)
        if rc == 0:
            return True, "scan requested"
        if rc == 5:
            return False, "access denied (code 5) - scan request refused"
        if rc == 1062:
            return False, "WLAN AutoConfig service not running (code 1062)"
        return False, "WlanScan failed (code %d)" % rc

    def bss_list(self, guid: GUID) -> List[Beacon]:
        ptr = ctypes.POINTER(WLAN_BSS_LIST)()
        rc = self.dll.WlanGetNetworkBssList(
            self.handle, ctypes.byref(guid), None,
            DOT11_BSS_TYPE_ANY, False, None, ctypes.byref(ptr))
        if rc != 0:
            raise OSError("WlanGetNetworkBssList failed (code %d)" % rc)
        try:
            lst = ptr.contents
            n = lst.dwNumberOfItems
            if n == 0:
                return []
            arr = ctypes.cast(
                ctypes.byref(lst.wlanBssEntries),
                ctypes.POINTER(WLAN_BSS_ENTRY * n)).contents
            out: List[Beacon] = []
            for e in arr:
                ch, band = _channel_from_khz(e.ulChCenterFrequency)
                out.append(Beacon(
                    bssid=_mac(e.dot11Bssid),
                    ssid=e.dot11Ssid.value(),
                    rssi_dbm=int(e.lRssi),
                    signal_pct=int(e.uLinkQuality),
                    channel=ch,
                    frequency_khz=int(e.ulChCenterFrequency),
                    band=band,
                    phy=PHY_NAMES.get(e.dot11BssPhyType, "phy_%d" % e.dot11BssPhyType),
                    beacon_period_ms=int(e.usBeaconPeriod),
                    link_quality=int(e.uLinkQuality),
                    capabilities=int(e.usCapabilityInformation),
                    rssi_approximated=False,
                ))
            return out
        finally:
            self.dll.WlanFreeMemory(ptr)


def scan(active: bool = True, settle_seconds: float = 4.5) -> Dict[str, object]:
    """
    Perform a full survey.

    Returns a dict carrying the beacons plus enough diagnostics that a reviewer
    can tell whether the data came from a fresh active scan or a stale cache.
    """
    result: Dict[str, object] = {
        "method": None,
        "platform": platform.platform(),
        "interfaces": [],
        "beacons": [],
        "warnings": [],
        "active_scan": False,
        "scan_notes": [],
    }

    if not IS_WINDOWS:
        result["method"] = "unsupported"
        result["warnings"].append(
            "Native scanning requires Windows. Supply BSSIDs manually, or run "
            "the tool on the Windows host that observed the network.")
        return result

    try:
        with WlanScanner() as w:
            result["negotiated_wlanapi_version"] = w.negotiated_version
            ifaces = w.interfaces()
            result["interfaces"] = [
                {k: v for k, v in i.items() if not k.startswith("_")} for i in ifaces]
            if not ifaces:
                result["method"] = "wlanapi"
                result["warnings"].append("No wireless interfaces present.")
                return result

            if active:
                any_ok = False
                for i in ifaces:
                    ok, note = w.trigger_scan(i["_guid_struct"])
                    result["scan_notes"].append("%s: %s" % (i["description"], note))
                    any_ok = any_ok or ok
                if any_ok:
                    result["active_scan"] = True
                    time.sleep(settle_seconds)
                else:
                    result["warnings"].append(
                        "Active scan was refused on every interface; reading the "
                        "cached BSS list instead. Results may be stale. Windows "
                        "throttles scan requests from unelevated processes.")

            merged: Dict[str, Beacon] = {}
            for i in ifaces:
                try:
                    for b in w.bss_list(i["_guid_struct"]):
                        prev = merged.get(b.bssid)
                        # Keep the strongest observation of each BSS.
                        if prev is None or (b.rssi_dbm or -999) > (prev.rssi_dbm or -999):
                            merged[b.bssid] = b
                except OSError as e:
                    result["warnings"].append("%s: %s" % (i["description"], e))

            result["method"] = "wlanapi.dll WlanScan + WlanGetNetworkBssList (ctypes)"
            result["beacons"] = sorted(
                merged.values(), key=lambda b: -(b.rssi_dbm or -999))
            if not merged:
                result["warnings"].append(
                    "The BSS list came back empty. The adapter may be disabled, "
                    "in airplane mode, or already busy.")
            return result

    except OSError as e:
        result["warnings"].append("wlanapi unavailable: %s" % e)

    # ---- fallback --------------------------------------------------------
    beacons, note = _netsh_scan()
    result["method"] = "netsh wlan show networks mode=bssid (FALLBACK)"
    result["beacons"] = beacons
    result["warnings"].append(
        "Fell back to netsh. Signal strength is a percentage that has been "
        "converted to an approximate dBm value; it is NOT a measurement and is "
        "flagged as approximated throughout this report.")
    if note:
        result["warnings"].append(note)
    return result


# --------------------------------------------------------------------------
# netsh fallback
# --------------------------------------------------------------------------
_NETSH_BSSID = re.compile(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", re.I)
_NETSH_PCT = re.compile(r"(\d{1,3})\s*%")
_NETSH_CHAN = re.compile(r"^\s*\S+\s*:\s*(\d{1,3})\s*$")


def _netsh_scan() -> Tuple[List[Beacon], str]:
    """
    Parse `netsh wlan show networks mode=bssid`.

    Structure-driven rather than keyword-driven: we key off blank-line-separated
    blocks, MAC-shaped tokens and percentage-shaped tokens, none of which are
    translated.  That keeps it working on localised Windows where the field
    labels are not English.
    """
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as e:
        return [], "netsh failed: %s" % e

    text = proc.stdout.decode("utf-8", "replace")
    if "\x00" in text or not text.strip():
        text = proc.stdout.decode("utf-16-le", "replace")
    if not text.strip():
        return [], "netsh produced no output (exit %d)" % proc.returncode

    beacons: List[Beacon] = []
    current_ssid = ""
    pending: Optional[Beacon] = None
    lines = text.splitlines()

    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        mac_hit = _NETSH_BSSID.search(line)
        if mac_hit:
            if pending:
                beacons.append(pending)
            pending = Beacon(bssid=mac_hit.group(1).lower(), ssid=current_ssid,
                             rssi_approximated=True)
            continue

        # A network header sits at the left margin; its properties are indented.
        # Keying off indentation rather than the field label keeps this working
        # on localised Windows, where labels are translated but layout is not.
        indent = len(line) - len(line.lstrip())
        if indent <= 1 and ":" in line and not _NETSH_PCT.search(line):
            value = line.split(":", 1)[1].strip()
            if value and len(value) <= 32:
                if pending:
                    beacons.append(pending)
                    pending = None
                current_ssid = value
            continue
        if pending is None:
            continue
        pct = _NETSH_PCT.search(line)
        if pct and pending.signal_pct is None:
            p = int(pct.group(1))
            if 0 <= p <= 100:
                pending.signal_pct = p
                pending.rssi_dbm = _pct_to_dbm(p)
            continue
        chan = _NETSH_CHAN.match(line)
        if chan and pending.channel is None:
            c = int(chan.group(1))
            if 1 <= c <= 233:
                pending.channel = c
                pending.band = ("2.4 GHz" if c <= 14
                                else "5 GHz" if c < 200 else "6 GHz")
    if pending:
        beacons.append(pending)

    for b in beacons:
        if not b.ssid:
            b.ssid = ""
    beacons.sort(key=lambda b: -(b.rssi_dbm or -999))
    return beacons, ""


# --------------------------------------------------------------------------
# SSID resolution
# --------------------------------------------------------------------------
def match_ssid(beacons: List[Beacon], ssid: str,
               exact: bool = False) -> List[Beacon]:
    """Find every BSS advertising a given SSID."""
    if not ssid:
        return []
    if exact:
        return [b for b in beacons if b.ssid == ssid]
    needle = ssid.strip().casefold()
    exact_hits = [b for b in beacons if b.ssid.casefold() == needle]
    if exact_hits:
        return exact_hits
    return [b for b in beacons if needle in b.ssid.casefold()]
