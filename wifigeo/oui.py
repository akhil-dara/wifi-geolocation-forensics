"""
MAC address analysis: administration bits, and vendor attribution.

Vendor attribution is handled conservatively on purpose.  Naming the wrong
manufacturer in a forensic report is worse than naming none, so:

  * The offline table below contains only OUI assignments held with high
    confidence.  It is small by design - this is a portable tool, not a copy
    of the IEEE registry.
  * The authoritative path is a live lookup against the public IEEE-derived
    macvendors.com service, whose response is preserved as an exhibit like
    any other network transaction.
  * Every attribution carries the source that produced it, so a reviewer can
    see whether a name came from a live registry query or a local table.

Structural facts about the address (locally administered bit, multicast bit)
are derived arithmetically and are always reliable, so they are reported
regardless of whether a vendor name was found.
"""

from __future__ import annotations

import re
import time
from typing import Dict, Optional

from .net import Transport

#: High-confidence OUI -> organisation.  Deliberately short.
OFFLINE_OUI: Dict[str, str] = {
    "000c29": "VMware, Inc.",
    "005056": "VMware, Inc.",
    "0003ff": "Microsoft Corporation",
    "00155d": "Microsoft Corporation (Hyper-V)",
    "0050f2": "Microsoft Corporation",
    "080027": "PCS Systemtechnik / Oracle VirtualBox",
    "525400": "QEMU / KVM virtual NIC",
    "0001c0": "Compulab",
    "001a11": "Google, Inc.",
    "3c5ab4": "Google, Inc.",
    "f4f5e8": "Google, Inc.",
    "001b63": "Apple, Inc.",
    "0017f2": "Apple, Inc.",
    "0021e9": "Apple, Inc.",
    "3c0754": "Apple, Inc.",
    "a45e60": "Apple, Inc.",
    "f0989d": "Apple, Inc.",
    "001d0f": "TP-Link Technologies Co., Ltd.",
    "003192": "TP-Link Technologies Co., Ltd.",
    "50c7bf": "TP-Link Technologies Co., Ltd.",
    "a42bb0": "TP-Link Technologies Co., Ltd.",
    "b0487a": "TP-Link Technologies Co., Ltd.",
    "001e58": "D-Link Corporation",
    "00265a": "D-Link Corporation",
    "1cbdb9": "D-Link Corporation",
    "0018e7": "Cameo Communications",
    "000fb5": "NETGEAR",
    "00223f": "NETGEAR",
    "a00460": "NETGEAR",
    "001601": "Buffalo Inc.",
    "0024a5": "Buffalo Inc.",
    "001a2b": "Ayecom Technology",
    "000e8f": "Sercomm Corporation",
    "0090cc": "PLANEX COMMUNICATIONS",
    "00e04c": "Realtek Semiconductor Corp.",
    "52544c": "Realtek (locally assigned)",
    "001c10": "Cisco-Linksys, LLC",
    "00259c": "Cisco-Linksys, LLC",
    "00408c": "Axis Communications AB",
    "accc8e": "Axis Communications AB",
    "001de5": "Cisco Systems, Inc.",
    "0026cb": "Cisco Systems, Inc.",
    "6400f1": "Cisco Systems, Inc.",
    "00073b": "Huawei Technologies Co., Ltd.",
    "001882": "Huawei Technologies Co., Ltd.",
    "00259e": "Huawei Technologies Co., Ltd.",
    "283152": "Huawei Technologies Co., Ltd.",
    "001e10": "Huawei Technologies Co., Ltd.",
    "0012fb": "Samsung Electronics Co., Ltd.",
    "0017c9": "Samsung Electronics Co., Ltd.",
    "002454": "Samsung Electronics Co., Ltd.",
    "5c0a5b": "Samsung Electronics Co., Ltd.",
    "0019c5": "Sony Corporation",
    "001a80": "Sony Corporation",
    "001b98": "Samsung Electro-Mechanics",
    "000d3a": "Microsoft Corporation",
    "001c14": "VMware, Inc.",
    "00163e": "Xensource, Inc.",
    "0021f6": "Oracle Corporation",
    "001967": "Zte Corporation",
    "0026ed": "Zte Corporation",
    "34e0cf": "Zte Corporation",
    "0024d2": "ASKEY Computer Corp",
    "001cdf": "Belkin International Inc.",
    "9c207b": "Apple, Inc.",
    "001517": "Intel Corporate",
    "001b21": "Intel Corporate",
    "0021 6a": "Intel Corporate",
    "00248c": "ASUSTek COMPUTER INC.",
    "2c56dc": "ASUSTek COMPUTER INC.",
    "d850e6": "ASUSTek COMPUTER INC.",
    "00904c": "Epigram, Inc. (Broadcom reference)",
    "001cc0": "Intel Corporate",
    "0022fb": "Intel Corporate",
    "001a73": "Gemtek Technology Co., Ltd.",
    "0024b2": "NETGEAR",
    "d8074a": "Belkin International Inc.",
    "ec086b": "TP-Link Technologies Co., Ltd.",
    "b0be76": "TP-Link Technologies Co., Ltd.",
    "6ce873": "TP-Link Technologies Co., Ltd.",
}

_CACHE: Dict[str, Dict[str, object]] = {}
_LAST_LOOKUP = [0.0]

#: macvendors.com asks for no more than one request per second unauthenticated.
_MIN_INTERVAL = 1.1


def structure(bssid: str) -> Dict[str, object]:
    """
    Decode what the address itself tells us, with no external lookup.

    The two flag bits in the first octet are defined by IEEE 802:
        bit 0 (0x01) - individual (0) / group i.e. multicast (1)
        bit 1 (0x02) - universally (0) / locally (1) administered

    A locally administered address was not assigned by a manufacturer.  On
    Wi-Fi that usually means a randomised client MAC, a virtual/guest SSID
    radio, a software hotspot, or a mesh backhaul interface.  It matters a
    great deal here: a randomised address is not a stable identifier, so a
    database hit against one may relate to a completely different device.
    """
    clean = re.sub(r"[^0-9a-fA-F]", "", bssid).lower()
    if len(clean) != 12:
        return {"valid": False, "reason": "not a 48-bit MAC address"}
    first = int(clean[0:2], 16)
    locally_administered = bool(first & 0x02)
    multicast = bool(first & 0x01)

    note = ""
    if locally_administered:
        note = ("Locally administered address. Not assigned by a hardware "
                "manufacturer; commonly a randomised MAC, a virtual access "
                "point (guest network / mesh backhaul), or a software hotspot. "
                "Treat as a weak identifier.")
    else:
        note = ("Universally administered address, assigned from an IEEE OUI "
                "block. Ordinarily stable for the life of the hardware.")

    return {
        "valid": True,
        "normalised": ":".join(clean[i:i + 2] for i in range(0, 12, 2)),
        "oui": clean[:6],
        "oui_formatted": ":".join(clean[i:i + 2] for i in range(0, 6, 2)).upper(),
        "nic": clean[6:],
        "locally_administered": locally_administered,
        "multicast": multicast,
        "interpretation": note,
    }


def vendor(bssid: str, transport: Optional[Transport] = None,
           allow_network: bool = True) -> Dict[str, object]:
    """Resolve the manufacturer.  Always returns; never raises."""
    info = structure(bssid)
    if not info.get("valid"):
        return {**info, "vendor": None, "vendor_source": None}

    oui = str(info["oui"])

    if info["locally_administered"]:
        return {**info, "vendor": None, "vendor_source": "n/a",
                "vendor_note": ("No manufacturer can be attributed: the address "
                                "is locally administered, so the OUI portion is "
                                "not a real IEEE assignment.")}

    if oui in _CACHE:
        return {**info, **_CACHE[oui]}

    if oui in OFFLINE_OUI:
        found = {"vendor": OFFLINE_OUI[oui],
                 "vendor_source": "built-in offline reference table"}
        _CACHE[oui] = found
        return {**info, **found}

    if allow_network and transport is not None:
        gap = time.monotonic() - _LAST_LOOKUP[0]
        if gap < _MIN_INTERVAL:
            time.sleep(_MIN_INTERVAL - gap)
        _LAST_LOOKUP[0] = time.monotonic()
        ex = transport.fetch(
            "https://api.macvendors.com/%s" % info["normalised"],
            label="oui.macvendors.%s" % oui,
            headers={"Accept": "text/plain"})
        if ex.ok and ex.response_body:
            name = ex.response_body.decode("utf-8", "replace").strip()
            if name and "<" not in name and len(name) < 200:
                found = {"vendor": name,
                         "vendor_source": "macvendors.com live IEEE lookup",
                         "vendor_exhibit_seq": ex.seq}
                _CACHE[oui] = found
                return {**info, **found}
        if ex.status == 404:
            found = {"vendor": None,
                     "vendor_source": "macvendors.com live IEEE lookup",
                     "vendor_note": "OUI is not present in the IEEE registry.",
                     "vendor_exhibit_seq": ex.seq}
            _CACHE[oui] = found
            return {**info, **found}

    return {**info, "vendor": None, "vendor_source": "unresolved",
            "vendor_note": "No offline entry and the registry lookup did not "
                           "return a name."}
