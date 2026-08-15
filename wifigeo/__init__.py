"""
WiFi Geolocation Forensics
============================================

A zero-dependency (pure CPython standard library) DFIR tool that resolves
Wi-Fi SSID / BSSID observations to geographic positions using two mutually
independent, credential-free crowd-sourced positioning services, cross
validates them, enriches the result with open-source geospatial intelligence
and emits a court-presentable evidence package.

Design constraints (deliberate):
  * NO third-party packages.  Everything is stdlib.  This keeps the portable
    build small and reproducible, and means nothing outside this repository
    can change what the tool does - which matters when the output is intended
    to be evidential.
  * NO API keys.  Every data source used is credential-free.
  * Every byte sent and received is preserved verbatim and hashed.
"""

__all__ = ["__version__", "TOOL_NAME", "TOOL_ID", "PROJECT_URL", "USER_AGENT"]

__version__ = "2.0.0"

TOOL_NAME = "WiFi Geolocation Forensics"
TOOL_ID = "wifigeo"

#: The one string to change when this repository is published under its real
#: name. It is deliberately the single source: the User-Agent below, the report
#: footer and the documentation all read from here, so there is one edit rather
#: than six, and CI fails while the placeholder is still in place.
PROJECT_URL = "https://github.com/akhil-dara/wifi-geolocation-forensics"

#: Identifies this tool to the open-data services it consumes.
#:
#: This is not decoration. The Nominatim and Overpass usage policies both
#: require a genuine identifying URL, and both rate-limit or refuse traffic that
#: presents as an unidentified bot. A bare "https://github.com/" - no path, no
#: project - reads as exactly that, and the failure would surface as the address
#: and places lookups mysteriously breaking for everyone who installs the tool.
USER_AGENT = (
    "WiFi-Geolocation-Forensics/{v} (+{url}; DFIR research tool)"
).format(v=__version__, url=PROJECT_URL)
