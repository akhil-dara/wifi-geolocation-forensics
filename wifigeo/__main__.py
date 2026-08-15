"""
Command line entry point.

    python -m wifigeo                       launch the interface
    python -m wifigeo --cli "Office WiFi"   run one enquiry headlessly
    python -m wifigeo --scan                list what the radio can see
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import TOOL_NAME, __version__


def _is_installed() -> bool:
    """
    True when running from an installed copy rather than a clone or the
    portable build.

    This decides where cases are written, so it matters. An installed package
    lives in site-packages, which is writable in a virtual environment - so a
    plain write test says "yes" and case evidence lands inside the
    installation, where `pip install --upgrade` or `pip uninstall` will
    silently delete it. Evidence must never live somewhere a package manager
    owns.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    parts = {p.lower() for p in here.split(os.sep)}
    return bool(parts & {"site-packages", "dist-packages"})


def _default_evidence_root() -> str:
    """
    Beside the application when portable, in the user's home when installed.

    The portable build is meant to be self-contained - extract it to a USB
    stick and the cases stay with it - so writing beside the application is
    right there and wrong everywhere else.
    """
    if not _is_installed():
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        portable = os.path.join(here, "evidence")
        try:
            os.makedirs(portable, exist_ok=True)
            probe = os.path.join(portable, ".writable")
            with open(probe, "w") as fh:
                fh.write("")
            os.remove(probe)
            return portable
        except OSError:
            pass
    return os.path.join(os.path.expanduser("~"), "WGF-Evidence")


def _console_utf8() -> None:
    """Windows consoles default to a codepage that cannot print degree signs."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv=None) -> int:
    _console_utf8()
    p = argparse.ArgumentParser(
        prog="wifigeo", description=TOOL_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Runs entirely locally. No API keys are used or required.")
    p.add_argument("target", nargs="?", default="",
                   help="SSID or BSSID to locate (CLI mode)")
    p.add_argument("--cli", metavar="TARGET",
                   help="run one enquiry without the interface")
    p.add_argument("--scan", action="store_true",
                   help="list networks visible to the radio and exit")
    p.add_argument("--host-artefacts", action="store_true",
                   help="recover access point addresses this machine has "
                        "associated with, from the WLAN-AutoConfig event log, "
                        "and locate them. Windows only. The registry is not "
                        "used: it records the gateway address, not the BSSID")
    p.add_argument("--evidence", metavar="DIR", default=None,
                   help="where to write evidence packages")
    p.add_argument("--port", type=int, default=8731, help="interface port")
    p.add_argument("--no-browser", action="store_true",
                   help="do not open a browser automatically")
    p.add_argument("--examiner", default="", help="examiner name for the case")
    p.add_argument("--organisation", default="")
    p.add_argument("--reference", default="", help="your own case reference")
    p.add_argument("--neighbours", type=int, default=400,
                   help="neighbouring access points to harvest (1-400)")
    p.add_argument("--radio-scan", action="store_true",
                   help="actively scan the radio to resolve an SSID and to "
                        "gather a beacon fingerprint (off by default; this "
                        "changes the local RF environment)")
    p.add_argument("--bssid", action="append", default=[], metavar="MAC",
                   help="an access point address to locate; repeatable, and "
                        "the usual way to run a passive enquiry")
    p.add_argument("--ssid", default="", metavar="NAME",
                   help="the network name, if known, for labelling the report")
    p.add_argument("--import", dest="import_path", metavar="FILE",
                   help="read access point addresses from a file - saved "
                        "netsh output, or a plain list")
    p.add_argument("--no-microsoft", action="store_true",
                   help="skip the Microsoft cross-check")
    p.add_argument("--msft-api-version", choices=("v22", "v21"), default="v22",
                   help="which Microsoft endpoint version to use (default v22)")
    p.add_argument("--observed-at", metavar="ISO8601", default="",
                   help="when the beacons were observed, if not now, e.g. "
                        "2025-09-21T11:59:23+00:00 - use when positioning an "
                        "address recovered from an artefact")
    p.add_argument("--send-device-profile", action="store_true",
                   help="include the optional DeviceProfile element, which "
                        "identifies this machine to the service (off by default)")
    p.add_argument("--replicates", type=int, default=4, metavar="N",
                   help="disjoint access-point groups to multilaterate "
                        "independently (default 4, 0 disables)")
    p.add_argument("--no-enrichment", action="store_true",
                   help="skip address, places, elevation and daylight lookups")
    p.add_argument("--no-tiles", action="store_true",
                   help="do not embed map imagery in the report")
    p.add_argument("--redact", action="store_true",
                   help="also write a redacted report for distribution: "
                        "vendor-prefix-only addresses, truncated coordinates, "
                        "no street address or map. The evidence package itself "
                        "is never redacted")
    p.add_argument("--json", action="store_true",
                   help="print the full result as JSON (CLI mode)")
    p.add_argument("--version", action="version",
                   version="%s %s" % (TOOL_NAME, __version__))
    args = p.parse_args(argv)

    root = args.evidence or _default_evidence_root()

    if args.scan:
        from . import scan as scanner
        survey = scanner.scan(active=True)
        print("Method : %s" % survey.get("method"))
        for w in survey.get("warnings") or []:
            print("Warning: %s" % w)
        beacons = survey.get("beacons") or []
        print("\n%-18s %-30s %6s %5s %-8s %s"
              % ("BSSID", "SSID", "RSSI", "CH", "BAND", "PHY"))
        print("-" * 88)
        for b in beacons:
            print("%-18s %-30s %5s  %4s %-8s %s"
                  % (b.bssid, (b.ssid or "<hidden>")[:30], b.rssi_dbm,
                     b.channel or "", b.band, b.phy))
        print("\n%d access points observed." % len(beacons))
        return 0

    if args.host_artefacts:
        from . import ingest
        # Registry deliberately excluded: NetworkList records the default
        # gateway's address rather than the BSSID, so nothing recovered from it
        # can be positioned. The event log's PeerMac genuinely is the access
        # point.
        found = ingest.collect_host_artefacts(use_registry=False)
        obs = found.get("observations") or []
        for w in found.get("warnings") or []:
            print("Warning: %s" % w, file=sys.stderr)
        print("Recovered %d access point address(es) from the WLAN event log."
              % len(obs), file=sys.stderr)
        if not obs:
            # The reason differs by platform, and the wrong reason is worse
            # than none: telling someone on Linux to retry in an elevated shell
            # sends them looking for a registry their system does not have.
            if sys.platform != "win32":
                p.error("reading a host's own wireless history requires "
                        "Windows: it comes from the WLAN-AutoConfig event "
                        "log. On this platform, "
                        "supply addresses with --bssid, or import an artefact "
                        "collected from a Windows host with --import.")
            p.error("no access point addresses could be recovered. Windows "
                    "records the associated access point only in a minority of "
                    "WLAN-AutoConfig events (field 'PeerMac'); the common "
                    "connect event 8001 names the network but not the access "
                    "point. Collect addresses from a scan instead.")
        observations_from_host = [o.to_dict() if hasattr(o, "to_dict") else o
                                  for o in obs]
    else:
        observations_from_host = []

    target = args.cli or args.target

    # Gather any addresses supplied directly or imported from artefacts.
    #
    # If the operator asked for something and it yielded nothing, say so and
    # stop. Falling through here would start the web interface instead, which
    # looks exactly like the tool hanging - the command appears to do nothing
    # and never returns.
    observations = list(observations_from_host)
    if args.bssid:
        from . import ingest
        parsed = ingest.parse_manual("\n".join(args.bssid))
        if not parsed:
            p.error("none of the --bssid values is a MAC address: %s\n"
                    "Expected 12 hex digits, optionally separated by colons, "
                    "hyphens, dots or spaces." % ", ".join(repr(b) for b in args.bssid))
        observations.extend(o.to_dict() for o in parsed)
    if args.import_path:
        from . import ingest
        if not os.path.isfile(args.import_path):
            p.error("no such file: %s" % args.import_path)
        got = ingest.ingest_file(args.import_path)
        obs = got.get("observations") or []
        if not obs:
            p.error("no access point addresses were found in %s (read as %s).\n"
                    "%s" % (args.import_path, got.get("format"),
                            got.get("note") or ""))
        observations.extend(o.to_dict() if hasattr(o, "to_dict") else o
                            for o in obs)
        print("Imported %d access point address(es) from %s (%s)"
              % (len(obs), args.import_path, got.get("format")),
              file=sys.stderr)

    if target or observations:
        from .engine import Investigation, Options

        # Progress is diagnostic output and goes to stderr, so that stdout
        # carries only the result. Without this, --json emits progress lines
        # ahead of the document and nothing downstream can parse it.
        def progress(phase, message, pct):
            sys.stderr.write("\r\033[K[%3.0f%%] %-11s %s" % (pct, phase, message))
            sys.stderr.flush()
            if pct >= 100:
                sys.stderr.write("\n")

        opts = Options(
            target=target, neighbours=max(1, min(400, args.neighbours)),
            extra_observations=observations,
            known_ssid=args.ssid,
            active_scan=args.radio_scan,
            use_microsoft=not args.no_microsoft,
            msft_api_version=args.msft_api_version,
            observed_at=args.observed_at,
            send_device_profile=args.send_device_profile,
            redacted_copy=args.redact,
            replicate_groups=max(0, args.replicates),
            use_enrichment=not args.no_enrichment,
            fetch_tiles=not args.no_tiles,
            examiner=args.examiner, organisation=args.organisation,
            reference=args.reference)
        result = Investigation(opts, root, progress=progress).run()

        if args.json:
            print(json.dumps(result, indent=2, default=str))
            return 0 if result.get("ok") else 1

        # An artefact import is a movement history, so lead with the places
        # rather than with a single fused position that would describe none of
        # them.
        places = result.get("places") or []
        if len(places) > 1:
            print()
            print("  %d distinct places" % len(places))
            for p in places:
                span = ""
                if p.get("earliest_seen") or p.get("latest_seen"):
                    span = "   %s to %s" % ((p.get("earliest_seen") or "?")[:10],
                                            (p.get("latest_seen") or "?")[:10])
                print("    %d. %.6f, %.6f   %d network(s)%s"
                      % (p["index"], p["latitude"], p["longitude"],
                         p["network_count"], span))
                for n in p["networks"][:6]:
                    print("       %s  %s%s"
                          % (n["bssid"], n["ssid"] or "(unnamed)",
                             ("  last seen " + n["last_seen"][:10])
                             if n.get("last_seen") else ""))
                if len(p["networks"]) > 6:
                    print("       ... and %d more" % (len(p["networks"]) - 6))

        v = result.get("validation") or {}
        pos = result.get("position")
        co = result.get("coordinates") or {}
        ev = result.get("evidence") or {}
        print()
        print("  Case      : %s" % result.get("case_id"))
        if v.get("verdict"):
            print("  Verdict   : %s  (%s/100, %s%% of checks run)"
                  % (v.get("verdict"), v.get("score"), v.get("coverage")))
        if pos:
            print("  Position  : %s  +/- %s m" % (co.get("decimal"),
                                                  pos.get("accuracy_m")))
            print("  Method    : %s" % pos.get("method"))
            print("  Plus Code : %s" % co.get("plus_code"))
            print("  MGRS      : %s" % co.get("mgrs"))
            addr = (result.get("enrichment") or {}).get("address") or {}
            if addr.get("display_name"):
                print("  Address   : %s" % addr["display_name"])
        else:
            import textwrap
            print("  Result    : no position established")
            for line in textwrap.wrap(str(result.get("failure") or ""), 68):
                print("              %s" % line)
        for c in result.get("collisions") or []:
            print("  ! excluded %s (%s km away)" % (c["bssid"], c["distance_km"]))
        print("  Report    : %s" % result.get("report_path"))
        if result.get("report_pdf_path"):
            print("  PDF       : %s" % result.get("report_pdf_path"))
        if result.get("report_redacted_path"):
            print("  Redacted  : %s" % result.get("report_redacted_path"))
        if result.get("report_redacted_pdf_path"):
            print("              %s" % result.get("report_redacted_pdf_path"))
        print("  Evidence  : %s" % ev.get("zip_path"))
        print("  Root hash : %s" % ev.get("root_hash"))
        return 0 if result.get("ok") else 1

    from .app import serve
    serve(root, port=args.port, open_browser=not args.no_browser)
    return 0


if __name__ == "__main__":
    sys.exit(main())
