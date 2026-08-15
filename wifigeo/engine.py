"""
Investigation orchestration.

One `Investigation` object owns one case: it decides what to collect, in what
order, how to reconcile the sources, and what the resulting position claim is.
Progress is emitted through a callback so the user interface can narrate a run
that takes tens of seconds without the engine knowing anything about HTTP or
HTML.
"""

from __future__ import annotations

import datetime as dt
import os
import traceback
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import (apple, geo, mapimage, msft, osint, oui, redact, report,
               reportpdf, scan)
from .evidence import Case, utc_iso
from .net import Transport

ProgressFn = Callable[[str, str, float], None]


@dataclass
class Options:
    """Everything the operator can vary about a run."""

    target: str = ""                     # SSID or BSSID
    mode: str = "auto"                   # auto | ssid | bssid | survey
    #: Additional access point addresses supplied by the operator or recovered
    #: from host artefacts.  A network commonly presents separate radios for
    #: 2.4 GHz and 5 GHz, and an investigator may know several; each is an
    #: independent lookup and they corroborate one another.
    extra_observations: List[Dict[str, object]] = field(default_factory=list)
    #: Access points that were audible *at the same time as* the target, but
    #: are not themselves being located.
    #:
    #: Microsoft does not answer "where is this access point" - it answers
    #: "where is a device that can see all of these at once", and it gets
    #: markedly better at it the more it is given. So when an operator has the
    #: whole scan and one address out of it is the subject of the enquiry, the
    #: rest is not noise to discard: it is the fingerprint that sharpens the
    #: answer. These are put to Microsoft with the target and are never treated
    #: as targets themselves, so the report still concerns one access point.
    context_observations: List[Dict[str, object]] = field(default_factory=list)
    #: The network name, where the operator already knows it.  Neither
    #: positioning service returns network names, so when an enquiry starts
    #: from a hardware address there is otherwise nothing to call the network
    #: in the report.  Supplying it here makes the report read clearly and is
    #: recorded as the operator's assertion, not as a derived fact.
    known_ssid: str = ""
    neighbours: int = apple.MAX_NEIGHBOURS
    #: Scanning is opt-in.  Triggering the radio is an active step that changes
    #: the local RF environment and is not always appropriate on an evidential
    #: host, so nothing touches the radio unless asked. The default
    #: workflow is entirely passive: the operator supplies access point
    #: addresses, or imports them from artefacts.
    active_scan: bool = False
    use_microsoft: bool = True
    #: How many access points to put to Microsoft individually.  Each is one
    #: request, so this trades runtime for corroboration strength.  Twenty is
    #: enough to establish agreement without labouring a free service.
    msft_probe_limit: int = 20
    #: Size of the derived locality probe.  Kept small and local on purpose:
    #: multilateration wants a tight cluster, and a large scattered set makes
    #: the answer worse rather than better.
    locality_probe_size: int = 24
    #: Replicated multilateration: how many disjoint groups, and how many
    #: access points in each.  Four groups of twelve re-derives the position
    #: four times from non-overlapping evidence at the cost of four requests.
    replicate_groups: int = 4
    replicate_size: int = 12
    #: Which version of the Microsoft endpoint to use. Both answer identically;
    #: the choice exists because a service can withdraw a version without
    #: notice, and an examiner should not be stuck when it does.
    msft_api_version: str = "v22"
    #: When the beacons were observed, if that is not now. Positioning an
    #: access point recovered from a registry hive months later should state
    #: the observation time, not the query time.
    observed_at: str = ""
    #: Emit the optional <DeviceProfile> element. Off by default because it
    #: identifies the examining machine to a third party.
    send_device_profile: bool = False
    #: Also produce a redacted copy of the report for distribution. The
    #: evidence package itself is never redacted.
    redacted_copy: bool = False
    use_corroborating: bool = True
    use_enrichment: bool = True
    fetch_tiles: bool = True
    tile_zoom: int = 17
    tile_grid: int = 3
    #: Render a standalone, print-quality map image (SVG) as an exhibit.
    export_map: bool = True
    export_map_grid: int = 5
    #: Raster multiplier for the PNG exhibit. 2 gives a print-quality image
    #: without making the file unwieldy.
    png_scale: int = 2
    poi_radius_m: int = 200
    #: How far out to look for recognisable landmarks.
    landmark_radius_m: int = 1400
    #: Additionally run the slow Overpass sweep. Off by default: Photon returns
    #: the same OpenStreetMap data in about a hundredth of the time.
    deep_places: bool = False
    verify_tls: bool = True
    case_id: Optional[str] = None
    examiner: str = ""
    organisation: str = ""
    reference: str = ""
    notes: str = ""



#: How close an access point has to be to count as corroborating a place.
#: Wide enough to cover a campus or a city block, tight enough that it is the
#: same place in any ordinary sense.
NEIGHBOUR_RADIUS_M = 500.0

#: How many places get a street address. Nominatim's usage policy is one
#: request a second, so a fifty-place import would otherwise spend a minute
#: geocoding. The rest still carry coordinates and map links.
PLACE_ADDRESS_LIMIT = 15


def _place_corroboration(grouped: int, profiled_here: int,
                         via_cloud: int) -> Dict[str, object]:
    """
    How well supported a place is, judged only on this host's own networks.

    The measure is the overlap between two lists built without reference to
    each other: the networks the host has a profile for, and the access points
    Apple places at this location. Several of the host's networks appearing in
    one Apple neighbourhood means Apple - which knows nothing about this host -
    has independently put that host's networks in one place.

    Deliberately NOT counted: how many unrelated access points Apple holds
    nearby. A city centre returns hundreds and a rural lane returns three, so
    that number measures how well mapped the area is, not whether the host was
    ever in it. Rating on it would have marked a busy street stronger than a
    quiet one on evidence that says nothing about the subject.
    """
    extra = ("" if not via_cloud else
             " %d of them appear only in the neighbouring access points Apple "
             "returned, not by locating them directly, so the grouping alone "
             "would have missed them." % via_cloud)

    if profiled_here >= 3:
        level, text = "strong", (
            "%d of this host's own networks are placed here by Apple.%s Several "
            "independently profiled networks in one Apple neighbourhood is "
            "strong support that the host was at this location."
            % (profiled_here, extra))
    elif profiled_here == 2:
        level, text = "moderate", (
            "Two of this host's own networks are placed here by Apple.%s That is "
            "mutual support, though two networks can also be two radios of one "
            "access point." % extra)
    elif grouped > 1:
        level, text = "moderate", (
            "%d supplied addresses resolve here, but they are not corroborated "
            "by any further profiled network in Apple's neighbouring records."
            % grouped)
    else:
        level, text = "weak", (
            "This place rests on a single access point record, with no other "
            "network from this host placed here by Apple. Treat it as a lead "
            "rather than an established location.")
    return {"level": level, "statement": text}


class Investigation:
    def __init__(self, opts: Options, evidence_root: str,
                 progress: Optional[ProgressFn] = None):
        self.opts = opts
        self.case = Case(evidence_root, case_id=opts.case_id,
                         examiner=opts.examiner, organisation=opts.organisation,
                         reference=opts.reference, notes=opts.notes)
        self.transport = Transport(recorder=self.case, verify_tls=opts.verify_tls)
        self._progress = progress or (lambda phase, msg, pct: None)
        self.result: Dict[str, object] = {}
        self.collisions: List[Dict[str, object]] = []
        #: Distinct locations the supplied access points resolve to. More than
        #: one means the input is a movement history rather than an observation.
        self.places: List[Dict[str, object]] = []
        #: What the Microsoft fingerprint was built from, in words for the
        #: report - or why none was built.
        self.fingerprint_note: str = ""

    def say(self, phase: str, message: str, pct: float) -> None:
        self._progress(phase, message, pct)
        self.case.log("progress", phase=phase, message=message, percent=pct)

    # ----------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        try:
            return self._run()
        except Exception as e:                       # pragma: no cover
            # Surface the fault. Reporting only "no position established" for
            # what is actually a crash sent an earlier bug (a division by zero
            # in the replicate grouping) out looking like an ordinary negative
            # result, with a full Apple response and a resolved Microsoft
            # position sitting unused in the case file.
            self.case.log("error.fatal", error=str(e),
                          traceback=traceback.format_exc())
            self.say("error", "The investigation failed: %s: %s"
                     % (type(e).__name__, e), 100)
            self.result = {"ok": False,
                           "error": "%s: %s" % (type(e).__name__, e),
                           "failure": ("The investigation did not complete: "
                                       "%s: %s. The evidence collected up to "
                                       "that point has still been sealed."
                                       % (type(e).__name__, e)),
                           "traceback": traceback.format_exc(),
                           "case_id": self.case.case_id}
            try:
                self.case.package(self.result)
            except Exception:
                pass
            return self.result

    def _run(self) -> Dict[str, object]:
        opts = self.opts
        started = utc_iso()
        self.say("start", "Opening case %s" % self.case.case_id, 2)

        # ---- 1. establish the target BSSIDs -----------------------------
        survey, targets, target_kind, ssid = self._resolve_targets()

        if not targets:
            if target_kind == "ssid-unresolvable":
                why = ("A network name alone cannot be positioned. Neither "
                       "provider accepts a network name, and there is no "
                       "credential-free database that maps a name to its "
                       "access points. Supply the access point address (BSSID), "
                       "import it from host artefacts, or enable a radio scan "
                       "if the network is within range of this machine.")
            else:
                why = ("No access point could be identified for the supplied "
                       "target.")
            self.say("done", why, 100)
            self.result = self._finish(started, survey, ssid, target_kind,
                                       targets, None, None, None, None, {}, None,
                                       why)
            return self.result

        # ---- 2. Apple -----------------------------------------------------
        self.say("apple", "Querying Apple Location Services for %d BSSID(s) and "
                          "up to %d neighbours" % (len(targets), opts.neighbours), 25)
        apple_res = apple.query(self.transport, targets, opts.neighbours)
        self.say("apple", "Apple returned %d access points (%d with positions)"
                 % (apple_res["total_returned"], apple_res["total_located"]), 40)

        # ---- 2a. distinct places -----------------------------------------
        # Grouped here, before Microsoft, and not merely for the report:
        # Microsoft is asked "where is a device that can see all of these at
        # once", so the set put to it must be a set that could have been seen
        # at once. Knowing how many places the addresses fall into is what
        # decides whether such a question can honestly be asked at all.
        self.places = self._group_places(apple_res)
        if len(self.places) > 1:
            self.say("analysis", "The supplied access points resolve to %d "
                                 "distinct places; reporting a location "
                                 "history rather than one position"
                     % len(self.places), 44)

        # ---- 3. Microsoft (independent) ----------------------------------
        msft_res = None
        msft_each = None
        msft_probe = None
        if opts.use_microsoft:
            beacons, kind, self.fingerprint_note = self._microsoft_fingerprint(
                survey, targets)
            if not beacons:
                self.say("microsoft", "No Microsoft fingerprint: the addresses "
                                      "span %d places and were never observed "
                                      "together" % len(self.places), 48)
            if beacons:
                self.say("microsoft", "Submitting a %d-beacon fingerprint to "
                                      "Microsoft (%s)" % (len(beacons), kind), 48)
                msft_res = msft.query(
                    self.transport, beacons,
                    endpoint=msft.API_VERSIONS.get(opts.msft_api_version),
                    observed_at=opts.observed_at or None,
                    device_profile=self._device_profile() if opts.send_device_profile
                    else None)
                res = msft_res["result"]
                if res.located:
                    self.say("microsoft", "Microsoft resolved %.6f, %.6f (+/-%s m)"
                             % (res.latitude, res.longitude,
                                res.radial_uncertainty_m), 53)
                elif res.ip_fallback:
                    self.say("microsoft", "Microsoft fell back to IP geolocation "
                                          "(+/-%s m) - discarded, it describes this "
                                          "connection, not the target."
                             % res.radial_uncertainty_m, 53)
                else:
                    self.say("microsoft", "Microsoft returned no position (%s)"
                             % (res.fault or "?"), 53)
            else:
                self.say("microsoft", "No beacons available for a Microsoft "
                                      "fingerprint.", 53)

            # Per-access-point cross-check: ask Microsoft about each access
            # point on its own, so the two providers answer the identical
            # question about the identical device.
            #
            # The targets alone are often too few to corroborate anything - a
            # single BSSID that Microsoft has never seen yields nothing. Apple,
            # however, has just handed us hundreds of positioned access points
            # in the same locality, and each of those is a legitimate question
            # to put to Microsoft individually.
            #
            # What we must NOT do is put Apple's neighbours into the beacon
            # fingerprint above. That request means "a device observed all of
            # these at once", and we observed no such thing; asserting it would
            # be fabricating an observation. Asking about each one separately
            # asserts nothing.
            # Derived locality probe. Where the observed fingerprint produced
            # nothing - which is the norm for a single BSSID Microsoft has
            # never seen - put Apple's neighbour set to Microsoft's engine and
            # ask where IT computes for that set. Independent databases, so
            # agreement is meaningful. Recorded as a probe, never as an
            # observation; see msft.probe_replicates.
            # Replicated multilateration. Apple's nearest neighbours are split
            # into disjoint groups and each is put to Microsoft separately, so
            # the position is re-derived several times from non-overlapping
            # evidence rather than once. This runs regardless of whether the
            # observed fingerprint succeeded - when it did, the replicates test
            # it; when it did not, they are the only cross-check available.
            pool, span = self._nearest_neighbours(
                apple_res, opts.replicate_groups * opts.replicate_size)
            groups = self._disjoint_groups(pool, opts.replicate_groups)
            if groups:
                self.say("microsoft", "Replicating multilateration: %d disjoint "
                                      "groups of %d access points (all within "
                                      "%.0f m of the target)"
                         % (len(groups), len(groups[0]), span), 54)
                msft_probe = msft.probe_replicates(
                    self.transport, groups,
                    origin=("the %d access points Apple places nearest the "
                            "target, all within %.0f m of it"
                            % (len(pool), span)))
                if msft_probe["groups_resolved"] >= 2:
                    self.say("microsoft", "%d of %d groups resolved "
                                          "independently; they agree to within "
                                          "%.0f m"
                             % (msft_probe["groups_resolved"],
                                msft_probe["groups_submitted"],
                                msft_probe["max_separation_m"]), 55)
                else:
                    self.say("microsoft", "%d of %d replicate groups resolved"
                             % (msft_probe["groups_resolved"],
                                msft_probe["groups_submitted"]), 55)
                    pr = msft_probe["result"]
                    self.say("microsoft",
                             ("Microsoft independently places that set at "
                              "%.6f, %.6f (+/-%s m)"
                              % (pr.latitude, pr.longitude,
                                 pr.radial_uncertainty_m)) if pr.located
                             else "Locality probe returned no position (%s)"
                                  % (pr.fault or "?"), 55)

            probe = self._corroboration_pool(targets, apple_res,
                                             opts.msft_probe_limit)
            self.say("microsoft", "Cross-checking %d access point(s) individually "
                                  "against Microsoft" % len(probe), 56)
            msft_each = msft.corroborate_each(self.transport, probe,
                                              limit=len(probe))
            msft_each["targets_probed"] = [m for m in probe if m in targets]
            msft_each["neighbours_probed"] = [m for m in probe if m not in targets]
            self.say("microsoft", "%d of %d access point(s) are known to both "
                                  "providers%s"
                     % (msft_each["known_to_microsoft"], msft_each["queried"],
                        (" (%d IP-fallback answers discarded)"
                         % msft_each["discarded_ip_fallback"])
                        if msft_each["discarded_ip_fallback"] else ""), 60)

        # ---- 4. cluster analysis -----------------------------------------
        self.say("analysis", "Analysing the neighbouring access-point cloud", 63)
        located = [a for a in apple_res["access_points"] if a.located]
        points = [(a.latitude, a.longitude) for a in located]
        weights = [1.0 / max(20.0, float(a.accuracy_m or 100)) for a in located]
        cluster = geo.analyse_cluster(points, weights) if points else {"kept_count": 0}

        anchor, anchor_note = self._choose_anchor(apple_res, cluster)

        # ---- 5. cross validation ------------------------------------------
        ctx = self._validation_context(survey, targets, apple_res, ssid,
                                       anchor, msft_res)
        ctx.update(self._per_ap_agreement(apple_res, msft_each))

        # `msft_dict` is what the service said, kept in full for the report.
        # `msft_usable` is what may influence a position. An IP-fallback answer
        # carries real-looking coordinates but describes this machine's
        # internet connection, so it must never reach the scoring or the
        # fusion - it would corroborate nothing while looking like it did.
        msft_dict = msft_res["result"].to_dict() if msft_res else None
        msft_usable = msft_dict if (msft_dict and msft_dict.get("located")) else None

        if msft_probe:
            ctx["replicate_groups"] = msft_probe["groups_submitted"]
            ctx["replicate_resolved"] = msft_probe["groups_resolved"]
            ctx["replicate_spread_m"] = msft_probe["max_separation_m"]
            if msft_usable is None and msft_probe.get("consensus"):
                # No observed fingerprint resolved, so the replicate consensus
                # becomes the Microsoft side of the cross-provider check. It is
                # flagged as derived so the rubric discounts it.
                con = msft_probe["consensus"]
                msft_usable = {
                    "latitude": con["latitude"], "longitude": con["longitude"],
                    "radial_uncertainty_m": max(
                        75.0, msft_probe["max_separation_m"] or 0.0),
                    "located": True, "ip_fallback": False,
                    "derived_probe": True,
                }
                ctx["microsoft_is_derived_probe"] = True
        validation = geo.cross_validate(anchor, msft_usable, cluster, ctx)
        validation["context"] = ctx
        self.say("analysis", "Verdict: %s (%.0f/100, coverage %.0f%%)"
                 % (validation["verdict"], validation["score"],
                    validation["coverage"]), 70)
        for c in self.collisions:
            self.say("analysis", "Excluded conflicting record %s at %.0f km"
                     % (c["bssid"], c["distance_km"]), 71)

        # ---- 6. the position claim ----------------------------------------
        final = self._consensus(anchor, msft_usable, cluster, ctx)

        # ---- 7. corroboration & enrichment --------------------------------
        corroborating: Dict[str, object] = {}
        if opts.use_corroborating:
            self.say("corroborate", "Querying additional open Wi-Fi datasets", 74)
            corroborating["mylnikov"] = osint.mylnikov(self.transport, targets[0])
            if ssid:
                corroborating["wifidb"] = osint.wifidb_ssid(self.transport, ssid)

        enrichment: Dict[str, object] = {}
        static_map = None
        export_map = None

        # Give every place in a location history a street address. Without one
        # the history is a column of coordinates, and an examiner has to paste
        # each into a map by hand to learn anything from it - which is most of
        # the work the report is supposed to have done. Capped, because
        # Nominatim's usage policy allows one request a second and a large
        # registry import can hold dozens of places.
        if len(self.places) > 1 and opts.use_enrichment:
            todo = self.places[:PLACE_ADDRESS_LIMIT]
            self.say("enrich", "Reverse geocoding %d place(s)" % len(todo), 74)
            for place in todo:
                addr = osint.reverse_geocode(self.transport,
                                             place["latitude"], place["longitude"])
                place["address"] = addr.get("display_name") or ""
                place["locality"] = (addr.get("city") or addr.get("district")
                                     or addr.get("state") or "")
                # The components separately as well as the one-line form. A
                # spreadsheet is sorted and filtered by town, postcode and
                # country, and splitting those back out of a display name
                # afterwards is guesswork.
                place["address_parts"] = {
                    "house_number": addr.get("house_number") or "",
                    "road": addr.get("road") or "",
                    "area": addr.get("neighbourhood") or "",
                    "city": addr.get("city") or "",
                    "district": addr.get("district") or "",
                    "state": addr.get("state") or "",
                    "postcode": addr.get("postcode") or "",
                    "country": addr.get("country") or "",
                    "country_code": addr.get("country_code") or "",
                }
            if len(self.places) > len(todo):
                self.say("enrich", "%d further place(s) left without an address "
                                   "to stay within the geocoder's rate limit"
                         % (len(self.places) - len(todo)), 76)

        if final and opts.use_enrichment:
            lat, lon = final["latitude"], final["longitude"]
            self.say("enrich", "Reverse geocoding the position", 78)
            enrichment["address"] = osint.reverse_geocode(self.transport, lat, lon)
            self.say("enrich", "Identifying nearby places", 82)
            enrichment["places"] = osint.nearby_places(
                self.transport, lat, lon, opts.poi_radius_m,
                landmark_radius_m=opts.landmark_radius_m,
                deep=opts.deep_places)
            self.say("enrich", "Retrieving elevation and timezone", 86)
            enrichment["environment"] = osint.environment(self.transport, lat, lon)
            enrichment["daylight"] = osint.daylight(
                self.transport, lat, lon,
                dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"))

            if opts.fetch_tiles:
                self.say("map", "Downloading and embedding map imagery", 89)
                static_map = osint.fetch_static_map(
                    self.transport, lat, lon, opts.tile_zoom, opts.tile_grid)
                self.say("map", "Embedded %d tiles (%.0f KB) for offline viewing"
                         % (static_map["tile_count"], static_map["bytes"] / 1024), 91)

                # A larger, higher-zoom tile set for the exportable image, so
                # the exhibit stands on its own at print resolution rather than
                # being an upscale of the in-report map.
                if opts.export_map:
                    self.say("map", "Rendering the exportable map image", 92)
                    export_map = osint.fetch_static_map(
                        self.transport, lat, lon,
                        min(19, opts.tile_zoom + 1), opts.export_map_grid)
                    self.say("map", "Export image: %d tiles at zoom %d (%.0f KB)"
                             % (export_map["tile_count"], export_map["zoom"],
                                export_map["bytes"] / 1024), 93)

        # ---- 8. vendor attribution ----------------------------------------
        self.say("enrich", "Attributing hardware vendors", 95)
        vendors: Dict[str, object] = {}
        for mac in targets[:8]:
            vendors[mac] = oui.vendor(mac, self.transport)

        self.result = self._finish(started, survey, ssid, target_kind, targets,
                                   apple_res, msft_res, cluster, validation,
                                   {"corroborating": corroborating,
                                    "enrichment": enrichment,
                                    "vendors": vendors,
                                    "static_map": static_map,
                                    "export_map": export_map,
                                    "anchor": anchor,
                                    "anchor_note": anchor_note,
                                    "collisions": self.collisions,
                                    "places": self.places,
                                    "microsoft_per_ap": msft_each,
                                    "microsoft_replicates": msft_probe},
                                   final, None)
        return self.result

    # ----------------------------------------------------------------------
    def _resolve_targets(self):
        """Turn whatever the operator typed into a list of BSSIDs."""
        opts = self.opts
        target = (opts.target or "").strip()
        survey: Dict[str, object] = {}
        ssid = ""

        # The radio is touched only when the operator has asked for it.
        want_scan = opts.active_scan and scan.IS_WINDOWS
        if opts.active_scan and not scan.IS_WINDOWS:
            self.say("scan", "A radio scan was requested but native scanning "
                             "requires Windows; continuing without it.", 8)

        if want_scan:
            self.say("scan", "Scanning for wireless networks", 8)
            survey = scan.scan(active=opts.active_scan)
            beacons = survey.get("beacons") or []
            self.say("scan", "Observed %d access points via %s"
                     % (len(beacons), survey.get("method")), 18)
            self.case.write_artifact(
                "scan.json",
                {**{k: v for k, v in survey.items() if k != "beacons"},
                 "beacons": [b.to_dict() for b in beacons]})

        beacons = survey.get("beacons") or []

        # Addresses supplied directly or recovered from artefacts are always
        # included, whatever the target resolves to.
        extra: List[str] = []
        for obs in opts.extra_observations:
            mac = str(obs.get("bssid") or "")
            if apple.is_bssid(mac):
                canon = apple.canonical_bssid(mac)
                if canon not in extra:
                    extra.append(canon)
        if extra:
            self.say("input", "%d access point address(es) supplied or recovered "
                              "from artefacts" % len(extra), 21)

        def _merge(macs: List[str]) -> List[str]:
            out = list(macs)
            for m in extra:
                if m not in out:
                    out.append(m)
            return out

        if target and apple.is_bssid(target):
            mac = apple.canonical_bssid(target)
            match = next((b for b in beacons if b.bssid == mac), None)
            ssid = match.ssid if match else ""
            return survey, _merge([mac]), "bssid", ssid

        if not target and extra:
            names = [str(o.get("ssid") or "") for o in opts.extra_observations
                     if o.get("ssid")]
            return survey, extra, "imported", (names[0] if names else "")

        if target:
            ssid = target
            hits = scan.match_ssid(beacons, target)
            if hits:
                self.say("scan", "SSID '%s' matched %d access point(s) in range"
                         % (target, len(hits)), 20)
                return survey, _merge([b.bssid for b in hits]), "ssid", hits[0].ssid
            if extra:
                self.say("scan", "Proceeding with the supplied access point "
                                 "addresses for '%s'" % target, 21)
                return survey, extra, "imported", target
            if not opts.active_scan:
                self.say("scan", "A network name was given but no access point "
                                 "addresses and no radio scan.", 20)
                return survey, [], "ssid-unresolvable", target
            self.say("scan", "SSID '%s' is not visible from this location; "
                             "searching open datasets" % target, 20)
            hits2 = osint.wifidb_ssid(self.transport, target)
            macs = [m["bssid"] for m in hits2.get("matches", [])
                    if m.get("bssid") and apple.is_bssid(m["bssid"])]
            if macs:
                return survey, [apple.canonical_bssid(m) for m in macs[:10]], "ssid-db", target
            return survey, [], "ssid", target

        # No target: survey mode - use the strongest thing we can see.
        if beacons:
            strongest = beacons[0]
            self.say("scan", "No target supplied; using the strongest observed "
                             "network '%s'" % (strongest.ssid or "<hidden>"), 20)
            return survey, [b.bssid for b in beacons[:10]], "survey", strongest.ssid
        return survey, [], "none", ""

    #: Observation sources that are a single moment at a single place, and so
    #: may honestly be put to Microsoft as one fingerprint. A radio scan is by
    #: definition everything audible at once; a saved-profile list is not.
    CO_OBSERVED_SOURCES = ("netsh output", "collector radio scan", "radio scan")

    #: Not an artefact at all - the operator typed these. They carry no claim
    #: about when anything was seen, so describing them as an artefact that
    #: "does not record the time" is simply wrong.
    DIRECT_SOURCES = ("operator input", "")

    def _microsoft_fingerprint(self, survey, targets
                               ) -> Tuple[List[Tuple[str, Optional[int]]], str, str]:
        """
        Build the beacon list for Microsoft, and say what it actually is.

        Microsoft is not asked "where is this access point". It is asked "where
        is a device that can see all of these at once", and it answers by
        multilaterating them as one observation. That makes the composition of
        this list a factual claim, and more beacons genuinely give a better
        answer - which is why a live scan is the ideal input.

        It also means the list must be something that could have been observed
        at once. A registry NetworkList is not: it is every network a machine
        has ever joined, over months, across towns. Submitting it whole asserted
        a co-observation of access points hundreds of kilometres apart - untrue,
        stated to a third party, and answerable only with nonsense or an
        IP-derived fallback.

        Returns the beacons, a short label for the progress line, and the full
        explanation for the report.
        """
        # Context supplied by the operator - the rest of a scan the target was
        # seen in - is a co-observation by definition and is preferred over
        # anything reconstructed from the targets alone.
        context = self.opts.context_observations
        if context and not survey.get("beacons"):
            seen = {m for m, _r in ()}
            pairs, seen = [], set()
            for m in targets:
                if m not in seen:
                    pairs.append((m, None)); seen.add(m)
            for obs in context:
                mac = str(obs.get("bssid") or "")
                if not apple.is_bssid(mac):
                    continue
                mac = apple.canonical_bssid(mac)
                if mac in seen:
                    continue
                rssi = obs.get("rssi_dbm")
                pairs.append((mac, int(rssi) if isinstance(rssi, (int, float))
                              else None))
                seen.add(mac)
            return (pairs, "the target with %d access point(s) seen alongside it"
                    % (len(pairs) - len(targets)),
                    "The enquiry concerns %d address(es); the other %d were "
                    "supplied as having been audible at the same time. "
                    "Microsoft multilaterates the whole set, so the additional "
                    "beacons tighten the position without becoming subjects of "
                    "the report." % (len(targets), len(pairs) - len(targets)))

        beacons = survey.get("beacons") or []
        if beacons:
            return ([(b.bssid, b.rssi_dbm) for b in beacons],
                    "live radio scan",
                    "%d access points audible together at one moment - the "
                    "strongest input this service accepts." % len(beacons))

        sources = {str(o.get("source") or "") for o in self.opts.extra_observations}
        historical = [x for x in sources
                      if x
                      and x not in self.DIRECT_SOURCES
                      and not any(c in x.lower()
                                  for c in self.CO_OBSERVED_SOURCES)]

        # More than one place is decisive on its own, whatever the source says.
        if len(self.places) > 1:
            return [], "not submitted", (
                "The supplied addresses resolve to %d distinct places, so no "
                "set of them was ever observed together and no honest "
                "fingerprint can be built from them. Submitting them as one "
                "would assert a co-observation that did not happen."
                % len(self.places))

        if historical:
            return ([(m, None) for m in targets], "recovered from an artefact", (
                "Recovered from %s. They resolve to a single place, so they are "
                "put to the service together, but the artefact does not record "
                "that they were seen at the same moment, and the result is "
                "weaker than a live scan." % ", ".join(sorted(historical))))

        return ([(m, None) for m in targets], "supplied by the operator", (
            "%d address(es) supplied directly. They resolve to a single place, "
            "so they are put to the service together." % len(targets)))

    def _group_places(self, apple_res) -> List[Dict[str, object]]:
        """
        Group the located, queried access points into distinct places.

        Each place carries the networks found there and, where the artefact
        supplied them, when the host was connected. That is the answer an
        imported NetworkList actually holds: not "where is this machine" but
        "where has this machine been, and when".
        """
        located = [a for a in apple_res.get("queried_located") or []]
        if not located:
            return []

        #: Everything Apple returned, including the neighbours it volunteered
        #: around each address. Used below to corroborate a place against
        #: Apple's own record rather than against our grouping of it.
        cloud = [a for a in apple_res.get("access_points") or [] if a.located]

        # Dates and names come from the artefact, not from either provider -
        # neither returns a network name or a timestamp.
        supplied = {}
        for obs in self.opts.extra_observations:
            mac = str(obs.get("bssid") or "").lower()
            if mac:
                supplied[apple.canonical_bssid(mac)
                         if apple.is_bssid(mac) else mac] = obs

        pts = [(a.latitude, a.longitude) for a in located]
        groups = geo.group_places(pts)

        places: List[Dict[str, object]] = []
        for n, idx in enumerate(groups, 1):
            members = [located[i] for i in idx]
            lat, lon = geo.centroid([pts[i] for i in idx])[:2]
            nets = []
            for a in members:
                obs = supplied.get(a.bssid, {})
                nets.append({
                    "bssid": a.bssid,
                    "ssid": obs.get("ssid") or "",
                    "latitude": a.latitude,
                    "longitude": a.longitude,
                    "accuracy_m": a.accuracy_m,
                    "first_seen": obs.get("first_seen") or "",
                    "last_seen": obs.get("last_seen") or "",
                    "source": obs.get("source") or "",
                })
            seen = [n_["last_seen"] for n_ in nets if n_["last_seen"]]
            first = [n_["first_seen"] for n_ in nets if n_["first_seen"]]
            spread = max(
                (geo.haversine_m(lat, lon, a.latitude, a.longitude)
                 for a in members), default=0.0)

            # Corroboration from Apple's own data rather than from our
            # grouping of it. Apple volunteers the access points it holds
            # around each address queried; a dense cloud at the same spot is
            # independent support that the place is real and that Apple has
            # good coverage there. A place standing alone in an otherwise
            # empty cloud rests on a single record and should be read
            # cautiously - so both cases are reported rather than only the
            # flattering one.
            # The corroboration that matters is the overlap between two lists
            # built independently of each other: the networks this host has a
            # profile for, and the access points Apple says are at this place.
            #
            # Apple returns up to 400 neighbours around every address queried.
            # If several of those neighbours are networks the host itself
            # connected to, then Apple - which knows nothing about this host -
            # has placed that host's own networks together at one location. A
            # count of unrelated neighbours says only that the area is
            # well-mapped; this says the host was here.
            #
            # It reaches further than the grouping does, because a profiled
            # network can appear in the neighbour cloud even when asking Apple
            # about it directly returned nothing.
            mine = {a.bssid for a in members}
            near = [a for a in cloud
                    if geo.haversine_m(lat, lon, a.latitude,
                                       a.longitude) <= NEIGHBOUR_RADIUS_M]
            profiled_here = [a for a in near if a.bssid in supplied]
            #: Profiled networks Apple puts here that were not placed here by
            #: locating them directly - evidence the grouping alone would miss.
            via_cloud = [a for a in profiled_here if a.bssid not in mine]
            names = sorted({n_["ssid"] for n_ in nets if n_["ssid"]})
            via_names = sorted({str((supplied.get(a.bssid) or {}).get("ssid") or "")
                                for a in via_cloud} - {""})

            places.append({
                "index": n,
                "latitude": lat,
                "longitude": lon,
                "network_count": len(nets),
                "spread_m": round(spread, 1),
                "earliest_seen": min(first) if first else "",
                "latest_seen": max(seen) if seen else "",
                "ssids": names,
                #: The overlap that constitutes corroboration.
                "profiled_here": len(profiled_here),
                "profiled_via_cloud": len(via_cloud),
                "profiled_via_cloud_ssids": via_names,
                "corroboration": _place_corroboration(
                    len(nets), len(profiled_here), len(via_cloud)),
                "networks": sorted(nets, key=lambda x: x["last_seen"] or "",
                                   reverse=True),
            })
        return places

    def _choose_anchor(self, apple_res, cluster):
        """
        Pick the Apple position that represents 'the target'.

        Two hazards have to be handled before simply taking the most accurate
        result:

        1.  A locally administered (randomised) BSSID is not a stable global
            identifier.  Two unrelated devices anywhere in the world can present
            the same randomised address, so Apple's record for one may describe
            the other.  Universally administered addresses are therefore
            preferred as the anchor.
        2.  Consequently, one queried access point can resolve thousands of
            kilometres from the rest.  Anchoring on it, or averaging it in,
            would relocate the whole investigation.

        Access points that disagree with the neighbour cluster are excluded from
        anchoring and reported as collisions rather than silently dropped.
        """
        from . import oui as _oui

        queried = list(apple_res["queried_located"])
        self.collisions: List[Dict[str, object]] = []

        # When the input genuinely spans several places, distance from the
        # neighbour cloud is not evidence of anything wrong - it is the finding.
        # Only the networks belonging to the leading place are anchored on; the
        # others are reported as places in their own right, not as collisions.
        places = getattr(self, "places", None) or []
        if len(places) > 1:
            lead = {n["bssid"] for n in places[0]["networks"]}
            queried = [a for a in queried if a.bssid in lead] or queried

        if queried and cluster.get("kept_count"):
            c = cluster["centroid"]
            plausible = []
            for a in queried:
                d = geo.haversine_m(c["latitude"], c["longitude"],
                                    a.latitude, a.longitude)
                if d <= 25000:            # same metropolitan area
                    plausible.append(a)
                else:
                    la = _oui.structure(a.bssid).get("locally_administered")
                    self.collisions.append({
                        "bssid": a.bssid,
                        "latitude": a.latitude, "longitude": a.longitude,
                        "distance_km": round(d / 1000.0, 1),
                        "locally_administered": bool(la),
                        "explanation": (
                            "Apple's record for %s places it %.0f km away, in "
                            "clear conflict with every other observation. The "
                            "address is %s, which is the usual cause: a "
                            "randomised MAC observed on an unrelated device "
                            "elsewhere. This access point has been excluded "
                            "from positioning."
                            % (a.bssid, d / 1000.0,
                               "locally administered (randomised)" if la
                               else "universally administered, so this is "
                                    "unusual and may indicate relocated "
                                    "hardware or a stale database record")),
                    })
            if plausible:
                queried = plausible

        if queried:
            universal = [a for a in queried
                         if not _oui.structure(a.bssid).get("locally_administered")]
            pool = universal or queried
            best = min(pool, key=lambda a: (a.accuracy_m or 9999))
            note = ("Anchored on the queried access point %s, which Apple "
                    "reports to %s m." % (best.bssid, best.accuracy_m))
            if not universal:
                note += (" No universally administered address was available, "
                         "so this anchor rests on a randomised MAC and is "
                         "correspondingly weaker.")
            if self.collisions:
                note += (" %d conflicting record(s) were excluded."
                         % len(self.collisions))
            return best.to_dict(), note

        if cluster.get("kept_count"):
            c = cluster["centroid"]
            return ({"latitude": c["latitude"], "longitude": c["longitude"],
                     "accuracy_m": cluster.get("radius_p95_m"),
                     "bssid": None, "synthetic": True},
                    ("Apple has no record of the queried access point. The "
                     "position shown is the centroid of %d neighbouring access "
                     "points and describes the area, not the device."
                     % cluster["kept_count"]))
        return None, "Apple returned no usable position."

    def _validation_context(self, survey, targets, apple_res, ssid, anchor,
                            msft_res):
        """
        Assemble the facts the scoring rubric needs.

        Only access points that survived collision filtering count towards
        multi-radio consistency; including an excluded outlier would produce the
        nonsensical "these radios are 14,000 km apart" result that the filter
        exists to prevent.
        """
        excluded = {c["bssid"] for c in getattr(self, "collisions", [])}
        pts = [(a.latitude, a.longitude) for a in apple_res["queried_located"]
               if a.bssid not in excluded]
        span = 0.0
        if len(pts) >= 2:
            span = max(geo.haversine_m(pts[i][0], pts[i][1], pts[j][0], pts[j][1])
                       for i in range(len(pts)) for j in range(i + 1, len(pts)))
        beacons = survey.get("beacons") or []

        anchor_mac = (anchor or {}).get("bssid")
        anchor_random = bool(anchor_mac) and bool(
            oui.structure(anchor_mac).get("locally_administered"))

        unreachable, reason = self._microsoft_availability(msft_res)
        collision_note = None
        if getattr(self, "collisions", None):
            c = self.collisions[0]
            collision_note = (
                "%d queried access point(s) resolved to a conflicting locality "
                "(nearest conflict: %s at %.0f km) and were excluded."
                % (len(self.collisions), c["bssid"], c["distance_km"]))

        return {
            "consistent_radios": len(pts),
            "radio_span_m": span if len(pts) >= 2 else None,
            "randomised_mac": anchor_random,
            "mac_collision": collision_note,
            "microsoft_unreachable": unreachable,
            "microsoft_unreachable_reason": reason,
            "stale_scan": bool(beacons) and not survey.get("active_scan", False),
            "approximated_rssi": any(b.rssi_approximated for b in beacons),
            "hidden_ssid": (not ssid) and bool(targets),
        }

    @staticmethod
    def _nearest_neighbours(apple_res, count: int) -> Tuple[List[str], float]:
        """
        The access points Apple places closest to the target.

        Multilateration works from a tight local set. Feeding in whatever
        happens to be in the response - including records hundreds of metres
        out, or a randomised address recorded on the far side of the world -
        would pull the computed position away from the target and make the
        result worse, not merely noisier. So the probe set is the nearest N to
        the target's own Apple position, and the report states the radius they
        span so a reader can judge whether the set was tight enough to mean
        anything.
        """
        located = [a for a in apple_res.get("access_points", []) if a.located]
        if not located:
            return [], 0.0

        anchors = apple_res.get("queried_located") or []
        if anchors:
            ref = min(anchors, key=lambda a: (a.accuracy_m or 9999))
            rlat, rlon = ref.latitude, ref.longitude
        else:
            kept, _rej, _st = geo.reject_outliers(
                [(a.latitude, a.longitude) for a in located])
            rlat, rlon = geo.centroid([(located[i].latitude, located[i].longitude)
                                       for i in kept] or
                                      [(located[0].latitude, located[0].longitude)])

        scored = sorted(
            ((geo.haversine_m(rlat, rlon, a.latitude, a.longitude), a)
             for a in located), key=lambda t: t[0])
        chosen = scored[:max(1, count)]
        return [a.bssid for _d, a in chosen], (chosen[-1][0] if chosen else 0.0)

    @staticmethod
    def _disjoint_groups(pool: List[str], count: int) -> List[List[str]]:
        """
        Deal a distance-sorted list into disjoint groups, round-robin.

        Dealing alternately rather than slicing matters: consecutive slices of
        a distance-sorted list would produce concentric rings, and the outer
        ring would multilaterate to a different place than the inner one for
        reasons of geometry rather than evidence. Round-robin gives every group
        the same spatial coverage, so a disagreement between them means the
        databases disagree, not that we handed them different problems.
        """
        if count < 1:                      # replication explicitly disabled
            return []
        if len(pool) < count * 3:          # too few to split meaningfully
            return [pool] if len(pool) >= 3 else []
        groups: List[List[str]] = [[] for _ in range(count)]
        for i, mac in enumerate(pool):
            groups[i % count].append(mac)
        return [g for g in groups if len(g) >= 3]

    @staticmethod
    def _corroboration_pool(targets: List[str], apple_res,
                            limit: int) -> List[str]:
        """
        Choose which access points to put to Microsoft individually.

        The targets always go first - they are what the enquiry is about.  The
        remaining slots are filled from Apple's neighbour cloud, preferring the
        records Apple itself is most confident about and that sit closest to
        the target, since those are the most likely to be independently held
        and the most informative if they are.
        """
        pool = list(targets)
        located = [a for a in apple_res.get("access_points", [])
                   if a.located and a.bssid not in pool]
        if not located or len(pool) >= limit:
            return pool[:max(limit, len(targets))]

        anchors = [a for a in apple_res.get("queried_located", [])]
        if anchors:
            ref = min(anchors, key=lambda a: (a.accuracy_m or 9999))
            rlat, rlon = ref.latitude, ref.longitude
        else:
            pts = [(a.latitude, a.longitude) for a in located]
            rlat, rlon = geo.centroid(pts)

        def rank(ap):
            d = geo.haversine_m(rlat, rlon, ap.latitude, ap.longitude)
            return (float(ap.accuracy_m or 500) * 2.0) + d

        for ap in sorted(located, key=rank):
            if len(pool) >= limit:
                break
            pool.append(ap.bssid)
        return pool

    @staticmethod
    def _per_ap_agreement(apple_res, msft_each) -> Dict[str, object]:
        """
        Compare the two providers access point by access point.

        This is the strongest form of corroboration available: rather than
        asking whether two differently-derived aggregate positions happen to
        land near each other, it asks whether two independent databases hold
        the same location for the same physical device.
        """
        if not msft_each or not apple_res:
            return {"per_ap_pairs": []}
        apple_by_mac = {a.bssid: a for a in apple_res.get("access_points", [])
                        if a.located}
        pairs = []
        for row in msft_each.get("results", []):
            res = row["result"]
            if not res.get("located"):
                continue
            a = apple_by_mac.get(row["bssid"])
            if not a:
                continue
            d = geo.haversine_m(a.latitude, a.longitude,
                                res["latitude"], res["longitude"])
            budget = max(60.0, float(a.accuracy_m or 0)
                         + float(res.get("radial_uncertainty_m") or 0))
            pairs.append({
                "bssid": row["bssid"],
                "apple": {"latitude": a.latitude, "longitude": a.longitude,
                          "accuracy_m": a.accuracy_m},
                "microsoft": {"latitude": res["latitude"],
                              "longitude": res["longitude"],
                              "radial_uncertainty_m": res.get("radial_uncertainty_m")},
                "separation_m": round(d, 1),
                "within_uncertainty": d <= budget,
            })
        agree = [p for p in pairs if p["within_uncertainty"]]
        return {
            "per_ap_pairs": pairs,
            "per_ap_agree": len(agree),
            "per_ap_total": len(pairs),
            "per_ap_median_separation_m": (
                round(geo.median([p["separation_m"] for p in pairs]), 1)
                if pairs else None),
        }

    @staticmethod
    def _microsoft_availability(msft_res) -> Tuple[bool, str]:
        """
        Decide whether Microsoft genuinely answered.

        A 403 from `Microsoft-Azure-Application-Gateway` is the edge refusing
        the request before the positioning service ever sees it - typically
        rate limiting by source address.  That is materially different from the
        service replying "I have no data", and the two must not be conflated.
        """
        if msft_res is None:
            return True, "the check was not attempted"
        status = msft_res.get("status")
        error = msft_res.get("error") or ""
        if status in (401, 403, 407, 429) or (status or 0) >= 500:
            return True, "HTTP %s from the service edge" % status
        if error and status is None:
            return True, error
        result = msft_res.get("result")
        if result is not None and getattr(result, "fault", None) \
                and not getattr(result, "located", False) \
                and "parse error" in str(result.fault):
            return True, "the response could not be parsed"
        return False, ""

    def _consensus(self, anchor, msft_dict, cluster, ctx=None):
        """
        The single position the tool reports.

        Where both providers answered, the two positions are combined weighted
        by the inverse square of their stated uncertainties - the standard way
        to fuse two independent estimates - and the reported uncertainty is the
        larger of the fused radius and the actual separation, so the stated
        circle always contains both source positions.

        Two guards apply before anything is fused:

        1.  Only a genuinely Wi-Fi-derived Microsoft position qualifies. The
            caller is responsible for having withheld IP-fallback answers, and
            this method re-checks rather than trusting that.
        2.  Positions that disagree by more than any plausible uncertainty are
            not averaged. Averaging two positions hundreds of kilometres apart
            produces a confident-looking coordinate in an empty field between
            them, which is worse than reporting either one. In that case the
            better-evidenced source is reported alone and the conflict is
            stated.
        """
        a_ok = anchor and anchor.get("latitude") is not None
        m_ok = bool(msft_dict and msft_dict.get("located")
                    and msft_dict.get("latitude") is not None)

        if a_ok and m_ok:
            gap = geo.haversine_m(anchor["latitude"], anchor["longitude"],
                                  msft_dict["latitude"], msft_dict["longitude"])
            budget = 10.0 * max(200.0,
                                float(anchor.get("accuracy_m") or 150)
                                + float(msft_dict.get("radial_uncertainty_m") or 150))
            if gap > budget:
                agree = int((ctx or {}).get("per_ap_agree") or 0)
                return {
                    "latitude": anchor["latitude"], "longitude": anchor["longitude"],
                    "accuracy_m": anchor.get("accuracy_m"),
                    "method": ("Apple Location Services only - the Microsoft "
                               "position was %.0f km away and irreconcilable, "
                               "so the two were not combined" % (gap / 1000.0)),
                    "inputs": ["apple"],
                    "conflict_m": round(gap, 1),
                    "note": ("The providers disagree beyond any plausible "
                             "uncertainty. %s"
                             % ("Device-level checks support the Apple position."
                                if agree else
                                "Neither position is corroborated; treat both "
                                "with caution.")),
                }

        if a_ok and m_ok:
            a_acc = float(anchor.get("accuracy_m") or 150)
            m_acc = float(msft_dict.get("radial_uncertainty_m") or 150)
            wa, wm = 1.0 / max(a_acc, 1) ** 2, 1.0 / max(m_acc, 1) ** 2
            lat, lon = geo.centroid(
                [(anchor["latitude"], anchor["longitude"]),
                 (msft_dict["latitude"], msft_dict["longitude"])], [wa, wm])
            sep = geo.haversine_m(anchor["latitude"], anchor["longitude"],
                                  msft_dict["latitude"], msft_dict["longitude"])
            fused = (1.0 / (wa + wm)) ** 0.5
            return {"latitude": lat, "longitude": lon,
                    "accuracy_m": round(max(fused, sep / 2 + min(a_acc, m_acc)), 1),
                    "method": "inverse-variance fusion of Apple and Microsoft",
                    "inputs": ["apple", "microsoft"]}
        if a_ok:
            return {"latitude": anchor["latitude"], "longitude": anchor["longitude"],
                    "accuracy_m": anchor.get("accuracy_m"),
                    "method": "Apple Location Services only",
                    "inputs": ["apple"]}
        if m_ok:
            return {"latitude": msft_dict["latitude"], "longitude": msft_dict["longitude"],
                    "accuracy_m": msft_dict.get("radial_uncertainty_m"),
                    "method": "Microsoft inference service only",
                    "inputs": ["microsoft"]}
        if cluster.get("kept_count"):
            c = cluster["centroid"]
            return {"latitude": c["latitude"], "longitude": c["longitude"],
                    "accuracy_m": cluster.get("radius_p95_m"),
                    "method": "centroid of neighbouring access points",
                    "inputs": ["apple-neighbours"]}
        return None

    # ----------------------------------------------------------------------
    def _finish(self, started, survey, ssid, target_kind, targets, apple_res,
                msft_res, cluster, validation, extras, final, failure):
        beacons = survey.get("beacons") or []
        apple_aps = (apple_res or {}).get("access_points", [])

        doc: Dict[str, object] = {
            "ok": failure is None,
            "failure": failure,
            "case_id": self.case.case_id,
            "started_utc": started,
            "completed_utc": utc_iso(),
            "target": {
                "input": self.opts.target,
                "kind": target_kind,
                "ssid": ssid or self.opts.known_ssid,
                "ssid_observed": ssid,
                "ssid_asserted_by_operator": self.opts.known_ssid,
                "bssids": targets,
                "imported_observations": self.opts.extra_observations,
            },
            "survey": {
                **{k: v for k, v in (survey or {}).items() if k != "beacons"},
                "beacon_count": len(beacons),
                "beacons": [b.to_dict() for b in beacons],
            },
            "apple": {
                **{k: v for k, v in (apple_res or {}).items()
                   if k not in ("access_points", "queried_access_points",
                                "queried_located")},
                "access_points": [a.to_dict() for a in apple_aps],
                "queried": [a.to_dict() for a in (apple_res or {}).get(
                    "queried_access_points", [])],
            } if apple_res else None,
            "microsoft": ({**{k: v for k, v in msft_res.items() if k != "result"},
                           "result": msft_res["result"].to_dict()}
                          if msft_res else None),
            "microsoft_per_ap": (extras or {}).get("microsoft_per_ap"),
            "microsoft_replicates": (extras or {}).get("microsoft_replicates"),
            "cluster": cluster,
            "validation": validation,
            "position": final,
            "coordinates": (geo.coordinate_formats(final["latitude"],
                                                   final["longitude"])
                            if final else None),
            **(extras or {}),
        }

        self._write_exports(doc, apple_aps, final)

        # The report is written into the package first, so the manifest covers
        # it, then re-rendered outside the package once the sealing hashes
        # exist.  A ZIP cannot contain its own hash, so the copy inside points
        # the reader at MANIFEST.sha256 and the copy outside carries the
        # sealed values.
        src_map = doc.get("export_map") or doc.get("static_map")
        images = {}
        svg = mapimage.render(doc, src_map)
        if svg:
            self.case.write_artifact("map.svg", svg, "exports")
            images["svg"] = {"file": "exports/map.svg",
                             "bytes": len(svg.encode("utf-8"))}
        if src_map:
            self.say("map", "Rasterising the map exhibit", 94)
            try:
                raster = mapimage.render_png(doc, src_map,
                                             scale=self.opts.png_scale)
            except Exception as e:
                self.case.log("map.png.failed", error=str(e))
                raster = None
            if raster:
                self.case.write_artifact("map.png", raster, "exports")
                images["png"] = {
                    "file": "exports/map.png", "bytes": len(raster),
                    "width": int(src_map["width"]) * self.opts.png_scale,
                    "height": (int(src_map["height"]) + 130) * self.opts.png_scale,
                }
                self.say("map", "Map exhibit: %d x %d PNG (%.0f KB)"
                         % (images["png"]["width"], images["png"]["height"],
                            len(raster) / 1024), 95)
        if images:
            doc["map_image"] = images
        self.case.write_artifact("resolved.json", doc)

        self.say("report", "Rendering the forensic report", 96)
        meta = self._case_meta()
        self.case.write_artifact("report.html", report.render(doc, meta))
        try:
            self.case.write_artifact("report.pdf",
                                     reportpdf.render(doc, meta), "exports")
        except Exception as e:
            self.case.log("report.pdf.failed", error=str(e),
                          traceback=traceback.format_exc())
            self.say("report", "PDF generation failed: %s" % e, 96)

        # The redacted copies must exist BEFORE the package is sealed, or the
        # manifest will not cover them and the verifier will correctly report
        # them as files added after sealing.
        if self.opts.redacted_copy:
            self.say("report", "Rendering the redacted copy", 96)
            safe_doc = redact.apply(doc)
            safe_meta = redact.apply_meta(meta)
            self.case.write_artifact("report.redacted.html",
                                     report.render(safe_doc, safe_meta), "exports")
            try:
                self.case.write_artifact("report.redacted.pdf",
                                         reportpdf.render(safe_doc, safe_meta),
                                         "exports")
            except Exception as e:
                self.case.log("report.redacted.pdf.failed", error=str(e))

        self.say("package", "Sealing the evidence package", 97)
        pkg = self.case.package(doc)
        doc["evidence"] = pkg

        sealed_meta = self._case_meta()
        standalone = os.path.join(os.path.dirname(self.case.dir),
                                  "%s_REPORT.html" % self.case.case_id)
        with open(standalone, "w", encoding="utf-8") as fh:
            fh.write(report.render(doc, sealed_meta))
        doc["report_path"] = standalone

        # The copies inside the package are rendered before sealing, so their
        # chain-of-custody section cannot state the package hash or the root
        # hash - a package cannot contain its own hash. Render once more here,
        # outside the package, now that those values exist.
        standalone_pdf = os.path.join(os.path.dirname(self.case.dir),
                                      "%s_REPORT.pdf" % self.case.case_id)
        try:
            with open(standalone_pdf, "wb") as fh:
                fh.write(reportpdf.render(doc, sealed_meta))
            doc["report_pdf_path"] = standalone_pdf
        except Exception as e:
            self.case.log("report.pdf.sealed.failed", error=str(e))

        # The redacted copy is the one that actually leaves the investigation,
        # so it is also written beside the package rather than only inside it.
        # Rendering it here, after sealing, is what lets it carry the root hash:
        # a recipient who is given only the redacted report can still quote a
        # hash that ties it to the sealed evidence. The in-package copy cannot,
        # because a package cannot contain its own hash.
        if self.opts.redacted_copy:
            safe_doc = redact.apply(doc)
            safe_meta = redact.apply_meta(sealed_meta)
            red_html = os.path.join(os.path.dirname(self.case.dir),
                                    "%s_REPORT.REDACTED.html" % self.case.case_id)
            with open(red_html, "w", encoding="utf-8") as fh:
                fh.write(report.render(safe_doc, safe_meta))
            doc["report_redacted_path"] = red_html
            red_pdf = os.path.join(os.path.dirname(self.case.dir),
                                   "%s_REPORT.REDACTED.pdf" % self.case.case_id)
            try:
                with open(red_pdf, "wb") as fh:
                    fh.write(reportpdf.render(safe_doc, safe_meta))
                doc["report_redacted_pdf_path"] = red_pdf
            except Exception as e:
                self.case.log("report.redacted.pdf.sealed.failed", error=str(e))

        self.say("done", "Complete. %d exhibits, root hash %s"
                 % (pkg["file_count"], pkg["root_hash"][:16]), 100)
        return doc

    def _device_profile(self) -> Dict[str, str]:
        """The optional Windows-style DeviceProfile, when explicitly enabled."""
        import platform as _plat
        import uuid as _uuid
        return {
            "ClientGuid": str(_uuid.uuid4()),
            "Platform": _plat.system() + _plat.release(),
            "DeviceType": "PC",
            "OSVersion": _plat.version(),
            "LFVersion": "4.2",
            "ExtendedDeviceInfo": "",
        }

    def _case_meta(self) -> Dict[str, object]:
        c = self.case
        return {
            "case_id": c.case_id, "examiner": c.examiner,
            "organisation": c.organisation, "reference": c.reference,
            "notes": c.notes, "opened_utc": c.opened_utc,
            "sealed_utc": utc_iso(), "environment": c.environment(),
            "exchanges": [e.summary() for e in c.exchanges],
        }

    def _write_exports(self, doc, apple_aps, final):
        """CSV / GeoJSON / KML so the positions drop straight into other tools."""
        rows = ["bssid,latitude,longitude,accuracy_m,altitude_m,"
                "altitude_accuracy_m,queried"]
        features = []
        placemarks = []

        for a in apple_aps:
            if not a.located:
                continue
            rows.append("%s,%.8f,%.8f,%s,%s,%s,%s" % (
                a.bssid, a.latitude, a.longitude, a.accuracy_m or "",
                a.altitude_m if a.altitude_m is not None else "",
                a.altitude_accuracy_m if a.altitude_accuracy_m is not None else "",
                "yes" if a.is_queried else "no"))
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [a.longitude, a.latitude]},
                "properties": {"bssid": a.bssid, "accuracy_m": a.accuracy_m,
                               "altitude_m": a.altitude_m,
                               "queried": a.is_queried,
                               "role": "target" if a.is_queried else "neighbour"},
            })
            placemarks.append(
                "<Placemark><name>%s</name><description>accuracy %s m</description>"
                "<Point><coordinates>%.8f,%.8f,0</coordinates></Point></Placemark>"
                % (_xml_escape(a.bssid), a.accuracy_m, a.longitude, a.latitude))

        if final:
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point",
                             "coordinates": [final["longitude"], final["latitude"]]},
                "properties": {"role": "consensus", "method": final["method"],
                               "accuracy_m": final["accuracy_m"]},
            })

        self.case.write_artifact("positions.csv", "\n".join(rows) + "\n", "exports")

        # positions.csv is one row per access point, which is the wrong unit
        # for a bulk enquiry: the finding is the place. An analyst wants to
        # sort by town or postcode and see which networks were there and when,
        # and cannot do that from a list of coordinates.
        places = getattr(self, "places", []) or []
        if len(places) > 1:
            head = ["place", "latitude", "longitude", "networks", "spread_m",
                    "corroboration", "earliest_seen", "latest_seen",
                    "house_number", "road", "area", "city", "district",
                    "state", "postcode", "country", "country_code",
                    "address", "ssids", "bssids", "map_url"]
            prows = [",".join(head)]
            for pl in places:
                parts = pl.get("address_parts") or {}
                cells = [
                    pl.get("index"), pl.get("latitude"), pl.get("longitude"),
                    pl.get("network_count"), pl.get("spread_m"),
                    (pl.get("corroboration") or {}).get("level") or "",
                    pl.get("earliest_seen") or "", pl.get("latest_seen") or "",
                    parts.get("house_number", ""), parts.get("road", ""),
                    parts.get("area", ""), parts.get("city", ""),
                    parts.get("district", ""), parts.get("state", ""),
                    parts.get("postcode", ""), parts.get("country", ""),
                    parts.get("country_code", ""), pl.get("address") or "",
                    " | ".join(pl.get("ssids") or []),
                    " | ".join(n["bssid"] for n in pl.get("networks") or []),
                    _map_url(pl.get("latitude"), pl.get("longitude")),
                ]
                prows.append(",".join(_csv_cell(c) for c in cells))
            self.case.write_artifact("places.csv",
                                     "\n".join(prows) + "\n", "exports")

        # A row per submitted address, resolved or not. This is the sheet to
        # open when a run returns less than expected: it says which addresses
        # the provider held, which it did not, and which place each landed in.
        supplied = {}
        for obs in self.opts.extra_observations:
            mac = str(obs.get("bssid") or "")
            if apple.is_bssid(mac):
                supplied[apple.canonical_bssid(mac)] = obs
        for mac in (doc.get("target") or {}).get("bssids") or []:
            supplied.setdefault(mac, {})

        if supplied:
            where = {}
            for pl in places:
                for n in pl.get("networks") or []:
                    where[n["bssid"]] = pl
            ap_res = doc.get("apple") or {}
            located = {a["bssid"]: a for a in (ap_res.get("queried_located") or [])
                       if isinstance(a, dict)}
            unknown = set(ap_res.get("unknown_to_apple") or [])

            head = ["bssid", "ssid", "resolved", "reason", "place", "city",
                    "latitude", "longitude", "accuracy_m", "first_seen",
                    "last_seen", "source", "map_url"]
            arows = [",".join(head)]
            for mac, obs in supplied.items():
                pl = where.get(mac)
                hit = located.get(mac)
                if hit:
                    reason = "held by Apple"
                elif mac in unknown:
                    reason = ("no record - never reported by a contributing "
                              "device, which is not evidence it does not exist")
                else:
                    reason = "not returned"
                lat = hit.get("latitude") if hit else ""
                lon = hit.get("longitude") if hit else ""
                arows.append(",".join(_csv_cell(c) for c in [
                    mac, obs.get("ssid") or "", "yes" if hit else "no", reason,
                    pl.get("index") if pl else "",
                    ((pl or {}).get("address_parts") or {}).get("city", ""),
                    lat, lon, hit.get("accuracy_m") if hit else "",
                    obs.get("first_seen") or "", obs.get("last_seen") or "",
                    obs.get("source") or "", _map_url(lat, lon),
                ]))
            self.case.write_artifact("addresses.csv",
                                     "\n".join(arows) + "\n", "exports")
        self.case.write_artifact("positions.geojson",
                                 {"type": "FeatureCollection", "features": features},
                                 "exports")
        self.case.write_artifact("positions.kml",
                                 KML_TEMPLATE % (_xml_escape(self.case.case_id),
                                                 "\n".join(placemarks)),
                                 "exports")


def _map_url(lat, lon) -> str:
    """
    A clickable link for a spreadsheet cell.

    A coordinate in a column is inert; opening it means copying it somewhere
    else, which is what a reader does with it anyway. Written at full
    precision, because the cell beside it is.
    """
    if lat in ("", None) or lon in ("", None):
        return ""
    return ("https://www.google.com/maps/search/?api=1&query=%s,%s"
            % (lat, lon))


def _csv_cell(value) -> str:
    """
    Quote a value for CSV.

    Addresses contain commas by nature and network names contain almost
    anything, so quoting is not optional: one unquoted street address silently
    shifts every column to its right, and the file still opens without
    complaint.
    """
    text = "" if value is None else str(value)
    if any(ch in text for ch in ',"\n\r'):
        return '"' + text.replace('"', '""') + '"'
    return text


def _xml_escape(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


KML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2"><Document>
<name>WiFi Geolocation Forensics %s</name>
%s
</Document></kml>
"""
