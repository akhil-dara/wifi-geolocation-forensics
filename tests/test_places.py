"""
Multi-location input.

An artefact import is not one observation. A registry NetworkList holds every
network a machine has ever joined, which may be hundreds of networks in dozens
of towns — a movement history. The engine originally assumed all supplied
addresses belonged to one access point's radios, so it fused them into a single
position and dismissed anything more than 25 km away as a randomised-address
collision. That produced a report which named one place and affirmatively
explained away the evidence for every other, which is worse than saying
nothing.
"""

import pathlib
import unittest

from wifigeo import geo
from wifigeo.apple import AccessPoint
from wifigeo.engine import Investigation, Options

LONDON = (51.5074, -0.1278)
LONDON_2 = (51.5075, -0.1279)
EDINBURGH = (55.9533, -3.1883)
PARIS = (48.8584, 2.2945)


class GroupPlaces(unittest.TestCase):

    def test_one_site_is_one_place(self):
        self.assertEqual(len(geo.group_places([LONDON, LONDON_2])), 1)

    def test_distant_points_are_separate_places(self):
        groups = geo.group_places([LONDON, LONDON_2, EDINBURGH, PARIS])
        self.assertEqual(len(groups), 3)

    def test_largest_place_comes_first(self):
        groups = geo.group_places([EDINBURGH, LONDON, LONDON_2])
        self.assertEqual(len(groups[0]), 2)

    def test_single_linkage_chains_adjacent_buildings(self):
        # Three buildings 300 m apart in a line are one site, even though the
        # ends are 600 m apart and so beyond the radius on their own.
        a = (51.5000, 0.0)
        b = (51.5027, 0.0)          # ~300 m north
        c = (51.5054, 0.0)          # ~300 m further
        self.assertEqual(len(geo.group_places([a, b, c])), 1)

    def test_a_site_across_town_is_a_different_place(self):
        # The regression that made this constant 500 m rather than 25 km: a
        # home and an office in the same city are two places, not one.
        office = (51.5074, -0.1278)
        home = (51.4779, -0.0015)          # ~9 km away, same city
        self.assertEqual(len(geo.group_places([office, home])), 2)

    def test_empty_input(self):
        self.assertEqual(geo.group_places([]), [])

    def test_every_point_is_placed_exactly_once(self):
        pts = [LONDON, LONDON_2, EDINBURGH, PARIS]
        seen = sorted(i for g in geo.group_places(pts) for i in g)
        self.assertEqual(seen, list(range(len(pts))))


def _ap(mac, lat, lon, acc=30):
    return AccessPoint(bssid=mac, bssid_as_returned=mac, latitude=lat,
                       longitude=lon, accuracy_m=acc, is_queried=True)


class LocationHistory(unittest.TestCase):

    APS = [_ap("00:00:5e:00:53:a6", *LONDON),
           _ap("00:00:5e:00:53:a7", *LONDON_2),
           _ap("00:00:5e:00:53:b1", *EDINBURGH)]

    OBS = [{"bssid": "00:00:5e:00:53:a6", "ssid": "HQ-Corp",
            "first_seen": "2026-01-04T08:12:00Z",
            "last_seen": "2026-08-01T18:40:00Z", "source": "registry"},
           {"bssid": "00:00:5e:00:53:a7", "ssid": "HQ-Corp",
            "first_seen": "2026-01-04T08:12:00Z",
            "last_seen": "2026-08-01T18:41:00Z", "source": "registry"},
           {"bssid": "00:00:5e:00:53:b1", "ssid": "Hotel-Guest",
            "first_seen": "2026-03-11T21:02:00Z",
            "last_seen": "2026-03-14T07:15:00Z", "source": "registry"}]

    def _investigation(self, obs=None):
        inv = Investigation.__new__(Investigation)
        inv.opts = Options(extra_observations=obs if obs is not None else self.OBS)
        inv.collisions = []
        inv.places = []
        return inv

    def test_two_places_are_reported(self):
        inv = self._investigation()
        places = inv._group_places({"queried_located": self.APS})
        self.assertEqual(len(places), 2)
        self.assertEqual(places[0]["network_count"], 2)
        self.assertEqual(places[1]["network_count"], 1)

    def test_names_and_dates_come_from_the_artefact(self):
        # Neither provider returns a network name or a timestamp, so anything
        # of the sort in the report must be traceable to the import.
        inv = self._investigation()
        places = inv._group_places({"queried_located": self.APS})
        hotel = places[1]["networks"][0]
        self.assertEqual(hotel["ssid"], "Hotel-Guest")
        self.assertEqual(hotel["last_seen"], "2026-03-14T07:15:00Z")
        self.assertEqual(places[1]["earliest_seen"], "2026-03-11T21:02:00Z")

    def test_a_place_without_artefact_dates_is_still_reported(self):
        inv = self._investigation(obs=[])
        places = inv._group_places({"queried_located": self.APS})
        self.assertEqual(len(places), 2)
        self.assertEqual(places[0]["networks"][0]["ssid"], "")
        self.assertEqual(places[0]["earliest_seen"], "")

    def test_a_genuine_second_place_is_not_called_a_collision(self):
        # The regression this whole module exists for.
        inv = self._investigation()
        inv.places = inv._group_places({"queried_located": self.APS})
        cluster = {"kept_count": 2,
                   "centroid": {"latitude": 51.50745, "longitude": -0.12785},
                   "radius_p95_m": 50.0}
        Investigation._choose_anchor(inv, {"queried_located": self.APS}, cluster)
        self.assertEqual(inv.collisions, [],
                         "a real second location was discarded as a "
                         "randomised-address collision")

    def test_anchor_stays_within_the_leading_place(self):
        inv = self._investigation()
        inv.places = inv._group_places({"queried_located": self.APS})
        cluster = {"kept_count": 2,
                   "centroid": {"latitude": 51.50745, "longitude": -0.12785},
                   "radius_p95_m": 50.0}
        anchor, _note = Investigation._choose_anchor(
            inv, {"queried_located": self.APS}, cluster)
        self.assertIn(anchor["bssid"], {"00:00:5e:00:53:a6", "00:00:5e:00:53:a7"})

    def test_single_place_input_is_unaffected(self):
        # A 2.4 GHz / 5 GHz pair must still fuse into one position, and a true
        # outlier must still be excluded.
        aps = [_ap("00:00:5e:00:53:a6", *LONDON),
               _ap("00:00:5e:00:53:a7", *LONDON_2)]
        inv = self._investigation(obs=[])
        inv.places = inv._group_places({"queried_located": aps})
        self.assertEqual(len(inv.places), 1)
        cluster = {"kept_count": 2,
                   "centroid": {"latitude": 51.50745, "longitude": -0.12785},
                   "radius_p95_m": 50.0}
        anchor, _ = Investigation._choose_anchor(inv, {"queried_located": aps},
                                                 cluster)
        self.assertIsNotNone(anchor["bssid"])
        self.assertEqual(inv.collisions, [])


class Reporting(unittest.TestCase):

    def _doc(self, places):
        return {"case_id": "CASE-TEST", "target": {"kind": "imported"},
                "validation": {"verdict": "CORROBORATED",
                               "verdict_statement": "", "score": 80.0,
                               "coverage": 100.0},
                "places": places}

    def _places(self, n):
        out = []
        for i, (lat, lon) in enumerate([LONDON, EDINBURGH, PARIS][:n], 1):
            out.append({"index": i, "latitude": lat, "longitude": lon,
                        "network_count": 1, "spread_m": 0.0,
                        "earliest_seen": "", "latest_seen": "",
                        "networks": [{"bssid": "00:00:5e:00:53:0%d" % i,
                                      "ssid": "", "latitude": lat,
                                      "longitude": lon, "accuracy_m": 30,
                                      "first_seen": "", "last_seen": "",
                                      "source": ""}]})
        return out

    def test_section_appears_when_there_are_several_places(self):
        from wifigeo import report
        html = report.render(self._doc(self._places(2)), {"case_id": "CASE-TEST"})
        self.assertIn("Location history", html)

    def test_section_is_omitted_for_a_single_place(self):
        # An ordinary enquiry should not grow a history section it cannot fill.
        from wifigeo import report
        html = report.render(self._doc(self._places(1)), {"case_id": "CASE-TEST"})
        self.assertNotIn("Location history", html)

    def test_html_entities_are_not_double_escaped(self):
        from wifigeo import report
        html = report.render(self._doc(self._places(2)), {"case_id": "CASE-TEST"})
        self.assertNotIn("&amp;mdash;", html)

    def test_network_names_are_escaped(self):
        from wifigeo import report
        places = self._places(2)
        places[0]["networks"][0]["ssid"] = "A&B <script>"
        html = report.render(self._doc(places), {"case_id": "CASE-TEST"})
        self.assertNotIn("<script>", html)
        self.assertIn("A&amp;B", html)


if __name__ == "__main__":
    unittest.main()


class Corroboration(unittest.TestCase):
    """
    The rating is the overlap between the host's own profiled networks and the
    access points Apple places at a location - two lists built without
    reference to each other.
    """

    def test_several_profiled_networks_is_strong(self):
        from wifigeo.engine import _place_corroboration
        self.assertEqual(_place_corroboration(3, 3, 0)["level"], "strong")

    def test_two_is_moderate_and_says_why(self):
        from wifigeo.engine import _place_corroboration
        out = _place_corroboration(2, 2, 0)
        self.assertEqual(out["level"], "moderate")
        # Two networks are very often one dual-band access point, and the
        # wording must not let that read as two independent confirmations.
        self.assertIn("two radios", out["statement"])

    def test_one_is_weak(self):
        from wifigeo.engine import _place_corroboration
        self.assertEqual(_place_corroboration(1, 1, 0)["level"], "weak")

    def test_neighbour_density_does_not_raise_the_rating(self):
        # A busy street returns hundreds of unrelated access points and a quiet
        # lane returns three. Rating on that would score a city centre higher
        # on evidence that says nothing whatever about this host.
        from wifigeo.engine import _place_corroboration
        self.assertEqual(_place_corroboration(1, 1, 0)["level"], "weak")

    def test_networks_found_only_in_the_cloud_are_called_out(self):
        from wifigeo.engine import _place_corroboration
        out = _place_corroboration(2, 4, 2)
        self.assertEqual(out["level"], "strong")
        self.assertIn("neighbouring access points", out["statement"])

    def test_overlap_counts_profiled_networks_not_strangers(self):
        # A place surrounded by hundreds of Apple records, but only one of the
        # host's own, must not come out looking well supported.
        aps = [_ap("00:00:5e:00:53:a6", *LONDON),
               _ap("00:00:5e:00:53:b1", *EDINBURGH)]
        strangers = [_ap("00:00:5e:00:53:%02x" % (0x20 + i),
                         LONDON[0] + i * 0.0001, LONDON[1]) for i in range(40)]
        inv = Investigation.__new__(Investigation)
        inv.opts = Options(extra_observations=[
            {"bssid": "00:00:5e:00:53:a6", "ssid": "Solo"},
            {"bssid": "00:00:5e:00:53:b1", "ssid": "Other"}])
        inv.collisions = []
        inv.places = []
        places = inv._group_places({"queried_located": aps,
                                    "access_points": aps + strangers})
        london = [p for p in places if abs(p["latitude"] - LONDON[0]) < 0.01][0]
        self.assertEqual(london["profiled_here"], 1)
        self.assertEqual(london["corroboration"]["level"], "weak")


class Timeline(unittest.TestCase):

    def _place(self, i, lat, lon, first, last):
        return {"index": i, "latitude": lat, "longitude": lon,
                "network_count": 1, "spread_m": 0.0, "locality": "",
                "earliest_seen": first, "latest_seen": last,
                "corroboration": {"level": "strong", "statement": ""},
                "networks": [{"bssid": "00:00:5e:00:53:0%d" % i, "ssid": "",
                              "latitude": lat, "longitude": lon,
                              "accuracy_m": 30, "first_seen": first,
                              "last_seen": last, "source": ""}]}

    def test_drawn_when_two_places_have_dates(self):
        from wifigeo.report import _timeline
        svg = _timeline([self._place(1, *LONDON, "2026-01-01", "2026-02-01"),
                         self._place(2, *EDINBURGH, "2026-03-01", "2026-03-04")])
        self.assertIn("<svg", svg)
        self.assertEqual(svg.count("<rect"), 2)

    def test_omitted_without_dates(self):
        # Nothing to place on an axis; an empty chart would imply the artefact
        # held timing information it did not.
        from wifigeo.report import _timeline
        self.assertEqual(_timeline([self._place(1, *LONDON, "", ""),
                                    self._place(2, *EDINBURGH, "", "")]), "")

    def test_a_single_day_still_has_a_visible_bar(self):
        from wifigeo.report import _timeline
        svg = _timeline([self._place(1, *LONDON, "2026-01-01", "2026-06-01"),
                         self._place(2, *EDINBURGH, "2026-03-02", "2026-03-02")])
        widths = [float(w) for w in __import__("re").findall(r'width="([\d.]+)"', svg)]
        self.assertTrue(all(w >= 3.0 for w in widths),
                        "a one-day stay must not render as an invisible sliver")

    def test_malformed_dates_do_not_raise(self):
        from wifigeo.report import _timeline
        try:
            _timeline([self._place(1, *LONDON, "not-a-date", "also-not"),
                       self._place(2, *EDINBURGH, "2026-03-01", "2026-03-04")])
        except Exception as exc:                       # pragma: no cover
            self.fail("timeline raised on a malformed artefact date: %r" % exc)


class MicrosoftFingerprint(unittest.TestCase):
    """
    Microsoft is asked "where is a device that can see all of these at once".
    The list submitted is therefore a factual claim of co-observation, and a
    saved-profile list is not one: those networks were joined at different
    times in different towns. Submitting one whole asserted that access points
    hundreds of kilometres apart were seen together.
    """

    def _inv(self, obs, places):
        inv = Investigation.__new__(Investigation)
        inv.opts = Options(extra_observations=obs)
        inv.places = places
        return inv

    def _place(self, i, lat, lon):
        return {"index": i, "latitude": lat, "longitude": lon,
                "network_count": 1, "networks": []}

    def test_a_live_scan_is_submitted_and_is_the_best_input(self):
        class B:
            def __init__(self, m, r): self.bssid, self.rssi_dbm = m, r
        survey = {"beacons": [B("00:00:5e:00:53:a6", -50),
                              B("00:00:5e:00:53:a7", -61)]}
        inv = self._inv([], [self._place(1, *LONDON)])
        beacons, kind, note = inv._microsoft_fingerprint(survey, [])
        self.assertEqual(len(beacons), 2)
        self.assertEqual(kind, "live radio scan")
        self.assertEqual(beacons[0][1], -50)      # signal strengths preserved

    def test_addresses_spanning_places_are_never_submitted_together(self):
        inv = self._inv(
            [{"bssid": "00:00:5e:00:53:a6", "source": "registry NetworkList"},
             {"bssid": "00:00:5e:00:53:b1", "source": "registry NetworkList"}],
            [self._place(1, *LONDON), self._place(2, *EDINBURGH)])
        beacons, kind, note = inv._microsoft_fingerprint(
            {}, ["00:00:5e:00:53:a6", "00:00:5e:00:53:b1"])
        self.assertEqual(kind, "not submitted")
        self.assertEqual(beacons, [],
                         "access points in two places were submitted as one "
                         "co-observation")
        self.assertIn("distinct places", note)

    def test_one_place_from_an_artefact_is_submitted_but_qualified(self):
        inv = self._inv(
            [{"bssid": "00:00:5e:00:53:a6", "source": "registry NetworkList"}],
            [self._place(1, *LONDON)])
        beacons, kind, note = inv._microsoft_fingerprint({}, ["00:00:5e:00:53:a6"])
        self.assertEqual(len(beacons), 1)
        self.assertIn("same moment", note)        # the caveat must be stated

    def test_netsh_output_counts_as_co_observed(self):
        # netsh lists what the radio hears now, so it is one observation - and
        # the more entries it carries, the better Microsoft's answer.
        inv = self._inv(
            [{"bssid": "00:00:5e:00:53:a6", "source": "netsh output"},
             {"bssid": "00:00:5e:00:53:a7", "source": "netsh output"}],
            [self._place(1, *LONDON)])
        _beacons, kind, note = inv._microsoft_fingerprint(
            {}, ["00:00:5e:00:53:a6", "00:00:5e:00:53:a7"])
        self.assertNotIn("same moment", note)

    def test_operator_addresses_at_one_place_are_submitted_plainly(self):
        inv = self._inv([], [self._place(1, *LONDON)])
        beacons, kind, note = inv._microsoft_fingerprint({}, ["00:00:5e:00:53:a6"])
        self.assertEqual(len(beacons), 1)
        self.assertEqual(kind, "supplied by the operator")


class CoObservedContext(unittest.TestCase):
    """
    A single enquiry may carry the rest of the scan the target was seen in.

    Microsoft answers "where is a device that can see all of these at once" and
    gets better the more it is given, so when the operator has the whole scan
    and one address out of it is the subject, the rest is the fingerprint. It
    must sharpen the answer without becoming a subject of the report.
    """

    NETSH = """
SSID 1 : Reception-WiFi
    BSSID 1                 : 00:00:5e:00:53:a6
         Signal             : 82%
    BSSID 2                 : 00:00:5e:00:53:a7
         Signal             : 61%
SSID 2 : Cafe-Guest
    BSSID 1                 : 00:00:5e:00:53:b4
         Signal             : 44%
"""
    TARGET = "00:00:5e:00:53:a6"

    def _inv(self, context):
        inv = Investigation.__new__(Investigation)
        inv.opts = Options(target=self.TARGET, context_observations=context)
        inv.places = [{"index": 1, "latitude": LONDON[0], "longitude": LONDON[1],
                       "network_count": 1, "networks": []}]
        return inv

    def _context(self):
        from wifigeo import ingest
        return [o.to_dict() for o in ingest.parse_netsh(self.NETSH)]

    def test_context_joins_the_fingerprint(self):
        beacons, _kind, _note = self._inv(self._context())._microsoft_fingerprint(
            {}, [self.TARGET])
        self.assertEqual(len(beacons), 3)

    def test_the_target_leads_and_appears_once(self):
        beacons, _k, _n = self._inv(self._context())._microsoft_fingerprint(
            {}, [self.TARGET])
        macs = [m for m, _r in beacons]
        self.assertEqual(macs[0], self.TARGET)
        self.assertEqual(macs.count(self.TARGET), 1)

    def test_signal_strengths_survive(self):
        # Without them the fingerprint is a weaker question, so losing them
        # silently costs accuracy no one would notice.
        beacons, _k, _n = self._inv(self._context())._microsoft_fingerprint(
            {}, [self.TARGET])
        strengths = {m: r for m, r in beacons}
        self.assertEqual(strengths["00:00:5e:00:53:a7"], -70)
        self.assertEqual(strengths["00:00:5e:00:53:b4"], -78)

    def test_context_is_not_a_target(self):
        # It must not end up in extra_observations, or the report would claim
        # to be about a café's access point as well.
        inv = self._inv(self._context())
        self.assertEqual(inv.opts.extra_observations, [])

    def test_no_context_behaves_as_before(self):
        beacons, kind, _n = self._inv([])._microsoft_fingerprint({}, [self.TARGET])
        self.assertEqual(len(beacons), 1)
        self.assertEqual(kind, "supplied by the operator")


class NetshSignal(unittest.TestCase):

    def test_percentage_becomes_plausible_dbm(self):
        from wifigeo.ingest import _percent_to_dbm
        self.assertEqual(_percent_to_dbm(100), -50)
        self.assertEqual(_percent_to_dbm(82), -59)
        self.assertEqual(_percent_to_dbm(0), -100)

    def test_out_of_range_is_clamped(self):
        from wifigeo.ingest import _percent_to_dbm
        self.assertEqual(_percent_to_dbm(-5), -100)
        self.assertEqual(_percent_to_dbm(250), -50)

    def test_signal_attaches_to_the_access_point_above_it(self):
        from wifigeo import ingest
        obs = {o.bssid: o.rssi_dbm
               for o in ingest.parse_netsh(CoObservedContext.NETSH)}
        self.assertEqual(obs["00:00:5e:00:53:a6"], -59)
        self.assertEqual(obs["00:00:5e:00:53:a7"], -70)

    def test_a_scan_without_signal_lines_still_parses(self):
        from wifigeo import ingest
        obs = ingest.parse_netsh(
            "SSID 1 : Net\n    BSSID 1 : 00:00:5e:00:53:a6\n")
        self.assertEqual(len(obs), 1)
        self.assertIsNone(obs[0].rssi_dbm)


class PlacesMap(unittest.TestCase):
    """The scale diagram of where the places sit relative to one another."""

    def _p(self, i, lat, lon, level="strong", locality=""):
        return {"index": i, "latitude": lat, "longitude": lon,
                "network_count": 1, "spread_m": 0.0, "locality": locality,
                "earliest_seen": "", "latest_seen": "",
                "corroboration": {"level": level, "statement": ""},
                "networks": []}

    def test_drawn_for_two_or_more_places(self):
        from wifigeo.report import _places_map
        svg = _places_map([self._p(1, *LONDON), self._p(2, *EDINBURGH)])
        self.assertIn("<svg", svg)
        self.assertEqual(svg.count('class="pm-num"'), 2)

    def test_omitted_for_a_single_place(self):
        from wifigeo.report import _places_map
        self.assertEqual(_places_map([self._p(1, *LONDON)]), "")

    def test_colliding_labels_are_suppressed_but_dots_are_not(self):
        # Three sites in one city land on top of each other at continental
        # scale. Overlapping names render as an unreadable smear, which looks
        # like a rendering fault; the numbers stay and the list below explains
        # them.
        from wifigeo.report import _places_map
        svg = _places_map([
            self._p(1, 51.5074, -0.1278, locality="Lambeth, London"),
            self._p(2, 51.4779, -0.0015, locality="Greenwich, London"),
            self._p(3, 51.4700, -0.4543, locality="Hillingdon, London"),
            self._p(4, 55.9533, -3.1883, locality="Edinburgh"),
        ])
        self.assertEqual(svg.count('class="pm-num"'), 4)
        self.assertLess(svg.count('class="pm-lbl"'), 4)
        self.assertIn("Edinburgh", svg)

    def test_identical_positions_do_not_divide_by_zero(self):
        from wifigeo.report import _places_map
        try:
            _places_map([self._p(1, 51.5, -0.1), self._p(2, 51.5, -0.1)])
        except Exception as exc:                       # pragma: no cover
            self.fail("places map raised on coincident places: %r" % exc)

    def test_labels_are_escaped(self):
        from wifigeo.report import _places_map
        svg = _places_map([self._p(1, *LONDON, locality="A&B <x>"),
                           self._p(2, *EDINBURGH)])
        self.assertNotIn("<x>", svg)


class BulkReportShape(unittest.TestCase):

    def _doc(self, n):
        places = []
        for i, (lat, lon) in enumerate([LONDON, EDINBURGH, PARIS][:n], 1):
            places.append({"index": i, "latitude": lat, "longitude": lon,
                           "network_count": 1, "spread_m": 0.0, "locality": "",
                           "earliest_seen": "2026-01-0%d" % i,
                           "latest_seen": "2026-02-0%d" % i,
                           "corroboration": {"level": "strong", "statement": ""},
                           "networks": [{"bssid": "00:00:5e:00:53:0%d" % i,
                                         "ssid": "", "latitude": lat,
                                         "longitude": lon, "accuracy_m": 30,
                                         "first_seen": "", "last_seen": "",
                                         "source": ""}]})
        return {"case_id": "CASE-TEST", "target": {"kind": "imported"},
                "validation": {"verdict": "CORROBORATED", "score": 80.0,
                               "coverage": 100.0, "verdict_statement": ""},
                "places": places}

    def test_no_position_section_when_there_are_several_places(self):
        # It printed "No position established" straight after establishing
        # four places, which reads as a failed run rather than a different
        # question answered.
        from wifigeo import report
        html = report.render(self._doc(3), {"case_id": "CASE-TEST"})
        self.assertNotIn("No position established", html)

    def test_a_single_place_still_gets_its_position_section(self):
        from wifigeo import report
        html = report.render(self._doc(1), {"case_id": "CASE-TEST"})
        self.assertIn("Position", html)

    def test_bulk_report_carries_map_timeline_and_places(self):
        from wifigeo import report
        html = report.render(self._doc(3), {"case_id": "CASE-TEST"})
        for part in ("Location history", "placesmap", "timeline",
                     "Artefact analysis"):
            self.assertIn(part, html, "%s missing from the bulk report" % part)


class PlacesExport(unittest.TestCase):
    """
    A row per place, with the address split into fields.

    positions.csv is a row per access point, which is the wrong unit for a bulk
    enquiry: the finding is the place. An analyst sorts by town and postcode,
    and cannot do that from a column of coordinates or by splitting a display
    name back apart.
    """

    def _place(self, i, city, postcode, ssids, macs):
        return {"index": i, "latitude": 51.5074, "longitude": -0.1278,
                "network_count": len(macs), "spread_m": 12.5,
                "earliest_seen": "2026-01-04T08:12:00Z",
                "latest_seen": "2026-08-01T18:40:00Z",
                "ssids": ssids,
                "address": "Somewhere, %s, %s" % (city, postcode),
                "locality": city,
                "address_parts": {"house_number": "12", "road": "High Street",
                                  "area": "South Bank", "city": city,
                                  "district": "Greater London",
                                  "state": "England", "postcode": postcode,
                                  "country": "United Kingdom",
                                  "country_code": "GB"},
                "corroboration": {"level": "strong", "statement": ""},
                "networks": [{"bssid": m, "ssid": "", "latitude": 51.5,
                              "longitude": -0.1, "accuracy_m": 30,
                              "first_seen": "", "last_seen": "",
                              "source": ""} for m in macs]}

    def _export(self, places):
        """Run the real export path and return the places.csv it wrote."""
        import shutil
        import tempfile
        from wifigeo.engine import Investigation
        from wifigeo.evidence import Case

        root = tempfile.mkdtemp()
        try:
            inv = Investigation.__new__(Investigation)
            inv.case = Case(root)
            inv.places = places
            # A real run always has these; the export reads the supplied
            # addresses to build the per-address sheet.
            inv.opts = Options(extra_observations=[
                {"bssid": n["bssid"], "ssid": "", "source": "operator input"}
                for pl in places for n in pl.get("networks") or []])
            Investigation._write_exports(inv, {}, [], None)
            path = pathlib.Path(inv.case.dir) / "exports" / "places.csv"
            return path.read_text(encoding="utf-8") if path.exists() else ""
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_quoting_protects_commas_and_quotes(self):
        # An unquoted street address silently shifts every column to its right
        # and the file still opens without complaint.
        from wifigeo.engine import _csv_cell
        self.assertEqual(_csv_cell("High St, Flat 2"), '"High St, Flat 2"')
        self.assertEqual(_csv_cell('He said "hi"'), '"He said ""hi"""')
        self.assertEqual(_csv_cell("Lambeth"), "Lambeth")
        self.assertEqual(_csv_cell(None), "")

    def test_newlines_are_quoted(self):
        from wifigeo.engine import _csv_cell
        self.assertTrue(_csv_cell("a\nb").startswith('"'))

    def test_written_file_has_a_row_per_place_with_address_columns(self):
        csv = self._export([
            self._place(1, "London", "SE1 8XZ", ["ACME-Corp"],
                        ["00:00:5e:00:53:a6", "00:00:5e:00:53:a7"]),
            self._place(2, "Edinburgh", "EH1 1BQ", ["Guest-WiFi"],
                        ["00:00:5e:00:53:b1"]),
        ])
        lines = [l for l in csv.strip().split(chr(10)) if l]
        self.assertEqual(len(lines), 3, "header plus one row per place")
        header = lines[0].split(",")
        for column in ("city", "postcode", "country", "country_code", "road",
                       "area", "district", "state", "corroboration",
                       "earliest_seen", "ssids", "bssids"):
            self.assertIn(column, header, "%s column missing" % column)
        self.assertIn("SE1 8XZ", lines[1])
        self.assertIn("Edinburgh", lines[2])

    def test_a_single_place_writes_no_places_file(self):
        # One place is an ordinary enquiry; positions.csv already covers it.
        self.assertEqual(
            self._export([self._place(1, "London", "SE1 8XZ", ["X"],
                                      ["00:00:5e:00:53:a6"])]), "")
