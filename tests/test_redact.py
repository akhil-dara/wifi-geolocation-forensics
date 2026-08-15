"""
Redaction.

These are adversarial: each test tries to smuggle an identifier through in a
shape the key-based rules do not obviously cover - as a dictionary key, inside
a URL, in free prose, in a bounding box under a different name. Redaction that
works only on the fields someone remembered to list is not redaction.
"""

import unittest

from wifigeo import redact

REAL_MAC = "00:00:5e:00:53:a6"
REAL_LAT, REAL_LON = 51.477928, -0.001545


class Addresses(unittest.TestCase):

    def test_keeps_the_vendor_prefix_and_masks_the_device(self):
        out = redact.apply({"bssid": REAL_MAC})
        self.assertEqual(out["bssid"], "00:00:5e:xx:xx:xx")

    def test_masks_addresses_used_as_dictionary_keys(self):
        # Vendor attribution is keyed BY the address. Masking only values would
        # leave every address on display in the keys.
        out = redact.apply({"vendors": {REAL_MAC: "Some Vendor Ltd"}})
        self.assertNotIn(REAL_MAC, str(out))

    def test_masks_addresses_inside_urls(self):
        doc = {"requests": [{"url":
                             "https://api.example.org/lookup?bssid=%s" % REAL_MAC}]}
        self.assertNotIn(REAL_MAC, str(redact.apply(doc)))

    def test_masks_hyphenated_addresses_in_prose(self):
        doc = {"note": "The device 00-00-5E-00-53-A6 was observed."}
        out = str(redact.apply(doc))
        self.assertNotIn("00-00-5E-00-53-A6", out)
        self.assertNotIn("00-00-5e-00-53-a6", out.lower())

    def test_masks_addresses_in_nested_lists(self):
        doc = {"a": [{"b": [{"c": {"mac": REAL_MAC}}]}]}
        self.assertNotIn(REAL_MAC, str(redact.apply(doc)))


class Coordinates(unittest.TestCase):

    def test_truncates_rather_than_scrambles(self):
        # Truncation is honest: the reader can see precision was reduced. A
        # fabricated coordinate would be a false statement in an exhibit.
        out = redact.apply({"position": {"latitude": REAL_LAT,
                                         "longitude": REAL_LON}})
        lat = out["position"]["latitude"]
        self.assertAlmostEqual(lat, 51.47, places=2)
        self.assertNotEqual(lat, REAL_LAT)

    def test_masks_bounding_box_corners(self):
        # north/south/east/west are coordinates under different names.
        doc = {"box": {"north": REAL_LAT, "south": REAL_LAT - 0.01,
                       "east": REAL_LON, "west": REAL_LON - 0.01}}
        blob = str(redact.apply(doc))
        self.assertNotIn("51.477928", blob)
        self.assertNotIn("-0.001545", blob)

    def test_truncates_coordinate_precision_in_free_text(self):
        doc = {"note": "Resolved to %f, %f exactly." % (REAL_LAT, REAL_LON)}
        blob = str(redact.apply(doc))
        self.assertNotIn("51.477928", blob)

    def test_rebuilds_derived_representations(self):
        # Plus Code, MGRS, UTM and geohash are lossless encodings of the
        # position. Leaving them intact would publish the location in five
        # other alphabets while the decimal pair looked redacted.
        doc = {"position": {"latitude": REAL_LAT, "longitude": REAL_LON},
               "coordinates": {"decimal": "%f, %f" % (REAL_LAT, REAL_LON),
                               "plus_code": "9C3XFXHX+59G",
                               "mgrs": "30U YC 08210 07238",
                               "utm": "30U 708210mE 5707239mN",
                               "geohash": "gcpuzgqbev",
                               "dms": "17d 24' 57\" N"}}
        out = redact.apply(doc)
        for key in ("plus_code", "mgrs", "utm", "geohash", "dms"):
            self.assertEqual(out["coordinates"][key], redact.MASK,
                             "%s survived redaction" % key)


class HostAndOperator(unittest.TestCase):

    def test_masks_examiner_and_organisation(self):
        out = redact.apply_meta({"examiner": "A. Person",
                                 "organisation": "Some Force"})
        self.assertEqual(out["examiner"], redact.MASK)
        self.assertEqual(out["organisation"], redact.MASK)

    def test_masks_the_examining_machine(self):
        out = redact.apply_meta({"environment": {"hostname": "LAPTOP-01",
                                                 "user": "someone",
                                                 "cwd": "C:\\Users\\someone",
                                                 "executable": "C:\\py\\python.exe"}})
        for key in ("hostname", "user", "cwd", "executable"):
            self.assertEqual(out["environment"][key], redact.MASK)

    def test_drops_every_filesystem_path(self):
        # A path carries the operator's account name, so a single missed path
        # key undoes the withholding of the examiner.
        doc = {"report_path": "C:\\Users\\someone\\r.html",
               "report_pdf_path": "C:\\Users\\someone\\r.pdf",
               "report_redacted_path": "C:\\Users\\someone\\r.RED.html",
               "report_redacted_pdf_path": "C:\\Users\\someone\\r.RED.pdf",
               "evidence": {"zip_path": "C:\\Users\\someone\\e.zip"}}
        blob = str(redact.apply(doc))
        self.assertNotIn("someone", blob)


class Enrichment(unittest.TestCase):

    def test_keeps_locality_but_drops_the_street(self):
        doc = {"enrichment": {"address": {
            "house_number": "12", "road": "Some Street",
            "postcode": "AB1 2CD", "city": "London",
            "country": "United Kingdom",
            "display_name": "12 Some Street, London, AB1 2CD"}}}
        out = redact.apply(doc)["enrichment"]["address"]
        self.assertEqual(out["city"], "London")
        self.assertEqual(out["country"], "United Kingdom")
        self.assertNotIn("Some Street", str(out))
        self.assertNotIn("AB1 2CD", str(out))

    def test_removes_the_map(self):
        # The map is a picture of the address; there is no way to blur it
        # safely, so it goes entirely.
        doc = {"static_map": {"tiles": ["data:image/png;base64,AAAA"]},
               "export_map": {"svg": "<svg/>"}}
        out = redact.apply(doc)
        self.assertNotIn("static_map", out)
        self.assertNotIn("export_map", out)


class Contract(unittest.TestCase):

    def test_the_original_document_is_not_mutated(self):
        # Redaction produces a derived copy. If it edited in place, the
        # unredacted report rendered afterwards would come out redacted.
        doc = {"bssid": REAL_MAC,
               "position": {"latitude": REAL_LAT, "longitude": REAL_LON}}
        redact.apply(doc)
        self.assertEqual(doc["bssid"], REAL_MAC)
        self.assertEqual(doc["position"]["latitude"], REAL_LAT)

    def test_declares_itself_redacted(self):
        out = redact.apply({})
        self.assertTrue(out["redacted"])
        self.assertIn("redact", out["redaction_note"].lower())

    def test_keeps_the_reasoning(self):
        # Redaction removes identifying detail, not the methodology - a reader
        # must still be able to see how the conclusion was reached.
        doc = {"validation": {"verdict": "CORROBORATED", "score": 91.1,
                              "checks": [{"name": "providers agree",
                                          "passed": True}]},
               "case_id": "CASE-123"}
        out = redact.apply(doc)
        self.assertEqual(out["validation"]["verdict"], "CORROBORATED")
        self.assertEqual(out["validation"]["score"], 91.1)
        self.assertEqual(out["case_id"], "CASE-123")


if __name__ == "__main__":
    unittest.main()
