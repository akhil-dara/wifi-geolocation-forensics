"""
Coordinate systems and distance maths.

Every expected value here is derived independently - from the defining formula
or from a published constant - not captured from this implementation's own
output. A test that records what the code currently does proves only that it
has not changed, which is worthless for a conversion an examiner will put in a
statement of evidence.
"""

import math
import unittest

from wifigeo import geo


class Haversine(unittest.TestCase):

    def test_one_degree_of_latitude(self):
        # A degree of latitude is 10 000 km / 90 = 111.19 km by the definition
        # of the metre's original French survey, and the spherical model agrees
        # to within a few hundred metres.
        d = geo.haversine_m(0.0, 0.0, 1.0, 0.0)
        self.assertAlmostEqual(d / 1000.0, 111.19, delta=0.5)

    def test_one_degree_of_longitude_at_the_equator(self):
        d = geo.haversine_m(0.0, 0.0, 0.0, 1.0)
        self.assertAlmostEqual(d / 1000.0, 111.19, delta=0.5)

    def test_longitude_shrinks_with_the_cosine_of_latitude(self):
        # At 60 degrees north a degree of longitude is half its equatorial span.
        equator = geo.haversine_m(0.0, 0.0, 0.0, 1.0)
        north = geo.haversine_m(60.0, 0.0, 60.0, 1.0)
        self.assertAlmostEqual(north / equator, math.cos(math.radians(60.0)),
                               places=3)

    def test_identical_points_are_zero(self):
        self.assertEqual(geo.haversine_m(51.5, -0.1, 51.5, -0.1), 0.0)

    def test_antipodes_are_half_the_circumference(self):
        d = geo.haversine_m(0.0, 0.0, 0.0, 180.0)
        self.assertAlmostEqual(d / 1000.0, 20015.0, delta=5.0)


class Bearing(unittest.TestCase):

    def test_due_north_is_zero(self):
        self.assertAlmostEqual(geo.bearing_deg(0, 0, 1, 0), 0.0, places=3)

    def test_due_east_is_ninety(self):
        self.assertAlmostEqual(geo.bearing_deg(0, 0, 0, 1), 90.0, places=3)

    def test_compass_points(self):
        for bearing, expected in ((0, "N"), (90, "E"), (180, "S"), (270, "W")):
            self.assertEqual(geo.compass_point(bearing), expected)


class UTM(unittest.TestCase):
    """Zone number and band letter both follow published formulae."""

    def test_zone_number_formula(self):
        # zone = floor((lon + 180) / 6) + 1
        for lon, zone in ((0.0, 31), (-0.0015, 30), (-180.0, 1), (179.9, 60),
                          (2.2945, 31), (-74.0, 18)):
            with self.subTest(lon=lon):
                out = geo.to_utm(51.0 if lon != 0.0 else 51.0, lon)
                self.assertEqual(int(str(out["zone"])[:2].rstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                                     or str(out["zone"])[:2]), zone)

    def test_latitude_band_letter(self):
        # Bands are 8 degrees tall, lettered C at -80 upward, skipping I and O.
        for lat, band in ((51.477928, "U"), (0.5, "N"), (-0.5, "M"),
                          (56.5, "V"), (-33.9, "H")):
            with self.subTest(lat=lat):
                self.assertEqual(geo._lat_band(lat), band)

    def test_bands_skip_i_and_o(self):
        bands = {geo._lat_band(lat) for lat in range(-79, 80)}
        self.assertNotIn("I", bands)
        self.assertNotIn("O", bands)


class PlusCode(unittest.TestCase):
    """
    Open Location Code, derived from its own specification.

    The alphabet is base 20: "23456789CFGHJMPQRVWX". The first character pair
    encodes latitude+90 and longitude+180 in units of 20 degrees.
    """

    ALPHABET = "23456789CFGHJMPQRVWX"

    def test_null_island_first_pair(self):
        # lat 0 -> (0+90)/20 = 4.5 -> index 4 -> '6'
        # lon 0 -> (0+180)/20 = 9.0 -> index 9 -> 'F'
        code = geo.plus_code(0.0, 0.0)
        self.assertEqual(code[0], "6")
        self.assertEqual(code[1], "F")

    def test_separator_is_the_ninth_character(self):
        for lat, lon in ((0.0, 0.0), (51.477928, -0.001545), (-33.86, 151.21)):
            with self.subTest(lat=lat, lon=lon):
                self.assertEqual(geo.plus_code(lat, lon)[8], "+")

    def test_uses_only_the_defined_alphabet(self):
        code = geo.plus_code(51.477928, -0.001545)
        for ch in code.replace("+", ""):
            self.assertIn(ch, self.ALPHABET, "%r is not an OLC digit" % ch)

    def test_nearby_points_share_a_prefix(self):
        # Two points a few metres apart must agree on the coarse digits.
        a = geo.plus_code(51.477928, -0.001545)
        b = geo.plus_code(51.477930, -0.001540)
        self.assertEqual(a[:8], b[:8])

    def test_distant_points_do_not(self):
        a = geo.plus_code(51.477928, -0.001545)
        b = geo.plus_code(-33.856784, 151.215297)
        self.assertNotEqual(a[:4], b[:4])


class Geohash(unittest.TestCase):

    def test_null_island_is_in_the_s_cell(self):
        # The first base-32 digit divides the world into 32 cells; the cell
        # containing (0,0) with positive lat and lon is 's'.
        self.assertTrue(geo.geohash(0.0, 0.0).startswith("s"))

    def test_precision_controls_length(self):
        for n in (4, 8, 12):
            self.assertEqual(len(geo.geohash(51.5, -0.1, precision=n)), n)

    def test_uses_only_the_base32_alphabet(self):
        # Geohash omits a, i, l and o to avoid confusion.
        allowed = set("0123456789bcdefghjkmnpqrstuvwxyz")
        for ch in geo.geohash(51.477928, -0.001545, precision=12):
            self.assertIn(ch, allowed)

    def test_nearby_points_share_a_prefix(self):
        self.assertEqual(geo.geohash(51.477928, -0.001545)[:6],
                         geo.geohash(51.477930, -0.001540)[:6])


class DMS(unittest.TestCase):

    def test_arithmetic_is_correct(self):
        # 51.477928 deg = 51 deg + 0.477928*60 = 28.67568 min
        #               = 28 min + 0.67568*60  = 40.54 sec
        out = geo.to_dms(51.477928, -0.001545)
        self.assertIn("51", out)
        self.assertIn("28", out)
        self.assertIn("40.5", out)
        self.assertIn("N", out)

    def test_hemispheres(self):
        self.assertIn("S", geo.to_dms(-33.86, 151.21))
        self.assertIn("E", geo.to_dms(-33.86, 151.21))
        self.assertIn("N", geo.to_dms(51.5, -0.1))
        self.assertIn("W", geo.to_dms(51.5, -0.1))


class CoordinateFormats(unittest.TestCase):

    def test_every_representation_is_present(self):
        out = geo.coordinate_formats(51.477928, -0.001545)
        for key in ("decimal", "decimal_precise", "dms", "utm", "mgrs",
                    "geohash", "plus_code"):
            self.assertIn(key, out)
            self.assertTrue(out[key], "%s is empty" % key)

    def test_decimal_is_not_truncated(self):
        # An examiner reading a coordinate out of a report must get the full
        # precision that was actually used; silently rounding here would make
        # the report disagree with the evidence package.
        out = geo.coordinate_formats(51.477928, -0.001545)
        self.assertIn("51.477928", out["decimal"])
        self.assertIn("-0.001545", out["decimal"])

    def test_southern_and_western_hemispheres(self):
        out = geo.coordinate_formats(-33.856784, 151.215297)
        self.assertIn("S", out["dms"])
        self.assertTrue(out["mgrs"])
        self.assertTrue(out["plus_code"])


class Centroid(unittest.TestCase):

    def test_of_a_single_point_is_that_point(self):
        lat, lon = geo.centroid([(51.5, -0.1)])[:2]
        self.assertAlmostEqual(lat, 51.5, places=6)
        self.assertAlmostEqual(lon, -0.1, places=6)

    def test_of_a_symmetric_pair_is_the_midpoint(self):
        lat, lon = geo.centroid([(0.0, -1.0), (0.0, 1.0)])[:2]
        self.assertAlmostEqual(lat, 0.0, places=6)
        self.assertAlmostEqual(abs(lon), 0.0, places=6)


class Verdict(unittest.TestCase):

    def test_cannot_claim_corroboration_without_a_cross_check(self):
        # A high score from a single provider is still single-source. Saying
        # otherwise would overstate the evidence.
        verdict, _ = geo.verdict_for(95.0, corroborated=False)
        self.assertNotIn("CORROBORATED", verdict.upper().replace("SINGLE-SOURCE", ""))

    def test_high_score_with_cross_check_is_corroborated(self):
        verdict, _ = geo.verdict_for(95.0, corroborated=True)
        self.assertIn("CORROBORATED", verdict.upper())


if __name__ == "__main__":
    unittest.main()
