"""
The two wire protocols.

Neither is documented by its vendor; both were reconstructed from captured
traffic. That makes them the most fragile thing in the tool and the most
important to pin: a protocol regression does not raise, it just quietly returns
nothing, or - far worse - returns a position derived from the wrong thing.

The Microsoft sample below is a sanitised capture held inline: synthetic
addresses, a placeholder position, and a zero TrackingId. Nothing here depends
on a real device, a real place, or on a file the project ships.
"""

import unittest

from wifigeo import msft, proto

#: A real GetLocationUsingFingerprint response with every identifying value
#: replaced. Kept here rather than in a shipped sample file so the test is
#: self-contained and the repository publishes no captured traffic.
MSFT_RESPONSE = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<GetLocationUsingFingerprintResponse'
    b' xmlns="http://inference.location.live.com">'
    b'<GetLocationUsingFingerprintResult>'
    b'<ResponseStatus>Success</ResponseStatus>'
    b'<LocationResult>'
    b'<ResolverStatus Status="Success" Source="Internal"/>'
    b'<ResolvedPosition Latitude="51.500000" Longitude="-0.120000" Altitude="0"/>'
    b'<RadialUncertainty>131</RadialUncertainty>'
    b'<TileResult/>'
    b'<TrackingId>00000000-0000-0000-0000-000000000000</TrackingId>'
    b'</LocationResult>'
    b'<ExtendedV21Result CrowdSourcingLevel="High"'
    b' ServerUtcTime="2026-01-01T00:00:00.0000000Z"/>'
    b'</GetLocationUsingFingerprintResult>'
    b'</GetLocationUsingFingerprintResponse>')


class Varint(unittest.TestCase):

    def test_round_trips(self):
        for value in (0, 1, 127, 128, 300, 16383, 16384, 2 ** 31, 2 ** 63 - 1):
            with self.subTest(value=value):
                encoded = proto.encode_varint(value)
                decoded, consumed = proto.decode_varint(encoded, 0)
                self.assertEqual(decoded, value)
                self.assertEqual(consumed, len(encoded))

    def test_single_byte_boundary(self):
        # 127 fits in one byte, 128 needs two: the continuation bit.
        self.assertEqual(len(proto.encode_varint(127)), 1)
        self.assertEqual(len(proto.encode_varint(128)), 2)

    def test_truncated_input_raises(self):
        with self.assertRaises(proto.ProtoError):
            proto.decode_varint(b"\xff\xff", 0)


class SignedInterpretation(unittest.TestCase):
    """
    Apple encodes latitude and longitude as int64 scaled by 1e8 - NOT zigzag.

    Reading them as zigzag halves every value and flips the sign of half of
    them, which lands the answer in the wrong hemisphere rather than failing.
    """

    def test_positive_values_are_unchanged(self):
        self.assertEqual(proto.as_signed64(1234567890), 1234567890)

    def test_large_values_become_negative(self):
        # Two's complement: 2**64 - 1 is -1, not a huge positive number.
        self.assertEqual(proto.as_signed64(2 ** 64 - 1), -1)
        self.assertEqual(proto.as_signed64(2 ** 64 - 100), -100)

    def test_the_sign_boundary(self):
        self.assertEqual(proto.as_signed64(2 ** 63 - 1), 2 ** 63 - 1)
        self.assertEqual(proto.as_signed64(2 ** 63), -(2 ** 63))

    def test_a_realistic_coordinate(self):
        # 51.477928 degrees scaled by 1e8, as Apple sends it.
        self.assertAlmostEqual(proto.as_signed64(5147792800) / 1e8,
                               51.477928, places=6)

    def test_a_realistic_negative_coordinate(self):
        raw = (2 ** 64) - 154500          # -0.001545 * 1e8
        self.assertAlmostEqual(proto.as_signed64(raw) / 1e8, -0.001545,
                               places=6)


class Fields(unittest.TestCase):

    def test_tag_packs_field_number_and_wire_type(self):
        # tag = (field << 3) | wire_type, emitted as a varint.
        self.assertEqual(proto.tag(1, proto.WIRE_VARINT), b"")
        self.assertEqual(proto.tag(2, proto.WIRE_LEN), b"")

    def test_string_field_round_trips(self):
        blob = proto.field_string(1, "00:00:5e:00:53:a6")
        got = dict((f, v) for f, _w, v in proto.iter_fields(blob))
        self.assertEqual(bytes(got[1]).decode(), "00:00:5e:00:53:a6")

    def test_varint_field_round_trips(self):
        blob = proto.field_varint(4, 400)
        got = dict((f, v) for f, _w, v in proto.iter_fields(blob))
        self.assertEqual(got[4], 400)


class MicrosoftRequest(unittest.TestCase):

    #: The service is asked "where is a device that can see all of these?", so
    #: a beacon is an address and the signal strength it was seen at.
    BEACONS = [("00:1a:2b:00:00:01", -55), ("00:1a:2b:00:00:02", -71)]

    def _xml(self, **kw):
        xml, _gz, _tid = msft.build_request(self.BEACONS, **kw)
        return xml.decode("utf-8")

    def test_every_address_is_present(self):
        text = self._xml()
        for mac, _rssi in self.BEACONS:
            self.assertIn(mac.replace(":", "-").upper(), text.upper())

    def test_the_body_is_gzip_and_the_xml_is_its_plaintext(self):
        # The request goes on the wire compressed; both halves are preserved as
        # evidence, and they must actually correspond.
        import gzip
        xml, gz, _tid = msft.build_request(self.BEACONS)
        self.assertEqual(gzip.decompress(gz), xml)

    def test_carries_the_gating_application_id(self):
        # Any other GUID gets a 403 from the gateway, so this is not cosmetic.
        self.assertIn(msft.APPLICATION_ID, self._xml())

    def test_a_fresh_tracking_id_per_request(self):
        # Reusing one would make responses impossible to tie to a single
        # request in the evidence package.
        _x1, _g1, t1 = msft.build_request(self.BEACONS)
        _x2, _g2, t2 = msft.build_request(self.BEACONS)
        self.assertNotEqual(t1, t2)

    def test_device_profile_is_absent_by_default(self):
        # It identifies the examining machine to a third party.
        self.assertNotIn("DeviceProfile", self._xml())

    def test_device_profile_appears_when_asked_for(self):
        text = self._xml(device_profile={"DeviceType": "PC"})
        self.assertIn("DeviceProfile", text)


class MicrosoftResponse(unittest.TestCase):

    def setUp(self):
        self.body = MSFT_RESPONSE

    def test_parses_the_position(self):
        result = msft.parse_response(self.body)
        self.assertAlmostEqual(result.latitude, 51.5, places=4)
        self.assertAlmostEqual(result.longitude, -0.12, places=4)

    def test_reads_the_uncertainty(self):
        self.assertAlmostEqual(msft.parse_response(self.body)
                               .radial_uncertainty_m, 131.0, places=1)

    def test_a_normal_answer_is_not_ip_fallback(self):
        self.assertFalse(msft.parse_response(self.body).ip_fallback)
        self.assertTrue(msft.parse_response(self.body).located)


class IPFallbackDetection(unittest.TestCase):
    """
    The single most dangerous failure mode: when Microsoft cannot position the
    beacons it answers with an IP-derived location instead of saying so. The
    answer looks entirely plausible - right city, sensible coordinates - and
    would appear to corroborate the Apple position while actually describing
    the examiner's own internet connection.
    """

    def _result(self, **kw):
        r = msft.InferenceResult(latitude=28.6, longitude=77.2)
        for k, v in kw.items():
            setattr(r, k, v)
        return r

    def test_source_ip_is_caught(self):
        r = self._result(resolver_source="IP", radial_uncertainty_m=500.0)
        self.assertTrue(r.ip_fallback)
        self.assertFalse(r.located)

    def test_source_ip_is_case_insensitive(self):
        self.assertTrue(self._result(resolver_source="ip").ip_fallback)

    def test_huge_uncertainty_is_caught_even_without_the_source_flag(self):
        r = self._result(resolver_source="Internal",
                         radial_uncertainty_m=100000.0)
        self.assertTrue(r.ip_fallback)

    def test_a_tight_internal_answer_is_accepted(self):
        r = self._result(resolver_source="Internal", radial_uncertainty_m=150.0)
        self.assertFalse(r.ip_fallback)
        self.assertTrue(r.located)

    def test_null_island_is_not_a_position(self):
        r = self._result(latitude=0.0, longitude=0.0,
                         resolver_source="Internal", radial_uncertainty_m=50.0)
        self.assertFalse(r.has_coordinates)
        self.assertFalse(r.located)

    def test_out_of_range_coordinates_are_rejected(self):
        r = self._result(latitude=91.0, longitude=0.5,
                         resolver_source="Internal", radial_uncertainty_m=50.0)
        self.assertFalse(r.has_coordinates)


class TrackingId(unittest.TestCase):
    """The echoed TrackingId is the only thing tying an answer to its question."""

    def test_matching_id_verifies(self):
        r = msft.InferenceResult(tracking_id="ABC-123")
        self.assertTrue(msft.verify_tracking_id(r, "ABC-123"))
        self.assertTrue(r.tracking_id_verified)

    def test_mismatched_id_fails(self):
        r = msft.InferenceResult(tracking_id="ABC-123")
        self.assertFalse(msft.verify_tracking_id(r, "DEF-456"))
        self.assertFalse(r.tracking_id_verified)

    def test_comparison_ignores_braces_and_case(self):
        # The service echoes the value back in whatever form it likes.
        r = msft.InferenceResult(tracking_id="{abc-123}")
        self.assertTrue(msft.verify_tracking_id(r, "ABC-123"))


if __name__ == "__main__":
    unittest.main()
