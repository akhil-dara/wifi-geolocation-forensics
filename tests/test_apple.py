"""
Apple WLoc client: address canonicalisation and request construction.

The request format is not documented by Apple; it was reconstructed from live
traffic. These tests pin the byte layout so a refactor cannot quietly change
what goes on the wire - a malformed request does not error, it just returns
fewer results, which is the kind of regression that hides for months.
"""

import unittest

from wifigeo import apple


class CanonicalBSSID(unittest.TestCase):
    """Investigators paste addresses from wherever they found them."""

    def test_accepts_every_notation(self):
        # Registry exports, event logs, Cisco kit, SIEM tables and vendor
        # documentation each use a different separator for the same address.
        for text in ("00:00:5e:00:53:a6",
                     "00-00-5E-00-53-A6",
                     "0000.5e00.53a6",
                     "00 00 5e 00 53 a6",
                     "00005e0053a6",
                     "00:00:5E:00:53:A6"):
            with self.subTest(text=text):
                self.assertEqual(apple.canonical_bssid(text),
                                 "00:00:5e:00:53:a6")

    def test_pads_short_octets(self):
        # Apple returns addresses with leading zeros stripped - `0:0:5e:...`
        # rather than `00:00:5e:...` - so an unpadded octet is a real input,
        # not a typo to reject.
        self.assertEqual(apple.canonical_bssid("0:0:5e:0:53:a6"),
                         "00:00:5e:00:53:a6")

    def test_rejects_non_addresses(self):
        for text in ("", "nope", "00:00:5e:00:53", "00:00:5e:00:53:a6:b7",
                     "zz:00:5e:00:53:a6", "not-a-mac"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    apple.canonical_bssid(text)

    def test_is_bssid_matches_canonicalisation(self):
        # is_bssid must agree with canonical_bssid, or the CLI accepts input
        # the parser then rejects.
        for text in ("00:00:5e:00:53:a6", "00-00-5E-00-53-A6", "00005e0053a6"):
            self.assertTrue(apple.is_bssid(text), text)
        for text in ("nope", "", "hello world"):
            self.assertFalse(apple.is_bssid(text), text)


class BuildRequest(unittest.TestCase):

    def _declared_length(self, body):
        """Read the payload length the envelope declares, and what follows it."""
        marker = body.index(b"\x00\x00\x00\x01")
        declared = int.from_bytes(body[marker + 4:marker + 8], "big")
        actual = len(body) - (marker + 8)
        return declared, actual

    def test_length_prefix_is_four_byte_big_endian(self):
        # Those four bytes are the payload length. Public implementations read
        # them as padding; a wrong value truncates the request and the service
        # answers with nothing rather than an error, so this hides for months.
        for count in (1, 2, 5):
            macs = ["00:00:5e:00:53:%02x" % i for i in range(count)]
            with self.subTest(addresses=count):
                declared, actual = self._declared_length(
                    apple.build_request(macs))
                self.assertEqual(declared, actual)

    def test_length_grows_with_each_address(self):
        one, _ = self._declared_length(
            apple.build_request(["00:00:5e:00:53:a6"]))
        two, _ = self._declared_length(
            apple.build_request(["00:00:5e:00:53:a6", "00:00:5e:00:53:a7"]))
        self.assertGreater(two, one)

    def test_contains_the_queried_address(self):
        body = apple.build_request(["00:00:5e:00:53:a6"])
        self.assertIn(b"00:00:5e:00:53:a6", body)

    def test_multiple_addresses_all_present(self):
        macs = ["00:00:5e:00:53:a6", "00:00:5e:00:53:a7"]
        body = apple.build_request(macs)
        for m in macs:
            self.assertIn(m.encode(), body)

    def test_neighbour_cap_is_four_hundred(self):
        self.assertEqual(apple.MAX_NEIGHBOURS, 400)

    def test_normalises_before_transmitting(self):
        # A hyphenated address must go on the wire in Apple's own notation.
        body = apple.build_request(["00-00-5E-00-53-A6"])
        self.assertIn(b"00:00:5e:00:53:a6", body)
        self.assertNotIn(b"00-00-5E-00-53-A6", body)


class ParseResponse(unittest.TestCase):
    """
    The parser and the query wrapper deliberately sit at different levels.

    `parse_response` is strict: a malformed body is a ProtoError, because
    silently returning an empty list would make a corrupted response
    indistinguishable from an honest "no records". `query` is the public entry
    point and absorbs that, recording it as a per-batch `parse_error` so one bad
    batch cannot abandon an investigation. Both halves are pinned here.
    """

    def test_empty_body_yields_no_access_points(self):
        aps, _offset = apple.parse_response(b"")
        self.assertEqual(aps, [])

    def test_second_return_value_is_the_payload_offset(self):
        # Not a record count. Mistaking the two silently corrupts any caller
        # that reports "records returned".
        _aps, offset = apple.parse_response(b"")
        self.assertIsInstance(offset, int)
        self.assertGreaterEqual(offset, 0)

    def test_malformed_body_raises_protoerror(self):
        from wifigeo import proto
        with self.assertRaises(proto.ProtoError):
            apple.parse_response(b"\x00\x01\x02\x03garbage")

    def test_query_absorbs_a_malformed_response(self):
        # The wrapper must never propagate a parse failure: one unreadable
        # batch is a diagnostic, not the end of the investigation.
        from wifigeo import proto

        class FakeExchange:
            ok, status, error = True, 200, None
            seq = 1
            response_body = b"\x00\x01\x02\x03garbage"

        class FakeTransport:
            def fetch(self, *a, **k):
                return FakeExchange()

        out = apple.query(FakeTransport(), ["00:00:5e:00:53:a6"])
        self.assertEqual(out["access_points"], [])
        self.assertTrue(any("parse_error" in b for b in out["batches"]),
                        "the parse failure should be recorded on the batch")


if __name__ == "__main__":
    unittest.main()
