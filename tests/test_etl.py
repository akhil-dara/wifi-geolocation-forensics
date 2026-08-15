"""Recovery of BSSIDs from a Windows wireless trace.

Fixtures are built here rather than shipped, so no real address appears in
the repository.  Addresses come from the RFC 7042 documentation range.
"""

import os
import struct
import tempfile
import unittest

from wifigeo.etl import (EtlBeacon, looks_like_etl, parse_etl, parse_rendered)


def _record(mac: str, ssid: str, state: bytes = b"EXISTING\x00") -> bytes:
    raw = bytes(int(x, 16) for x in mac.split(":"))
    body = ssid.encode()
    return state + raw + struct.pack("<H", len(body)) + body


def _container(payload: bytes) -> bytes:
    """A buffer whose header declares a size ETL readers recognise."""
    head = struct.pack("<III", 0x10000, 0x240, 0x240) + b"\0" * 52
    return head + payload + b"\0" * 64


class LooksLikeEtl(unittest.TestCase):
    def test_recognises_a_known_buffer_size(self):
        self.assertTrue(looks_like_etl(_container(b"")))

    def test_rejects_something_else(self):
        self.assertFalse(looks_like_etl(b"PK\x03\x04" + b"\0" * 200))

    def test_rejects_a_runt(self):
        self.assertFalse(looks_like_etl(b"\x00\x00\x01\x00"))


class ParseEtl(unittest.TestCase):
    def _parse(self, payload, **kw):
        fd, path = tempfile.mkstemp(suffix=".etl")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(_container(payload))
            return parse_etl(path, **kw)
        finally:
            os.unlink(path)

    def test_recovers_an_anchored_scan_record(self):
        res = self._parse(_record("00:00:5e:00:53:a6", "Reception"))
        self.assertEqual([b.bssid for b in res.beacons], ["00:00:5e:00:53:a6"])
        self.assertEqual(res.beacons[0].ssid, "Reception")

    def test_accepts_the_new_state_tag_as_well(self):
        res = self._parse(_record("00:00:5e:00:53:a7", "Guest", state=b"NEW\x00"))
        self.assertEqual([b.bssid for b in res.beacons], ["00:00:5e:00:53:a7"])

    def test_ignores_a_record_with_no_state_tag(self):
        raw = bytes(int(x, 16) for x in "00:00:5e:00:53:a8".split(":"))
        payload = b"\xff\xff\xff\xff" + raw + struct.pack("<H", 4) + b"Nope"
        self.assertEqual(self._parse(payload).beacons, [])

    def test_deep_mode_reports_the_unanchored_record(self):
        raw = bytes(int(x, 16) for x in "00:00:5e:00:53:a8".split(":"))
        payload = b"\xff\xff\xff\xff" + raw + struct.pack("<H", 4) + b"Nope"
        res = self._parse(payload, deep=True)
        self.assertEqual([b.bssid for b in res.beacons], ["00:00:5e:00:53:a8"])
        # ...but never as something worth putting in a report.
        self.assertEqual(res.confident(), [])

    def test_excludes_a_mac_the_caller_names_as_the_host(self):
        res = self._parse(_record("00:00:5e:00:53:a9", "Office"),
                          host_macs=["00:00:5E:00:53:A9"])
        self.assertEqual(res.beacons, [])
        self.assertIn("00:00:5e:00:53:a9", res.host_macs)

    def test_excludes_a_mac_printed_after_an_adapter_description(self):
        payload = ("Intel(R) Wi-Fi 6 AX201 160MHz\x00"
                   "00:00:5E:00:53:AA\x00").encode("utf-16-le")
        res = self._parse(payload)
        self.assertEqual(res.beacons, [])
        self.assertIn("00:00:5e:00:53:aa", res.host_macs)

    def test_keeps_an_adjacent_ap_that_also_appears_in_a_scan_record(self):
        # The host radio never scans itself; an address in a scan record is an
        # access point even when a vendor string happens to sit near it.
        payload = (("Intel(R) Wi-Fi 6 AX201 160MHz\x00"
                    "00:00:5E:00:53:AB\x00").encode("utf-16-le")
                   + _record("00:00:5e:00:53:ab", "Lobby"))
        res = self._parse(payload)
        self.assertEqual([b.bssid for b in res.beacons], ["00:00:5e:00:53:ab"])
        self.assertEqual(res.host_macs, set())

    def test_rejects_broadcast_and_multicast(self):
        payload = b"".join(_record(m, "X") for m in
                           ("ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb",
                            "33:33:00:00:00:01", "00:00:00:00:00:00"))
        self.assertEqual(self._parse(payload).beacons, [])

    def test_counts_repeat_sightings_and_records_offsets(self):
        rec = _record("00:00:5e:00:53:ac", "Repeat")
        res = self._parse(rec + b"\x00" * 8 + rec)
        self.assertEqual(len(res.beacons), 1)
        self.assertEqual(res.beacons[0].occurrences, 2)
        self.assertEqual(len(res.beacons[0].offsets), 2)

    def test_warns_when_the_container_is_not_a_trace(self):
        fd, path = tempfile.mkstemp(suffix=".etl")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(b"not a trace" + _record("00:00:5e:00:53:ad", "Odd"))
            res = parse_etl(path)
        finally:
            os.unlink(path)
        self.assertTrue(res.warnings)
        self.assertEqual([b.bssid for b in res.beacons], ["00:00:5e:00:53:ad"])


class Beacon(unittest.TestCase):
    def test_locally_administered_bit(self):
        self.assertFalse(EtlBeacon("00:00:5e:00:53:a6").locally_administered)
        self.assertTrue(EtlBeacon("02:00:5e:00:53:a6").locally_administered)

    def test_band_from_frequency(self):
        self.assertEqual(EtlBeacon("00:00:5e:00:53:a6", freq_mhz=2437).band, "2.4 GHz")
        self.assertEqual(EtlBeacon("00:00:5e:00:53:a6", freq_mhz=5240).band, "5 GHz")
        self.assertEqual(EtlBeacon("00:00:5e:00:53:a6", freq_mhz=5975).band, "6 GHz")
        self.assertIsNone(EtlBeacon("00:00:5e:00:53:a6").band)


class ParseRendered(unittest.TestCase):
    def test_reads_a_converted_scan_row(self):
        row = "Reception\t526563\t00:00:5E:00:53:A6\t5240\t65\t-67\t7\t4\t509\n"
        got = parse_rendered(row)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].bssid, "00:00:5e:00:53:a6")
        self.assertEqual(got[0].rssi_dbm, -67)
        self.assertEqual(got[0].freq_mhz, 5240)
        self.assertEqual(got[0].band, "5 GHz")
        self.assertEqual(got[0].ssid, "Reception")

    def test_rejects_a_row_whose_frequency_is_not_a_channel(self):
        row = "X\tAA\t00:00:5E:00:53:A6\t1234\t65\t-67\n"
        self.assertEqual(parse_rendered(row), [])

    def test_rejects_an_impossible_signal_level(self):
        row = "X\tAA\t00:00:5E:00:53:A6\t2437\t65\t-250\n"
        self.assertEqual(parse_rendered(row), [])

    def test_keeps_the_strongest_sighting(self):
        rows = ("A\tAA\t00:00:5E:00:53:A6\t2437\t20\t-88\n"
                "A\tAA\t00:00:5E:00:53:A6\t5240\t80\t-51\n")
        got = parse_rendered(rows)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].rssi_dbm, -51)
        self.assertEqual(got[0].freq_mhz, 5240)
        self.assertEqual(got[0].occurrences, 2)

    def test_sorts_strongest_first(self):
        rows = ("A\tAA\t00:00:5E:00:53:A6\t2437\t20\t-88\n"
                "B\tBB\t00:00:5E:00:53:A7\t2437\t80\t-42\n")
        self.assertEqual([b.bssid for b in parse_rendered(rows)],
                         ["00:00:5e:00:53:a7", "00:00:5e:00:53:a6"])


if __name__ == "__main__":
    unittest.main()
