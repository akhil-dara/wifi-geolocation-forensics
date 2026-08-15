"""
Artefact ingestion.

The input here is whatever an investigator managed to extract from a subject
machine, so it is messy by nature: registry exports, event XML, SIEM CSV,
pasted console output. Two failure modes matter more than the rest, and both
have bitten this code:

  * parsing something that is not an address (a GUID cut into six pairs), which
    invents an access point that never existed;
  * geolocating the host's own adapter, which places the investigator rather
    than the subject.
"""

import unittest

from wifigeo import ingest


class ManualEntry(unittest.TestCase):

    def test_accepts_the_notations_an_investigator_will_paste(self):
        text = "\n".join(["00:00:5e:00:53:a6",
                          "00-00-5E-00-53-A7",
                          "0000.5e00.53a8",
                          "00005e0053a9"])
        got = {o.bssid for o in ingest.parse_manual(text)}
        self.assertEqual(got, {"00:00:5e:00:53:a6", "00:00:5e:00:53:a7",
                               "00:00:5e:00:53:a8", "00:00:5e:00:53:a9"})

    def test_accepts_a_label_after_the_address(self):
        obs = ingest.parse_manual("00:00:5e:00:53:a6  Reception 2.4GHz")
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].bssid, "00:00:5e:00:53:a6")

    def test_ignores_blank_lines_and_comments(self):
        obs = ingest.parse_manual("\n# a comment\n\n00:00:5e:00:53:a6\n\n")
        self.assertEqual(len(obs), 1)

    def test_returns_nothing_for_input_with_no_addresses(self):
        self.assertEqual(ingest.parse_manual("not a mac at all\nhello"), [])

    def test_deduplicates(self):
        obs = ingest.parse_manual("00:00:5e:00:53:a6\n00-00-5e-00-53-a6")
        self.assertEqual(len(obs), 1)


class GUIDsAreNotAddresses(unittest.TestCase):
    """
    A GUID is 32 hex digits with hyphens. Split naively it yields perfectly
    plausible six-octet addresses that were never on any network.

    Registry exports and event logs are full of GUIDs - interface identifiers,
    profile identifiers, provider identifiers - so this is not a hypothetical.
    """

    GUIDS = [
        "{11111111-2222-3333-4444-555555555555}",
        "11111111-2222-3333-4444-555555555555",
        "{6E1D1B5C-1234-4321-ABCD-0123456789AB}",
    ]

    def test_a_bare_guid_yields_no_addresses(self):
        for guid in self.GUIDS:
            with self.subTest(guid=guid):
                self.assertEqual(ingest.parse_manual(guid), [],
                                 "%s was parsed as an address" % guid)

    def test_a_guid_beside_a_real_address_yields_only_the_address(self):
        text = ("InterfaceGuid={11111111-2222-3333-4444-555555555555}\n"
                "BSSID=00:00:5e:00:53:a6\n")
        got = [o.bssid for o in ingest.parse_manual(text)]
        self.assertEqual(got, ["00:00:5e:00:53:a6"])

    def test_a_guid_inside_a_longer_line(self):
        text = "profile {6E1D1B5C-1234-4321-ABCD-0123456789AB} loaded"
        self.assertEqual(ingest.parse_manual(text), [])


class HostAdapterExclusion(unittest.TestCase):
    """The subject's access point is evidence; the host's own radio is not."""

    def test_local_mac_columns_are_not_treated_as_access_points(self):
        # The distinction is by column name: PeerMac/BSSID/APMac describe the
        # access point, LocalMac describes this machine's own adapter. A SIEM
        # export routinely carries both on the same row.
        csv_text = ("LocalMac,PeerMac,SSID\n"
                    "00:00:5e:00:53:ea,00:00:5e:00:53:a6,Reception-WiFi\n")
        macs = {o.bssid for o in ingest.parse_table(csv_text)}
        self.assertIn("00:00:5e:00:53:a6", macs)
        self.assertNotIn("00:00:5e:00:53:ea", macs)


class Netsh(unittest.TestCase):

    SAMPLE = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : Reception-WiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    BSSID 1                 : 00:00:5e:00:53:a6
         Signal             : 82%
         Radio type         : 802.11ac
         Channel            : 36
    BSSID 2                 : 00:00:5e:00:53:a7
         Signal             : 61%
         Channel            : 6

SSID 2 :
    BSSID 1                 : 00:1a:2b:00:00:01
         Signal             : 30%
"""

    def test_extracts_every_bssid(self):
        obs = ingest.parse_netsh(self.SAMPLE)
        macs = {o.bssid for o in obs}
        self.assertEqual(macs, {"00:00:5e:00:53:a6", "00:00:5e:00:53:a7",
                                "00:1a:2b:00:00:01"})

    def test_associates_the_network_name(self):
        obs = {o.bssid: o for o in ingest.parse_netsh(self.SAMPLE)}
        self.assertEqual(obs["00:00:5e:00:53:a6"].ssid, "Reception-WiFi")

    def test_a_hidden_network_is_not_given_a_name(self):
        obs = {o.bssid: o for o in ingest.parse_netsh(self.SAMPLE)}
        self.assertFalse(obs["00:1a:2b:00:00:01"].ssid)


class FormatSniffing(unittest.TestCase):

    def test_recognises_netsh_output(self):
        self.assertTrue(ingest.sniff_any(Netsh.SAMPLE))

    def test_recognises_a_plain_address_list(self):
        self.assertTrue(ingest.sniff_any("00:00:5e:00:53:a6"))

    def test_finds_nothing_in_unrelated_text(self):
        self.assertFalse(ingest.sniff_any("the quick brown fox"))


if __name__ == "__main__":
    unittest.main()
