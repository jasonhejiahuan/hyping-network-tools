import unittest

from hyping.fingerprint import (
    attach_device_fingerprint,
    compare_device_fingerprints,
    device_fingerprint,
    unique_fingerprint_candidate,
)


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_excludes_address_and_time_fields(self) -> None:
        fingerprint = device_fingerprint(
            {
                "ip": "192.168.1.20",
                "mac": "aa:bb:cc:dd:ee:01",
                "last_seen": "now",
                "vendor": "Apple, Inc.",
                "bettercap_meta": {
                    "values": {
                        "mdns:model": "MacBookAir",
                        "ipv4": "192.168.1.20",
                    }
                },
            }
        )

        self.assertEqual(fingerprint["vendor"], "apple, inc.")
        self.assertEqual(
            fingerprint["values"], {"mdns:model": "macbookair"}
        )
        self.assertNotIn("ip", fingerprint)
        self.assertNotIn("mac", fingerprint)

    def test_changed_mac_can_have_high_explainable_score(self) -> None:
        target = attach_device_fingerprint(
            {
                "mac": "aa:bb:cc:dd:ee:01",
                "vendor": "Apple, Inc.",
                "bettercap_meta": {
                    "values": {
                        "mdns:model": "MacBookAir",
                        "mdns:type": "_airplay._tcp",
                    }
                },
            }
        )
        candidate = {
            "mac": "02:00:00:00:00:99",
            "vendor": "Apple, Inc.",
            "bettercap_meta": {
                "values": {
                    "mdns:model": "MacBookAir",
                    "mdns:type": "_airplay._tcp",
                }
            },
        }

        match = compare_device_fingerprints(target, candidate)

        self.assertGreaterEqual(match.score, 70)
        self.assertIn("MAC 不同，可能启用了随机地址", match.evidence)
        self.assertTrue(any("型号" in item for item in match.evidence))

    def test_vendor_alone_is_not_enough(self) -> None:
        match = compare_device_fingerprints(
            {"vendor": "Apple, Inc."},
            {"vendor": "Apple, Inc."},
        )

        self.assertEqual(match.score, 15)

    def test_equal_high_scoring_candidates_are_ambiguous(self) -> None:
        target = {
            "vendor": "Acme",
            "fingerprint": {
                "values": {"mdns:model": "X1", "mdns:type": "_demo._tcp"}
            },
        }
        candidates = [
            {
                "mac": mac,
                "vendor": "Acme",
                "bettercap_meta": {
                    "values": {"mdns:model": "X1", "mdns:type": "_demo._tcp"}
                },
            }
            for mac in ("02:00:00:00:00:01", "02:00:00:00:00:02")
        ]

        self.assertIsNone(unique_fingerprint_candidate(target, candidates))


if __name__ == "__main__":
    unittest.main()
