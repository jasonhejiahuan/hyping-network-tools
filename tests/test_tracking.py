import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hyping.auto_wifi_scan import WiFiScanTarget
from hyping.discovery.bettercap import BettercapClient
from hyping.storage import load_device_records, save_device_records
from hyping.tracking import (
    match_tracking_record,
    track_device_across_wifi,
    tracking_identity,
)


class TrackingTests(unittest.TestCase):
    def test_identity_matches_historical_mac_and_exact_hostname(self) -> None:
        identity = tracking_identity(
            {
                "hostname": "Laptop.local",
                "mac": "aa:bb:cc:dd:ee:01",
                "mac_addresses": ["aa:bb:cc:dd:ee:02"],
            }
        )

        self.assertEqual(
            match_tracking_record(identity, {"mac": "AA-BB-CC-DD-EE-02"}),
            "mac",
        )
        self.assertEqual(
            match_tracking_record(identity, {"hostname": "laptop.local."}),
            "hostname",
        )
        self.assertIsNone(
            match_tracking_record(identity, {"hostname": "other-laptop.local"})
        )

    def test_bettercap_tracking_rotates_then_locks_known_mac(self) -> None:
        selected = {
            "hostname": "laptop.local",
            "note": "测试电脑",
            "mac": "aa:bb:cc:dd:ee:01",
            "mac_addresses": ["aa:bb:cc:dd:ee:99"],
        }
        client = BettercapClient()
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "devices.json"
            save_device_records([selected], store)
            with (
                patch("hyping.tracking.is_elevated", return_value=True),
                patch("hyping.tracking.wifi_interface", return_value="en0"),
                patch(
                    "hyping.tracking.current_wifi_ssid",
                    side_effect=["Home", "Home", "Home"],
                ),
                patch("hyping.tracking._ensure_bettercap_ready"),
                patch("hyping.tracking.shutdown_bettercap") as shutdown,
                patch("hyping.tracking.start_bettercap_api") as start,
                patch("hyping.tracking.switch_wifi_network") as switch,
                patch(
                    "hyping.tracking._records_from_bettercap",
                    side_effect=[
                        [{"ip": "192.168.1.3", "mac": "00:00:00:00:00:03"}],
                        [{"ip": "10.0.0.8", "mac": "aa:bb:cc:dd:ee:99"}],
                    ],
                ),
            ):
                result = track_device_across_wifi(
                    selected,
                    [WiFiScanTarget("Home"), WiFiScanTarget("Lab", "secret")],
                    client=client,
                    max_rounds=1,
                    store_path=store,
                )

            saved = load_device_records(store)

        self.assertTrue(result.locked)
        self.assertEqual(result.ssid, "Lab")
        self.assertEqual(result.match_method, "mac")
        self.assertEqual(result.rounds, 1)
        switch.assert_called_once_with(
            "Lab",
            password="secret",
            interface="en0",
            verify=True,
            verify_timeout=12.0,
        )
        start.assert_called_once()
        self.assertGreaterEqual(shutdown.call_count, 2)
        target = next(record for record in saved if record.get("tracking"))
        self.assertTrue(target["tracking"]["locked"])
        self.assertEqual(target["tracking"]["ssid"], "Lab")

    def test_exact_hostname_learns_new_mac(self) -> None:
        selected = {
            "hostname": "laptop.local",
            "mac": "aa:bb:cc:dd:ee:01",
        }
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "devices.json"
            save_device_records([selected], store)
            with (
                patch("hyping.tracking.is_elevated", return_value=True),
                patch("hyping.tracking.wifi_interface", return_value="en0"),
                patch(
                    "hyping.tracking.current_wifi_ssid", side_effect=["Home", "Home"]
                ),
                patch("hyping.tracking._ensure_bettercap_ready"),
                patch("hyping.tracking.shutdown_bettercap"),
                patch(
                    "hyping.tracking._records_from_bettercap",
                    return_value=[
                        {
                            "hostname": "laptop.local.",
                            "ip": "192.168.1.9",
                            "mac": "aa:bb:cc:dd:ee:77",
                        }
                    ],
                ),
            ):
                result = track_device_across_wifi(
                    selected,
                    [WiFiScanTarget("Home")],
                    client=BettercapClient(),
                    max_rounds=1,
                    store_path=store,
                )

        self.assertEqual(result.match_method, "hostname")
        self.assertEqual(
            result.target.mac_addresses,
            ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:77"),
        )

    def test_unique_fingerprint_learns_random_mac_and_records_evidence(self) -> None:
        selected = {
            "hostname": "old-name.local",
            "mac": "aa:bb:cc:dd:ee:01",
            "vendor": "Acme",
            "fingerprint": {
                "values": {"mdns:model": "X1", "mdns:type": "_demo._tcp"}
            },
        }
        candidate = {
            "hostname": "random-name.local",
            "ip": "192.168.1.9",
            "mac": "02:00:00:00:00:77",
            "vendor": "Acme",
            "bettercap_meta": {
                "values": {"mdns:model": "X1", "mdns:type": "_demo._tcp"}
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "devices.json"
            save_device_records([selected], store)
            with (
                patch("hyping.tracking.is_elevated", return_value=True),
                patch("hyping.tracking.wifi_interface", return_value="en0"),
                patch(
                    "hyping.tracking.current_wifi_ssid", side_effect=["Home", "Home"]
                ),
                patch("hyping.tracking._ensure_bettercap_ready"),
                patch("hyping.tracking.shutdown_bettercap"),
                patch(
                    "hyping.tracking._records_from_bettercap",
                    return_value=[candidate],
                ),
            ):
                result = track_device_across_wifi(
                    selected,
                    [WiFiScanTarget("Home")],
                    client=BettercapClient(),
                    max_rounds=1,
                    store_path=store,
                )
            saved = load_device_records(store)

        self.assertTrue(result.locked)
        self.assertEqual(result.match_method, "fingerprint")
        self.assertGreaterEqual(result.association_score or 0, 70)
        self.assertEqual(len(saved), 1)
        self.assertEqual(
            set(result.target.mac_addresses),
            {"aa:bb:cc:dd:ee:01", "02:00:00:00:00:77"},
        )
        self.assertEqual(
            saved[0]["tracking"]["association_evidence"],
            list(result.association_evidence),
        )

    def test_builtin_tracking_uses_same_locking_path(self) -> None:
        selected = {"note": "传感器", "mac": "aa:bb:cc:dd:ee:08"}
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "devices.json"
            save_device_records([selected], store)
            with (
                patch("hyping.tracking.is_elevated", return_value=True),
                patch("hyping.tracking.wifi_interface", return_value="en0"),
                patch("hyping.tracking.current_wifi_ssid", side_effect=["Lab", "Lab"]),
                patch(
                    "hyping.tracking._records_from_builtin",
                    return_value=[
                        {
                            "ip": "10.0.0.8",
                            "mac": "aa:bb:cc:dd:ee:08",
                            "hostname": None,
                        }
                    ],
                ),
            ):
                result = track_device_across_wifi(
                    selected,
                    [WiFiScanTarget("Lab")],
                    scanner="builtin",
                    max_rounds=1,
                    store_path=store,
                )

        self.assertTrue(result.locked)
        self.assertEqual(result.scanner, "builtin")
        self.assertEqual(result.match_method, "mac")

    def test_failed_round_restores_original_wifi(self) -> None:
        selected = {"hostname": "missing.local", "mac": "aa:bb:cc:dd:ee:08"}
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "devices.json"
            save_device_records([selected], store)
            with patch("hyping.tracking.is_elevated", return_value=True), patch(
                "hyping.tracking.wifi_interface", return_value="en0"
            ), patch(
                "hyping.tracking.current_wifi_ssid",
                side_effect=["Home", "Home", "Home", "Lab"],
            ), patch(
                "hyping.tracking._ensure_bettercap_ready"
            ), patch(
                "hyping.tracking.shutdown_bettercap"
            ), patch(
                "hyping.tracking.start_bettercap_api"
            ), patch(
                "hyping.tracking._records_from_bettercap", return_value=[]
            ), patch(
                "hyping.tracking.switch_wifi_network"
            ) as switch:
                result = track_device_across_wifi(
                    selected,
                    [WiFiScanTarget("Home", "home-pass"), WiFiScanTarget("Lab")],
                    client=BettercapClient(),
                    max_rounds=1,
                    store_path=store,
                )

        self.assertFalse(result.locked)
        self.assertEqual(
            [call.args[0] for call in switch.call_args_list],
            ["Lab", "Home"],
        )


if __name__ == "__main__":
    unittest.main()
