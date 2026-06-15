import json
import tempfile
import unittest
from ipaddress import IPv4Address
from pathlib import Path
from unittest.mock import patch

from hyping.auto_wifi_scan import (
    DEFAULT_WIFI_ROTATION_PATH,
    AutoWiFiScanError,
    WiFiScanTarget,
    expand_wifi_rotation_path,
    find_hostname_with_bettercap_then_wifi_rotation,
    load_wifi_scan_targets,
    run_auto_wifi_scan,
    shutdown_bettercap,
    write_wifi_scan_template,
)
from hyping.discovery.bettercap import BettercapAPIError, BettercapClient, BettercapHost
from hyping.discovery.wifi import WiFiError
from hyping.storage import load_device_records


class AutoWiFiScanTests(unittest.TestCase):
    def test_load_wifi_scan_targets_from_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wifi.json"
            path.write_text(
                json.dumps(
                    {
                        "networks": [
                            {"ssid": "Office-WiFi"},
                            {"ssid": "Lab-WiFi", "password": "secret"},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            targets = load_wifi_scan_targets(path)

        self.assertEqual(
            targets,
            [
                WiFiScanTarget("Office-WiFi"),
                WiFiScanTarget("Lab-WiFi", "secret"),
            ],
        )

    def test_load_wifi_scan_targets_from_csv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wifi.csv"
            path.write_text(
                "ssid,password\nOffice-WiFi,\nLab-WiFi,secret\n",
                encoding="utf-8",
            )

            targets = load_wifi_scan_targets(path)

        self.assertEqual(
            targets,
            [
                WiFiScanTarget("Office-WiFi"),
                WiFiScanTarget("Lab-WiFi", "secret"),
            ],
        )

    def test_expand_wifi_rotation_path_maps_legacy_default(self) -> None:
        self.assertEqual(
            expand_wifi_rotation_path("~/.hyping/wifi-rotation.json"),
            DEFAULT_WIFI_ROTATION_PATH,
        )

    def test_load_wifi_scan_targets_rejects_empty_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wifi.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaises(AutoWiFiScanError):
                load_wifi_scan_targets(path)

    def test_write_wifi_scan_template_does_not_overwrite_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wifi.json"
            path.write_text("[]\n", encoding="utf-8")

            write_wifi_scan_template(path)

            self.assertEqual(path.read_text(encoding="utf-8"), "[]\n")

    def test_run_auto_wifi_scan_switches_restarts_scans_and_saves(self) -> None:
        host = BettercapHost(
            ip=IPv4Address("192.168.10.20"),
            mac="aa:bb:cc:dd:ee:20",
            hostname="printer.local",
            vendor="Printer Inc.",
        )
        client = BettercapClient()
        statuses: list[str] = []

        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "devices.json"
            with patch("hyping.auto_wifi_scan.is_elevated", return_value=True), patch(
                "hyping.auto_wifi_scan.wifi_interface",
                return_value="en0",
            ), patch(
                "hyping.auto_wifi_scan.current_wifi_ssid",
                side_effect=["Original-WiFi", "Lab-WiFi"],
            ), patch(
                "hyping.auto_wifi_scan.shutdown_bettercap",
            ) as shutdown, patch(
                "hyping.auto_wifi_scan.switch_wifi_network",
            ) as switch, patch(
                "hyping.auto_wifi_scan.start_bettercap_api",
            ) as start, patch(
                "hyping.auto_wifi_scan.list_bettercap_hosts",
                return_value=[host],
            ) as scan:
                results = run_auto_wifi_scan(
                    [
                        WiFiScanTarget("Original-WiFi", "original-secret"),
                        WiFiScanTarget("Lab-WiFi", "secret"),
                    ],
                    client=client,
                    bettercap_command="bettercap",
                    store_path=store_path,
                    on_status=statuses.append,
                )

            records = load_device_records(store_path)

        self.assertEqual(len(results), 2)
        self.assertEqual([result.ssid for result in results], [
            "Original-WiFi",
            "Lab-WiFi",
        ])
        self.assertEqual(records[0]["hostname"], "printer.local")
        self.assertEqual(records[0]["ssid"], "Lab-WiFi")
        switch.assert_any_call(
            "Lab-WiFi",
            password="secret",
            interface="en0",
            verify=True,
            verify_timeout=12.0,
        )
        switch.assert_any_call(
            "Original-WiFi",
            password="original-secret",
            interface="en0",
            verify=True,
            verify_timeout=12.0,
        )
        self.assertEqual(start.call_count, 2)
        self.assertEqual(scan.call_count, 2)
        self.assertEqual(shutdown.call_count, 3)
        self.assertIn("准备扫描 Wi-Fi：Lab-WiFi", statuses)

    def test_run_auto_wifi_scan_records_errors_and_continues(self) -> None:
        client = BettercapClient()
        host = BettercapHost(
            ip=IPv4Address("192.168.10.21"),
            mac="aa:bb:cc:dd:ee:21",
        )

        def switch(ssid: str, **kwargs) -> str:
            if ssid == "Bad-WiFi":
                raise WiFiError("join failed")
            return ssid

        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "devices.json"
            with patch("hyping.auto_wifi_scan.is_elevated", return_value=True), patch(
                "hyping.auto_wifi_scan.wifi_interface",
                return_value="en0",
            ), patch(
                "hyping.auto_wifi_scan.current_wifi_ssid",
                side_effect=["Original-WiFi", "Good-WiFi"],
            ), patch(
                "hyping.auto_wifi_scan.shutdown_bettercap",
            ), patch(
                "hyping.auto_wifi_scan.switch_wifi_network",
                side_effect=switch,
            ), patch(
                "hyping.auto_wifi_scan.start_bettercap_api",
            ), patch(
                "hyping.auto_wifi_scan.list_bettercap_hosts",
                return_value=[host],
            ):
                results = run_auto_wifi_scan(
                    [WiFiScanTarget("Bad-WiFi"), WiFiScanTarget("Good-WiFi")],
                    client=client,
                    store_path=store_path,
                )

        self.assertEqual([result.ssid for result in results], [
            "Bad-WiFi",
            "Good-WiFi",
        ])
        self.assertEqual(results[0].hosts, ())
        self.assertEqual(results[0].error, "join failed")
        self.assertEqual(len(results[1].hosts), 1)

    def test_find_hostname_uses_current_bettercap_before_rotation(self) -> None:
        target = BettercapHost(
            ip=IPv4Address("192.168.10.30"),
            mac="aa:bb:cc:dd:ee:30",
            hostname="printer.local",
        )

        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "devices.json"
            with patch(
                "hyping.auto_wifi_scan.list_bettercap_hosts",
                return_value=[target],
            ), patch(
                "hyping.auto_wifi_scan.ensure_bettercap_api_online",
                return_value=None,
            ) as ensure_api, patch(
                "hyping.auto_wifi_scan.current_wifi_ssid",
                return_value="Office-WiFi",
            ), patch(
                "hyping.auto_wifi_scan.switch_wifi_network",
            ) as switch, patch(
                "hyping.auto_wifi_scan.start_bettercap_api",
            ) as start:
                result = find_hostname_with_bettercap_then_wifi_rotation(
                    "printer.local",
                    [WiFiScanTarget("Lab-WiFi", "secret")],
                    client=BettercapClient(),
                    store_path=store_path,
                )
            records = load_device_records(store_path)

        self.assertEqual(result.host, target)
        self.assertEqual(result.ssid, "Office-WiFi")
        self.assertEqual(result.scanned_ssids, ())
        self.assertEqual(records[0]["ssid"], "Office-WiFi")
        ensure_api.assert_called_once()
        switch.assert_not_called()
        start.assert_not_called()

    def test_find_hostname_rotates_wifi_after_current_miss(self) -> None:
        other = BettercapHost(
            ip=IPv4Address("192.168.10.31"),
            mac="aa:bb:cc:dd:ee:31",
            hostname="other.local",
        )
        target = BettercapHost(
            ip=IPv4Address("192.168.10.32"),
            mac="aa:bb:cc:dd:ee:32",
            hostname="printer.local",
        )

        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "devices.json"
            with patch("hyping.auto_wifi_scan.is_elevated", return_value=True), patch(
                "hyping.auto_wifi_scan.wifi_interface",
                return_value="en0",
            ), patch(
                "hyping.auto_wifi_scan.current_wifi_ssid",
                side_effect=["Original-WiFi", "Lab-WiFi"],
            ), patch(
                "hyping.auto_wifi_scan.shutdown_bettercap",
            ), patch(
                "hyping.auto_wifi_scan.switch_wifi_network",
            ) as switch, patch(
                "hyping.auto_wifi_scan.start_bettercap_api",
            ), patch(
                "hyping.auto_wifi_scan.ensure_bettercap_api_online",
                return_value=None,
            ), patch(
                "hyping.auto_wifi_scan.list_bettercap_hosts",
                side_effect=[[other], [other], [target]],
            ):
                result = find_hostname_with_bettercap_then_wifi_rotation(
                    "printer",
                    [
                        WiFiScanTarget("Original-WiFi", "original-secret"),
                        WiFiScanTarget("Lab-WiFi", "secret"),
                    ],
                    client=BettercapClient(),
                    partial_hostname=True,
                    store_path=store_path,
                )

        self.assertEqual(result.host, target)
        self.assertEqual(result.ssid, "Lab-WiFi")
        self.assertEqual(result.scanned_ssids, ("Original-WiFi", "Lab-WiFi"))
        switch.assert_any_call(
            "Lab-WiFi",
            password="secret",
            interface="en0",
            verify=True,
            verify_timeout=12.0,
        )
        switch.assert_any_call(
            "Original-WiFi",
            password="original-secret",
            interface="en0",
            verify=True,
            verify_timeout=12.0,
        )

    def test_run_auto_wifi_scan_requires_sudo(self) -> None:
        with patch("hyping.auto_wifi_scan.is_elevated", return_value=False):
            with self.assertRaises(AutoWiFiScanError):
                run_auto_wifi_scan(
                    [WiFiScanTarget("Lab-WiFi")],
                    client=BettercapClient(),
                )

    def test_shutdown_bettercap_can_require_confirmed_stop(self) -> None:
        class Client:
            def is_online(self, *, timeout: float | None = None) -> bool:
                return True

            def shutdown(self) -> None:
                return None

        with patch("hyping.auto_wifi_scan.time.monotonic", side_effect=[0.0, 6.0]):
            with self.assertRaises(BettercapAPIError):
                shutdown_bettercap(Client(), require_stopped=True)


if __name__ == "__main__":
    unittest.main()
