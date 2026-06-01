import unittest
from unittest.mock import patch

from hyping.discovery.wifi import (
    WiFiError,
    WiFiNetwork,
    _parse_preferred_wifi_output,
    _parse_system_profiler_wifi_networks,
    list_available_saved_wifi_networks,
    switch_wifi_network,
)


class WiFiTests(unittest.TestCase):
    def test_parse_preferred_wifi_output(self) -> None:
        output = """
Preferred networks on en0:
    SCBS-Student
    SCBS-Guest
"""
        self.assertEqual(
            _parse_preferred_wifi_output(output),
            ["SCBS-Student", "SCBS-Guest"],
        )

    def test_parse_system_profiler_networks(self) -> None:
        output = """
Wi-Fi:

      Interfaces:
        en0:
          Current Network Information:
            SCBS-Student:
              PHY Mode: 802.11ac
              Channel: 44 (5GHz, 20MHz)
              Security: WPA2 Personal
              Signal / Noise: -50 dBm / -99 dBm
          Other Local Wi-Fi Networks:
            SCBS-Guest:
              PHY Mode: 802.11a/n/ac
              Channel: 44 (5GHz, 20MHz)
              Security: WPA2 Personal
            SCBS-Guest:
              PHY Mode: 802.11b/g/n/ac
              Channel: 1 (2GHz, 20MHz)
              Security: WPA2 Personal
"""
        networks = _parse_system_profiler_wifi_networks(output)

        self.assertEqual([network.ssid for network in networks], [
            "SCBS-Student",
            "SCBS-Guest",
            "SCBS-Guest",
        ])
        self.assertTrue(networks[0].current)
        self.assertEqual(networks[1].channel, "44 (5GHz, 20MHz)")
        self.assertEqual(networks[2].security, "WPA2 Personal")

    def test_available_saved_wifi_preserves_saved_order(self) -> None:
        with patch(
            "hyping.discovery.wifi.list_saved_wifi_networks",
            return_value=["SCBS-Student", "SCBS-Staff", "SCBS-Guest"],
        ), patch(
            "hyping.discovery.wifi.list_nearby_wifi_networks",
            return_value=[
                WiFiNetwork("SCBS-Guest"),
                WiFiNetwork("SCBS-Student", current=True),
            ],
        ):
            self.assertEqual(
                list_available_saved_wifi_networks("en0"),
                ["SCBS-Student", "SCBS-Guest"],
            )

    def test_switch_wifi_detects_successful_verified_join(self) -> None:
        with patch("hyping.discovery.wifi.wifi_interface", return_value="en0"), patch(
            "hyping.discovery.wifi._run",
            return_value="",
        ) as run, patch(
            "hyping.discovery.wifi.current_wifi_ssid",
            return_value="SCBS-Guest",
        ), patch("hyping.discovery.wifi.time.sleep", lambda _: None):
            self.assertEqual(
                switch_wifi_network("SCBS-Guest", password="Guest2017"),
                "SCBS-Guest",
            )

        run.assert_called_once_with(
            [
                "networksetup",
                "-setairportnetwork",
                "en0",
                "SCBS-Guest",
                "Guest2017",
            ],
            timeout=45.0,
        )

    def test_switch_wifi_treats_failed_output_as_error(self) -> None:
        with patch("hyping.discovery.wifi.wifi_interface", return_value="en0"), patch(
            "hyping.discovery.wifi._run",
            return_value="Failed to join network SCBS-Guest.",
        ):
            with self.assertRaises(WiFiError):
                switch_wifi_network("SCBS-Guest", verify=False)


if __name__ == "__main__":
    unittest.main()
