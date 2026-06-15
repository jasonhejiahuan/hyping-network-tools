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
    Example-Student
    Example-Guest
"""
        self.assertEqual(
            _parse_preferred_wifi_output(output),
            ["Example-Student", "Example-Guest"],
        )

    def test_parse_system_profiler_networks(self) -> None:
        output = """
Wi-Fi:

      Interfaces:
        en0:
          Current Network Information:
            Example-Student:
              PHY Mode: 802.11ac
              Channel: 44 (5GHz, 20MHz)
              Security: WPA2 Personal
              Signal / Noise: -50 dBm / -99 dBm
          Other Local Wi-Fi Networks:
            Example-Guest:
              PHY Mode: 802.11a/n/ac
              Channel: 44 (5GHz, 20MHz)
              Security: WPA2 Personal
            Example-Guest:
              PHY Mode: 802.11b/g/n/ac
              Channel: 1 (2GHz, 20MHz)
              Security: WPA2 Personal
"""
        networks = _parse_system_profiler_wifi_networks(output)

        self.assertEqual([network.ssid for network in networks], [
            "Example-Student",
            "Example-Guest",
            "Example-Guest",
        ])
        self.assertTrue(networks[0].current)
        self.assertEqual(networks[1].channel, "44 (5GHz, 20MHz)")
        self.assertEqual(networks[2].security, "WPA2 Personal")

    def test_available_saved_wifi_preserves_saved_order(self) -> None:
        with patch(
            "hyping.discovery.wifi.list_saved_wifi_networks",
            return_value=["Example-Student", "Example-Staff", "Example-Guest"],
        ), patch(
            "hyping.discovery.wifi.list_nearby_wifi_networks",
            return_value=[
                WiFiNetwork("Example-Guest"),
                WiFiNetwork("Example-Student", current=True),
            ],
        ):
            self.assertEqual(
                list_available_saved_wifi_networks("en0"),
                ["Example-Student", "Example-Guest"],
            )

    def test_saved_wifi_rejects_untrusted_interface_before_run(self) -> None:
        with patch("hyping.discovery.wifi._run_networksetup") as run:
            with self.assertRaises(WiFiError):
                list_available_saved_wifi_networks("en0;touch /tmp/pwned")

        run.assert_not_called()

    def test_saved_wifi_requires_known_wifi_interface(self) -> None:
        with patch(
            "hyping.discovery.wifi._macos_hardware_ports",
            return_value={"en1": "Thunderbolt Ethernet"},
        ), patch("hyping.discovery.wifi._run_networksetup") as run:
            with self.assertRaises(WiFiError):
                list_available_saved_wifi_networks("en1")

        run.assert_not_called()

    def test_switch_wifi_detects_successful_verified_join(self) -> None:
        with patch("hyping.discovery.wifi.wifi_interface", return_value="en0"), patch(
            "hyping.discovery.wifi._run_networksetup",
            return_value="",
        ) as run, patch(
            "hyping.discovery.wifi._current_wifi_ssid_for_interface",
            return_value="Example-Guest",
        ), patch("hyping.discovery.wifi.time.sleep", lambda _: None):
            self.assertEqual(
                switch_wifi_network("Example-Guest", password="example-password"),
                "Example-Guest",
            )

        run.assert_called_once_with(
            [
                "-setairportnetwork",
                "en0",
                "Example-Guest",
                "example-password",
            ],
            timeout=45.0,
        )

    def test_switch_wifi_treats_failed_output_as_error(self) -> None:
        with patch("hyping.discovery.wifi.wifi_interface", return_value="en0"), patch(
            "hyping.discovery.wifi._run_networksetup",
            return_value="Failed to join network Example-Guest.",
        ):
            with self.assertRaises(WiFiError):
                switch_wifi_network("Example-Guest", verify=False)

    def test_switch_wifi_rejects_control_char_ssid(self) -> None:
        with patch("hyping.discovery.wifi._run_networksetup") as run:
            with self.assertRaises(WiFiError):
                switch_wifi_network("Example\nGuest", verify=False)

        run.assert_not_called()

    def test_switch_wifi_does_not_echo_password_in_run_error(self) -> None:
        with patch("hyping.discovery.wifi.wifi_interface", return_value="en0"), patch(
            "hyping.discovery.wifi.subprocess.run",
            side_effect=OSError("boom"),
        ):
            with self.assertRaises(WiFiError) as context:
                switch_wifi_network(
                    "Example-Guest",
                    password="secret-password",
                    verify=False,
                )

        self.assertNotIn("secret-password", str(context.exception))


if __name__ == "__main__":
    unittest.main()
