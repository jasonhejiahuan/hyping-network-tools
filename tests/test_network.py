import unittest
from unittest.mock import patch

from hyping.discovery.network import (
    _netmask_from_text,
    _ssid_from_system_profiler,
    _wifi_ssid,
    detect_local_ipv4_network,
)


class NetworkTests(unittest.TestCase):
    def test_hex_netmask(self) -> None:
        self.assertEqual(_netmask_from_text("0xffffff00"), "255.255.255.0")

    def test_detect_local_ipv4_network_from_default_interface(self) -> None:
        def fake_run(command):
            if command == ["route", "-n", "get", "default"]:
                return "interface: en0\n"
            if command == ["ifconfig", "en0"]:
                return "inet 192.168.50.23 netmask 0xffffff00 broadcast 192.168.50.255"
            return ""

        with patch("hyping.discovery.network._run", fake_run):
            self.assertEqual(detect_local_ipv4_network(), "192.168.50.0/24")

    def test_ssid_from_system_profiler_current_network(self) -> None:
        output = """
Wi-Fi:

      Interfaces:
        en0:
          Current Network Information:
            Jason Home 5G:
              PHY Mode: 802.11ax
"""
        self.assertEqual(_ssid_from_system_profiler(output), "Jason Home 5G")

    def test_wifi_ssid_prefers_streamed_system_profiler(self) -> None:
        with patch(
            "hyping.discovery.network._ssid_from_system_profiler_live",
            return_value="Office Wi-Fi",
        ) as profiler, patch("hyping.discovery.network._run") as run:
            self.assertEqual(_wifi_ssid("en0"), "Office Wi-Fi")

        profiler.assert_called_once_with(timeout=5.0)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
