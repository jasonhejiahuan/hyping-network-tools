import unittest
from unittest.mock import patch

from hyping.discovery.network import _netmask_from_text, detect_local_ipv4_network


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


if __name__ == "__main__":
    unittest.main()
