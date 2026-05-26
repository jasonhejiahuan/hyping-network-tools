import unittest
from ipaddress import IPv4Address
from unittest.mock import patch

from hyping.discovery.arp import list_network_devices
from hyping.models.device import Device


class ARPTests(unittest.TestCase):
    def test_list_network_devices_sorts_and_resolves(self) -> None:
        devices = [
            Device(ip=IPv4Address("192.168.1.20"), mac="aa:bb:cc:dd:ee:20"),
            Device(ip=IPv4Address("192.168.1.10"), mac="aa:bb:cc:dd:ee:10"),
        ]
        enriched = [
            Device(
                ip=IPv4Address("192.168.1.20"),
                mac="aa:bb:cc:dd:ee:20",
                hostname="camera.local",
            ),
            Device(
                ip=IPv4Address("192.168.1.10"),
                mac="aa:bb:cc:dd:ee:10",
                hostname="printer.local",
            ),
        ]

        with (
            patch("hyping.discovery.arp.iter_arp_scan", return_value=iter(devices)),
            patch("hyping.discovery.resolver.enrich_hostnames", return_value=enriched),
        ):
            self.assertEqual(
                list_network_devices("192.168.1.0/24"),
                [enriched[1], enriched[0]],
            )

    def test_list_network_devices_can_skip_hostname_resolution(self) -> None:
        devices = [
            Device(ip=IPv4Address("192.168.1.20"), mac="aa:bb:cc:dd:ee:20"),
            Device(ip=IPv4Address("192.168.1.10"), mac="aa:bb:cc:dd:ee:10"),
        ]

        with patch("hyping.discovery.arp.iter_arp_scan", return_value=iter(devices)):
            self.assertEqual(
                list_network_devices(
                    "192.168.1.0/24",
                    resolve_hostnames=False,
                ),
                [devices[1], devices[0]],
            )

    def test_list_network_devices_calls_progress_callback(self) -> None:
        devices = [
            Device(ip=IPv4Address("192.168.1.20"), mac="aa:bb:cc:dd:ee:20"),
            Device(ip=IPv4Address("192.168.1.10"), mac="aa:bb:cc:dd:ee:10"),
        ]
        seen: list[Device] = []

        with patch("hyping.discovery.arp.iter_arp_scan", return_value=iter(devices)):
            list_network_devices(
                "192.168.1.0/24",
                resolve_hostnames=False,
                on_device=seen.append,
            )

        self.assertEqual(seen, devices)


if __name__ == "__main__":
    unittest.main()
