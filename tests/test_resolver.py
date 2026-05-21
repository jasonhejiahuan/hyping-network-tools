import socket
import unittest
from ipaddress import IPv4Address
from unittest.mock import patch

from hyping.discovery.resolver import (
    AmbiguousDeviceError,
    DeviceNotFoundError,
    find_devices,
    find_one_device,
    locate_device,
    normalize_mac,
    resolve_ipv4_addresses,
)
from hyping.models.device import Device


class ResolverTests(unittest.TestCase):
    def test_find_devices_matches_hostname_alias_and_note(self) -> None:
        devices = [
            Device(
                ip=IPv4Address("192.168.1.10"),
                mac="aa:bb:cc:dd:ee:10",
                hostname="Printer.local",
                note="Living Room Printer",
            ),
            Device(
                ip=IPv4Address("192.168.1.11"),
                mac="aa:bb:cc:dd:ee:11",
                hostname="nas.local",
                note="Storage",
            ),
        ]

        matches = find_devices(
            devices,
            hostname="printer",
            note="living room printer",
        )

        self.assertEqual(matches, [devices[0]])

    def test_find_devices_supports_partial_note(self) -> None:
        device = Device(
            ip=IPv4Address("192.168.1.20"),
            mac="aa:bb:cc:dd:ee:20",
            hostname="camera.local",
            note="Front Door Camera",
        )

        self.assertEqual(
            find_devices([device], note="door", partial_note=True),
            [device],
        )
        self.assertEqual(find_devices([device], note="door"), [])

    def test_find_one_rejects_ambiguous_matches(self) -> None:
        devices = [
            Device(
                ip=IPv4Address("192.168.1.30"),
                mac="aa:bb:cc:dd:ee:30",
                hostname="cam-a.local",
                note="camera",
            ),
            Device(
                ip=IPv4Address("192.168.1.31"),
                mac="aa:bb:cc:dd:ee:31",
                hostname="cam-b.local",
                note="camera",
            ),
        ]

        with self.assertRaises(AmbiguousDeviceError):
            find_one_device(devices, note="camera")

    def test_locate_device_uses_note_hostname_alias_and_known_devices(self) -> None:
        device = Device(
            ip=IPv4Address("192.168.1.40"),
            mac="aa:bb:cc:dd:ee:40",
            hostname="desk-mini.local",
        )

        located = locate_device(
            note="desk mac",
            note_hosts={"desk mac": "desk-mini"},
            devices=[device],
        )

        self.assertEqual(located, device)

    def test_locate_device_resolves_hostname_then_arp_cache(self) -> None:
        with (
            patch(
                "hyping.discovery.resolver.resolve_ipv4_addresses",
                return_value=[IPv4Address("192.168.1.50")],
            ),
            patch(
                "hyping.discovery.resolver._read_arp_cache",
                return_value="aa:bb:cc:dd:ee:50",
            ),
        ):
            located = locate_device(hostname="server.local")

        self.assertEqual(located.ip, IPv4Address("192.168.1.50"))
        self.assertEqual(located.mac, "aa:bb:cc:dd:ee:50")
        self.assertEqual(located.hostname, "server.local")

    def test_locate_device_primes_arp_cache_when_cache_is_empty(self) -> None:
        with (
            patch(
                "hyping.discovery.resolver.resolve_ipv4_addresses",
                return_value=[IPv4Address("192.168.1.51")],
            ),
            patch(
                "hyping.discovery.resolver._read_arp_cache",
                side_effect=[None, "aa:bb:cc:dd:ee:51"],
            ) as read_arp_cache,
            patch("hyping.discovery.resolver._prime_arp_cache") as prime_arp_cache,
        ):
            located = locate_device(hostname="server.local")

        self.assertEqual(located.ip, IPv4Address("192.168.1.51"))
        self.assertEqual(located.mac, "aa:bb:cc:dd:ee:51")
        self.assertEqual(read_arp_cache.call_count, 2)
        prime_arp_cache.assert_called_once_with(
            IPv4Address("192.168.1.51"),
            timeout=1.0,
        )

    def test_locate_device_supports_partial_note_alias(self) -> None:
        device = Device(
            ip=IPv4Address("192.168.1.60"),
            mac="aa:bb:cc:dd:ee:60",
            hostname="printer.local",
        )

        located = locate_device(
            note="printer",
            note_hosts={"living room printer": "printer"},
            devices=[device],
            partial_note=True,
        )

        self.assertEqual(located, device)

    def test_resolve_ipv4_addresses_tries_mdns_alias(self) -> None:
        def fake_getaddrinfo(hostname, *args, **kwargs):
            if hostname == "printer":
                raise socket.gaierror
            return [
                (
                    None,
                    None,
                    None,
                    None,
                    ("192.168.1.70", 0),
                )
            ]

        with patch("hyping.discovery.resolver.socket.getaddrinfo", fake_getaddrinfo):
            addresses = resolve_ipv4_addresses("printer")

        self.assertEqual(addresses, [IPv4Address("192.168.1.70")])

    def test_locate_device_raises_when_not_found(self) -> None:
        with patch(
            "hyping.discovery.resolver.resolve_ipv4_addresses",
            return_value=[],
        ):
            with self.assertRaises(DeviceNotFoundError):
                locate_device(hostname="missing.local")

    def test_normalize_mac(self) -> None:
        self.assertEqual(normalize_mac("A:B:C:D:E:F"), "0a:0b:0c:0d:0e:0f")
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")


if __name__ == "__main__":
    unittest.main()
