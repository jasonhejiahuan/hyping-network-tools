import unittest
from ipaddress import IPv4Address
from unittest.mock import patch

from hyping.discovery.bettercap import (
    BettercapAPIError,
    BettercapClient,
    BettercapHost,
    host_from_bettercap,
    hosts_from_session,
    iter_bettercap_hosts,
    record_from_bettercap_host,
)


class BettercapTests(unittest.TestCase):
    def test_host_from_bettercap_uses_alias_hostname_vendor_and_meta(self) -> None:
        host = host_from_bettercap(
            {
                "ipv4": "192.168.10.210",
                "mac": "AA:BA:36:4D:1A:6B",
                "hostname": "",
                "alias": "Ivan's MacBook Air",
                "vendor": "Apple, Inc.",
                "first_seen": "first",
                "last_seen": "last",
                "meta": {"values": {"mdns:hostname": "IvandeMacBook-Air.local."}},
            }
        )

        self.assertIsNotNone(host)
        assert host is not None
        self.assertEqual(host.ip, IPv4Address("192.168.10.210"))
        self.assertEqual(host.mac, "aa:ba:36:4d:1a:6b")
        self.assertEqual(host.hostname, "IvandeMacBook-Air.local")
        self.assertEqual(host.display_name, "Ivan's MacBook Air")
        self.assertEqual(host.vendor, "Apple, Inc.")

    def test_hosts_from_session_includes_interface_gateway_and_lan(self) -> None:
        session = {
            "interface": {
                "ipv4": "192.168.1.10",
                "mac": "aa:bb:cc:dd:ee:10",
                "hostname": "en0",
            },
            "gateway": {
                "ipv4": "192.168.1.1",
                "mac": "aa:bb:cc:dd:ee:01",
                "alias": "gateway",
            },
            "lan": {
                "hosts": [
                    {
                        "ipv4": "192.168.1.20",
                        "mac": "aa:bb:cc:dd:ee:20",
                        "hostname": "printer.local.",
                    }
                ]
            },
        }

        self.assertEqual(
            [str(host.ip) for host in hosts_from_session(session)],
            ["192.168.1.1", "192.168.1.10", "192.168.1.20"],
        )

    def test_record_from_bettercap_host_preserves_vendor(self) -> None:
        record = record_from_bettercap_host(
            BettercapHost(
                ip=IPv4Address("192.168.1.20"),
                mac="aa:bb:cc:dd:ee:20",
                hostname="printer.local",
                vendor="Printer Inc.",
            )
        )

        self.assertEqual(record["hostname"], "printer.local")
        self.assertEqual(record["vendor"], "Printer Inc.")

    def test_iter_bettercap_hosts_starts_discovery_and_yields_new_hosts(self) -> None:
        class Client:
            def __init__(self):
                self.started = False
                self.calls = 0

            def start_discovery(self):
                self.started = True

            def hosts(self):
                self.calls += 1
                if self.calls == 1:
                    return [
                        BettercapHost(
                            ip=IPv4Address("192.168.1.20"),
                            mac="aa:bb:cc:dd:ee:20",
                        )
                    ]
                return [
                    BettercapHost(
                        ip=IPv4Address("192.168.1.20"),
                        mac="aa:bb:cc:dd:ee:20",
                    ),
                    BettercapHost(
                        ip=IPv4Address("192.168.1.21"),
                        mac="aa:bb:cc:dd:ee:21",
                    ),
                ]

        client = Client()
        with patch("hyping.discovery.bettercap.time.sleep", lambda _: None):
            hosts = list(iter_bettercap_hosts(client, wait=0.01, poll_interval=0.01))

        self.assertTrue(client.started)
        self.assertEqual(
            [str(host.ip) for host in hosts],
            ["192.168.1.20", "192.168.1.21"],
        )

    def test_client_online_check_returns_false_when_api_unreachable(self) -> None:
        client = BettercapClient()

        with patch.object(
            client,
            "session",
            side_effect=BettercapAPIError("offline"),
        ):
            self.assertFalse(client.is_online())

    def test_client_online_check_returns_true_when_session_loads(self) -> None:
        client = BettercapClient()

        with patch.object(client, "session", return_value={}):
            self.assertTrue(client.is_online())

    def test_client_online_check_uses_temporary_timeout(self) -> None:
        client = BettercapClient(timeout=3.0)
        observed = []

        def fake_session():
            observed.append(client.timeout)
            return {}

        with patch.object(client, "session", fake_session):
            self.assertTrue(client.is_online(timeout=0.25))

        self.assertEqual(observed, [0.25])
        self.assertEqual(client.timeout, 3.0)


if __name__ == "__main__":
    unittest.main()
