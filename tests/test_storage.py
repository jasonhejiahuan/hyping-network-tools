import tempfile
import unittest
from pathlib import Path

from hyping.storage import (
    load_device_records,
    mac_addresses_from_record,
    note_hosts_from_records,
    observed_device_record,
    save_device_records,
    upsert_device_record,
)


class StorageTests(unittest.TestCase):
    def test_save_load_and_upsert_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "devices.json"
            records = [
                {
                    "hostname": "Printer.local",
                    "ip": "192.168.1.10",
                    "mac": "aa:bb:cc:dd:ee:10",
                    "note": "printer",
                }
            ]
            save_device_records(records, path)

            loaded = load_device_records(path)
            upsert_device_record(
                loaded,
                {
                    "hostname": "printer.local.",
                    "note": "living room printer",
                    "mdns": {"ty": "Lenovo"},
                },
            )

            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["note"], "living room printer")
            self.assertEqual(loaded[0]["ip"], "192.168.1.10")
            self.assertEqual(loaded[0]["mdns"], {"ty": "Lenovo"})

    def test_note_hosts_from_records(self) -> None:
        self.assertEqual(
            note_hosts_from_records(
                [
                    {"hostname": "printer.local", "note": "printer"},
                    {"hostname": "", "note": "missing"},
                ]
            ),
            {"printer": "printer.local"},
        )

    def test_upsert_preserves_mac_and_network_location_history(self) -> None:
        records = [
            observed_device_record(
                {
                    "hostname": "laptop.local",
                    "ip": "192.168.1.20",
                    "mac": "aa:bb:cc:dd:ee:01",
                },
                ssid="Home",
                source="bettercap",
                observed_at="2026-09-09T10:00:00+00:00",
            )
        ]

        upsert_device_record(
            records,
            observed_device_record(
                {
                    "hostname": "laptop.local.",
                    "ip": "10.0.0.20",
                    "mac": "AA-BB-CC-DD-EE-02",
                },
                ssid="Lab",
                source="builtin",
                observed_at="2026-09-09T11:00:00+00:00",
            ),
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(
            set(mac_addresses_from_record(records[0])),
            {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"},
        )
        self.assertEqual(
            [location["ssid"] for location in records[0]["locations"]],
            ["Home", "Lab"],
        )

    def test_upsert_does_not_merge_distinct_hostnames_reusing_an_ip(self) -> None:
        records = [
            {
                "hostname": "first.local",
                "ip": "192.168.1.20",
                "mac": "aa:bb:cc:dd:ee:01",
            }
        ]

        upsert_device_record(
            records,
            {
                "hostname": "second.local",
                "ip": "192.168.1.20",
                "mac": "aa:bb:cc:dd:ee:02",
            },
        )

        self.assertEqual(len(records), 2)

    def test_upsert_keeps_distinct_macs_reusing_ip_without_names(self) -> None:
        records = [{"ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:01"}]

        upsert_device_record(
            records,
            {"ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:02"},
        )

        self.assertEqual(len(records), 2)

    def test_alias_match_preserves_saved_hostname(self) -> None:
        records = [
            {
                "hostname": "laptop.local",
                "mac": "aa:bb:cc:dd:ee:01",
                "note": "我的电脑",
            }
        ]

        upsert_device_record(
            records,
            {
                "hostname": "Friendly Laptop",
                "alias": "Friendly Laptop",
                "hostnames": ["laptop.local", "Friendly Laptop"],
                "mac": "aa:bb:cc:dd:ee:02",
            },
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["hostname"], "laptop.local")
        self.assertEqual(records[0]["note"], "我的电脑")
        self.assertEqual(
            set(mac_addresses_from_record(records[0])),
            {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"},
        )


if __name__ == "__main__":
    unittest.main()
