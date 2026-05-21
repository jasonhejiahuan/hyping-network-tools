import tempfile
import unittest
from pathlib import Path

from hyping.storage import (
    load_device_records,
    note_hosts_from_records,
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


if __name__ == "__main__":
    unittest.main()
