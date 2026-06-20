import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from ipaddress import IPv4Address
from pathlib import Path
from unittest.mock import patch

from hyping.discovery.bettercap import BettercapHost
from hyping.main import _build_parser, _resolve_auto_locate_hostname, main
from hyping.storage import save_device_records


class MainAutoLocateTests(unittest.TestCase):
    def test_web_help_explains_passkey_prerequisite(self) -> None:
        parser = _build_parser({})
        stdout = io.StringIO()

        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            parser.parse_args(["web", "--help"])

        self.assertEqual(raised.exception.code, 0)
        help_text = stdout.getvalue()
        self.assertIn("jasonhejiahuan/Passkey-Auth", help_text)
        self.assertIn("web_auth.enabled=false", help_text)
        self.assertIn("github.com/jasonhejiahuan/Passkey-Auth/wiki", help_text)

    def test_resolve_auto_locate_hostname_uses_saved_selector(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "devices.json"
            save_device_records(
                [
                    {
                        "hostname": "printer.local",
                        "note": "office printer",
                        "ip": "192.168.1.20",
                        "mac": "aa:bb:cc:dd:ee:20",
                    }
                ],
                store_path,
            )

            hostname = _resolve_auto_locate_hostname(
                hostname=None,
                saved_selector="office printer",
                store_path=store_path,
            )

        self.assertEqual(hostname, "printer.local")

    def test_auto_locate_saved_json_outputs_ssid_and_host(self) -> None:
        target = BettercapHost(
            ip=IPv4Address("192.168.1.20"),
            mac="aa:bb:cc:dd:ee:20",
            hostname="printer.local",
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_path = root / "devices.json"
            wifi_path = root / "wifi.json"
            save_device_records(
                [
                    {
                        "hostname": "printer.local",
                        "note": "office printer",
                        "ip": "192.168.1.10",
                        "mac": "aa:bb:cc:dd:ee:10",
                    }
                ],
                store_path,
            )
            wifi_path.write_text(
                json.dumps({"networks": [{"ssid": "Lab-WiFi"}]}),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with patch("hyping.main.ensure_config", return_value={}), patch(
                "hyping.auto_wifi_scan.list_bettercap_hosts",
                return_value=[target],
            ), patch(
                "hyping.auto_wifi_scan.ensure_bettercap_api_online",
                return_value=None,
            ), patch(
                "hyping.auto_wifi_scan.current_wifi_ssid",
                return_value="Lab-WiFi",
            ), redirect_stdout(stdout):
                code = main(
                    [
                        "auto-locate",
                        "--saved",
                        "office printer",
                        "--wifi-list",
                        str(wifi_path),
                        "--store",
                        str(store_path),
                        "--json",
                    ]
                )

        self.assertEqual(code, 0)
        summary = json.loads(stdout.getvalue())
        self.assertTrue(summary["found"])
        self.assertEqual(summary["query"], "printer.local")
        self.assertEqual(summary["ssid"], "Lab-WiFi")
        self.assertEqual(summary["host"]["ip"], "192.168.1.20")
        self.assertEqual(summary["host"]["ssid"], "Lab-WiFi")


if __name__ == "__main__":
    unittest.main()
