import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from hyping.storage import save_device_records
from hyping.web import HypingWebHandler, HypingWebServer


class WebServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store_path = Path(self.tmp.name) / "devices.json"
        save_device_records(
            [
                {
                    "hostname": "printer.local",
                    "ip": "192.168.1.20",
                    "mac": "aa:bb:cc:dd:ee:20",
                    "note": "office printer",
                }
            ],
            self.store_path,
        )
        self.server = HypingWebServer(
            ("127.0.0.1", 0),
            HypingWebHandler,
            config={},
            store_path=self.store_path,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.tmp.cleanup()

    def get(self, path: str) -> bytes:
        with urllib.request.urlopen(f"{self.base_url}{path}", timeout=2) as response:
            return response.read()

    def post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_serves_static_ui_assets(self) -> None:
        self.assertIn(b"Hyping Web UI", self.get("/"))
        self.assertIn(b"--ink", self.get("/app.css"))
        self.assertIn(b"drawTopology", self.get("/app.js"))

    def test_devices_api_can_save_and_delete_records(self) -> None:
        saved = self.post(
            "/api/devices/save",
            {
                "record": {
                    "hostname": "nas.local",
                    "ip": "192.168.1.30",
                    "mac": "aa:bb:cc:dd:ee:30",
                    "note": "NAS",
                }
            },
        )

        self.assertTrue(saved["ok"])
        self.assertEqual(len(saved["devices"]), 2)

        deleted = self.post("/api/devices/delete", {"index": 1})

        self.assertTrue(deleted["ok"])
        self.assertEqual(len(deleted["devices"]), 1)
        self.assertEqual(deleted["removed"]["hostname"], "nas.local")


if __name__ == "__main__":
    unittest.main()
