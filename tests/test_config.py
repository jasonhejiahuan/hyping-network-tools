import json
import tempfile
import unittest
from pathlib import Path

from hyping.config import DEFAULT_CONFIG, ensure_config


class ConfigTests(unittest.TestCase):
    def test_ensure_config_creates_default_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"

            config = ensure_config(path)

            self.assertEqual(config, DEFAULT_CONFIG)
            self.assertTrue(path.exists())
            written_config = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(written_config, DEFAULT_CONFIG)

    def test_ensure_config_merges_missing_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps({"load": {"tcp_port": 6000}}, ensure_ascii=False),
                encoding="utf-8",
            )

            config = ensure_config(path)

            self.assertEqual(config["load"]["tcp_port"], 6000)
            self.assertEqual(config["load"]["concurrency"], 32)
            self.assertEqual(config["bettercap"]["url"], "http://127.0.0.1:8081")


if __name__ == "__main__":
    unittest.main()
