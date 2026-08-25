import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from hyping.interactive import _save_records
from hyping.storage import load_device_records


class _TTYBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


class InteractiveSaveTests(unittest.TestCase):
    def test_save_records_refreshes_progress_on_one_terminal_line(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "devices.json"
            stdout = _TTYBuffer()

            with redirect_stdout(stdout):
                _save_records(
                    path,
                    [
                        {"hostname": "one.local", "ip": "192.168.1.1"},
                        {"hostname": "two.local", "ip": "192.168.1.2"},
                    ],
                )

            output = stdout.getvalue()
            self.assertEqual(output.count("\n"), 1)
            self.assertIn(f"\r\033[2K已保存 1 项到 {path}", output)
            self.assertTrue(output.endswith(f"\r\033[2K已保存 2 项到 {path}\n"))
            self.assertEqual(len(load_device_records(path)), 2)

    def test_save_records_prints_only_final_count_when_not_a_tty(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "devices.json"
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                _save_records(
                    path,
                    [
                        {"hostname": "one.local"},
                        {"hostname": "two.local"},
                    ],
                )

            self.assertEqual(stdout.getvalue(), f"已保存 2 项到 {path}\n")


if __name__ == "__main__":
    unittest.main()
