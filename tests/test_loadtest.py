import time
import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from hyping.loadtest import LoadTestConfig, _icmp_probe, run_load_test


class LoadTestTests(unittest.TestCase):
    def test_count_limited_load_test_uses_concurrency(self) -> None:
        def fake_probe(config):
            time.sleep(0.001)
            return True, 1.0

        with patch("hyping.loadtest._probe", fake_probe):
            summary = run_load_test(
                LoadTestConfig(
                    target="127.0.0.1",
                    concurrency=8,
                    duration=None,
                    count=20,
                    timeout=0.1,
                    ramp_up=0,
                    per_worker_jitter=0,
                ),
                live=False,
            )

        self.assertEqual(summary["issued"], 20)
        self.assertEqual(summary["completed"], 20)
        self.assertEqual(summary["succeeded"], 20)
        self.assertEqual(summary["failed"], 0)

    def test_tcp_requires_port(self) -> None:
        with self.assertRaises(ValueError):
            run_load_test(
                LoadTestConfig(
                    target="127.0.0.1",
                    protocol="tcp",
                    duration=None,
                    count=1,
                ),
                live=False,
            )

    def test_latency_is_recorded_for_failed_probes(self) -> None:
        def fake_probe(config):
            return False, 12.5

        with patch("hyping.loadtest._probe", fake_probe):
            summary = run_load_test(
                LoadTestConfig(
                    target="127.0.0.1",
                    concurrency=2,
                    duration=None,
                    count=3,
                    timeout=0.1,
                    ramp_up=0,
                    per_worker_jitter=0,
                ),
                live=False,
            )

        self.assertEqual(summary["succeeded"], 0)
        self.assertEqual(summary["failed"], 3)
        self.assertEqual(summary["avg_latency_ms"], 12.5)
        self.assertEqual(summary["recent_p95_latency_ms"], 12.5)

    def test_icmp_probe_parses_ping_reported_latency(self) -> None:
        completed = CompletedProcess(
            args=["ping"],
            returncode=0,
            stdout="64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.118 ms\n",
            stderr="",
        )

        with patch("hyping.loadtest.subprocess.run", return_value=completed):
            success, latency_ms = _icmp_probe("127.0.0.1", 1.0)

        self.assertTrue(success)
        self.assertEqual(latency_ms, 0.118)

    def test_ramp_up_and_jitter_must_not_be_negative(self) -> None:
        with self.assertRaises(ValueError):
            run_load_test(
                LoadTestConfig(
                    target="127.0.0.1",
                    duration=None,
                    count=1,
                    ramp_up=-1,
                ),
                live=False,
            )

        with self.assertRaises(ValueError):
            run_load_test(
                LoadTestConfig(
                    target="127.0.0.1",
                    duration=None,
                    count=1,
                    per_worker_jitter=-0.1,
                ),
                live=False,
            )


if __name__ == "__main__":
    unittest.main()
