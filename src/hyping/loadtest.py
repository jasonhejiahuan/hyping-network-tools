import math
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Literal

ProbeProtocol = Literal["icmp", "tcp"]
_PING_TIME_RE = re.compile(r"time[=<]([0-9.]+)\s*ms")


@dataclass(slots=True, frozen=True)
class LoadTestConfig:
    target: str
    protocol: ProbeProtocol = "icmp"
    concurrency: int = 32
    duration: float | None = 10.0
    count: int | None = None
    timeout: float = 1.0
    tcp_port: int | None = None
    refresh_interval: float = 0.25
    ramp_up: float = 0.75
    per_worker_jitter: float = 0.002


@dataclass(slots=True)
class LoadTestStats:
    started_at: float = field(default_factory=time.perf_counter)
    finished_at: float | None = None
    issued: int = 0
    completed: int = 0
    succeeded: int = 0
    failed: int = 0
    in_flight: int = 0
    total_latency_ms: float = 0.0
    min_latency_ms: float | None = None
    max_latency_ms: float | None = None
    recent_latencies_ms: deque[float] = field(
        default_factory=lambda: deque(maxlen=5000)
    )
    lock: threading.Lock = field(default_factory=threading.Lock)

    def mark_issued(self) -> None:
        with self.lock:
            self.issued += 1
            self.in_flight += 1

    def mark_done(self, *, success: bool, latency_ms: float) -> None:
        with self.lock:
            self.completed += 1
            self.in_flight = max(0, self.in_flight - 1)
            self.total_latency_ms += latency_ms
            self.recent_latencies_ms.append(latency_ms)
            if self.min_latency_ms is None or latency_ms < self.min_latency_ms:
                self.min_latency_ms = latency_ms
            if self.max_latency_ms is None or latency_ms > self.max_latency_ms:
                self.max_latency_ms = latency_ms

            if success:
                self.succeeded += 1
            else:
                self.failed += 1

    def finish(self) -> None:
        with self.lock:
            self.finished_at = time.perf_counter()

    def snapshot(self) -> dict[str, float | int | None]:
        with self.lock:
            now = self.finished_at or time.perf_counter()
            elapsed = max(now - self.started_at, 0.000001)
            recent = list(self.recent_latencies_ms)
            avg_latency = (
                self.total_latency_ms / self.completed if self.completed else None
            )
            p95_latency = _percentile(recent, 95) if recent else None
            return {
                "elapsed": elapsed,
                "issued": self.issued,
                "completed": self.completed,
                "succeeded": self.succeeded,
                "failed": self.failed,
                "in_flight": self.in_flight,
                "rate": self.completed / elapsed,
                "success_rate": self.succeeded / self.completed
                if self.completed
                else None,
                "avg_latency_ms": avg_latency,
                "min_latency_ms": self.min_latency_ms,
                "max_latency_ms": self.max_latency_ms,
                "recent_p95_latency_ms": p95_latency,
            }


def _percentile(values: list[float], percentile: int) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * percentile / 100) - 1)
    return ordered[index]


def _format_ms(value: float | int | None) -> str:
    return "-" if value is None else f"{float(value):.2f} ms"


def _format_rate(value: float | int | None) -> str:
    return "-" if value is None else f"{float(value):.1f}/s"


def _terminal_width() -> int:
    return max(72, shutil.get_terminal_size(fallback=(100, 24)).columns)


def _progress_bar(done: int, total: int | None, *, width: int) -> str:
    if total is None or total <= 0:
        spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[done % 10]
        return f"{spinner} running"

    ratio = min(1.0, done / total)
    filled = round(width * ratio)
    return f"{'█' * filled}{'░' * (width - filled)} {ratio * 100:5.1f}%"


def _ping_args(target: str, timeout: float) -> list[str]:
    if sys.platform == "darwin":
        wait_arg = str(max(100, int(timeout * 1000)))
    else:
        wait_arg = str(max(1, math.ceil(timeout)))

    return ["ping", "-n", "-c", "1", "-W", wait_arg, target]


def _icmp_probe(target: str, timeout: float) -> tuple[bool, float]:
    started = time.perf_counter()
    elapsed_ms = 0.0
    try:
        result = subprocess.run(
            _ping_args(target, timeout),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout + 0.75,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        success = result.returncode == 0
        match = _PING_TIME_RE.search(result.stdout)
        if match is not None:
            return success, float(match.group(1))
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        elapsed_ms = (time.perf_counter() - started) * 1000
        success = False

    if elapsed_ms == 0.0:
        elapsed_ms = (time.perf_counter() - started) * 1000

    return success, elapsed_ms


def _tcp_probe(target: str, port: int, timeout: float) -> tuple[bool, float]:
    started = time.perf_counter()
    try:
        with socket.create_connection((target, port), timeout=timeout):
            success = True
    except OSError:
        success = False

    return success, (time.perf_counter() - started) * 1000


def _probe(config: LoadTestConfig) -> tuple[bool, float]:
    if config.protocol == "tcp":
        if config.tcp_port is None:
            msg = "tcp_port is required for tcp protocol"
            raise ValueError(msg)
        return _tcp_probe(config.target, config.tcp_port, config.timeout)

    return _icmp_probe(config.target, config.timeout)


def _validate_config(config: LoadTestConfig) -> None:
    if not config.target.strip():
        msg = "target must not be empty"
        raise ValueError(msg)
    if config.concurrency <= 0:
        msg = "concurrency must be greater than 0"
        raise ValueError(msg)
    if config.duration is not None and config.duration <= 0:
        msg = "duration must be greater than 0"
        raise ValueError(msg)
    if config.count is not None and config.count <= 0:
        msg = "count must be greater than 0"
        raise ValueError(msg)
    if config.duration is None and config.count is None:
        msg = "duration or count is required"
        raise ValueError(msg)
    if config.timeout <= 0:
        msg = "timeout must be greater than 0"
        raise ValueError(msg)
    if config.ramp_up < 0:
        msg = "ramp_up must not be negative"
        raise ValueError(msg)
    if config.per_worker_jitter < 0:
        msg = "per_worker_jitter must not be negative"
        raise ValueError(msg)
    if config.protocol == "tcp" and config.tcp_port is None:
        msg = "tcp_port is required for tcp protocol"
        raise ValueError(msg)


def _worker(
    config: LoadTestConfig,
    stats: LoadTestStats,
    stop_event: threading.Event,
    issue_lock: threading.Lock,
    worker_index: int,
) -> None:
    if config.concurrency > 1 and config.ramp_up > 0:
        delay = config.ramp_up * worker_index / (config.concurrency - 1)
        if stop_event.wait(delay):
            return

    deadline = (
        time.perf_counter() + config.duration
        if config.duration is not None
        else None
    )

    while not stop_event.is_set():
        if deadline is not None and time.perf_counter() >= deadline:
            stop_event.set()
            return

        with issue_lock:
            if config.count is not None and stats.issued >= config.count:
                stop_event.set()
                return
            stats.mark_issued()

        if config.per_worker_jitter > 0:
            # Slightly de-phase loops so workers do not re-align after each probe.
            time.sleep(config.per_worker_jitter * ((worker_index % 7) + 1) / 7)

        try:
            success, latency_ms = _probe(config)
        except Exception:
            success, latency_ms = False, 0.0

        stats.mark_done(success=success, latency_ms=latency_ms)


def _render(config: LoadTestConfig, stats: LoadTestStats) -> None:
    width = _terminal_width()
    snap = stats.snapshot()
    target = f"{config.protocol}://{config.target}"
    if config.protocol == "tcp":
        target = f"{target}:{config.tcp_port}"

    print("\033[2J\033[H", end="")
    print("Hyping 并发负载测试")
    print("─" * min(width, 100))
    print(f"目标: {target}")
    print(
        f"并发: {config.concurrency}  "
        f"超时: {config.timeout}s  "
        f"渐进启动: {config.ramp_up}s  "
        f"模式: {'包数' if config.count else '时长'}"
    )
    if config.duration is not None:
        print(f"时长: {config.duration}s")
    if config.count is not None:
        print(f"总请求/包数: {config.count}")
    print()
    print(
        _progress_bar(
            int(snap["completed"] or 0),
            config.count,
            width=min(40, max(10, width - 24)),
        )
    )
    print()
    print(f"已运行: {float(snap['elapsed']):.1f}s")
    print(
        f"完成: {snap['completed']}  "
        f"成功: {snap['succeeded']}  "
        f"失败: {snap['failed']}  "
        f"进行中: {snap['in_flight']}"
    )
    success_rate = (
        f"{float(snap['success_rate']) * 100:.1f}%"
        if snap["success_rate"] is not None
        else "-"
    )
    print(f"吞吐: {_format_rate(snap['rate'])}  成功率: {success_rate}")
    print(
        f"延迟 avg/min/max/p95_recent: "
        f"{_format_ms(snap['avg_latency_ms'])} / "
        f"{_format_ms(snap['min_latency_ms'])} / "
        f"{_format_ms(snap['max_latency_ms'])} / "
        f"{_format_ms(snap['recent_p95_latency_ms'])}"
    )
    print("\n按 Ctrl+C 停止。")


def run_load_test(config: LoadTestConfig, *, live: bool = True) -> dict[str, object]:
    """Run a threaded ICMP/TCP load test and return final statistics."""

    _validate_config(config)
    stats = LoadTestStats()
    stop_event = threading.Event()
    issue_lock = threading.Lock()

    try:
        with ThreadPoolExecutor(max_workers=config.concurrency) as executor:
            futures = [
                executor.submit(
                    _worker,
                    config,
                    stats,
                    stop_event,
                    issue_lock,
                    worker_index,
                )
                for worker_index in range(config.concurrency)
            ]

            while not stop_event.is_set():
                if all(future.done() for future in futures):
                    break
                if live:
                    _render(config, stats)
                time.sleep(config.refresh_interval)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        stop_event.set()
        stats.finish()
        if live:
            _render(config, stats)
            print()

    return dict(stats.snapshot())
