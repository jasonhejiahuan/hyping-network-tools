import math
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import termios
import threading
import time
import tty
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Literal

ProbeProtocol = Literal["icmp", "tcp"]
_PING_TIME_RE = re.compile(r"time[=<]([0-9.]+)\s*ms")
ANSI_RESET = "\033[0m"
ANSI_BOLD = "1"
ANSI_DIM = "2"
ANSI_ORANGE = "38;5;166"
ANSI_CYAN = "38;5;31"
ANSI_TEAL = "38;5;37"
ANSI_GREEN = "38;5;35"
ANSI_RED = "38;5;160"
ANSI_MUTED = "38;5;245"


def _supports_color() -> bool:
    return (
        sys.stdout.isatty()
        and sys.stdout.encoding is not None
        and sys.platform != "win32"
        and "NO_COLOR" not in os.environ
        and os.environ.get("TERM", "dumb") != "dumb"
    )


def _style(text: object, *codes: str) -> str:
    value = str(text)
    if not codes or not _supports_color():
        return value
    return f"\033[{';'.join(codes)}m{value}{ANSI_RESET}"


def _muted(text: object) -> str:
    return _style(text, ANSI_MUTED)


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
    payload_size: int = 0
    tcp_keep_open: bool = False


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
    bytes_sent: int = 0
    last_sample_at: float = field(default_factory=time.perf_counter)
    last_sample_completed: int = 0
    last_sample_bytes_sent: int = 0
    recent_rates: deque[float] = field(default_factory=lambda: deque(maxlen=5000))
    recent_bandwidths_Bps: deque[float] = field(
        default_factory=lambda: deque(maxlen=5000)
    )
    recent_latencies_ms: deque[float] = field(
        default_factory=lambda: deque(maxlen=5000)
    )
    lock: threading.Lock = field(default_factory=threading.Lock)

    def mark_issued(self) -> None:
        with self.lock:
            self.issued += 1
            self.in_flight += 1

    def mark_done(self, *, success: bool, latency_ms: float, bytes_sent: int) -> None:
        with self.lock:
            self.completed += 1
            self.in_flight = max(0, self.in_flight - 1)
            self.bytes_sent += max(0, bytes_sent)
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

    def mark_sample(self) -> None:
        with self.lock:
            now = time.perf_counter()
            elapsed = now - self.last_sample_at
            if elapsed <= 0:
                return

            completed_delta = self.completed - self.last_sample_completed
            bytes_delta = self.bytes_sent - self.last_sample_bytes_sent
            self.recent_rates.append(completed_delta / elapsed)
            self.recent_bandwidths_Bps.append(bytes_delta / elapsed)
            self.last_sample_at = now
            self.last_sample_completed = self.completed
            self.last_sample_bytes_sent = self.bytes_sent

    def finish(self) -> None:
        with self.lock:
            self.finished_at = time.perf_counter()

    def snapshot(self, *, include_series: bool = False) -> dict[str, object]:
        with self.lock:
            now = self.finished_at or time.perf_counter()
            elapsed = max(now - self.started_at, 0.000001)
            recent = list(self.recent_latencies_ms)
            recent_rates = list(self.recent_rates)
            recent_bandwidths = list(self.recent_bandwidths_Bps)
            avg_latency = (
                self.total_latency_ms / self.completed if self.completed else None
            )
            p95_latency = _percentile(recent, 95) if recent else None
            rate = self.completed / elapsed
            bandwidth = self.bytes_sent / elapsed
            summary: dict[str, object] = {
                "elapsed": elapsed,
                "issued": self.issued,
                "completed": self.completed,
                "succeeded": self.succeeded,
                "failed": self.failed,
                "in_flight": self.in_flight,
                "rate": rate,
                "avg_rate": rate if self.completed else None,
                "min_rate": min(recent_rates) if recent_rates else None,
                "max_rate": max(recent_rates) if recent_rates else None,
                "recent_p95_rate": _percentile(recent_rates, 95)
                if recent_rates
                else None,
                "bytes_sent": self.bytes_sent,
                "bandwidth_Bps": bandwidth,
                "avg_bandwidth_Bps": bandwidth if self.bytes_sent else None,
                "min_bandwidth_Bps": min(recent_bandwidths)
                if recent_bandwidths
                else None,
                "max_bandwidth_Bps": max(recent_bandwidths)
                if recent_bandwidths
                else None,
                "recent_p95_bandwidth_Bps": _percentile(recent_bandwidths, 95)
                if recent_bandwidths
                else None,
                "success_rate": self.succeeded / self.completed
                if self.completed
                else None,
                "avg_latency_ms": avg_latency,
                "min_latency_ms": self.min_latency_ms,
                "max_latency_ms": self.max_latency_ms,
                "recent_p95_latency_ms": p95_latency,
            }
            if include_series:
                summary.update(
                    {
                        "recent_rates": recent_rates,
                        "recent_bandwidths_Bps": recent_bandwidths,
                        "recent_latencies_ms": recent,
                    }
                )
            return summary


def _percentile(values: list[float], percentile: int) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * percentile / 100) - 1)
    return ordered[index]


def _format_ms(value: float | int | None) -> str:
    return "-" if value is None else f"{float(value):.2f} ms"


def _format_rate(value: float | int | None) -> str:
    return "-" if value is None else f"{float(value):.1f}/s"


def _format_bytes(value: float | int | None) -> str:
    if value is None:
        return "-"

    amount = float(value)
    units = ("B", "KB", "MB", "GB")
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024

    return f"{amount:.1f} {unit}"


def _format_bandwidth(value: float | int | None) -> str:
    return "-" if value is None else f"{_format_bytes(value)}/s"


def _terminal_width() -> int:
    return max(72, shutil.get_terminal_size(fallback=(100, 24)).columns)


def _progress_bar(done: int, total: int | None, *, width: int) -> str:
    if total is None or total <= 0:
        spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[done % 10]
        return f"{spinner} running"

    ratio = min(1.0, done / total)
    filled = round(width * ratio)
    return f"{'█' * filled}{'░' * (width - filled)} {ratio * 100:5.1f}%"


def _sample_values(values: list[float], width: int) -> list[float]:
    if width <= 0 or not values:
        return []
    if len(values) <= width:
        return values

    sampled: list[float] = []
    step = len(values) / width
    for index in range(width):
        start = int(index * step)
        end = max(start + 1, int((index + 1) * step))
        bucket = values[start:end]
        sampled.append(sum(bucket) / len(bucket))
    return sampled


def _sparkline(values: list[float], width: int) -> str:
    samples = _sample_values(values, width)
    if not samples:
        return "·" * max(1, min(width, 12))

    low = min(samples)
    high = max(samples)
    blocks = "▁▂▃▄▅▆▇█"
    if high <= low:
        return blocks[0] * len(samples)

    return "".join(
        blocks[min(len(blocks) - 1, int((value - low) / (high - low) * 7))]
        for value in samples
    )


def _area_chart(values: list[float], width: int, *, height: int = 4) -> list[str]:
    samples = _sample_values(values, width)
    if not samples:
        return [_muted("尚无足够样本，测试开始后会实时绘制趋势。")]

    low = min(samples)
    high = max(samples)
    if high <= low:
        high = low + 1

    lines: list[str] = []
    for row in range(height, 0, -1):
        threshold = low + (high - low) * row / height
        line = "".join("█" if value >= threshold else " " for value in samples)
        lines.append(line.rstrip() or " ")
    return lines


def _float_series(value: object) -> list[float]:
    if not isinstance(value, list):
        return []
    series: list[float] = []
    for item in value:
        try:
            series.append(float(item))
        except (TypeError, ValueError):
            continue
    return series


def _print_chart(
    title: str,
    values: list[float],
    *,
    width: int,
    color: str,
    formatter,
) -> None:
    if values:
        latest = formatter(values[-1])
        peak = formatter(max(values))
        header = f"{title:<8} {_sparkline(values, width)}  now {latest} · peak {peak}"
    else:
        header = f"{title:<8} {'·' * min(width, 24)}"

    print(_style(header, color, ANSI_BOLD))
    for line in _area_chart(values, width):
        print(_style(f"  {line}", color, ANSI_DIM))


def _ping_args(target: str, timeout: float, payload_size: int) -> list[str]:
    if sys.platform == "darwin":
        wait_arg = str(max(100, int(timeout * 1000)))
    else:
        wait_arg = str(max(1, math.ceil(timeout)))

    args = ["ping", "-n", "-c", "1", "-W", wait_arg]
    if payload_size > 0:
        args.extend(["-s", str(payload_size)])
    args.append(target)
    return args


def _icmp_probe(
    target: str,
    timeout: float,
    payload_size: int = 0,
) -> tuple[bool, float, int]:
    started = time.perf_counter()
    elapsed_ms = 0.0
    try:
        result = subprocess.run(
            _ping_args(target, timeout, payload_size),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout + 0.75,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        success = result.returncode == 0
        match = _PING_TIME_RE.search(result.stdout)
        if match is not None:
            return success, float(match.group(1)), payload_size if success else 0
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        elapsed_ms = (time.perf_counter() - started) * 1000
        success = False

    if elapsed_ms == 0.0:
        elapsed_ms = (time.perf_counter() - started) * 1000

    return success, elapsed_ms, payload_size if success else 0


def _tcp_probe(
    target: str,
    port: int,
    timeout: float,
    payload_size: int = 0,
) -> tuple[bool, float, int]:
    started = time.perf_counter()
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            bytes_sent = 0
            if payload_size > 0:
                sock.settimeout(timeout)
                payload = b"\0" * payload_size
                sock.sendall(payload)
                bytes_sent = payload_size
            success = True
    except OSError:
        return False, (time.perf_counter() - started) * 1000, 0

    return success, (time.perf_counter() - started) * 1000, bytes_sent


def _tcp_stream_until(
    target: str,
    port: int,
    timeout: float,
    payload_size: int,
    stop_event: threading.Event,
    deadline: float | None,
) -> tuple[bool, float, int]:
    started = time.perf_counter()
    chunk_size = payload_size or 65536
    payload = b"\0" * chunk_size
    bytes_sent = 0

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            while not stop_event.is_set():
                if deadline is not None and time.perf_counter() >= deadline:
                    break
                sock.sendall(payload)
                bytes_sent += chunk_size
    except OSError:
        return bytes_sent > 0, (time.perf_counter() - started) * 1000, bytes_sent

    return True, (time.perf_counter() - started) * 1000, bytes_sent


def _probe(config: LoadTestConfig) -> tuple[bool, float, int]:
    if config.protocol == "tcp":
        if config.tcp_port is None:
            msg = "tcp_port is required for tcp protocol"
            raise ValueError(msg)
        return _tcp_probe(
            config.target,
            config.tcp_port,
            config.timeout,
            config.payload_size,
        )

    return _icmp_probe(config.target, config.timeout, config.payload_size)


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
    if config.payload_size < 0:
        msg = "payload_size must not be negative"
        raise ValueError(msg)
    if config.protocol == "tcp" and config.tcp_port is None:
        msg = "tcp_port is required for tcp protocol"
        raise ValueError(msg)
    if config.tcp_keep_open and config.protocol != "tcp":
        msg = "tcp_keep_open can only be used with tcp protocol"
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
            if config.tcp_keep_open:
                if config.tcp_port is None:
                    raise ValueError
                success, latency_ms, bytes_sent = _tcp_stream_until(
                    config.target,
                    config.tcp_port,
                    config.timeout,
                    config.payload_size,
                    stop_event,
                    deadline,
                )
            else:
                success, latency_ms, bytes_sent = _probe(config)
        except Exception:
            success, latency_ms, bytes_sent = False, 0.0, 0

        stats.mark_done(
            success=success,
            latency_ms=latency_ms,
            bytes_sent=bytes_sent,
        )


class _LiveKeyboard:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and sys.stdin.isatty()
        self.fd: int | None = None
        self.previous: list[object] | None = None

    def __enter__(self) -> "_LiveKeyboard":
        if not self.enabled:
            return self
        try:
            self.fd = sys.stdin.fileno()
            self.previous = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
        except (termios.error, OSError):
            self.enabled = False
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.enabled and self.fd is not None and self.previous is not None:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.previous)

    def escape_pressed(self) -> bool:
        if not self.enabled or self.fd is None:
            return False
        try:
            ready, _, _ = select.select([sys.stdin], [], [], 0)
            if not ready:
                return False
            return sys.stdin.read(1) == "\x1b"
        except (OSError, ValueError):
            return False


def _render(config: LoadTestConfig, stats: LoadTestStats) -> None:
    width = _terminal_width()
    snap = stats.snapshot(include_series=True)
    target = f"{config.protocol}://{config.target}"
    if config.protocol == "tcp":
        target = f"{target}:{config.tcp_port}"

    print("\033[2J\033[H", end="")
    print(_style("Hyping 并发负载测试", ANSI_ORANGE, ANSI_BOLD))
    print(_muted("─" * min(width, 100)))
    print(f"{_muted('目标:')} {_style(target, ANSI_CYAN, ANSI_BOLD)}")
    print(
        f"{_muted('并发:')} {_style(config.concurrency, ANSI_ORANGE, ANSI_BOLD)}  "
        f"{_muted('超时:')} {config.timeout}s  "
        f"{_muted('负载:')} {_format_bytes(config.payload_size)}  "
        f"{_muted('渐进启动:')} {config.ramp_up}s  "
        f"{_muted('模式:')} {'包数' if config.count else '时长'}"
    )
    if config.tcp_keep_open:
        print(_style("TCP 模式: 保持连接并持续发送", ANSI_TEAL, ANSI_BOLD))
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
        f"{_muted('完成:')} {snap['completed']}  "
        f"{_muted('成功:')} {_style(snap['succeeded'], ANSI_GREEN, ANSI_BOLD)}  "
        f"{_muted('失败:')} {_style(snap['failed'], ANSI_RED, ANSI_BOLD)}  "
        f"{_muted('进行中:')} {snap['in_flight']}"
    )
    success_rate = (
        f"{float(snap['success_rate']) * 100:.1f}%"
        if snap["success_rate"] is not None
        else "-"
    )
    print(
        f"吞吐: {_format_rate(snap['rate'])}  "
        f"发送: {_format_bytes(snap['bytes_sent'])}  "
        f"带宽: {_format_bandwidth(snap['bandwidth_Bps'])}  "
        f"成功率: {success_rate}"
    )
    print(
        f"吞吐 avg/min/max/p95_recent: "
        f"{_format_rate(snap['avg_rate'])} / "
        f"{_format_rate(snap['min_rate'])} / "
        f"{_format_rate(snap['max_rate'])} / "
        f"{_format_rate(snap['recent_p95_rate'])}"
    )
    print(
        f"带宽 avg/min/max/p95_recent: "
        f"{_format_bandwidth(snap['avg_bandwidth_Bps'])} / "
        f"{_format_bandwidth(snap['min_bandwidth_Bps'])} / "
        f"{_format_bandwidth(snap['max_bandwidth_Bps'])} / "
        f"{_format_bandwidth(snap['recent_p95_bandwidth_Bps'])}"
    )
    print(
        f"延迟 avg/min/max/p95_recent: "
        f"{_format_ms(snap['avg_latency_ms'])} / "
        f"{_format_ms(snap['min_latency_ms'])} / "
        f"{_format_ms(snap['max_latency_ms'])} / "
        f"{_format_ms(snap['recent_p95_latency_ms'])}"
    )
    chart_width = min(64, max(24, width - 26))
    print()
    _print_chart(
        "吞吐趋势",
        _float_series(snap.get("recent_rates")),
        width=chart_width,
        color=ANSI_CYAN,
        formatter=_format_rate,
    )
    _print_chart(
        "延迟趋势",
        _float_series(snap.get("recent_latencies_ms")),
        width=chart_width,
        color=ANSI_ORANGE,
        formatter=_format_ms,
    )
    if int(snap["bytes_sent"] or 0) > 0:
        _print_chart(
            "带宽趋势",
            _float_series(snap.get("recent_bandwidths_Bps")),
            width=chart_width,
            color=ANSI_TEAL,
            formatter=_format_bandwidth,
        )
    print(_muted("\n按 Esc 或 Ctrl+C 停止。"))


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

            with _LiveKeyboard(live) as keyboard:
                while not stop_event.is_set():
                    if all(future.done() for future in futures):
                        break
                    if live and keyboard.escape_pressed():
                        stop_event.set()
                        break
                    if live:
                        stats.mark_sample()
                        _render(config, stats)
                    time.sleep(config.refresh_interval)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        stop_event.set()
        stats.finish()
        if live:
            stats.mark_sample()
            _render(config, stats)
            print()

    return dict(stats.snapshot())
