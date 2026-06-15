import csv
import json
import os
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hyping.discovery.bettercap import (
    BettercapAPIError,
    BettercapClient,
    BettercapHost,
    ensure_bettercap_api_online,
    list_bettercap_hosts,
    record_from_bettercap_host,
    start_bettercap_api,
)
from hyping.discovery.wifi import (
    WiFiError,
    current_wifi_ssid,
    switch_wifi_network,
    wifi_interface,
)
from hyping.paths import (
    WIFI_ROTATION_PATH,
    copy_legacy_file_if_present,
    expand_runtime_path,
    legacy_hyping_path,
)
from hyping.storage import (
    DEFAULT_STORE_PATH,
    DeviceRecord,
    load_device_records,
    save_device_records,
    upsert_device_record,
)

DEFAULT_WIFI_ROTATION_PATH = WIFI_ROTATION_PATH


class AutoWiFiScanError(RuntimeError):
    """Raised when unattended Wi-Fi rotation cannot continue."""


@dataclass(slots=True, frozen=True)
class WiFiScanTarget:
    ssid: str
    password: str | None = None


@dataclass(slots=True, frozen=True)
class WiFiScanResult:
    ssid: str
    hosts: tuple[BettercapHost, ...]
    saved_count: int
    error: str | None = None


@dataclass(slots=True, frozen=True)
class AutoHostnameSearchResult:
    query: str
    host: BettercapHost | None
    ssid: str | None
    scanned_ssids: tuple[str, ...]
    saved_count: int = 0
    error: str | None = None


def expand_wifi_rotation_path(value: str | Path) -> Path:
    return expand_runtime_path(value)


def is_elevated() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        return os.getuid() == 0
    except AttributeError:
        return False


def _target_from_mapping(value: Mapping[str, Any]) -> WiFiScanTarget:
    ssid = value.get("ssid")
    if not isinstance(ssid, str) or not ssid.strip():
        msg = "Wi-Fi rotation entry is missing ssid"
        raise AutoWiFiScanError(msg)

    password = value.get("password")
    if password is not None and not isinstance(password, str):
        msg = f"Wi-Fi rotation password for {ssid!r} must be a string or null"
        raise AutoWiFiScanError(msg)

    return WiFiScanTarget(ssid=ssid.strip(), password=password or None)


def _targets_from_json(data: Any) -> list[WiFiScanTarget]:
    if isinstance(data, dict):
        data = data.get("wifi") or data.get("networks")

    if not isinstance(data, list):
        msg = "Wi-Fi rotation JSON must be a list or contain a networks list"
        raise AutoWiFiScanError(msg)

    targets: list[WiFiScanTarget] = []
    for value in data:
        if isinstance(value, str):
            ssid = value.strip()
            if ssid:
                targets.append(WiFiScanTarget(ssid=ssid))
            continue
        if isinstance(value, Mapping):
            targets.append(_target_from_mapping(value))
            continue

        msg = f"invalid Wi-Fi rotation entry: {value!r}"
        raise AutoWiFiScanError(msg)

    return targets


def _targets_from_csv(path: Path) -> list[WiFiScanTarget]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or "ssid" not in reader.fieldnames:
            msg = "Wi-Fi rotation CSV must include an ssid header"
            raise AutoWiFiScanError(msg)

        targets: list[WiFiScanTarget] = []
        for row in reader:
            targets.append(_target_from_mapping(row))

    return targets


def load_wifi_scan_targets(path: Path) -> list[WiFiScanTarget]:
    if not path.exists():
        msg = f"Wi-Fi rotation config not found: {path}"
        raise AutoWiFiScanError(msg)

    suffix = path.suffix.casefold()
    if suffix == ".csv":
        targets = _targets_from_csv(path)
    else:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            msg = f"invalid Wi-Fi rotation JSON: {path}"
            raise AutoWiFiScanError(msg) from exc
        targets = _targets_from_json(data)

    if not targets:
        msg = f"Wi-Fi rotation config has no SSIDs: {path}"
        raise AutoWiFiScanError(msg)
    return targets


def write_wifi_scan_template(path: Path = DEFAULT_WIFI_ROTATION_PATH) -> None:
    if path.exists():
        return

    if copy_legacy_file_if_present(legacy_hyping_path("wifi-rotation.json"), path):
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "networks": [
                    {"ssid": "SCBS-Student", "password": None},
                    {"ssid": "SCBS-Teacher", "password": None},
                    {"ssid": "SCBS-Staff", "password": None},
                ]
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def shutdown_bettercap(
    client: BettercapClient,
    *,
    on_status: Callable[[str], None] | None = None,
    require_stopped: bool = False,
) -> None:
    if not client.is_online(timeout=0.25):
        if on_status is not None:
            on_status("Bettercap API 未在线，无需关闭。")
        return

    if on_status is not None:
        on_status("正在关闭当前 Bettercap 核心...")
    try:
        client.shutdown()
    except BettercapAPIError as exc:
        if "could not reach Bettercap API" not in str(exc):
            raise

    deadline = time.monotonic() + 5.0
    while time.monotonic() <= deadline:
        if not client.is_online(timeout=0.25):
            if on_status is not None:
                on_status("Bettercap 已关闭。")
            return
        time.sleep(0.25)

    msg = "Bettercap API 关闭超时，未确认旧进程退出。"
    if require_stopped:
        raise BettercapAPIError(msg)
    if on_status is not None:
        on_status(msg)


def _records_from_hosts(
    hosts: Iterable[BettercapHost],
    *,
    ssid: str | None,
) -> list[DeviceRecord]:
    records: list[DeviceRecord] = []
    for host in hosts:
        record = record_from_bettercap_host(host)
        if ssid:
            record["ssid"] = ssid
        records.append(record)
    return records


def _save_hosts(
    hosts: Iterable[BettercapHost],
    *,
    ssid: str | None,
    store_path: Path,
) -> int:
    records = load_device_records(store_path)
    saved_count = 0
    for record in _records_from_hosts(hosts, ssid=ssid):
        before = list(records)
        records = upsert_device_record(records, record)
        if records != before:
            saved_count += 1
    save_device_records(records, store_path)
    return saved_count


def _password_for_ssid(
    targets: Iterable[WiFiScanTarget],
    ssid: str | None,
) -> str | None:
    if not ssid:
        return None

    normalized = ssid.strip().casefold()
    for target in targets:
        if target.ssid.strip().casefold() == normalized:
            return target.password
    return None


def _safe_current_wifi_ssid(interface: str | None) -> str | None:
    try:
        return current_wifi_ssid(interface)
    except WiFiError:
        return None


def _normalize_hostname(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().rstrip(".").casefold()
    return cleaned or None


def _host_names(host: BettercapHost) -> set[str]:
    names = {
        _normalize_hostname(host.hostname),
        _normalize_hostname(host.alias),
        _normalize_hostname(host.display_name),
    }
    return {name for name in names if name is not None}


def find_bettercap_host_by_hostname(
    hosts: Iterable[BettercapHost],
    hostname: str,
    *,
    partial: bool = False,
) -> BettercapHost | None:
    query = _normalize_hostname(hostname)
    if query is None:
        msg = "hostname 不能为空"
        raise AutoWiFiScanError(msg)

    for host in hosts:
        names = _host_names(host)
        if query in names:
            return host
        if partial and any(query in name for name in names):
            return host
    return None


def _scan_bettercap_hosts(
    client: BettercapClient,
    *,
    wait: float,
    poll_interval: float,
    discovery_warmup: float,
    label: str,
    on_status: Callable[[str], None] | None = None,
) -> tuple[BettercapHost, ...]:
    if on_status is not None:
        on_status(f"{label}：正在读取 Bettercap 主机列表，持续 {wait:g} 秒...")

    hosts = tuple(
        list_bettercap_hosts(
            client,
            wait=wait,
            poll_interval=poll_interval,
            start_discovery=True,
            discovery_warmup=discovery_warmup,
            on_discovery_starting=None
            if on_status is None
            else lambda module: on_status(
                f"{label}：{module} 正在启动，等待 {discovery_warmup:g} 秒预热..."
            ),
        )
    )
    if on_status is not None:
        if hosts:
            on_status(f"{label}：Bettercap 扫描完成，发现 {len(hosts)} 台设备。")
        else:
            on_status(f"{label}：Bettercap 未返回任何设备。")
    return hosts


def _ensure_bettercap_ready(
    client: BettercapClient,
    *,
    auto_start: bool,
    command: str,
    interface: str | None,
    online_check_timeout: float,
    startup_timeout: float,
    startup_poll_interval: float,
    on_status: Callable[[str], None] | None,
) -> None:
    if on_status is not None:
        on_status(f"正在检查 Bettercap API：{client.base_url}")
    launch = ensure_bettercap_api_online(
        client,
        online_check_timeout=online_check_timeout,
        auto_start=auto_start,
        command=command,
        interface=interface,
        startup_timeout=startup_timeout,
        startup_poll_interval=startup_poll_interval,
        on_status=on_status,
    )
    if on_status is not None:
        if launch is None:
            on_status(f"Bettercap API 已在线：{client.base_url}")
        else:
            on_status(f"Bettercap API 已就绪：{client.base_url}")


def find_hostname_with_bettercap_then_wifi_rotation(
    hostname: str,
    targets: Iterable[WiFiScanTarget],
    *,
    client: BettercapClient,
    interface: str | None = None,
    bettercap_command: str = "bettercap",
    auto_start_bettercap_api: bool = True,
    online_check_timeout: float = 0.25,
    startup_timeout: float = 8.0,
    startup_poll_interval: float = 0.25,
    bettercap_wait: float = 5.0,
    bettercap_poll: float = 0.5,
    discovery_warmup: float = 3.0,
    verify_timeout: float = 12.0,
    restore_original: bool = True,
    partial_hostname: bool = False,
    store_path: Path = DEFAULT_STORE_PATH,
    on_status: Callable[[str], None] | None = None,
) -> AutoHostnameSearchResult:
    query = _normalize_hostname(hostname)
    if query is None:
        msg = "hostname 不能为空"
        raise AutoWiFiScanError(msg)

    scanned_ssids: list[str] = []
    saved_total = 0

    if on_status is not None:
        on_status(f"正在使用当前 Bettercap 搜索 hostname：{hostname}")
    _ensure_bettercap_ready(
        client,
        auto_start=auto_start_bettercap_api,
        command=bettercap_command,
        interface=interface,
        online_check_timeout=online_check_timeout,
        startup_timeout=startup_timeout,
        startup_poll_interval=startup_poll_interval,
        on_status=on_status,
    )
    current_hosts = _scan_bettercap_hosts(
        client,
        wait=bettercap_wait,
        poll_interval=bettercap_poll,
        discovery_warmup=discovery_warmup,
        label="当前 Bettercap",
        on_status=on_status,
    )
    found = find_bettercap_host_by_hostname(
        current_hosts,
        hostname,
        partial=partial_hostname,
    )
    if found is not None:
        if on_status is not None:
            on_status(
                f"当前 Bettercap 已匹配 hostname：{found.display_name or found.ip}"
            )
        current_ssid = _safe_current_wifi_ssid(interface)
        saved_total += _save_hosts(
            current_hosts,
            ssid=current_ssid,
            store_path=store_path,
        )
        return AutoHostnameSearchResult(
            query=hostname,
            host=found,
            ssid=current_ssid,
            scanned_ssids=(),
            saved_count=saved_total,
        )
    if on_status is not None:
        if current_hosts:
            on_status(
                f"当前 Bettercap 发现 {len(current_hosts)} 台设备，"
                f"但未匹配 hostname：{hostname}"
            )
        else:
            on_status("当前 Bettercap 没有发现设备，将尝试 Wi-Fi 轮换。")

    if not is_elevated():
        msg = "当前 Bettercap 未找到；轮换 Wi-Fi 继续查找需要 sudo/root 权限"
        raise AutoWiFiScanError(msg)

    resolved_interface = interface or wifi_interface()
    target_list = list(targets)
    if not target_list:
        msg = "当前 Bettercap 未找到，且没有可轮换的 Wi-Fi SSID"
        raise AutoWiFiScanError(msg)

    original_ssid = current_wifi_ssid(resolved_interface)
    original_password = _password_for_ssid(target_list, original_ssid)
    try:
        for target in target_list:
            scanned_ssids.append(target.ssid)
            if on_status is not None:
                on_status(f"当前未找到，准备切换并扫描 Wi-Fi：{target.ssid}")
            try:
                shutdown_bettercap(
                    client,
                    on_status=on_status,
                    require_stopped=True,
                )
                switch_wifi_network(
                    target.ssid,
                    password=target.password,
                    interface=resolved_interface,
                    verify=True,
                    verify_timeout=verify_timeout,
                )
                start_bettercap_api(
                    client,
                    command=bettercap_command,
                    interface=resolved_interface,
                    startup_timeout=startup_timeout,
                    poll_interval=startup_poll_interval,
                    on_status=on_status,
                )
                if on_status is not None:
                    on_status(f"{target.ssid}：Bettercap API 已在线，开始扫描。")
                hosts = _scan_bettercap_hosts(
                    client,
                    wait=bettercap_wait,
                    poll_interval=bettercap_poll,
                    discovery_warmup=discovery_warmup,
                    label=target.ssid,
                    on_status=on_status,
                )
                saved_total += _save_hosts(
                    hosts,
                    ssid=target.ssid,
                    store_path=store_path,
                )
                found = find_bettercap_host_by_hostname(
                    hosts,
                    hostname,
                    partial=partial_hostname,
                )
                if found is not None:
                    if on_status is not None:
                        on_status(
                            f"{target.ssid}：已匹配 hostname："
                            f"{found.display_name or found.ip}"
                        )
                    return AutoHostnameSearchResult(
                        query=hostname,
                        host=found,
                        ssid=target.ssid,
                        scanned_ssids=tuple(scanned_ssids),
                        saved_count=saved_total,
                    )
                if on_status is not None:
                    if hosts:
                        on_status(
                            f"{target.ssid}：发现 {len(hosts)} 台设备，"
                            f"但未匹配 hostname：{hostname}"
                        )
                    else:
                        on_status(f"{target.ssid}：没有扫描到任何设备。")
            except (BettercapAPIError, WiFiError) as exc:
                shutdown_bettercap(
                    client,
                    on_status=on_status,
                    require_stopped=True,
                )
                if on_status is not None:
                    on_status(f"{target.ssid} 查找失败：{exc}")
                continue
    finally:
        shutdown_bettercap(client, on_status=on_status)
        if restore_original and original_ssid and original_ssid != current_wifi_ssid(
            resolved_interface
        ):
            if on_status is not None:
                on_status(f"正在恢复原 Wi-Fi：{original_ssid}")
            switch_wifi_network(
                original_ssid,
                password=original_password,
                interface=resolved_interface,
                verify=True,
                verify_timeout=verify_timeout,
            )

    return AutoHostnameSearchResult(
        query=hostname,
        host=None,
        ssid=None,
        scanned_ssids=tuple(scanned_ssids),
        saved_count=saved_total,
    )


def run_auto_wifi_scan(
    targets: Iterable[WiFiScanTarget],
    *,
    client: BettercapClient,
    interface: str | None = None,
    bettercap_command: str = "bettercap",
    startup_timeout: float = 8.0,
    startup_poll_interval: float = 0.25,
    bettercap_wait: float = 5.0,
    bettercap_poll: float = 0.5,
    discovery_warmup: float = 3.0,
    verify_timeout: float = 12.0,
    restore_original: bool = True,
    store_path: Path = DEFAULT_STORE_PATH,
    on_status: Callable[[str], None] | None = None,
) -> list[WiFiScanResult]:
    if not is_elevated():
        msg = "自动轮换 Wi-Fi 扫描需要 sudo/root 权限"
        raise AutoWiFiScanError(msg)

    resolved_interface = interface or wifi_interface()
    target_list = list(targets)
    if not target_list:
        msg = "没有可轮换的 Wi-Fi SSID"
        raise AutoWiFiScanError(msg)

    original_ssid = current_wifi_ssid(resolved_interface)
    original_password = _password_for_ssid(target_list, original_ssid)
    results: list[WiFiScanResult] = []

    try:
        for target in target_list:
            if on_status is not None:
                on_status(f"准备扫描 Wi-Fi：{target.ssid}")
            try:
                shutdown_bettercap(client, on_status=on_status)

                switch_wifi_network(
                    target.ssid,
                    password=target.password,
                    interface=resolved_interface,
                    verify=True,
                    verify_timeout=verify_timeout,
                )

                start_bettercap_api(
                    client,
                    command=bettercap_command,
                    interface=resolved_interface,
                    startup_timeout=startup_timeout,
                    poll_interval=startup_poll_interval,
                    on_status=on_status,
                )
                if on_status is not None:
                    on_status(f"{target.ssid}：Bettercap API 已在线，开始扫描。")

                hosts = _scan_bettercap_hosts(
                    client,
                    wait=bettercap_wait,
                    poll_interval=bettercap_poll,
                    discovery_warmup=discovery_warmup,
                    label=target.ssid,
                    on_status=on_status,
                )
                saved_count = _save_hosts(
                    hosts,
                    ssid=target.ssid,
                    store_path=store_path,
                )
                results.append(
                    WiFiScanResult(
                        ssid=target.ssid,
                        hosts=hosts,
                        saved_count=saved_count,
                    )
                )
                if on_status is not None:
                    on_status(
                        f"{target.ssid}：扫描完成，发现 {len(hosts)} 台，"
                        f"写入/更新 {saved_count} 条。"
                    )
            except (BettercapAPIError, WiFiError) as exc:
                shutdown_bettercap(client, on_status=on_status)
                if on_status is not None:
                    on_status(f"{target.ssid} 扫描失败：{exc}")
                results.append(
                    WiFiScanResult(
                        ssid=target.ssid,
                        hosts=(),
                        saved_count=0,
                        error=str(exc),
                    )
                )
    finally:
        shutdown_bettercap(client, on_status=on_status)
        if restore_original and original_ssid and original_ssid != current_wifi_ssid(
            resolved_interface
        ):
            if on_status is not None:
                on_status(f"正在恢复原 Wi-Fi：{original_ssid}")
            switch_wifi_network(
                original_ssid,
                password=original_password,
                interface=resolved_interface,
                verify=True,
                verify_timeout=verify_timeout,
            )

    return results
