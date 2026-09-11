import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from hyping.auto_wifi_scan import (
    AutoWiFiScanError,
    WiFiScanTarget,
    _ensure_bettercap_ready,
    _password_for_ssid,
    _scan_bettercap_hosts,
    is_elevated,
    shutdown_bettercap,
)
from hyping.discovery.arp import ARPScanError, list_network_devices
from hyping.discovery.bettercap import (
    BettercapAPIError,
    BettercapClient,
    record_from_bettercap_host,
    start_bettercap_api,
)
from hyping.discovery.network import detect_local_ipv4_network
from hyping.discovery.wifi import (
    WiFiError,
    current_wifi_ssid,
    switch_wifi_network,
    wifi_interface,
)
from hyping.fingerprint import unique_fingerprint_candidate
from hyping.storage import (
    DEFAULT_STORE_PATH,
    DeviceRecord,
    load_device_records,
    mac_addresses_from_record,
    merge_device_records,
    normalize_mac_address,
    observed_device_record,
    save_device_records,
    upsert_device_record,
)

ScannerBackend = Literal["bettercap", "builtin"]


@dataclass(slots=True, frozen=True)
class TrackingIdentity:
    display_name: str
    hostnames: tuple[str, ...]
    mac_addresses: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class DeviceTrackingResult:
    target: TrackingIdentity
    device: DeviceRecord | None
    ssid: str | None
    match_method: str | None
    scanner: ScannerBackend
    rounds: int
    scanned_ssids: tuple[str, ...]
    association_score: int | None = None
    association_evidence: tuple[str, ...] = ()

    @property
    def locked(self) -> bool:
        return self.device is not None


def _clean_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().casefold().rstrip(".")
    return cleaned or None


def tracking_identity(record: DeviceRecord) -> TrackingIdentity:
    names: list[str] = []
    for key in ("hostname", "alias"):
        name = _clean_name(record.get(key))
        if name is not None and name not in names:
            names.append(name)
    historical_names = record.get("hostnames")
    if isinstance(historical_names, list):
        for value in historical_names:
            name = _clean_name(value)
            if name is not None and name not in names:
                names.append(name)

    addresses = mac_addresses_from_record(record)
    if not names and not addresses:
        raise AutoWiFiScanError("保存设备必须至少包含 hostname 或有效 MAC 地址")

    display_name = str(
        record.get("note")
        or record.get("hostname")
        or record.get("mac")
        or "已保存设备"
    )
    return TrackingIdentity(display_name, tuple(names), addresses)


def match_tracking_record(
    identity: TrackingIdentity,
    record: DeviceRecord,
) -> str | None:
    address = normalize_mac_address(record.get("mac"))
    if address is not None and address in identity.mac_addresses:
        return "mac"

    candidate_names = [record.get("hostname"), record.get("alias")]
    extra_names = record.get("hostnames")
    if isinstance(extra_names, list):
        candidate_names.extend(extra_names)
    normalized = {_clean_name(value) for value in candidate_names}
    normalized.discard(None)
    if normalized & set(identity.hostnames):
        return "hostname"
    return None


def _records_from_bettercap(
    client: BettercapClient,
    *,
    wait: float,
    poll_interval: float,
    discovery_warmup: float,
    label: str,
    on_status: Callable[[str], None] | None,
) -> list[DeviceRecord]:
    hosts = _scan_bettercap_hosts(
        client,
        wait=wait,
        poll_interval=poll_interval,
        discovery_warmup=discovery_warmup,
        label=label,
        on_status=on_status,
    )
    records: list[DeviceRecord] = []
    for host in hosts:
        record = record_from_bettercap_host(host)
        record["alias"] = host.alias
        record["hostnames"] = [
            value for value in (host.hostname, host.alias) if value is not None
        ]
        records.append(record)
    return records


def _records_from_builtin(
    *,
    timeout: float,
    passes: int,
    batch_size: int,
    interval: float,
    on_status: Callable[[str], None] | None,
) -> list[DeviceRecord]:
    network = detect_local_ipv4_network()
    if network is None:
        raise AutoWiFiScanError("无法确定当前 Wi-Fi 的 IPv4 网段")
    if on_status is not None:
        on_status(f"内建扫描：正在扫描 {network}...")
    try:
        devices = list_network_devices(
            network,
            timeout=timeout,
            passes=passes,
            batch_size=batch_size,
            interval=interval,
            resolve_hostnames=True,
        )
    except ARPScanError as exc:
        raise AutoWiFiScanError(f"内建 ARP 扫描失败：{exc}") from exc
    return [
        {
            "ip": str(device.ip),
            "mac": device.mac,
            "hostname": device.hostname,
            "note": device.note,
        }
        for device in devices
    ]


def _save_observations(
    records: Iterable[DeviceRecord],
    *,
    ssid: str,
    source: ScannerBackend,
    store_path: Path,
) -> list[DeviceRecord]:
    stored = load_device_records(store_path)
    observations: list[DeviceRecord] = []
    for record in records:
        observation = observed_device_record(record, ssid=ssid, source=source)
        observations.append(observation)
        upsert_device_record(stored, observation)
    save_device_records(stored, store_path)
    return observations


def _lock_device(
    selected: DeviceRecord,
    found: DeviceRecord,
    *,
    ssid: str,
    source: ScannerBackend,
    match_method: str,
    association_score: int,
    association_evidence: tuple[str, ...],
    store_path: Path,
) -> DeviceRecord:
    records = load_device_records(store_path)
    locked = observed_device_record(found, ssid=ssid, source=source)
    locked = merge_device_records(selected, locked)
    latest_location = next(
        (
            location
            for location in locked.get("locations", [])
            if isinstance(location, dict) and location.get("ssid") == ssid
        ),
        {},
    )
    locked["tracking"] = {
        "locked": True,
        "ssid": ssid,
        "source": source,
        "match_method": match_method,
        "association_score": association_score,
        "association_evidence": list(association_evidence),
        "locked_at": latest_location.get("last_seen"),
    }
    selected_identity = tracking_identity(selected)
    found_mac = normalize_mac_address(found.get("mac"))
    records = [
        record
        for record in records
        if match_tracking_record(selected_identity, record) is None
        and (
            found_mac is None
            or found_mac not in mac_addresses_from_record(record)
        )
    ]
    records.append(locked)
    save_device_records(records, store_path)
    identity = tracking_identity(locked)
    locked["mac_addresses"] = list(identity.mac_addresses)
    return locked


def track_device_across_wifi(
    selected: DeviceRecord,
    targets: Iterable[WiFiScanTarget],
    *,
    scanner: ScannerBackend = "bettercap",
    client: BettercapClient | None = None,
    interface: str | None = None,
    bettercap_command: str = "bettercap",
    auto_start_bettercap_api: bool = True,
    online_check_timeout: float = 0.25,
    startup_timeout: float = 8.0,
    startup_poll_interval: float = 0.25,
    bettercap_wait: float = 5.0,
    bettercap_poll: float = 0.5,
    discovery_warmup: float = 3.0,
    scan_timeout: float = 0.5,
    scan_passes: int = 3,
    scan_batch_size: int = 64,
    scan_interval: float = 0.002,
    verify_timeout: float = 12.0,
    round_interval: float = 5.0,
    max_rounds: int = 0,
    restore_original_on_failure: bool = True,
    fingerprint_association: bool = True,
    fingerprint_threshold: int = 70,
    fingerprint_margin: int = 15,
    store_path: Path = DEFAULT_STORE_PATH,
    on_status: Callable[[str], None] | None = None,
) -> DeviceTrackingResult:
    """Continuously rotate Wi-Fi networks until an authorized device is found.

    A result is locked by a known MAC, exact hostname, or a unique high-confidence
    fingerprint candidate. Fingerprint decisions never use IP as identity.
    ``max_rounds=0`` keeps tracking until a match or keyboard interruption.
    """

    if scanner not in {"bettercap", "builtin"}:
        raise AutoWiFiScanError(f"不支持的扫描后端：{scanner}")
    if max_rounds < 0 or round_interval < 0:
        raise AutoWiFiScanError("轮次和轮次间隔不能为负数")
    if not 0 <= fingerprint_threshold <= 100 or fingerprint_margin < 0:
        raise AutoWiFiScanError("指纹阈值必须为 0-100，候选分差不能为负数")
    if not is_elevated():
        raise AutoWiFiScanError("跨 Wi-Fi 持续追踪需要 sudo/root 权限")
    if scanner == "bettercap" and client is None:
        raise AutoWiFiScanError("Bettercap 追踪需要 API 客户端")

    identity = tracking_identity(selected)
    known_macs = list(identity.mac_addresses)
    resolved_interface = interface or wifi_interface()
    target_list = list(targets)
    if not target_list:
        raise AutoWiFiScanError("没有可枚举的 Wi-Fi SSID")

    original_ssid = current_wifi_ssid(resolved_interface)
    original_password = _password_for_ssid(target_list, original_ssid)
    ordered_targets: list[WiFiScanTarget] = []
    if original_ssid:
        ordered_targets.append(WiFiScanTarget(original_ssid, original_password))
    for target in target_list:
        if not any(
            item.ssid.casefold() == target.ssid.casefold() for item in ordered_targets
        ):
            ordered_targets.append(target)

    rounds = 0
    scanned_ssids: list[str] = []
    locked = False
    try:
        while max_rounds == 0 or rounds < max_rounds:
            rounds += 1
            if on_status is not None:
                on_status(
                    f"追踪第 {rounds} 轮：目标 {identity.display_name}，"
                    f"已知 MAC {len(known_macs)} 个。"
                )
            for target in ordered_targets:
                scanned_ssids.append(target.ssid)
                try:
                    active_ssid = current_wifi_ssid(resolved_interface)
                    if active_ssid != target.ssid:
                        if scanner == "bettercap" and client is not None:
                            shutdown_bettercap(client, on_status=on_status)
                        if on_status is not None:
                            on_status(f"正在切换到候选位置：{target.ssid}")
                        switch_wifi_network(
                            target.ssid,
                            password=target.password,
                            interface=resolved_interface,
                            verify=True,
                            verify_timeout=verify_timeout,
                        )

                    if scanner == "bettercap":
                        assert client is not None
                        if active_ssid != target.ssid:
                            start_bettercap_api(
                                client,
                                command=bettercap_command,
                                interface=resolved_interface,
                                startup_timeout=startup_timeout,
                                poll_interval=startup_poll_interval,
                                on_status=on_status,
                            )
                        else:
                            _ensure_bettercap_ready(
                                client,
                                auto_start=auto_start_bettercap_api,
                                command=bettercap_command,
                                interface=resolved_interface,
                                online_check_timeout=online_check_timeout,
                                startup_timeout=startup_timeout,
                                startup_poll_interval=startup_poll_interval,
                                on_status=on_status,
                            )
                        raw_records = _records_from_bettercap(
                            client,
                            wait=bettercap_wait,
                            poll_interval=bettercap_poll,
                            discovery_warmup=discovery_warmup,
                            label=target.ssid,
                            on_status=on_status,
                        )
                    else:
                        raw_records = _records_from_builtin(
                            timeout=scan_timeout,
                            passes=scan_passes,
                            batch_size=scan_batch_size,
                            interval=scan_interval,
                            on_status=on_status,
                        )
                except (AutoWiFiScanError, BettercapAPIError, WiFiError) as exc:
                    if on_status is not None:
                        on_status(f"{target.ssid} 追踪失败，将继续：{exc}")
                    continue

                observations = _save_observations(
                    raw_records,
                    ssid=target.ssid,
                    source=scanner,
                    store_path=store_path,
                )
                current_identity = TrackingIdentity(
                    identity.display_name,
                    identity.hostnames,
                    tuple(known_macs),
                )
                for observation in observations:
                    method = match_tracking_record(current_identity, observation)
                    if method is None:
                        continue
                    address = normalize_mac_address(observation.get("mac"))
                    if address is not None and address not in known_macs:
                        known_macs.append(address)
                    evidence = (
                        "已知 MAC 精确匹配"
                        if method == "mac"
                        else "保存的 hostname 精确匹配"
                    )
                    result_record = _lock_device(
                        selected,
                        observation,
                        ssid=target.ssid,
                        source=scanner,
                        match_method=method,
                        association_score=100,
                        association_evidence=(evidence,),
                        store_path=store_path,
                    )
                    result_record["mac_addresses"] = known_macs
                    locked = True
                    if on_status is not None:
                        on_status(
                            f"已锁定设备：{identity.display_name} @ {target.ssid} "
                            f"（{method} 匹配）"
                        )
                    return DeviceTrackingResult(
                        target=TrackingIdentity(
                            identity.display_name,
                            identity.hostnames,
                            tuple(known_macs),
                        ),
                        device=result_record,
                        ssid=target.ssid,
                        match_method=method,
                        scanner=scanner,
                        rounds=rounds,
                        scanned_ssids=tuple(scanned_ssids),
                        association_score=100,
                        association_evidence=(evidence,),
                    )

                if fingerprint_association:
                    candidate = unique_fingerprint_candidate(
                        selected,
                        observations,
                        threshold=fingerprint_threshold,
                        margin=fingerprint_margin,
                    )
                    if candidate is not None:
                        best_match, best_record = candidate
                        address = normalize_mac_address(best_record.get("mac"))
                        if address is not None and address not in known_macs:
                            known_macs.append(address)
                        result_record = _lock_device(
                            selected,
                            best_record,
                            ssid=target.ssid,
                            source=scanner,
                            match_method="fingerprint",
                            association_score=best_match.score,
                            association_evidence=best_match.evidence,
                            store_path=store_path,
                        )
                        result_record["mac_addresses"] = known_macs
                        locked = True
                        if on_status is not None:
                            on_status(
                                f"已锁定设备：{identity.display_name} "
                                f"@ {target.ssid} "
                                f"（指纹 {best_match.score}/100）"
                            )
                        return DeviceTrackingResult(
                            target=TrackingIdentity(
                                identity.display_name,
                                identity.hostnames,
                                tuple(known_macs),
                            ),
                            device=result_record,
                            ssid=target.ssid,
                            match_method="fingerprint",
                            scanner=scanner,
                            rounds=rounds,
                            scanned_ssids=tuple(scanned_ssids),
                            association_score=best_match.score,
                            association_evidence=best_match.evidence,
                        )
            if max_rounds == 0 or rounds < max_rounds:
                if on_status is not None:
                    on_status(f"本轮未找到，{round_interval:g} 秒后继续追踪。")
                time.sleep(round_interval)
    finally:
        if scanner == "bettercap" and client is not None:
            shutdown_bettercap(client, on_status=on_status)
        if (
            not locked
            and restore_original_on_failure
            and original_ssid
            and current_wifi_ssid(resolved_interface) != original_ssid
        ):
            if on_status is not None:
                on_status(f"追踪结束，正在恢复原 Wi-Fi：{original_ssid}")
            switch_wifi_network(
                original_ssid,
                password=original_password,
                interface=resolved_interface,
                verify=True,
                verify_timeout=verify_timeout,
            )

    return DeviceTrackingResult(
        target=TrackingIdentity(
            identity.display_name,
            identity.hostnames,
            tuple(known_macs),
        ),
        device=None,
        ssid=None,
        match_method=None,
        scanner=scanner,
        rounds=rounds,
        scanned_ssids=tuple(scanned_ssids),
    )


__all__ = [
    "DeviceTrackingResult",
    "ScannerBackend",
    "TrackingIdentity",
    "match_tracking_record",
    "track_device_across_wifi",
    "tracking_identity",
]
