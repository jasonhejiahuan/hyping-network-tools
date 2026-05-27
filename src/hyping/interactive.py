import json
import os
import shutil
import sys
from collections.abc import Mapping
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

from hyping.config import ensure_config
from hyping.discovery.arp import can_run_active_arp_scan, list_network_devices
from hyping.discovery.bettercap import (
    BettercapAPIError,
    BettercapClient,
    list_bettercap_hosts,
    record_from_bettercap_host,
)
from hyping.discovery.mdns import (
    DEFAULT_SERVICE_TYPES,
    find_mdns_services_by_hostname,
    format_mdns_key_values,
    format_mdns_service,
    merge_mdns_services,
)
from hyping.discovery.network import (
    detect_local_ipv4_network,
    detect_local_network_info,
)
from hyping.discovery.resolver import DeviceNotFoundError, locate_devices
from hyping.loadtest import LoadTestConfig, run_load_test
from hyping.models.device import Device
from hyping.storage import (
    DEFAULT_STORE_PATH,
    DeviceRecord,
    load_device_records,
    note_hosts_from_records,
    save_device_records,
    upsert_device_record,
)

MIN_TERMINAL_WIDTH = 72


def _terminal_width() -> int:
    return max(MIN_TERMINAL_WIDTH, shutil.get_terminal_size(fallback=(100, 24)).columns)


def _clip(value: object, width: int) -> str:
    text = "-" if value is None or value == "" else str(value)
    if width <= 1:
        return text[:width]
    if len(text) <= width:
        return text
    return f"{text[: width - 1]}…"


def _clear_screen() -> None:
    """Clear the terminal when running interactively."""

    if not sys.stdout.isatty():
        return

    command = "cls" if os.name == "nt" else "clear"
    os.system(command)


def _pause() -> None:
    if sys.stdin.isatty():
        input("\n按 Enter 返回菜单...")


def _title(text: str) -> None:
    width = _terminal_width()
    print(text)
    print("─" * min(width, 100))


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return default if not value and default is not None else value


def _yes(prompt: str, *, default: bool = True) -> bool:
    default_text = "Y/n" if default else "y/N"
    value = input(f"{prompt} [{default_text}]: ").strip().casefold()
    if not value:
        return default

    return value in {"y", "yes", "是", "好"}


def _current_summary(record: DeviceRecord | None) -> str:
    if record is None:
        return "当前设备：无"

    hostname = record.get("hostname") or "-"
    ip = record.get("ip") or "-"
    mac = record.get("mac") or "-"
    note = record.get("note") or "-"
    return f"当前设备：{hostname} | {ip} | {mac} | {note}"


def _merge_current(
    current: DeviceRecord | None,
    record: DeviceRecord,
) -> DeviceRecord:
    return {**(current or {}), **record}


def _print_record(index: int, record: DeviceRecord) -> None:
    width = _terminal_width()
    fixed = 2 + 2 + 15 + 2 + 17 + 2
    hostname_width = max(18, min(32, (width - fixed) // 2))
    note_width = max(10, width - fixed - hostname_width)
    hostname = record.get("hostname") or "-"
    ip = record.get("ip") or "-"
    mac = record.get("mac") or "-"
    note = record.get("note") or "-"
    if note == "-":
        note = record.get("vendor") or "-"
    print(
        f"{index:>2}. "
        f"{_clip(hostname, hostname_width):<{hostname_width}}  "
        f"{_clip(ip, 15):<15}  "
        f"{_clip(mac, 17):<17}  "
        f"{_clip(note, note_width)}"
    )


def _show_records(records: list[DeviceRecord]) -> None:
    if not records:
        print("还没有保存设备。")
        return

    width = _terminal_width()
    print(" #  hostname                         ip              mac               note")
    print("─" * min(width, 100))
    for index, record in enumerate(records, start=1):
        _print_record(index, record)


def _record_from_located_device(device) -> DeviceRecord:
    return {
        "ip": str(device.ip),
        "mac": device.mac,
        "hostname": device.hostname,
        "note": device.note,
    }


def _record_from_scan_item(item) -> DeviceRecord:
    if hasattr(item, "display_name"):
        return record_from_bettercap_host(item)

    return _record_from_located_device(item)


def _record_title(record: DeviceRecord) -> str:
    return str(
        record.get("hostname")
        or record.get("ip")
        or record.get("mac")
        or record
    )


def _save_record(store_path: Path, record: DeviceRecord) -> None:
    records = load_device_records(store_path)
    upsert_device_record(records, record)
    save_device_records(records, store_path)
    print(f"已保存到 {store_path}")


def _note_hosts_with_current(
    records: list[DeviceRecord],
    current: DeviceRecord | None,
) -> dict[str, str]:
    note_hosts = note_hosts_from_records(records)
    if current is not None:
        note = current.get("note")
        hostname = current.get("hostname")
        if isinstance(note, str) and note and isinstance(hostname, str) and hostname:
            note_hosts[note] = hostname

    return note_hosts


def _devices_from_records(records: list[DeviceRecord]) -> list[Device]:
    devices: list[Device] = []

    for record in records:
        ip = record.get("ip")
        mac = record.get("mac")
        if not isinstance(ip, str) or not ip.strip():
            continue
        if not isinstance(mac, str) or not mac.strip():
            continue

        try:
            address = IPv4Address(ip.strip())
        except ValueError:
            continue

        hostname = record.get("hostname")
        note = record.get("note")
        devices.append(
            Device(
                ip=address,
                mac=mac.strip(),
                hostname=hostname.strip() if isinstance(hostname, str) else None,
                note=note.strip() if isinstance(note, str) else None,
            )
        )

    return devices


def _known_devices_with_current(
    records: list[DeviceRecord],
    current: DeviceRecord | None,
) -> list[Device]:
    known_records = [*records]
    if current is not None:
        known_records.append(current)

    return _devices_from_records(known_records)


def _choose_record(records: list[DeviceRecord], prompt: str) -> DeviceRecord | None:
    if not records:
        print("没有可选择的设备。")
        return None

    _show_records(records)
    raw_index = _ask(prompt)
    try:
        index = int(raw_index) - 1
    except ValueError:
        print("编号无效。")
        return None

    if index < 0 or index >= len(records):
        print("编号不存在。")
        return None

    return records[index]


def _located_devices_action_flow(
    store_path: Path,
    records: list[DeviceRecord],
) -> DeviceRecord | None:
    current: DeviceRecord | None = None

    while True:
        _title("搜索结果")
        _show_records(records)
        if current is not None:
            print(_clip(_current_summary(current), _terminal_width()))

        print(
            "\n请选择操作：\n"
            "  1. 选择一台作为当前设备\n"
            "  2. 保存一台设备\n"
            "  3. 保存全部设备\n"
            "  4. 查看一台设备详情\n"
            "  5. 返回"
        )
        choice = _ask("输入编号", "1")
        _clear_screen()

        if choice == "1":
            selected = _choose_record(records, "输入要设为当前设备的编号")
            if selected is not None:
                current = selected
                print(f"已设为当前设备：{_record_title(selected)}")
            _pause()
            _clear_screen()
        elif choice == "2":
            selected = _choose_record(records, "输入要保存的编号")
            if selected is not None:
                _save_record(store_path, selected)
            _pause()
            _clear_screen()
        elif choice == "3":
            for record in records:
                _save_record(store_path, record)
            _pause()
            _clear_screen()
        elif choice == "4":
            selected = _choose_record(records, "输入要查看详情的编号")
            if selected is not None:
                print(json.dumps(selected, ensure_ascii=False, indent=2))
            _pause()
            _clear_screen()
        elif choice == "5":
            return current
        else:
            print("未知选项，请重新输入。")
            _pause()
            _clear_screen()


def _scan_network_flow(
    store_path: Path,
    config: Mapping[str, Any],
) -> DeviceRecord | None:
    _title("列出当前网段设备")

    scan_config = config.get("scan", {})
    bettercap_config = config.get("bettercap", {})

    scanner = str(scan_config.get("scanner", "bettercap")).casefold()
    network = str(scan_config.get("network", "auto"))
    timeout = float(scan_config.get("timeout", 0.5))
    passes = int(scan_config.get("passes", 3))
    batch_size = int(scan_config.get("batch_size", 64))
    interval = float(scan_config.get("interval", 0.002))
    resolve_hostnames = bool(scan_config.get("resolve_hostnames", True))

    api_url = str(bettercap_config.get("url", "http://127.0.0.1:8081"))
    api_user = str(bettercap_config.get("username", "user"))
    api_pass = str(bettercap_config.get("password", "pass"))
    api_timeout = float(bettercap_config.get("api_timeout", 3.0))
    wait = float(bettercap_config.get("wait", 5.0))
    poll_interval = float(bettercap_config.get("poll_interval", 0.5))
    start_discovery = bool(bettercap_config.get("start_discovery", True))
    discovery_warmup = float(bettercap_config.get("discovery_warmup", 3.0))

    try:
        print("\n将使用这些参数：")
        print(f"扫描来源: {scanner}")
        if scanner == "bettercap":
            print(f"Bettercap API 地址: {api_url}")
            print(f"Bettercap 用户名: {api_user}")
            print(f"API 超时时间秒: {api_timeout}")
            print(f"持续读取 Bettercap 秒数: {wait}")
            print(f"刷新间隔秒: {poll_interval}")
            print(f"自动启动 net.recon/net.probe: {'是' if start_discovery else '否'}")
            print(f"net.recon/net.probe 预热秒数: {discovery_warmup}")
        elif scanner == "builtin":
            print(f"扫描网段: {network}")
            print(f"每批等待秒: {timeout}")
            print(f"扫描轮数: {passes}")
            print(f"每批扫描 IP 数: {batch_size}")
            print(f"ARP 包间隔秒: {interval}")
            print(f"解析 hostname: {'是' if resolve_hostnames else '否'}")
        else:
            print("扫描来源只能是 bettercap 或 builtin。")
            return None

        if _yes("是否修改参数", default=False):
            scanner = _ask("扫描来源 bettercap/builtin", scanner).casefold()
            if scanner not in {"bettercap", "builtin"}:
                print("扫描来源只能是 bettercap 或 builtin。")
                return None

            if scanner == "bettercap":
                api_url = _ask("Bettercap API 地址", api_url)
                api_user = _ask("Bettercap 用户名", api_user)
                api_pass = _ask("Bettercap 密码", api_pass)
                api_timeout = float(_ask("API 超时时间秒", str(api_timeout)))
                wait = float(_ask("持续读取 Bettercap 秒数", str(wait)))
                poll_interval = float(_ask("刷新间隔秒", str(poll_interval)))
                start_discovery = _yes(
                    "是否自动启动 net.recon/net.probe",
                    default=start_discovery,
                )
                discovery_warmup = float(
                    _ask("net.recon/net.probe 预热秒数", str(discovery_warmup))
                )
            else:
                network = _ask("扫描网段；auto 表示自动检测", network)
                timeout = float(_ask("每批等待秒；0.3-1.0 通常够用", str(timeout)))
                passes = int(_ask("扫描轮数；轮数越多发现越全", str(passes)))
                batch_size = int(_ask("每批扫描 IP 数", str(batch_size)))
                interval = float(_ask("ARP 包间隔秒", str(interval)))
                resolve_hostnames = _yes(
                    "是否尝试解析 hostname",
                    default=resolve_hostnames,
                )

        if scanner == "builtin":
            if not network or network.casefold() == "auto":
                detected = detect_local_ipv4_network()
                if detected:
                    network = detected
                    print(f"已自动检测本机网段：{network}")
                else:
                    print("未能自动检测本机网段。")
                    return None

            if not can_run_active_arp_scan():
                print("当前没有 root 权限，无法主动扫描整个网段。")
                print("建议使用 Bettercap；或用 sudo 启动内置扫描。")
                return None
    except ValueError:
        print("参数格式无效。")
        return None

    live_records: list[DeviceRecord] = []

    def on_device(device) -> None:
        record = _record_from_scan_item(device)
        live_records.append(record)
        _print_record(len(live_records), record)

    print("\n实时发现：")
    print(" #  hostname                         ip              mac               note")
    print("─" * min(_terminal_width(), 100))

    try:
        if scanner == "bettercap":
            client = BettercapClient(
                api_url,
                api_user,
                api_pass,
                timeout=api_timeout,
            )
            devices = list_bettercap_hosts(
                client,
                wait=wait,
                poll_interval=poll_interval,
                start_discovery=start_discovery,
                discovery_warmup=discovery_warmup,
                on_discovery_starting=lambda module: print(
                    f"{module} 正在启动，等待 {discovery_warmup:g} 秒预热...",
                    flush=True,
                ),
                on_host=on_device,
            )
        else:
            devices = list_network_devices(
                network,
                timeout=timeout,
                passes=passes,
                batch_size=batch_size,
                interval=interval,
                resolve_hostnames=resolve_hostnames,
                on_device=on_device,
            )
    except BettercapAPIError as exc:
        print(f"扫描失败：{exc}")
        return None
    except Exception as exc:
        print(f"扫描失败：{exc}")
        return None

    if not devices:
        print("没有发现设备。")
        return None

    records = [_record_from_scan_item(device) for device in devices]
    print(f"发现 {len(records)} 台设备：")
    return _located_devices_action_flow(store_path, records)


def _locate_flow(
    store_path: Path,
    current: DeviceRecord | None = None,
) -> DeviceRecord | None:
    _title("通过 hostname/note 查询 IP 和 MAC")
    records = load_device_records(store_path)
    default_hostname = current.get("hostname") if current else None
    default_note = current.get("note") if current else None
    hostname = _ask("hostname，可留空", default_hostname)
    note = _ask("note/备注，可留空", default_note)
    network = _ask("ARP 扫描网段；留空自动检测，输入 none 跳过")
    if not network:
        network = detect_local_ipv4_network()
        if network:
            print(f"已自动检测本机网段：{network}")
        else:
            print("未能自动检测本机网段，将跳过 ARP 扫描。")
    elif network.casefold() in {"none", "no", "skip", "跳过"}:
        network = ""
    if network and not can_run_active_arp_scan():
        print("当前没有 root 权限，已跳过主动 ARP 扫描。")
        print("仍会尝试 DNS/mDNS 和系统 ARP 缓存；如需全网 ARP 扫描请用 sudo 运行。")
        network = ""
    partial_hostname = _yes("是否允许 hostname 部分匹配", default=True)
    partial_note = _yes("是否允许 note 部分匹配", default=False)
    timeout = float(_ask("超时时间秒", "1.0"))

    try:
        devices = locate_devices(
            hostname=hostname or None,
            note=note or None,
            network=network or None,
            devices=_known_devices_with_current(records, current),
            note_hosts=_note_hosts_with_current(records, current),
            timeout=timeout,
            partial_hostname=partial_hostname,
            partial_note=partial_note,
        )
    except (DeviceNotFoundError, ValueError) as exc:
        print(f"查询失败：{exc}")
        return current

    if not devices:
        print("没有找到匹配设备。")
        return current

    found_records = [_record_from_located_device(device) for device in devices]
    print(f"找到 {len(found_records)} 台设备：")
    selected = _located_devices_action_flow(store_path, found_records)
    if selected is not None:
        return selected

    return current


def _mdns_flow(
    store_path: Path,
    current: DeviceRecord | None = None,
) -> DeviceRecord | None:
    _title("查询 mDNS/Bonjour 详细信息")
    default_hostname = current.get("hostname") if current else None
    hostname = _ask("hostname，例如 haozdeMacBook-Air.local", default_hostname)
    if not hostname:
        print("hostname 不能为空。")
        return current

    service_type_text = _ask(
        "服务类型，逗号分隔；留空则扫描常见类型",
    )
    service_types = (
        tuple(part.strip() for part in service_type_text.split(",") if part.strip())
        if service_type_text
        else DEFAULT_SERVICE_TYPES
    )
    timeout = float(_ask("每步超时时间秒", "1.0"))
    first = _yes("是否只显示第一条匹配服务", default=False)
    merge = _yes("是否合并同一 hostname 的多条服务", default=True)

    try:
        services = find_mdns_services_by_hostname(
            hostname,
            service_types=service_types,
            timeout=timeout,
            first=first,
        )
    except FileNotFoundError:
        print("查询失败：找不到 dns-sd 命令。")
        return current

    if not services:
        print("没有找到匹配的 mDNS 服务。")
        return current

    values = merge_mdns_services(services)
    if merge:
        print(format_mdns_key_values(values))
    else:
        print("\n\n".join(format_mdns_service(service) for service in services))

    record: DeviceRecord = _merge_current(
        current,
        {
            "hostname": values.get("hostname") or hostname.rstrip("."),
            "note": values.get("note"),
            "mdns": values,
        },
    )
    if _yes("是否保存这些 mDNS 信息"):
        _save_record(store_path, record)

    return record


def _delete_flow(store_path: Path) -> None:
    _title("删除已保存设备")
    records = load_device_records(store_path)
    _show_records(records)
    if not records:
        return

    raw_index = _ask("输入要删除的编号")
    try:
        index = int(raw_index) - 1
    except ValueError:
        print("编号无效。")
        return

    if index < 0 or index >= len(records):
        print("编号不存在。")
        return

    removed = records.pop(index)
    save_device_records(records, store_path)
    print(f"已删除：{removed.get('hostname') or removed.get('ip') or removed}")


def _select_saved_flow(store_path: Path) -> DeviceRecord | None:
    _title("选择已保存设备为当前设备")
    records = load_device_records(store_path)
    _show_records(records)
    if not records:
        return None

    raw_index = _ask("输入要设为当前设备的编号")
    try:
        index = int(raw_index) - 1
    except ValueError:
        print("编号无效。")
        return None

    if index < 0 or index >= len(records):
        print("编号不存在。")
        return None

    record = records[index]
    print(f"已设为当前设备：{record.get('hostname') or record.get('ip') or record}")
    return record


def _saved_devices_flow(
    store_path: Path,
    current: DeviceRecord | None = None,
) -> DeviceRecord | None:
    """Manage saved devices from a secondary menu."""

    while True:
        _clear_screen()
        _title("已保存设备管理")
        print(_clip(_current_summary(current), _terminal_width()))
        print(
            "\n请选择操作：\n"
            "  1. 查看已保存设备\n"
            "  2. 选择已保存设备为当前设备\n"
            "  3. 删除已保存设备\n"
            "  4. 返回主菜单"
        )
        choice = _ask("输入编号", "1")
        _clear_screen()

        if choice == "1":
            _title("查看已保存设备")
            _show_records(load_device_records(store_path))
            _pause()
        elif choice == "2":
            selected = _select_saved_flow(store_path)
            if selected is not None:
                current = selected
            _pause()
        elif choice == "3":
            _delete_flow(store_path)
            _pause()
        elif choice == "4":
            return current
        else:
            print("未知选项，请重新输入。")
            _pause()


def _load_test_flow(
    current: DeviceRecord | None = None,
    config: Mapping[str, Any] | None = None,
) -> None:
    _title("并发 ping / TCP 负载测试")
    load_config = (config or {}).get("load", {})
    default_target = None
    if current is not None:
        default_target = current.get("ip") or current.get("hostname")

    target = _ask("目标 IP 或 hostname", default_target)
    if not target:
        print("目标不能为空。")
        return

    protocol = _ask(
        "协议 icmp/tcp",
        str(load_config.get("protocol", "icmp")),
    ).casefold()
    if protocol not in {"icmp", "tcp"}:
        print("协议只能是 icmp 或 tcp。")
        return

    port: int | None = (
        int(load_config.get("tcp_port", 5000))
        if protocol == "tcp"
        else None
    )
    concurrency = int(load_config.get("concurrency", 32))
    duration_value = load_config.get("duration", 10.0)
    duration: float | None = None if duration_value is None else float(duration_value)
    count_value = load_config.get("count")
    count: int | None = None if count_value is None else int(count_value)
    timeout = float(load_config.get("timeout", 1.0))
    payload_size = int(load_config.get("payload_size", 0))
    tcp_keep_open = bool(load_config.get("tcp_keep_open", False))
    ramp_up = float(load_config.get("ramp_up", 0.75))
    jitter = float(load_config.get("per_worker_jitter", 0.002))

    try:
        print("\n将使用这些参数：")
        print(f"目标: {target}")
        print(f"协议: {protocol}")
        if protocol == "tcp":
            print(f"TCP 端口: {port}")
            print(f"保持连接持续发送: {'是' if tcp_keep_open else '否'}")
        print(f"并发线程数: {concurrency}")
        print(f"持续时间秒: {duration}")
        print(f"总请求/包数: {'按持续时间' if count is None else count}")
        print(f"单次超时时间秒: {timeout}")
        print(f"每次发送负载字节数: {payload_size}")
        print(f"渐进启动秒数: {ramp_up}")
        print(f"线程错峰抖动秒数: {jitter}")

        if _yes("是否修改参数", default=False):
            if protocol == "tcp":
                port = int(_ask("TCP 端口", str(port)))
                tcp_keep_open = _yes(
                    "是否保持 TCP 连接并持续发送",
                    default=tcp_keep_open,
                )
            concurrency = int(_ask("并发线程数", str(concurrency)))
            duration_text = _ask("持续时间秒；输入 0 则仅按总数量", str(duration))
            count_text = _ask("总请求/包数；留空则按持续时间")
            timeout = float(_ask("单次超时时间秒", str(timeout)))
            payload_size = int(_ask("每次发送负载字节数；0 表示默认", "0"))
            ramp_up = float(_ask("渐进启动秒数；0 表示同时启动", str(ramp_up)))
            jitter = float(_ask("线程错峰抖动秒数", str(jitter)))

            duration = None if duration_text in {"", "0"} else float(duration_text)
            count = int(count_text) if count_text else None
            if duration is None and count is None:
                duration = float(load_config.get("duration", 10.0) or 10.0)
    except ValueError:
        print("参数格式无效。")
        return

    try:
        run_load_test(
            LoadTestConfig(
                target=target,
                protocol=protocol,  # type: ignore[arg-type]
                concurrency=concurrency,
                duration=duration,
                count=count,
                timeout=timeout,
                tcp_port=port,
                ramp_up=ramp_up,
                per_worker_jitter=jitter,
                payload_size=payload_size,
                tcp_keep_open=tcp_keep_open,
            )
        )
    except ValueError as exc:
        print(f"参数错误：{exc}")


def _is_elevated() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        return os.getuid() == 0
    except AttributeError:
        return False


def _format_network_status() -> str:
    info = detect_local_network_info()
    parts: list[str] = []

    if info.hardware_port:
        parts.append(info.hardware_port)
    elif info.interface:
        parts.append(info.interface)
    else:
        parts.append("未知网络")

    is_wifi = bool(info.hardware_port and "wi-fi" in info.hardware_port.casefold())
    if info.ssid:
        parts.append(f"SSID: {info.ssid}")
    elif is_wifi:
        parts.append("SSID: 未获取")
    if info.interface and info.hardware_port:
        parts.append(f"接口: {info.interface}")
    if info.ipv4_network:
        parts.append(f"网段: {info.ipv4_network}")

    return "当前网络：" + " | ".join(parts)


def _print_menu(store_path: Path, current: DeviceRecord | None) -> None:
    _title("Hyping 交互式网络设备工具")
    print(f"设备保存文件：{store_path}")
    if _is_elevated():
        print("运行权限：提升权限/root")
    print(_format_network_status())
    print(_clip(_current_summary(current), _terminal_width()))
    print(
        "\n请选择操作：\n"
        "  1. 通过 hostname/note 查询 IP 和 MAC\n"
        "  2. 列出当前网段设备\n"
        "  3. 查询 mDNS/Bonjour 详细信息\n"
        "  4. 管理已保存设备\n"
        "  5. 并发 ping / TCP 负载测试\n"
        "  6. 退出"
    )


def _shutdown_bettercap_on_exit(config: Mapping[str, Any]) -> None:
    bettercap_config = config.get("bettercap", {})
    if not bool(bettercap_config.get("shutdown_on_ui_exit", True)):
        return

    client = BettercapClient(
        str(bettercap_config.get("url", "http://127.0.0.1:8081")),
        str(bettercap_config.get("username", "user")),
        str(bettercap_config.get("password", "pass")),
        timeout=float(bettercap_config.get("api_timeout", 3.0)),
    )
    try:
        print("正在通过 Bettercap API 关闭 bettercap...", flush=True)
        client.shutdown()
        print("bettercap 已请求关闭。", flush=True)
    except BettercapAPIError as exc:
        print(f"关闭 bettercap 失败：{exc}", flush=True)


def run_interactive(
    store_path: Path = DEFAULT_STORE_PATH,
    config: Mapping[str, Any] | None = None,
) -> int:
    """Run the interactive command-line UI."""

    config = config or ensure_config()
    current: DeviceRecord | None = None

    try:
        while True:
            _clear_screen()
            _print_menu(store_path, current)
            choice = _ask("输入编号", "1")
            _clear_screen()

            if choice == "1":
                current = _locate_flow(store_path, current)
                _pause()
            elif choice == "2":
                selected = _scan_network_flow(store_path, config)
                if selected is not None:
                    current = selected
                _pause()
            elif choice == "3":
                current = _mdns_flow(store_path, current)
                _pause()
            elif choice == "4":
                current = _saved_devices_flow(store_path, current)
            elif choice == "5":
                _load_test_flow(current, config)
                _pause()
            elif choice == "6":
                return 0
            else:
                print("未知选项，请重新输入。")
                _pause()
    finally:
        _shutdown_bettercap_on_exit(config)
