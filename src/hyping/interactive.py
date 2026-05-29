import json
import os
import shutil
import sys
import termios
import tty
from collections.abc import Callable, Mapping
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
    LocalNetworkInfo,
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
FAST_API_CHECK_TIMEOUT = 0.25
ANSI_RESET = "\033[0m"
ANSI_BOLD = "1"
ANSI_DIM = "2"
ANSI_ORANGE = "38;5;166"
ANSI_CYAN = "38;5;31"
ANSI_TEAL = "38;5;37"
ANSI_GREEN = "38;5;35"
ANSI_RED = "38;5;160"
ANSI_MUTED = "38;5;245"

_NETWORK_INFO_CACHE: LocalNetworkInfo | None = None


class BackRequested(Exception):
    """Raised when the user presses Esc to return to the previous screen."""


def _supports_color() -> bool:
    return (
        sys.stdout.isatty()
        and os.environ.get("TERM", "dumb") != "dumb"
        and "NO_COLOR" not in os.environ
    )


def _style(text: object, *codes: str) -> str:
    value = str(text)
    if not codes or not _supports_color():
        return value
    return f"\033[{';'.join(codes)}m{value}{ANSI_RESET}"


def _muted(text: object) -> str:
    return _style(text, ANSI_MUTED)


def _accent(text: object) -> str:
    return _style(text, ANSI_ORANGE, ANSI_BOLD)


def _cyan(text: object) -> str:
    return _style(text, ANSI_CYAN, ANSI_BOLD)


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

    print("\033[2J\033[H", end="", flush=True)


def _read_line_interactive(prompt: str) -> str:
    """Read a line while allowing Esc to return immediately on TTYs."""

    if not sys.stdin.isatty():
        return input(prompt)

    fd = sys.stdin.fileno()
    previous = termios.tcgetattr(fd)
    buffer: list[str] = []
    print(prompt, end="", flush=True)
    try:
        tty.setraw(fd)
        while True:
            char = sys.stdin.read(1)
            if char in {"\r", "\n"}:
                print()
                return "".join(buffer)
            if char == "\x1b":
                print()
                raise BackRequested
            if char == "\x03":
                raise KeyboardInterrupt
            if char == "\x04":
                raise EOFError
            if char in {"\x7f", "\b"}:
                if buffer:
                    buffer.pop()
                    print("\b \b", end="", flush=True)
                continue
            if char.isprintable():
                buffer.append(char)
                print(char, end="", flush=True)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, previous)


def _pause() -> None:
    if not sys.stdin.isatty():
        return

    try:
        _read_line_interactive(_muted("\n按 Enter 继续 / Esc 返回上一级..."))
    except BackRequested:
        return


def _title(text: str) -> None:
    width = _terminal_width()
    line_width = min(width, 100)
    print(_accent(text))
    print(_muted("─" * line_width))


def _navigation_hint() -> None:
    print(_muted("Esc 返回上一级 · Enter 使用默认值"))


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = _read_line_interactive(f"{_cyan('›')} {prompt}{suffix}: ").strip()
    return default if not value and default is not None else value


def _yes(prompt: str, *, default: bool = True) -> bool:
    default_text = "Y/n" if default else "y/N"
    value = _read_line_interactive(
        f"{_cyan('›')} {prompt} [{default_text}]: "
    ).strip().casefold()
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
        try:
            choice = _ask("输入编号", "1")
        except BackRequested:
            return current
        _clear_screen()

        if choice == "1":
            try:
                selected = _choose_record(records, "输入要设为当前设备的编号")
            except BackRequested:
                _clear_screen()
                continue
            if selected is not None:
                current = selected
                print(f"已设为当前设备：{_record_title(selected)}")
            _pause()
            _clear_screen()
        elif choice == "2":
            try:
                selected = _choose_record(records, "输入要保存的编号")
            except BackRequested:
                _clear_screen()
                continue
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
            try:
                selected = _choose_record(records, "输入要查看详情的编号")
            except BackRequested:
                _clear_screen()
                continue
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
    online_check_timeout = float(
        bettercap_config.get("online_check_timeout", FAST_API_CHECK_TIMEOUT)
    )
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
            print(f"API 在线检查超时时间秒: {online_check_timeout}")
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
                online_check_timeout = float(
                    _ask("API 在线检查超时时间秒", str(online_check_timeout))
                )
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
            if not client.is_online(timeout=online_check_timeout):
                print(f"Bettercap API 未在线：{api_url}")
                print("请先启动 Bettercap REST API，或改用内置 ARP 扫描。")
                return None
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
        try:
            choice = _ask("输入编号", "1")
        except BackRequested:
            return current
        _clear_screen()

        try:
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
        except BackRequested:
            continue


def _bool_text(value: bool) -> str:
    return "是" if value else "否"


def _load_param_rows(params: dict[str, Any]) -> list[tuple[str, str, object, bool]]:
    protocol = str(params["protocol"])
    tcp_enabled = protocol == "tcp"
    return [
        ("1", "目标", params["target"], True),
        ("2", "协议", protocol, True),
        ("3", "TCP 端口", params["port"] or "-", tcp_enabled),
        (
            "4",
            "保持连接持续发送",
            _bool_text(bool(params["tcp_keep_open"])),
            tcp_enabled,
        ),
        ("5", "并发线程数", params["concurrency"], True),
        (
            "6",
            "持续时间秒",
            "按总请求/包数" if params["duration"] is None else params["duration"],
            True,
        ),
        (
            "7",
            "总请求/包数",
            "按持续时间" if params["count"] is None else params["count"],
            True,
        ),
        ("8", "单次超时时间秒", params["timeout"], True),
        ("9", "每次发送负载字节数", params["payload_size"], True),
        ("10", "渐进启动秒数", params["ramp_up"], True),
        ("11", "线程错峰抖动秒数", params["jitter"], True),
    ]


def _print_load_test_params(params: dict[str, Any], *, numbered: bool = False) -> None:
    print(_accent("将使用这些参数"))
    for number, label, value, enabled in _load_param_rows(params):
        prefix = f"{number:>2}. " if numbered else ""
        label_text = _style(f"{label:<18}", ANSI_MUTED if enabled else ANSI_DIM)
        value_text = _style(
            value,
            ANSI_ORANGE if enabled else ANSI_MUTED,
            ANSI_BOLD if enabled else ANSI_DIM,
        )
        print(f"{prefix}{label_text} {_muted('│')} {value_text}")


def _require_tcp(params: dict[str, Any]) -> bool:
    if params["protocol"] == "tcp":
        return True
    print("该参数仅在 TCP 协议下可用。")
    _pause()
    return False


def _edit_load_test_params(params: dict[str, Any]) -> None:
    """Let the user edit one load-test parameter at a time."""

    while True:
        _clear_screen()
        _title("调整负载测试参数")
        _print_load_test_params(params, numbered=True)
        print(_muted("\n输入编号只修改该项；0 或 Enter 开始测试；Esc 返回上一级。"))
        choice = _ask("要修改的参数编号", "0").casefold()
        if choice in {"", "0", "done", "完成"}:
            if params["duration"] is None and params["count"] is None:
                print("持续时间和总请求/包数不能同时为空。")
                _pause()
                continue
            return

        try:
            if choice == "1":
                value = _ask("目标 IP 或 hostname", str(params["target"]))
                if not value:
                    print("目标不能为空。")
                    _pause()
                    continue
                params["target"] = value
            elif choice == "2":
                protocol = _ask("协议 icmp/tcp", str(params["protocol"])).casefold()
                if protocol not in {"icmp", "tcp"}:
                    print("协议只能是 icmp 或 tcp。")
                    _pause()
                    continue
                params["protocol"] = protocol
                if protocol == "tcp" and params["port"] is None:
                    params["port"] = 5000
                if protocol == "icmp":
                    params["tcp_keep_open"] = False
            elif choice == "3":
                if not _require_tcp(params):
                    continue
                params["port"] = int(_ask("TCP 端口", str(params["port"] or 5000)))
            elif choice == "4":
                if not _require_tcp(params):
                    continue
                params["tcp_keep_open"] = _yes(
                    "是否保持 TCP 连接并持续发送",
                    default=bool(params["tcp_keep_open"]),
                )
            elif choice == "5":
                params["concurrency"] = int(
                    _ask("并发线程数", str(params["concurrency"]))
                )
            elif choice == "6":
                current = "" if params["duration"] is None else str(params["duration"])
                value = _ask("持续时间秒；输入 0/留空则按总数量", current)
                params["duration"] = None if value in {"", "0"} else float(value)
            elif choice == "7":
                current = "" if params["count"] is None else str(params["count"])
                value = _ask("总请求/包数；留空则按持续时间", current)
                params["count"] = None if not value else int(value)
            elif choice == "8":
                params["timeout"] = float(
                    _ask("单次超时时间秒", str(params["timeout"]))
                )
            elif choice == "9":
                params["payload_size"] = int(
                    _ask("每次发送负载字节数；0 表示默认", str(params["payload_size"]))
                )
            elif choice == "10":
                params["ramp_up"] = float(
                    _ask("渐进启动秒数；0 表示同时启动", str(params["ramp_up"]))
                )
            elif choice == "11":
                params["jitter"] = float(
                    _ask("线程错峰抖动秒数", str(params["jitter"]))
                )
            else:
                print("未知参数编号。")
                _pause()
        except ValueError:
            print("参数格式无效。")
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

    params: dict[str, Any] = {
        "target": target,
        "protocol": protocol,
        "port": (
            int(load_config.get("tcp_port", 5000))
            if protocol == "tcp"
            else None
        ),
        "concurrency": int(load_config.get("concurrency", 32)),
    }
    duration_value = load_config.get("duration", 10.0)
    params["duration"] = None if duration_value is None else float(duration_value)
    count_value = load_config.get("count")
    params["count"] = None if count_value is None else int(count_value)
    params["timeout"] = float(load_config.get("timeout", 1.0))
    params["payload_size"] = int(load_config.get("payload_size", 0))
    params["tcp_keep_open"] = bool(load_config.get("tcp_keep_open", False))
    params["ramp_up"] = float(load_config.get("ramp_up", 0.75))
    params["jitter"] = float(load_config.get("per_worker_jitter", 0.002))

    try:
        print()
        _print_load_test_params(params)

        if _yes("是否修改参数", default=False):
            _edit_load_test_params(params)
    except ValueError:
        print("参数格式无效。")
        return

    try:
        run_load_test(
            LoadTestConfig(
                target=str(params["target"]),
                protocol=params["protocol"],  # type: ignore[arg-type]
                concurrency=int(params["concurrency"]),
                duration=params["duration"],
                count=params["count"],
                timeout=float(params["timeout"]),
                tcp_port=params["port"],
                ramp_up=float(params["ramp_up"]),
                per_worker_jitter=float(params["jitter"]),
                payload_size=int(params["payload_size"]),
                tcp_keep_open=bool(params["tcp_keep_open"]),
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


def _get_network_info(
    *,
    refresh: bool = False,
    on_reading_ssid: Callable[[], None] | None = None,
) -> LocalNetworkInfo:
    global _NETWORK_INFO_CACHE

    if refresh or _NETWORK_INFO_CACHE is None:
        _NETWORK_INFO_CACHE = detect_local_network_info(
            on_reading_ssid=on_reading_ssid
        )

    return _NETWORK_INFO_CACHE


def _format_status_part(label: str, value: object, *, color: str = ANSI_CYAN) -> str:
    return f"{_muted(label + ':')} {_style(value, color, ANSI_BOLD)}"


def _format_network_status(
    *,
    refresh: bool = False,
    on_reading_ssid: Callable[[], None] | None = None,
) -> str:
    info = _get_network_info(
        refresh=refresh,
        on_reading_ssid=on_reading_ssid,
    )
    parts: list[str] = []

    if info.hardware_port:
        parts.append(_style(info.hardware_port, ANSI_CYAN, ANSI_BOLD))
    elif info.interface:
        parts.append(_style(info.interface, ANSI_CYAN, ANSI_BOLD))
    else:
        parts.append(_style("未知网络", ANSI_RED, ANSI_BOLD))

    is_wifi = bool(info.hardware_port and "wi-fi" in info.hardware_port.casefold())
    if info.ssid:
        parts.append(_format_status_part("SSID", info.ssid, color=ANSI_ORANGE))
    elif is_wifi:
        parts.append(_format_status_part("SSID", "未获取", color=ANSI_RED))
    if info.interface and info.hardware_port:
        parts.append(_format_status_part("接口", info.interface, color=ANSI_TEAL))
    if info.ipv4_network:
        parts.append(_format_status_part("网段", info.ipv4_network, color=ANSI_GREEN))

    separator = _muted(" | ")
    return f"{_accent('当前网络')} {separator.join(parts)}"


def _print_menu(
    store_path: Path,
    current: DeviceRecord | None,
    *,
    refresh_network: bool = False,
) -> None:
    _title("Hyping 交互式网络设备工具")
    reading_ssid = False

    def on_reading_ssid() -> None:
        nonlocal reading_ssid
        reading_ssid = True
        print(_muted("正在读取 Wi-Fi SSID..."), flush=True)

    network_status = _format_network_status(
        refresh=refresh_network,
        on_reading_ssid=on_reading_ssid,
    )
    if reading_ssid:
        _clear_screen()
        _title("Hyping 交互式网络设备工具")

    print(network_status)
    _navigation_hint()
    print(_format_status_part("设备保存文件", store_path, color=ANSI_TEAL))
    if _is_elevated():
        print(_format_status_part("运行权限", "提升权限/root", color=ANSI_GREEN))
    print(_clip(_current_summary(current), _terminal_width()))
    print(
        "\n请选择操作：\n"
        "  1. 通过 hostname/note 查询 IP 和 MAC\n"
        "  2. 列出当前网段设备\n"
        "  3. 查询 mDNS/Bonjour 详细信息\n"
        "  4. 管理已保存设备\n"
        "  5. 并发 ping / TCP 负载测试\n"
        "  r. 刷新当前网络\n"
        "  6. 退出"
    )


def _shutdown_bettercap_on_exit(config: Mapping[str, Any]) -> None:
    bettercap_config = config.get("bettercap", {})
    if not bool(bettercap_config.get("shutdown_on_ui_exit", True)):
        return

    check_timeout = float(
        bettercap_config.get("online_check_timeout", FAST_API_CHECK_TIMEOUT)
    )
    client = BettercapClient(
        str(bettercap_config.get("url", "http://127.0.0.1:8081")),
        str(bettercap_config.get("username", "user")),
        str(bettercap_config.get("password", "pass")),
        timeout=float(bettercap_config.get("api_timeout", 3.0)),
    )
    if not client.is_online(timeout=check_timeout):
        print("Bettercap API 已不可达，视为 bettercap 已关闭或未启动。", flush=True)
        return

    try:
        print("正在通过 Bettercap API 关闭 bettercap...", flush=True)
        client.shutdown()
        print("bettercap 已请求关闭。", flush=True)
    except BettercapAPIError as exc:
        print(
            "bettercap 关闭请求已发送后 API 不可达，视为已关闭。"
            if "could not reach Bettercap API" in str(exc)
            else f"关闭 bettercap 失败：{exc}",
            flush=True,
        )


def run_interactive(
    store_path: Path = DEFAULT_STORE_PATH,
    config: Mapping[str, Any] | None = None,
) -> int:
    """Run the interactive command-line UI."""

    config = config or ensure_config()
    current: DeviceRecord | None = None
    refresh_network = False

    try:
        while True:
            _clear_screen()
            _print_menu(store_path, current, refresh_network=refresh_network)
            refresh_network = False
            try:
                choice = _ask("输入编号", "1").casefold()
            except BackRequested:
                return 0
            _clear_screen()

            try:
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
                elif choice == "r":
                    refresh_network = True
                elif choice == "6":
                    return 0
                else:
                    print("未知选项，请重新输入。")
                    _pause()
            except BackRequested:
                continue
    finally:
        _shutdown_bettercap_on_exit(config)
