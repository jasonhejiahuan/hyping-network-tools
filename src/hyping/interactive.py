import json
import os
import shutil
import sys
from pathlib import Path

from hyping.discovery.mdns import (
    DEFAULT_SERVICE_TYPES,
    find_mdns_services_by_hostname,
    format_mdns_key_values,
    format_mdns_service,
    merge_mdns_services,
)
from hyping.discovery.resolver import DeviceNotFoundError, locate_device
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
    network = _ask("ARP 扫描网段，可留空，例如 192.168.1.0/24")
    partial_note = _yes("是否允许 note 部分匹配", default=False)
    timeout = float(_ask("超时时间秒", "1.0"))

    try:
        device = locate_device(
            hostname=hostname or None,
            note=note or None,
            network=network or None,
            note_hosts=_note_hosts_with_current(records, current),
            timeout=timeout,
            partial_note=partial_note,
        )
    except (DeviceNotFoundError, ValueError) as exc:
        print(f"查询失败：{exc}")
        return current

    record = _merge_current(current, _record_from_located_device(device))
    print(json.dumps(record, ensure_ascii=False, indent=2))
    if _yes("是否保存这个设备"):
        if not record.get("note"):
            saved_note = _ask("给它添加 note/备注，可留空")
            if saved_note:
                record["note"] = saved_note
        _save_record(store_path, record)

    return record


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


def _print_menu(store_path: Path, current: DeviceRecord | None) -> None:
    _title("Hyping 交互式网络设备工具")
    print(f"设备保存文件：{store_path}")
    print(_clip(_current_summary(current), _terminal_width()))
    print(
        "\n请选择操作：\n"
        "  1. 通过 hostname/note 查询 IP 和 MAC\n"
        "  2. 查询 mDNS/Bonjour 详细信息\n"
        "  3. 查看已保存设备\n"
        "  4. 删除已保存设备\n"
        "  5. 选择已保存设备为当前设备\n"
        "  6. 退出"
    )


def run_interactive(store_path: Path = DEFAULT_STORE_PATH) -> int:
    """Run the interactive command-line UI."""

    current: DeviceRecord | None = None

    while True:
        _clear_screen()
        _print_menu(store_path, current)
        choice = _ask("输入编号", "1")
        _clear_screen()

        if choice == "1":
            current = _locate_flow(store_path, current)
            _pause()
        elif choice == "2":
            current = _mdns_flow(store_path, current)
            _pause()
        elif choice == "3":
            _title("查看已保存设备")
            _show_records(load_device_records(store_path))
            _pause()
        elif choice == "4":
            _delete_flow(store_path)
            _pause()
        elif choice == "5":
            selected = _select_saved_flow(store_path)
            if selected is not None:
                current = selected
            _pause()
        elif choice == "6":
            return 0
        else:
            print("未知选项，请重新输入。")
            _pause()
