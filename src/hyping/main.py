import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from hyping.auto_wifi_scan import (
    DEFAULT_WIFI_ROTATION_PATH,
    AutoWiFiScanError,
    expand_wifi_rotation_path,
    find_hostname_with_bettercap_then_wifi_rotation,
    load_wifi_scan_targets,
    run_auto_wifi_scan,
    write_wifi_scan_template,
)
from hyping.config import ensure_config
from hyping.discovery.arp import can_run_active_arp_scan, list_network_devices
from hyping.discovery.bettercap import (
    BettercapAPIError,
    BettercapClient,
    ensure_bettercap_api_online,
    list_bettercap_hosts,
    record_from_bettercap_host,
)
from hyping.discovery.mdns import (
    DEFAULT_SERVICE_TYPES,
    find_mdns_services_by_hostname,
    format_mdns_key_values,
    format_mdns_service,
    merge_mdns_services,
    resolve_mdns_service,
)
from hyping.discovery.network import detect_local_ipv4_network
from hyping.discovery.resolver import DeviceNotFoundError, locate_device
from hyping.discovery.wifi import (
    WiFiError,
    WiFiNetwork,
    current_wifi_ssid,
    list_available_saved_wifi_networks,
    list_nearby_wifi_networks,
    list_saved_wifi_networks,
    switch_wifi_network,
)
from hyping.interactive import run_interactive
from hyping.loadtest import LoadTestConfig, run_load_test
from hyping.storage import DEFAULT_STORE_PATH, DeviceRecord, load_device_records
from hyping.web import run_web


def _parse_note_hosts(values: Sequence[str]) -> dict[str, str]:
    note_hosts: dict[str, str] = {}

    for value in values:
        if "=" not in value:
            msg = f"invalid --note-host value {value!r}; expected NOTE=HOSTNAME"
            raise argparse.ArgumentTypeError(msg)

        note, hostname = value.split("=", 1)
        note = note.strip()
        hostname = hostname.strip()
        if not note or not hostname:
            msg = f"invalid --note-host value {value!r}; expected NOTE=HOSTNAME"
            raise argparse.ArgumentTypeError(msg)

        note_hosts[note] = hostname

    return note_hosts


def _device_to_record(device) -> dict[str, str | None]:
    return {
        "ip": str(device.ip),
        "mac": device.mac,
        "hostname": device.hostname,
        "note": device.note,
    }


def _scan_item_to_record(item) -> dict[str, object]:
    if hasattr(item, "display_name"):
        return record_from_bettercap_host(item)

    return _device_to_record(item)


def _print_scan_header() -> None:
    print(
        " #   ip               mac                "
        "name                         vendor"
    )
    print("─" * 96)


def _print_scan_item(index: int, item) -> None:
    record = _scan_item_to_record(item)
    print(
        f"{index:>3}. "
        f"{str(record.get('ip') or '-'):<15}  "
        f"{str(record.get('mac') or '-'):<17}  "
        f"{str(record.get('hostname') or '-'):<28}  "
        f"{str(record.get('vendor') or '-')}",
        flush=True,
    )


def _wifi_network_to_record(network: WiFiNetwork) -> dict[str, object]:
    return {
        "ssid": network.ssid,
        "current": network.current,
        "phy_mode": network.phy_mode,
        "channel": network.channel,
        "security": network.security,
        "signal_noise": network.signal_noise,
    }


def _record_text(record: DeviceRecord, key: str) -> str | None:
    value = record.get(key)
    if not isinstance(value, str):
        return None

    cleaned = value.strip()
    return cleaned or None


def _normalize_saved_selector(value: str) -> str:
    return value.strip().casefold().rstrip(".")


def _saved_hostname(record: DeviceRecord) -> str | None:
    hostname = _record_text(record, "hostname")
    if hostname is None:
        return None
    return hostname.rstrip(".") or None


def _format_saved_hostname_choices(records: Sequence[DeviceRecord]) -> str:
    lines = ["可用的已保存 hostname："]
    for index, record in enumerate(records, start=1):
        hostname = _saved_hostname(record)
        if hostname is None:
            continue
        ip = _record_text(record, "ip") or "-"
        mac = _record_text(record, "mac") or "-"
        note = _record_text(record, "note") or _record_text(record, "vendor") or "-"
        lines.append(f"{index}. {hostname} | {ip} | {mac} | {note}")

    if len(lines) == 1:
        lines.append("（没有带 hostname 的保存设备）")
    return "\n".join(lines)


def _select_saved_hostname_record(
    records: Sequence[DeviceRecord],
    selector: str | None,
) -> DeviceRecord:
    hostname_records = [
        (index, record)
        for index, record in enumerate(records, start=1)
        if _saved_hostname(record) is not None
    ]
    if not hostname_records:
        msg = "没有带 hostname 的已保存设备"
        raise ValueError(msg)

    if selector is None or not selector.strip():
        if len(hostname_records) == 1:
            return hostname_records[0][1]
        msg = (
            "找到多个已保存 hostname，请使用 --saved 编号/hostname/note/IP/MAC 指定\n"
            f"{_format_saved_hostname_choices(records)}"
        )
        raise ValueError(msg)

    cleaned_selector = selector.strip()
    if cleaned_selector.isdecimal():
        selected_index = int(cleaned_selector)
        for index, record in enumerate(records, start=1):
            if index == selected_index:
                hostname = _saved_hostname(record)
                if hostname is None:
                    msg = f"编号 {selected_index} 的保存设备没有 hostname"
                    raise ValueError(msg)
                return record
        msg = f"找不到编号 {selected_index} 的保存设备"
        raise ValueError(msg)

    normalized_selector = _normalize_saved_selector(cleaned_selector)
    matches: list[DeviceRecord] = []
    for record in records:
        for key in ("hostname", "note", "ip", "mac"):
            value = _record_text(record, key)
            if value is None:
                continue
            if _normalize_saved_selector(value) == normalized_selector:
                matches.append(record)
                break

    if not matches:
        msg = (
            f"找不到匹配 {cleaned_selector!r} 的已保存设备\n"
            f"{_format_saved_hostname_choices(records)}"
        )
        raise ValueError(msg)
    if len(matches) > 1:
        msg = (
            f"{cleaned_selector!r} 匹配到多台保存设备，请改用编号\n"
            f"{_format_saved_hostname_choices(records)}"
        )
        raise ValueError(msg)

    hostname = _saved_hostname(matches[0])
    if hostname is None:
        msg = f"匹配到的保存设备没有 hostname：{cleaned_selector}"
        raise ValueError(msg)
    return matches[0]


def _resolve_auto_locate_hostname(
    *,
    hostname: str | None,
    saved_selector: str | None,
    store_path: Path,
) -> str:
    if hostname and saved_selector is not None:
        msg = "--hostname 和 --saved 只能选择一个"
        raise ValueError(msg)

    if saved_selector is not None:
        record = _select_saved_hostname_record(
            load_device_records(store_path),
            saved_selector,
        )
        saved_hostname = _saved_hostname(record)
        if saved_hostname is None:
            msg = "匹配到的保存设备没有 hostname"
            raise ValueError(msg)
        return saved_hostname

    cleaned = hostname.strip().rstrip(".") if hostname else ""
    if not cleaned:
        msg = "auto-locate 需要 --hostname，或使用 --saved 读取已保存设备"
        raise ValueError(msg)
    return cleaned


def _print_wifi_networks(networks: Sequence[WiFiNetwork]) -> None:
    print(" #  SSID                         频段/信道              安全性")
    print("─" * 72)
    for index, network in enumerate(networks, start=1):
        marker = "*" if network.current else " "
        print(
            f"{index:>2}{marker} "
            f"{network.ssid:<28} "
            f"{str(network.channel or '-'):<20} "
            f"{network.security or '-'}"
        )


def _build_parser(config: Mapping[str, Any] | None = None) -> argparse.ArgumentParser:
    config = config or {}
    scan_config = config.get("scan", {})
    bettercap_config = config.get("bettercap", {})
    load_config = config.get("load", {})
    locate_config = config.get("locate", {})
    mdns_config = config.get("mdns", {})
    wifi_config = config.get("wifi", {})
    auto_wifi_config = config.get("auto_wifi_scan", {})

    parser = argparse.ArgumentParser(
        prog="hyping",
        description="Locate LAN devices by hostname or human note.",
    )
    subparsers = parser.add_subparsers(dest="command")

    locate = subparsers.add_parser(
        "locate",
        help="resolve a device's IPv4 address and MAC address",
    )
    locate.add_argument("--hostname", help="DNS/mDNS hostname, e.g. nas or nas.local")
    locate.add_argument("--note", help="human alias/note, e.g. living room printer")
    locate.add_argument(
        "--note-host",
        action="append",
        default=[],
        metavar="NOTE=HOSTNAME",
        help="map a note to a hostname; can be passed multiple times",
    )
    locate.add_argument(
        "--network",
        help=(
            "optional CIDR to ARP scan before DNS lookup, e.g. 192.168.1.0/24; "
            "use 'auto' to detect the local subnet"
        ),
    )
    locate.add_argument(
        "--timeout",
        type=float,
        default=locate_config.get("timeout", 1.0),
        help="ARP scan/ping timeout in seconds",
    )
    locate.add_argument(
        "--partial-hostname",
        action=argparse.BooleanOptionalAction,
        default=locate_config.get("partial_hostname", False),
        help="allow substring hostname matching for known/scanned devices",
    )
    locate.add_argument(
        "--partial-note",
        action=argparse.BooleanOptionalAction,
        default=locate_config.get("partial_note", False),
        help="allow substring note matching for note aliases/inventory",
    )
    locate.add_argument(
        "--prime-arp-cache",
        action=argparse.BooleanOptionalAction,
        default=locate_config.get("prime_arp_cache", True),
        help="ping the resolved IP before reading the local ARP cache",
    )

    scan = subparsers.add_parser(
        "scan",
        aliases=["list"],
        help="list devices on the current or specified local subnet",
    )
    scan.add_argument(
        "--network",
        default=scan_config.get("network", "auto"),
        help="CIDR for builtin scan, e.g. 192.168.1.0/24; defaults to auto",
    )
    scan.add_argument(
        "--scanner",
        choices=["bettercap", "builtin"],
        default=scan_config.get("scanner", "bettercap"),
        help="scanner backend; defaults to Bettercap REST API",
    )
    scan.add_argument(
        "--bettercap-url",
        default=bettercap_config.get("url", "http://127.0.0.1:8081"),
        help="Bettercap REST API base URL",
    )
    scan.add_argument(
        "--bettercap-user",
        default=bettercap_config.get("username", "user"),
        help="Bettercap REST API username",
    )
    scan.add_argument(
        "--bettercap-pass",
        default=bettercap_config.get("password", "pass"),
        help="Bettercap REST API password",
    )
    scan.add_argument(
        "--bettercap-api-timeout",
        type=float,
        default=bettercap_config.get("api_timeout", 3.0),
        help="Bettercap REST API request timeout in seconds",
    )
    scan.add_argument(
        "--bettercap-wait",
        type=float,
        default=bettercap_config.get("wait", 5.0),
        help="seconds to poll Bettercap for newly discovered hosts",
    )
    scan.add_argument(
        "--bettercap-poll",
        type=float,
        default=bettercap_config.get("poll_interval", 0.5),
        help="Bettercap polling interval in seconds",
    )
    scan.add_argument(
        "--bettercap-discovery-warmup",
        type=float,
        default=bettercap_config.get("discovery_warmup", 3.0),
        help="seconds to wait after starting net.recon/net.probe",
    )
    scan.add_argument(
        "--start-bettercap",
        action=argparse.BooleanOptionalAction,
        default=bettercap_config.get("start_discovery", True),
        help="send 'net.recon on' and 'net.probe on' to Bettercap",
    )
    scan.add_argument(
        "--auto-start-bettercap-api",
        action=argparse.BooleanOptionalAction,
        default=bettercap_config.get("auto_start_api", True),
        help=(
            "when using sudo, start local bettercap REST API only if it is needed "
            "and unreachable"
        ),
    )
    scan.add_argument(
        "--bettercap-command",
        default=bettercap_config.get("command", "bettercap"),
        help="bettercap executable used for on-demand API startup",
    )
    scan.add_argument(
        "--bettercap-interface",
        default=bettercap_config.get("interface", "auto"),
        help="interface passed to bettercap on startup; 'auto' lets bettercap choose",
    )
    scan.add_argument(
        "--bettercap-startup-timeout",
        type=float,
        default=bettercap_config.get("startup_timeout", 8.0),
        help="seconds to wait for an auto-started Bettercap API",
    )
    scan.add_argument(
        "--bettercap-startup-poll",
        type=float,
        default=bettercap_config.get("startup_poll_interval", 0.25),
        help="poll interval while waiting for Bettercap API startup",
    )
    scan.add_argument(
        "--timeout",
        type=float,
        default=scan_config.get("timeout", 0.5),
        help="seconds to wait for each ARP batch; 0.3-1.0 is usually enough",
    )
    scan.add_argument(
        "--passes",
        type=int,
        default=scan_config.get("passes", 3),
        help="number of scan passes; repeating finds more Wi-Fi clients",
    )
    scan.add_argument(
        "--batch-size",
        type=int,
        default=scan_config.get("batch_size", 64),
        help="number of IPs to probe per batch",
    )
    scan.add_argument(
        "--interval",
        type=float,
        default=scan_config.get("interval", 0.002),
        help="small delay between ARP packets in seconds",
    )
    scan.add_argument(
        "--resolve-hostnames",
        action=argparse.BooleanOptionalAction,
        default=scan_config.get("resolve_hostnames", True),
        help="try reverse DNS for discovered devices",
    )
    scan.add_argument(
        "--json",
        action=argparse.BooleanOptionalAction,
        default=scan_config.get("json", False),
        help="print only the final JSON list instead of progressive rows",
    )

    mdns_info = subparsers.add_parser(
        "mdns-info",
        help="print mDNS/Bonjour TXT records as tab-separated key/value lines",
    )
    mdns_info.add_argument(
        "--hostname",
        help="target mDNS hostname, e.g. haozdeMacBook-Air.local or with final dot",
    )
    mdns_info.add_argument(
        "--instance",
        help="service instance name, e.g. Lenovo M101DW Pro",
    )
    mdns_info.add_argument(
        "--service-type",
        action="append",
        default=[],
        help=(
            "Bonjour service type, e.g. _ipp._tcp; can be passed multiple times. "
            "Defaults to common device/printer service types when using --hostname."
        ),
    )
    mdns_info.add_argument(
        "--domain",
        default=mdns_config.get("domain", "local"),
        help="Bonjour domain; defaults to local",
    )
    mdns_info.add_argument(
        "--timeout",
        type=float,
        default=mdns_config.get("timeout", 1.0),
        help="seconds to wait for each dns-sd browse/resolve step",
    )
    mdns_info.add_argument(
        "--first",
        action=argparse.BooleanOptionalAction,
        default=mdns_config.get("first", False),
        help="print only the first matching service",
    )
    mdns_info.add_argument(
        "--merge",
        action=argparse.BooleanOptionalAction,
        default=mdns_config.get("merge", False),
        help="merge all matching services for the hostname into one key/value list",
    )

    wifi = subparsers.add_parser(
        "wifi",
        help="show saved/nearby Wi-Fi networks or switch SSID on macOS",
    )
    wifi.add_argument(
        "--interface",
        help="Wi-Fi interface, e.g. en0; defaults to auto-detected Wi-Fi device",
    )
    wifi_subparsers = wifi.add_subparsers(dest="wifi_command")

    wifi_current = wifi_subparsers.add_parser(
        "current",
        help="show the current Wi-Fi SSID",
    )
    wifi_current.add_argument(
        "--json",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="print JSON",
    )

    wifi_saved = wifi_subparsers.add_parser(
        "saved",
        help="list saved/preferred Wi-Fi networks",
    )
    wifi_saved.add_argument(
        "--json",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="print JSON",
    )

    wifi_nearby = wifi_subparsers.add_parser(
        "nearby",
        help="scan nearby Wi-Fi networks with system_profiler",
    )
    wifi_nearby.add_argument(
        "--include-current",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="include the currently connected SSID in the result",
    )
    wifi_nearby.add_argument(
        "--json",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="print JSON",
    )

    wifi_available = wifi_subparsers.add_parser(
        "available",
        aliases=["saved-nearby"],
        help="list saved Wi-Fi networks that are visible nearby",
    )
    wifi_available.add_argument(
        "--json",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="print JSON",
    )

    wifi_switch = wifi_subparsers.add_parser(
        "switch",
        aliases=["connect"],
        help="switch to the specified Wi-Fi SSID",
    )
    wifi_switch.add_argument("ssid", help="SSID to join")
    wifi_switch.add_argument(
        "--password",
        help="Wi-Fi password; omit to use saved credentials when available",
    )
    wifi_switch.add_argument(
        "--verify",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="verify the current SSID after switching",
    )
    wifi_switch.add_argument(
        "--verify-timeout",
        type=float,
        default=wifi_config.get("verify_timeout", 12.0),
        help="seconds to wait while verifying the joined SSID",
    )

    auto_wifi = subparsers.add_parser(
        "auto-wifi-scan",
        aliases=["autoscan-wifi"],
        help="rotate Wi-Fi SSIDs, restart Bettercap, scan hosts, and save devices",
    )
    auto_wifi.add_argument(
        "--wifi-list",
        type=Path,
        default=expand_wifi_rotation_path(
            auto_wifi_config.get("wifi_list", str(DEFAULT_WIFI_ROTATION_PATH))
        ),
        help=(
            "JSON or CSV file containing SSIDs to rotate; defaults to "
            f"{DEFAULT_WIFI_ROTATION_PATH}"
        ),
    )
    auto_wifi.add_argument(
        "--store",
        type=Path,
        default=DEFAULT_STORE_PATH,
        help=f"device store JSON path; defaults to {DEFAULT_STORE_PATH}",
    )
    auto_wifi.add_argument(
        "--interface",
        default=wifi_config.get("interface"),
        help="Wi-Fi interface, e.g. en0; defaults to auto-detected Wi-Fi device",
    )
    auto_wifi.add_argument(
        "--bettercap-url",
        default=bettercap_config.get("url", "http://127.0.0.1:8081"),
        help="Bettercap REST API base URL",
    )
    auto_wifi.add_argument(
        "--bettercap-user",
        default=bettercap_config.get("username", "user"),
        help="Bettercap REST API username",
    )
    auto_wifi.add_argument(
        "--bettercap-pass",
        default=bettercap_config.get("password", "pass"),
        help="Bettercap REST API password",
    )
    auto_wifi.add_argument(
        "--bettercap-api-timeout",
        type=float,
        default=bettercap_config.get("api_timeout", 3.0),
        help="Bettercap REST API request timeout in seconds",
    )
    auto_wifi.add_argument(
        "--bettercap-command",
        default=bettercap_config.get("command", "bettercap"),
        help="bettercap executable used for each restarted Bettercap core",
    )
    auto_wifi.add_argument(
        "--bettercap-startup-timeout",
        type=float,
        default=bettercap_config.get("startup_timeout", 8.0),
        help="seconds to wait for each restarted Bettercap API",
    )
    auto_wifi.add_argument(
        "--bettercap-startup-poll",
        type=float,
        default=bettercap_config.get("startup_poll_interval", 0.25),
        help="poll interval while waiting for Bettercap API startup",
    )
    auto_wifi.add_argument(
        "--bettercap-wait",
        type=float,
        default=bettercap_config.get("wait", 5.0),
        help="seconds to poll Bettercap for hosts on each Wi-Fi",
    )
    auto_wifi.add_argument(
        "--bettercap-poll",
        type=float,
        default=bettercap_config.get("poll_interval", 0.5),
        help="Bettercap host polling interval in seconds",
    )
    auto_wifi.add_argument(
        "--bettercap-discovery-warmup",
        type=float,
        default=bettercap_config.get("discovery_warmup", 3.0),
        help="seconds to wait after starting net.recon/net.probe",
    )
    auto_wifi.add_argument(
        "--verify-timeout",
        type=float,
        default=wifi_config.get("verify_timeout", 12.0),
        help="seconds to wait while verifying each joined SSID",
    )
    auto_wifi.add_argument(
        "--restore-original",
        action=argparse.BooleanOptionalAction,
        default=auto_wifi_config.get("restore_original", True),
        help="switch back to the original Wi-Fi after the rotation",
    )
    auto_wifi.add_argument(
        "--create-template",
        action=argparse.BooleanOptionalAction,
        default=auto_wifi_config.get("create_template", True),
        help="create a sample Wi-Fi rotation file when --wifi-list is missing",
    )
    auto_wifi.add_argument(
        "--json",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="print JSON summary",
    )

    auto_locate = subparsers.add_parser(
        "auto-locate",
        aliases=["auto-find"],
        help="find a hostname with Bettercap first, then rotate Wi-Fi if needed",
    )
    auto_locate.add_argument("--hostname", help="hostname to find")
    auto_locate.add_argument(
        "--saved",
        nargs="?",
        const="",
        metavar="SELECTOR",
        help=(
            "use a saved device hostname; selector can be a saved-device number, "
            "hostname, note, IP, or MAC"
        ),
    )
    auto_locate.add_argument(
        "--partial-hostname",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="allow substring hostname matching",
    )
    auto_locate.add_argument(
        "--wifi-list",
        type=Path,
        default=expand_wifi_rotation_path(
            auto_wifi_config.get("wifi_list", str(DEFAULT_WIFI_ROTATION_PATH))
        ),
        help=(
            "JSON or CSV file containing SSIDs to rotate; defaults to "
            f"{DEFAULT_WIFI_ROTATION_PATH}"
        ),
    )
    auto_locate.add_argument(
        "--store",
        type=Path,
        default=DEFAULT_STORE_PATH,
        help=f"device store JSON path; defaults to {DEFAULT_STORE_PATH}",
    )
    auto_locate.add_argument(
        "--interface",
        default=wifi_config.get("interface"),
        help="Wi-Fi interface, e.g. en0; defaults to auto-detected Wi-Fi device",
    )
    auto_locate.add_argument(
        "--bettercap-url",
        default=bettercap_config.get("url", "http://127.0.0.1:8081"),
        help="Bettercap REST API base URL",
    )
    auto_locate.add_argument(
        "--bettercap-user",
        default=bettercap_config.get("username", "user"),
        help="Bettercap REST API username",
    )
    auto_locate.add_argument(
        "--bettercap-pass",
        default=bettercap_config.get("password", "pass"),
        help="Bettercap REST API password",
    )
    auto_locate.add_argument(
        "--bettercap-api-timeout",
        type=float,
        default=bettercap_config.get("api_timeout", 3.0),
        help="Bettercap REST API request timeout in seconds",
    )
    auto_locate.add_argument(
        "--bettercap-online-check-timeout",
        type=float,
        default=bettercap_config.get("online_check_timeout", 0.25),
        help="seconds to use for the quick Bettercap API online check",
    )
    auto_locate.add_argument(
        "--auto-start-bettercap-api",
        action=argparse.BooleanOptionalAction,
        default=bettercap_config.get("auto_start_api", True),
        help="start local Bettercap REST API when it is unreachable and sudo is used",
    )
    auto_locate.add_argument(
        "--bettercap-command",
        default=bettercap_config.get("command", "bettercap"),
        help="bettercap executable used for each restarted Bettercap core",
    )
    auto_locate.add_argument(
        "--bettercap-startup-timeout",
        type=float,
        default=bettercap_config.get("startup_timeout", 8.0),
        help="seconds to wait for each restarted Bettercap API",
    )
    auto_locate.add_argument(
        "--bettercap-startup-poll",
        type=float,
        default=bettercap_config.get("startup_poll_interval", 0.25),
        help="poll interval while waiting for Bettercap API startup",
    )
    auto_locate.add_argument(
        "--bettercap-wait",
        type=float,
        default=bettercap_config.get("wait", 5.0),
        help="seconds to poll Bettercap for hosts on each Wi-Fi",
    )
    auto_locate.add_argument(
        "--bettercap-poll",
        type=float,
        default=bettercap_config.get("poll_interval", 0.5),
        help="Bettercap host polling interval in seconds",
    )
    auto_locate.add_argument(
        "--bettercap-discovery-warmup",
        type=float,
        default=bettercap_config.get("discovery_warmup", 3.0),
        help="seconds to wait after starting net.recon/net.probe",
    )
    auto_locate.add_argument(
        "--verify-timeout",
        type=float,
        default=wifi_config.get("verify_timeout", 12.0),
        help="seconds to wait while verifying each joined SSID",
    )
    auto_locate.add_argument(
        "--restore-original",
        action=argparse.BooleanOptionalAction,
        default=auto_wifi_config.get("restore_original", True),
        help="switch back to the original Wi-Fi after the rotation",
    )
    auto_locate.add_argument(
        "--create-template",
        action=argparse.BooleanOptionalAction,
        default=auto_wifi_config.get("create_template", True),
        help="create a sample Wi-Fi rotation file when --wifi-list is missing",
    )
    auto_locate.add_argument(
        "--json",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="print JSON summary",
    )

    interactive = subparsers.add_parser(
        "ui",
        aliases=["interactive"],
        help="start an interactive command-line UI",
    )
    interactive.add_argument(
        "--store",
        type=Path,
        default=DEFAULT_STORE_PATH,
        help=f"device store JSON path; defaults to {DEFAULT_STORE_PATH}",
    )

    web = subparsers.add_parser(
        "web",
        help="start the local Web UI",
    )
    web.add_argument(
        "--host",
        default="localhost",
        help="host/interface to bind; defaults to localhost",
    )
    web.add_argument(
        "--port",
        type=int,
        default=8765,
        help="port to bind; defaults to 8765",
    )
    web.add_argument(
        "--store",
        type=Path,
        default=DEFAULT_STORE_PATH,
        help=f"device store JSON path; defaults to {DEFAULT_STORE_PATH}",
    )

    load = subparsers.add_parser(
        "load",
        aliases=["ping-load"],
        help="run a threaded ICMP/TCP load test with live statistics",
    )
    load.add_argument("target", help="target IP address or hostname")
    load.add_argument(
        "--protocol",
        choices=["icmp", "tcp"],
        default=load_config.get("protocol", "icmp"),
        help="probe protocol; defaults to icmp",
    )
    load.add_argument(
        "--port",
        type=int,
        default=load_config.get("tcp_port", 5000),
        help="TCP port; defaults to 5000",
    )
    load.add_argument(
        "--concurrency",
        type=int,
        default=load_config.get("concurrency", 32),
        help="number of worker threads",
    )
    load.add_argument(
        "--duration",
        type=float,
        default=load_config.get("duration", 10.0),
        help="test duration in seconds; use 0 with --count for count-only mode",
    )
    load.add_argument(
        "--count",
        type=int,
        default=load_config.get("count"),
        help="total probe count across all workers",
    )
    load.add_argument(
        "--timeout",
        type=float,
        default=load_config.get("timeout", 1.0),
        help="per-probe timeout in seconds",
    )
    load.add_argument(
        "--refresh",
        type=float,
        default=load_config.get("refresh_interval", 0.25),
        help="live UI refresh interval in seconds",
    )
    load.add_argument(
        "--ramp-up",
        type=float,
        default=load_config.get("ramp_up", 0.75),
        help="seconds used to gradually start worker threads; 0 starts at once",
    )
    load.add_argument(
        "--jitter",
        type=float,
        default=load_config.get("per_worker_jitter", 0.002),
        help="small per-worker loop jitter in seconds to avoid synchronized bursts",
    )
    load.add_argument(
        "--payload-size",
        type=int,
        default=load_config.get("payload_size", 0),
        help=(
            "bytes to send per probe; for ICMP this maps to ping -s, "
            "for TCP it sends this many zero bytes after connecting"
        ),
    )
    load.add_argument(
        "--tcp-keep-open",
        action=argparse.BooleanOptionalAction,
        default=load_config.get("tcp_keep_open", False),
        help=(
            "with --protocol tcp, keep each connection open and keep sending "
            "payload chunks until the test ends"
        ),
    )
    load.add_argument(
        "--no-live",
        action="store_true",
        help="disable live terminal UI and print only the final JSON summary",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    config = ensure_config()
    parser = _build_parser(config)
    args = parser.parse_args(argv)

    if args.command in {"ui", "interactive"}:
        return run_interactive(args.store, config=config)

    if args.command == "web":
        return run_web(
            host=args.host,
            port=args.port,
            store_path=args.store,
            config=config,
        )

    if args.command in {"load", "ping-load"}:
        duration = None if args.duration == 0 else args.duration
        try:
            summary = run_load_test(
                LoadTestConfig(
                    target=args.target,
                    protocol=args.protocol,
                    concurrency=args.concurrency,
                    duration=duration,
                    count=args.count,
                    timeout=args.timeout,
                    tcp_port=args.port,
                    refresh_interval=args.refresh,
                    ramp_up=args.ramp_up,
                    per_worker_jitter=args.jitter,
                    payload_size=args.payload_size,
                    tcp_keep_open=args.tcp_keep_open,
                ),
                live=not args.no_live,
            )
        except ValueError as exc:
            parser.exit(2, f"{exc}\n")
        if args.no_live:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "wifi":
        try:
            if args.wifi_command == "current":
                ssid = current_wifi_ssid(args.interface)
                if args.json:
                    print(json.dumps({"ssid": ssid}, ensure_ascii=False, indent=2))
                else:
                    print(f"当前 Wi-Fi SSID：{ssid or '未获取'}")
                return 0

            if args.wifi_command == "saved":
                networks = list_saved_wifi_networks(args.interface)
                if args.json:
                    print(json.dumps(networks, ensure_ascii=False, indent=2))
                else:
                    print("已保存 Wi-Fi：")
                    for index, ssid in enumerate(networks, start=1):
                        print(f"{index:>2}. {ssid}")
                return 0

            if args.wifi_command == "nearby":
                networks = list_nearby_wifi_networks(
                    include_current=args.include_current
                )
                if args.json:
                    print(
                        json.dumps(
                            [_wifi_network_to_record(network) for network in networks],
                            ensure_ascii=False,
                            indent=2,
                        )
                    )
                else:
                    _print_wifi_networks(networks)
                return 0

            if args.wifi_command in {"available", "saved-nearby"}:
                networks = list_available_saved_wifi_networks(args.interface)
                if args.json:
                    print(json.dumps(networks, ensure_ascii=False, indent=2))
                else:
                    print("附近可用的已保存 Wi-Fi：")
                    for index, ssid in enumerate(networks, start=1):
                        print(f"{index:>2}. {ssid}")
                return 0

            if args.wifi_command in {"switch", "connect"}:
                ssid = switch_wifi_network(
                    args.ssid,
                    password=args.password,
                    interface=args.interface,
                    verify=args.verify,
                    verify_timeout=args.verify_timeout,
                )
                if args.verify:
                    print(f"已连接到 Wi-Fi：{ssid or args.ssid}")
                else:
                    print(f"已发送 Wi-Fi 切换命令：{args.ssid}")
                return 0
        except WiFiError as exc:
            parser.exit(1, f"{exc}\n")

        parser.exit(
            2,
            "wifi requires a subcommand: current/saved/nearby/available/switch\n",
        )

    if args.command in {"auto-locate", "auto-find"}:
        try:
            hostname = _resolve_auto_locate_hostname(
                hostname=args.hostname,
                saved_selector=args.saved,
                store_path=args.store,
            )
            if args.create_template and not args.wifi_list.exists():
                write_wifi_scan_template(args.wifi_list)
                parser.exit(
                    1,
                    f"已创建 Wi-Fi 轮换配置模板：{args.wifi_list}\n"
                    "请编辑 SSID/password 后重新运行。\n",
                )
            targets = load_wifi_scan_targets(args.wifi_list)
            client = BettercapClient(
                args.bettercap_url,
                args.bettercap_user,
                args.bettercap_pass,
                timeout=args.bettercap_api_timeout,
            )
            result = find_hostname_with_bettercap_then_wifi_rotation(
                hostname,
                targets,
                client=client,
                interface=args.interface,
                bettercap_command=args.bettercap_command,
                auto_start_bettercap_api=args.auto_start_bettercap_api,
                online_check_timeout=args.bettercap_online_check_timeout,
                startup_timeout=args.bettercap_startup_timeout,
                startup_poll_interval=args.bettercap_startup_poll,
                bettercap_wait=args.bettercap_wait,
                bettercap_poll=args.bettercap_poll,
                discovery_warmup=args.bettercap_discovery_warmup,
                verify_timeout=args.verify_timeout,
                restore_original=args.restore_original,
                partial_hostname=args.partial_hostname,
                store_path=args.store,
                on_status=None
                if args.json
                else lambda message: print(message, flush=True),
            )
        except (AutoWiFiScanError, BettercapAPIError, ValueError, WiFiError) as exc:
            parser.exit(1, f"{exc}\n")

        record = _scan_item_to_record(result.host) if result.host else None
        if record is not None and result.ssid:
            record["ssid"] = result.ssid
        summary = {
            "query": result.query,
            "found": result.host is not None,
            "ssid": result.ssid,
            "scanned_ssids": list(result.scanned_ssids),
            "saved_count": result.saved_count,
            "host": record,
        }
        if args.json:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        elif result.host is not None:
            print("已找到设备：")
            _print_scan_header()
            _print_scan_item(1, result.host)
            source = result.ssid or "当前 Wi-Fi / 当前 Bettercap 会话（SSID 未获取）"
            print(f"SSID：{result.ssid or '未获取'}")
            print(f"来源：{source}")
            print(f"写入/更新记录数：{result.saved_count}")
            print(f"设备库：{args.store}")
        else:
            print(f"未找到 hostname：{hostname}")
            if result.scanned_ssids:
                print("已扫描 Wi-Fi：" + ", ".join(result.scanned_ssids))
            print(f"设备库：{args.store}")
            return 1
        return 0

    if args.command in {"auto-wifi-scan", "autoscan-wifi"}:
        try:
            if args.create_template and not args.wifi_list.exists():
                write_wifi_scan_template(args.wifi_list)
                parser.exit(
                    1,
                    f"已创建 Wi-Fi 轮换配置模板：{args.wifi_list}\n"
                    "请编辑 SSID/password 后重新运行。\n",
                )
            targets = load_wifi_scan_targets(args.wifi_list)
            if not args.json:
                print(
                    f"自动轮换扫描：{len(targets)} 个 Wi-Fi，配置 {args.wifi_list}",
                    flush=True,
                )
            client = BettercapClient(
                args.bettercap_url,
                args.bettercap_user,
                args.bettercap_pass,
                timeout=args.bettercap_api_timeout,
            )
            results = run_auto_wifi_scan(
                targets,
                client=client,
                interface=args.interface,
                bettercap_command=args.bettercap_command,
                startup_timeout=args.bettercap_startup_timeout,
                startup_poll_interval=args.bettercap_startup_poll,
                bettercap_wait=args.bettercap_wait,
                bettercap_poll=args.bettercap_poll,
                discovery_warmup=args.bettercap_discovery_warmup,
                verify_timeout=args.verify_timeout,
                restore_original=args.restore_original,
                store_path=args.store,
                on_status=None
                if args.json
                else lambda message: print(message, flush=True),
            )
        except (AutoWiFiScanError, BettercapAPIError, WiFiError) as exc:
            parser.exit(1, f"{exc}\n")

        summary = [
            {
                "ssid": result.ssid,
                "host_count": len(result.hosts),
                "saved_count": result.saved_count,
                "hosts": [_scan_item_to_record(host) for host in result.hosts],
            }
            for result in results
        ]
        if args.json:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        else:
            for result in results:
                print(
                    f"{result.ssid}: 发现 {len(result.hosts)} 台，"
                    f"写入/更新 {result.saved_count} 条。"
                )
            print(f"设备库：{args.store}")
        return 0

    if args.command in {"scan", "list"}:
        discovered_count = 0

        def on_item(item) -> None:
            nonlocal discovered_count
            discovered_count += 1
            _print_scan_item(discovered_count, item)

        if not args.json:
            if args.scanner == "bettercap":
                print(f"扫描来源：Bettercap API {args.bettercap_url}")
            else:
                print("扫描来源：内置 ARP 扫描")
            _print_scan_header()

        try:
            if args.scanner == "bettercap":
                client = BettercapClient(
                    args.bettercap_url,
                    args.bettercap_user,
                    args.bettercap_pass,
                    timeout=args.bettercap_api_timeout,
                )
                bettercap_interface = (
                    None
                    if str(args.bettercap_interface).casefold() == "auto"
                    else args.bettercap_interface
                )
                ensure_bettercap_api_online(
                    client,
                    online_check_timeout=config.get("bettercap", {}).get(
                        "online_check_timeout",
                        0.25,
                    ),
                    auto_start=args.auto_start_bettercap_api,
                    command=args.bettercap_command,
                    interface=bettercap_interface,
                    startup_timeout=args.bettercap_startup_timeout,
                    startup_poll_interval=args.bettercap_startup_poll,
                    on_status=None
                    if args.json
                    else lambda message: print(message, flush=True),
                )
                if not client.is_online(timeout=0.25):
                    parser.exit(
                        1,
                        f"Bettercap API is not reachable at {args.bettercap_url}\n",
                    )
                items = list_bettercap_hosts(
                    client,
                    wait=args.bettercap_wait,
                    poll_interval=args.bettercap_poll,
                    start_discovery=args.start_bettercap,
                    discovery_warmup=args.bettercap_discovery_warmup,
                    on_discovery_starting=None
                    if args.json
                    else lambda module: print(
                        f"{module} 正在启动，等待 "
                        f"{args.bettercap_discovery_warmup:g} 秒预热...",
                        flush=True,
                    ),
                    on_host=None if args.json else on_item,
                )
            else:
                network = args.network
                if isinstance(network, str) and network.casefold() == "auto":
                    network = detect_local_ipv4_network()
                    if network is None:
                        parser.exit(1, "could not auto-detect local IPv4 network\n")
                if not can_run_active_arp_scan():
                    parser.exit(
                        1,
                        "active ARP scan requires root/admin privileges; "
                        "try running with sudo\n",
                    )

                items = list_network_devices(
                    network,
                    timeout=args.timeout,
                    passes=args.passes,
                    batch_size=args.batch_size,
                    interval=args.interval,
                    resolve_hostnames=args.resolve_hostnames,
                    on_device=None if args.json else on_item,
                )
        except BettercapAPIError as exc:
            parser.exit(1, f"{exc}\n")

        if args.json:
            print(
                json.dumps(
                    [_scan_item_to_record(item) for item in items],
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            print(f"\n扫描完成，发现 {len(items)} 台设备。")
            if args.scanner == "builtin" and args.resolve_hostnames:
                print("\n最终列表：")
                _print_scan_header()
                for index, item in enumerate(items, start=1):
                    _print_scan_item(index, item)
        return 0

    if args.command == "mdns-info":
        try:
            if args.instance:
                service_types = tuple(args.service_type) or ("_ipp._tcp",)
                if len(service_types) != 1:
                    parser.exit(2, "--instance requires exactly one --service-type\n")
                services = [
                    resolve_mdns_service(
                        args.instance,
                        service_types[0],
                        domain=args.domain,
                        timeout=args.timeout,
                    )
                ]
            elif args.hostname:
                service_types = tuple(args.service_type) or DEFAULT_SERVICE_TYPES
                services = find_mdns_services_by_hostname(
                    args.hostname,
                    service_types=service_types,
                    domain=args.domain,
                    timeout=args.timeout,
                    first=args.first,
                )
            else:
                parser.exit(2, "mdns-info requires --hostname or --instance\n")
        except FileNotFoundError:
            parser.exit(127, "dns-sd command not found; this feature needs Bonjour\n")

        if not services:
            parser.exit(1, "no matching mDNS service found\n")

        if args.merge:
            print(format_mdns_key_values(merge_mdns_services(services)))
        else:
            print("\n\n".join(format_mdns_service(service) for service in services))
        return 0

    if args.command != "locate":
        parser.print_help()
        return 0

    try:
        note_hosts = _parse_note_hosts(args.note_host)
        network = args.network
        if isinstance(network, str) and network.casefold() == "auto":
            network = detect_local_ipv4_network()
            if network is None:
                parser.exit(1, "could not auto-detect local IPv4 network\n")
        if network and not can_run_active_arp_scan():
            print(
                "warning: active ARP scan requires root on this system; "
                "falling back to DNS/mDNS and ARP cache"
            )
            network = None

        device = locate_device(
            hostname=args.hostname,
            note=args.note,
            network=network,
            note_hosts=note_hosts,
            timeout=args.timeout,
            partial_hostname=args.partial_hostname,
            partial_note=args.partial_note,
            prime_arp_cache=args.prime_arp_cache,
        )
    except argparse.ArgumentTypeError as exc:
        parser.exit(2, f"{exc}\n")
    except DeviceNotFoundError as exc:
        parser.exit(1, f"{exc}\n")

    print(
        json.dumps(
            {
                **_device_to_record(device),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
