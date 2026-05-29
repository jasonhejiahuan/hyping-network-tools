import argparse
import json
from collections.abc import Mapping, Sequence
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
    resolve_mdns_service,
)
from hyping.discovery.network import detect_local_ipv4_network
from hyping.discovery.resolver import DeviceNotFoundError, locate_device
from hyping.interactive import run_interactive
from hyping.loadtest import LoadTestConfig, run_load_test
from hyping.storage import DEFAULT_STORE_PATH


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


def _build_parser(config: Mapping[str, Any] | None = None) -> argparse.ArgumentParser:
    config = config or {}
    scan_config = config.get("scan", {})
    bettercap_config = config.get("bettercap", {})
    load_config = config.get("load", {})
    locate_config = config.get("locate", {})
    mdns_config = config.get("mdns", {})

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
