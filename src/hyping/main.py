import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from hyping.discovery.arp import can_run_active_arp_scan
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


def _build_parser() -> argparse.ArgumentParser:
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
        default=1.0,
        help="ARP scan/ping timeout in seconds",
    )
    locate.add_argument(
        "--partial-hostname",
        action="store_true",
        help="allow substring hostname matching for known/scanned devices",
    )
    locate.add_argument(
        "--partial-note",
        action="store_true",
        help="allow substring note matching for note aliases/inventory",
    )
    locate.add_argument(
        "--no-prime-arp-cache",
        action="store_true",
        help="do not ping the resolved IP before reading the local ARP cache",
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
        default="local",
        help="Bonjour domain; defaults to local",
    )
    mdns_info.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="seconds to wait for each dns-sd browse/resolve step",
    )
    mdns_info.add_argument(
        "--first",
        action="store_true",
        help="print only the first matching service",
    )
    mdns_info.add_argument(
        "--merge",
        action="store_true",
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
        default="icmp",
        help="probe protocol; defaults to icmp",
    )
    load.add_argument(
        "--port",
        type=int,
        help="TCP port; required when --protocol tcp",
    )
    load.add_argument(
        "--concurrency",
        type=int,
        default=32,
        help="number of worker threads",
    )
    load.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="test duration in seconds; use 0 with --count for count-only mode",
    )
    load.add_argument(
        "--count",
        type=int,
        help="total probe count across all workers",
    )
    load.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="per-probe timeout in seconds",
    )
    load.add_argument(
        "--refresh",
        type=float,
        default=0.25,
        help="live UI refresh interval in seconds",
    )
    load.add_argument(
        "--ramp-up",
        type=float,
        default=0.75,
        help="seconds used to gradually start worker threads; 0 starts at once",
    )
    load.add_argument(
        "--jitter",
        type=float,
        default=0.002,
        help="small per-worker loop jitter in seconds to avoid synchronized bursts",
    )
    load.add_argument(
        "--no-live",
        action="store_true",
        help="disable live terminal UI and print only the final JSON summary",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command in {"ui", "interactive"}:
        return run_interactive(args.store)

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
                ),
                live=not args.no_live,
            )
        except ValueError as exc:
            parser.exit(2, f"{exc}\n")
        if args.no_live:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
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
            prime_arp_cache=not args.no_prime_arp_cache,
        )
    except argparse.ArgumentTypeError as exc:
        parser.exit(2, f"{exc}\n")
    except DeviceNotFoundError as exc:
        parser.exit(1, f"{exc}\n")

    print(
        json.dumps(
            {
                "ip": str(device.ip),
                "mac": device.mac,
                "hostname": device.hostname,
                "note": device.note,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
