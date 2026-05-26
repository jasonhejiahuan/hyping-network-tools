import re
import shlex
import subprocess
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from ipaddress import IPv4Address

from hyping.discovery.resolver import resolve_ipv4_addresses

LOCAL_HOSTNAME_SUFFIX = ".local"
DEFAULT_SERVICE_TYPES = (
    "_ipp._tcp",
    "_ipps._tcp",
    "_printer._tcp",
    "_pdl-datastream._tcp",
    "_airplay._tcp",
    "_raop._tcp",
    "_companion-link._tcp",
    "_device-info._tcp",
    "_ssh._tcp",
)

_REACHED_RE = re.compile(r"can be reached at\s+(.+?)\.:([0-9]+)\s")
_TXT_RE = re.compile(r"(?P<key>[^=\s]+)=(?P<value>(?:\\.|[^\s])*)")


@dataclass(slots=True, frozen=True)
class MDNSService:
    """Resolved Bonjour/mDNS service information."""

    instance: str
    service_type: str
    domain: str
    hostname: str
    port: int | None
    txt: dict[str, str]


def normalize_mdns_hostname(hostname: str) -> str:
    """Normalize an mDNS hostname and remove the optional final root dot."""

    normalized = hostname.strip().rstrip(".")
    if not normalized:
        msg = "hostname must not be empty"
        raise ValueError(msg)

    return normalized


def as_mdns_hostname(hostname: str) -> str:
    """Return *hostname* as a Bonjour/mDNS hostname."""

    normalized = normalize_mdns_hostname(hostname)

    if normalized.casefold().endswith(LOCAL_HOSTNAME_SUFFIX):
        return normalized

    return f"{normalized}{LOCAL_HOSTNAME_SUFFIX}"


def resolve_mdns_ipv4_addresses(hostname: str) -> list[IPv4Address]:
    """Resolve a Bonjour/mDNS hostname to IPv4 addresses.

    On macOS, ``socket.getaddrinfo`` is backed by mDNSResponder, so resolving
    ``*.local`` names does not need an extra runtime dependency.
    """

    return resolve_ipv4_addresses(as_mdns_hostname(hostname))


def _run_dns_sd(args: list[str], *, timeout: float) -> str:
    """Run a dns-sd command briefly and return the output it produced."""

    process = subprocess.Popen(
        ["dns-sd", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        stdout, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            stdout, _ = process.communicate(timeout=1.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, _ = process.communicate()

    if isinstance(stdout, bytes):
        return stdout.decode("utf-8", errors="replace")

    return stdout


def _decode_dns_sd_escapes(value: str) -> str:
    """Decode dns-sd's decimal backslash escapes, e.g. ``\\032`` for spaces."""

    result: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\":
            result.append(char)
            index += 1
            continue

        escaped = value[index + 1 : index + 4]
        if len(escaped) == 3 and escaped.isdigit():
            result.append(chr(int(escaped, 10)))
            index += 4
            continue

        if index + 1 < len(value):
            result.append(value[index + 1])
            index += 2
        else:
            result.append(char)
            index += 1

    return "".join(result)


def _parse_txt_record(output: str) -> dict[str, str]:
    txt: dict[str, str] = {}

    for match in _TXT_RE.finditer(output):
        key = match.group("key").strip('"')
        value = match.group("value").strip('"')
        if key in {"at", "Flags", "interface"}:
            continue

        txt[key] = _decode_dns_sd_escapes(value)

    return txt


def _parse_reached_host(output: str) -> tuple[str, int | None]:
    for line in output.splitlines():
        match = _REACHED_RE.search(line)
        if match is not None:
            return normalize_mdns_hostname(match.group(1)), int(match.group(2))

    return "", None


def _parse_browse_instances(output: str, service_type: str, domain: str) -> list[str]:
    instances: list[str] = []

    for line in output.splitlines():
        if " Add " not in line:
            continue

        columns = line.split(maxsplit=6)
        if len(columns) < 7:
            continue

        line_domain = columns[4].rstrip(".")
        line_type = columns[5].rstrip(".")
        instance = columns[6].strip()
        if line_domain != domain.rstrip(".") or line_type != service_type.rstrip("."):
            continue

        instances.append(instance)

    return list(dict.fromkeys(instances))


def browse_mdns_services(
    service_type: str,
    *,
    domain: str = "local",
    timeout: float = 2.0,
) -> list[str]:
    """Return Bonjour service instance names for *service_type*."""

    output = _run_dns_sd(["-B", service_type, domain], timeout=timeout)
    return _parse_browse_instances(output, service_type, domain)


def resolve_mdns_service(
    instance: str,
    service_type: str,
    *,
    domain: str = "local",
    timeout: float = 2.0,
) -> MDNSService:
    """Resolve a Bonjour service and return its host, port, and TXT record."""

    output = _run_dns_sd(["-L", instance, service_type, domain], timeout=timeout)
    hostname, port = _parse_reached_host(output)
    return MDNSService(
        instance=instance,
        service_type=service_type,
        domain=domain,
        hostname=hostname,
        port=port,
        txt=_parse_txt_record(output),
    )


def find_mdns_services_by_hostname(
    hostname: str,
    *,
    service_types: Iterable[str] = DEFAULT_SERVICE_TYPES,
    domain: str = "local",
    timeout: float = 2.0,
    first: bool = False,
) -> list[MDNSService]:
    """Find resolved Bonjour services whose target hostname matches *hostname*."""

    target = as_mdns_hostname(hostname).casefold()
    service_type_list = list(dict.fromkeys(service_types))
    matches: list[MDNSService] = []

    with ThreadPoolExecutor(max_workers=max(1, len(service_type_list))) as executor:
        browse_futures = {
            executor.submit(
                browse_mdns_services,
                service_type,
                domain=domain,
                timeout=timeout,
            ): service_type
            for service_type in service_type_list
        }

        resolve_jobs: list[tuple[str, str]] = []
        for future in as_completed(browse_futures):
            service_type = browse_futures[future]
            for instance in future.result():
                resolve_jobs.append((instance, service_type))

    if not resolve_jobs:
        return []

    with ThreadPoolExecutor(max_workers=max(1, len(resolve_jobs))) as executor:
        resolve_futures = [
            executor.submit(
                resolve_mdns_service,
                instance,
                service_type,
                domain=domain,
                timeout=timeout,
            )
            for instance, service_type in resolve_jobs
        ]

        for future in as_completed(resolve_futures):
            service = future.result()
            if service.hostname.casefold() == target:
                matches.append(service)
                if first:
                    return matches

    order = {
        service_type: index
        for index, service_type in enumerate(service_type_list)
    }
    return sorted(
        matches,
        key=lambda service: (
            order.get(service.service_type, len(order)),
            service.instance,
        ),
    )


def _service_matches_text(service: MDNSService, text: str) -> bool:
    query = text.strip().casefold()
    if not query:
        return False

    haystacks = [
        service.instance,
        service.hostname,
        *service.txt.values(),
    ]
    return any(query in haystack.casefold() for haystack in haystacks)


def find_mdns_services_by_text(
    text: str,
    *,
    service_types: Iterable[str] = DEFAULT_SERVICE_TYPES,
    domain: str = "local",
    timeout: float = 2.0,
    first: bool = False,
) -> list[MDNSService]:
    """Find Bonjour services whose instance, hostname or TXT values contain text."""

    if not text.strip():
        msg = "search text must not be empty"
        raise ValueError(msg)

    service_type_list = list(dict.fromkeys(service_types))
    matches: list[MDNSService] = []

    with ThreadPoolExecutor(max_workers=max(1, len(service_type_list))) as executor:
        browse_futures = {
            executor.submit(
                browse_mdns_services,
                service_type,
                domain=domain,
                timeout=timeout,
            ): service_type
            for service_type in service_type_list
        }

        resolve_jobs: list[tuple[str, str]] = []
        for future in as_completed(browse_futures):
            service_type = browse_futures[future]
            for instance in future.result():
                resolve_jobs.append((instance, service_type))

    if not resolve_jobs:
        return []

    with ThreadPoolExecutor(max_workers=max(1, len(resolve_jobs))) as executor:
        resolve_futures = [
            executor.submit(
                resolve_mdns_service,
                instance,
                service_type,
                domain=domain,
                timeout=timeout,
            )
            for instance, service_type in resolve_jobs
        ]

        for future in as_completed(resolve_futures):
            service = future.result()
            if _service_matches_text(service, text):
                matches.append(service)
                if first:
                    return matches

    order = {
        service_type: index
        for index, service_type in enumerate(service_type_list)
    }
    return sorted(
        matches,
        key=lambda service: (
            order.get(service.service_type, len(order)),
            service.hostname,
            service.instance,
        ),
    )


def merge_mdns_services(services: Iterable[MDNSService]) -> dict[str, str]:
    """Merge multiple Bonjour service TXT records into one key/value mapping."""

    merged: dict[str, str] = {}
    service_names: list[str] = []
    service_types: list[str] = []
    ports: list[str] = []

    for service in services:
        if service.hostname and "hostname" not in merged:
            merged["hostname"] = service.hostname
        if service.instance not in service_names:
            service_names.append(service.instance)
        if service.service_type not in service_types:
            service_types.append(service.service_type)
        if service.port is not None and str(service.port) not in ports:
            ports.append(str(service.port))

        for key in sorted(service.txt):
            value = service.txt[key]
            if key not in merged:
                merged[key] = value
            elif merged[key] != value:
                service_key = f"{service.service_type}.{key}"
                merged[service_key] = value

    if service_names:
        merged["service"] = ", ".join(service_names)
    if service_types:
        merged["type"] = ", ".join(service_types)
    if ports:
        merged["port"] = ", ".join(ports)

    return merged


def format_mdns_service(service: MDNSService) -> str:
    """Format a resolved Bonjour service as tab-separated key/value lines."""

    lines = [
        f"hostname\t{service.hostname}",
        f"service\t{service.instance}",
        f"type\t{service.service_type}",
    ]
    if service.port is not None:
        lines.append(f"port\t{service.port}")

    for key in sorted(service.txt):
        lines.append(f"{key}\t{service.txt[key]}")

    return "\n".join(lines)


def format_mdns_key_values(values: dict[str, str]) -> str:
    """Format a key/value mapping as tab-separated lines."""

    preferred = ["hostname", "service", "type", "port", "note", "model", "ty"]
    lines: list[str] = []
    emitted: set[str] = set()

    for key in preferred:
        if key in values:
            lines.append(f"{key}\t{values[key]}")
            emitted.add(key)

    for key in sorted(values):
        if key not in emitted:
            lines.append(f"{key}\t{values[key]}")

    return "\n".join(lines)


def shell_quote_service_types(service_types: Iterable[str]) -> str:
    """Return a shell-friendly representation for help/debug output."""

    return " ".join(shlex.quote(service_type) for service_type in service_types)
