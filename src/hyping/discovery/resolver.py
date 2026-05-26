import re
import socket
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import replace
from ipaddress import IPv4Address
from math import ceil

from hyping.discovery.arp import ARPScanError, arp_scan
from hyping.models.device import Device

_MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}\b")
_RAW_MAC_RE = re.compile(r"(?i)^[0-9a-f]{12}$")


class DeviceNotFoundError(LookupError):
    """Raised when no device can be located for a hostname/note query."""


class AmbiguousDeviceError(LookupError):
    """Raised when a query matches more than one device."""


def _clean_hostname(hostname: str | None) -> str | None:
    """Strip whitespace and the optional DNS root dot from a hostname."""

    if hostname is None:
        return None

    cleaned = hostname.strip().rstrip(".")
    if not cleaned:
        return None

    return cleaned


def _normalize_hostname(hostname: str | None) -> str | None:
    cleaned = _clean_hostname(hostname)
    if cleaned is None:
        return None

    return cleaned.casefold()


def _hostname_candidates(hostname: str) -> set[str]:
    normalized = _normalize_hostname(hostname)
    if normalized is None:
        return set()

    candidates = {normalized}

    if normalized.endswith(".local"):
        candidates.add(normalized.removesuffix(".local"))
    else:
        candidates.add(f"{normalized}.local")

    return candidates


def _resolution_hostname_candidates(hostname: str) -> list[str]:
    """Return DNS/mDNS candidate names to try for a user supplied hostname."""

    normalized = _clean_hostname(hostname)
    if normalized is None:
        msg = "hostname must not be empty"
        raise ValueError(msg)

    candidates = [normalized]
    if normalized.casefold().endswith(".local"):
        candidates.append(normalized[: -len(".local")])
    else:
        candidates.append(f"{normalized}.local")

    return list(dict.fromkeys(candidates))


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip().casefold()
    if not normalized:
        return None

    return normalized


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address to lower-case, colon-separated octets."""

    cleaned = mac.strip()
    if _RAW_MAC_RE.fullmatch(cleaned):
        parts = [cleaned[index : index + 2] for index in range(0, 12, 2)]
    else:
        parts = re.split("[:-]", cleaned)

    if len(parts) != 6 or any(not part or len(part) > 2 for part in parts):
        msg = f"invalid MAC address: {mac!r}"
        raise ValueError(msg)

    try:
        return ":".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError as exc:
        msg = f"invalid MAC address: {mac!r}"
        raise ValueError(msg) from exc


def _device_matches_hostname(
    device: Device,
    hostname: str,
    *,
    partial_hostname: bool,
) -> bool:
    if device.hostname is None:
        return False

    device_hostnames = _hostname_candidates(device.hostname)
    query_hostnames = _hostname_candidates(hostname)

    if device_hostnames & query_hostnames:
        return True

    if not partial_hostname:
        return False

    return any(
        query_hostname in device_hostname
        for query_hostname in query_hostnames
        for device_hostname in device_hostnames
    )


def _device_matches_note(
    device: Device,
    note: str,
    *,
    partial_note: bool,
) -> bool:
    device_note = _normalize_text(device.note)
    query_note = _normalize_text(note)

    if device_note is None or query_note is None:
        return False

    if partial_note:
        return query_note in device_note

    return device_note == query_note


def find_devices(
    devices: Iterable[Device],
    *,
    hostname: str | None = None,
    note: str | None = None,
    partial_hostname: bool = False,
    partial_note: bool = False,
) -> list[Device]:
    """Find devices by hostname, note, or both.

    Matching is case-insensitive. Hostname matching also treats ``host`` and
    ``host.local`` as aliases so callers can use either DNS or mDNS-style
    names. When ``partial_hostname`` is true, ``hostname`` can be a substring
    of the known hostname. When both ``hostname`` and ``note`` are provided, a
    device must match both.
    """

    if _normalize_hostname(hostname) is None and _normalize_text(note) is None:
        msg = "hostname or note is required"
        raise ValueError(msg)

    matches: list[Device] = []

    for device in devices:
        if hostname is not None and not _device_matches_hostname(
            device,
            hostname,
            partial_hostname=partial_hostname,
        ):
            continue

        if note is not None and not _device_matches_note(
            device,
            note,
            partial_note=partial_note,
        ):
            continue

        matches.append(device)

    return matches


def find_one_device(
    devices: Iterable[Device],
    *,
    hostname: str | None = None,
    note: str | None = None,
    partial_hostname: bool = False,
    partial_note: bool = False,
) -> Device | None:
    """Return a single matching device, or ``None`` if no device matches."""

    matches = find_devices(
        devices,
        hostname=hostname,
        note=note,
        partial_hostname=partial_hostname,
        partial_note=partial_note,
    )

    if len(matches) > 1:
        query = _format_query(hostname=hostname, note=note)
        msg = f"multiple devices match {query}: {matches!r}"
        raise AmbiguousDeviceError(msg)

    return matches[0] if matches else None


def resolve_ipv4_addresses(hostname: str) -> list[IPv4Address]:
    """Resolve *hostname* to unique IPv4 addresses using the system resolver.

    Both plain hostnames and their Bonjour/mDNS ``.local`` aliases are tried.
    For example, resolving ``"printer"`` also tries ``"printer.local"``.
    """

    hostnames = _resolution_hostname_candidates(hostname)

    addresses: list[IPv4Address] = []
    seen: set[IPv4Address] = set()

    for name in hostnames:
        try:
            infos = socket.getaddrinfo(
                name,
                None,
                family=socket.AF_INET,
                type=socket.SOCK_DGRAM,
            )
        except socket.gaierror:
            continue

        for info in infos:
            sockaddr = info[4]
            ip = IPv4Address(sockaddr[0])
            if ip in seen:
                continue

            seen.add(ip)
            addresses.append(ip)

    return addresses


def resolve_hostname(ip: IPv4Address | str) -> str | None:
    """Resolve an IPv4 address back to a hostname, if reverse DNS knows it."""

    try:
        hostname, _, _ = socket.gethostbyaddr(str(ip))
    except (socket.gaierror, socket.herror, OSError):
        return None

    return hostname.rstrip(".")


def enrich_hostnames(devices: Iterable[Device]) -> list[Device]:
    """Return devices with missing hostnames filled from reverse DNS when possible."""

    enriched: list[Device] = []

    for device in devices:
        if device.hostname is not None:
            enriched.append(device)
            continue

        hostname = resolve_hostname(device.ip)
        if hostname is None:
            enriched.append(device)
        else:
            enriched.append(replace(device, hostname=hostname))

    return enriched


def _read_arp_cache(ip: IPv4Address | str) -> str | None:
    """Read the local OS ARP cache for *ip* and return a normalized MAC address."""

    try:
        result = subprocess.run(
            ["arp", "-n", str(ip)],
            check=False,
            capture_output=True,
            text=True,
            timeout=1.0,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None

    output = f"{result.stdout}\n{result.stderr}"
    match = _MAC_RE.search(output)
    if match is None:
        return None

    return normalize_mac(match.group(0))


def _prime_arp_cache(ip: IPv4Address | str, *, timeout: float) -> None:
    """Best-effort ping to make the OS learn the IP's MAC in the ARP cache."""

    wait = max(timeout, 0.1)
    if sys.platform == "darwin":
        # macOS ping's -W value is milliseconds.
        wait_arg = str(max(100, int(wait * 1000)))
    else:
        # Linux ping's -W value is seconds.
        wait_arg = str(max(1, ceil(wait)))

    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", wait_arg, str(ip)],
            check=False,
            capture_output=True,
            text=True,
            timeout=wait + 0.5,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return


def _find_by_ip(devices: Iterable[Device], ip: IPv4Address) -> Device | None:
    for device in devices:
        if device.ip == ip:
            return device

    return None


def _dedupe_devices(devices: Iterable[Device]) -> list[Device]:
    unique: dict[tuple[str, str], Device] = {}
    for device in devices:
        key = ("ip", str(device.ip))
        existing = unique.get(key)
        if existing is None:
            unique[key] = device
            continue

        unique[key] = Device(
            ip=device.ip,
            mac=device.mac or existing.mac,
            hostname=device.hostname or existing.hostname,
            note=device.note or existing.note,
        )

    return list(unique.values())


def _device_from_resolved_ip(
    ip: IPv4Address,
    *,
    hostname: str,
    note: str | None,
    known_devices: Iterable[Device],
    read_arp_cache: bool,
    prime_arp_cache: bool,
    timeout: float,
) -> Device | None:
    device = _find_by_ip(known_devices, ip)
    if device is not None:
        return replace(
            device,
            hostname=device.hostname or hostname,
            note=device.note or note,
        )

    if not read_arp_cache:
        return None

    mac = _read_arp_cache(ip)
    if mac is None and prime_arp_cache:
        _prime_arp_cache(ip, timeout=timeout)
        mac = _read_arp_cache(ip)

    if mac is None:
        return None

    return Device(
        ip=ip,
        mac=mac,
        hostname=hostname,
        note=note,
    )


def _hostname_from_note(
    note: str | None,
    note_hosts: Mapping[str, str] | None,
    *,
    partial_note: bool = False,
) -> str | None:
    normalized_note = _normalize_text(note)
    if normalized_note is None or note_hosts is None:
        return None

    partial_matches: list[str] = []

    for known_note, known_hostname in note_hosts.items():
        normalized_known_note = _normalize_text(known_note)
        if normalized_known_note is None:
            continue

        if normalized_known_note == normalized_note:
            return _clean_hostname(known_hostname)

        if partial_note and normalized_note in normalized_known_note:
            cleaned_hostname = _clean_hostname(known_hostname)
            if cleaned_hostname is not None:
                partial_matches.append(cleaned_hostname)

    if len(partial_matches) > 1:
        msg = f"multiple note aliases match note={note!r}: {partial_matches!r}"
        raise AmbiguousDeviceError(msg)

    if partial_matches:
        return partial_matches[0]

    return None


def _hostnames_from_note(
    note: str | None,
    note_hosts: Mapping[str, str] | None,
    *,
    partial_note: bool = False,
) -> list[str]:
    normalized_note = _normalize_text(note)
    if normalized_note is None or note_hosts is None:
        return []

    hostnames: list[str] = []
    seen: set[str] = set()

    for known_note, known_hostname in note_hosts.items():
        normalized_known_note = _normalize_text(known_note)
        if normalized_known_note is None:
            continue

        if normalized_known_note != normalized_note and not (
            partial_note and normalized_note in normalized_known_note
        ):
            continue

        cleaned_hostname = _clean_hostname(known_hostname)
        if cleaned_hostname is None:
            continue

        normalized_hostname = cleaned_hostname.casefold()
        if normalized_hostname in seen:
            continue

        seen.add(normalized_hostname)
        hostnames.append(cleaned_hostname)

    return hostnames


def _format_query(*, hostname: str | None, note: str | None) -> str:
    parts: list[str] = []

    if hostname is not None:
        parts.append(f"hostname={hostname!r}")

    if note is not None:
        parts.append(f"note={note!r}")

    return ", ".join(parts) if parts else "<empty query>"


def _candidate_hostnames_from_mdns_text(
    text: str,
    *,
    timeout: float,
) -> list[str]:
    from hyping.discovery.mdns import find_mdns_services_by_text

    services = find_mdns_services_by_text(text, timeout=timeout)
    hostnames: list[str] = []
    seen: set[str] = set()
    for service in services:
        cleaned = _clean_hostname(service.hostname)
        if cleaned is None:
            continue

        normalized = cleaned.casefold()
        if normalized in seen:
            continue

        seen.add(normalized)
        hostnames.append(cleaned)

    return hostnames


def _find_known_device(
    devices: Iterable[Device],
    *,
    hostname: str | None,
    note: str | None,
    note_hosts: Mapping[str, str] | None,
    partial_hostname: bool,
    partial_note: bool,
) -> Device | None:
    known_devices = list(devices)

    match = find_one_device(
        known_devices,
        hostname=hostname,
        note=note,
        partial_hostname=partial_hostname,
        partial_note=partial_note,
    )
    if match is not None:
        return match

    # A note can also be an alias for a hostname via note_hosts. In that case
    # inventory entries do not need to duplicate the note string themselves.
    hostname_alias = _hostname_from_note(
        note,
        note_hosts,
        partial_note=partial_note,
    )
    if hostname is not None or hostname_alias is None:
        return None

    return find_one_device(
        known_devices,
        hostname=hostname_alias,
        partial_hostname=partial_hostname,
    )


def _find_known_devices(
    devices: Iterable[Device],
    *,
    hostname: str | None,
    note: str | None,
    note_hosts: Mapping[str, str] | None,
    partial_hostname: bool,
    partial_note: bool,
) -> list[Device]:
    known_devices = list(devices)
    matches = find_devices(
        known_devices,
        hostname=hostname,
        note=note,
        partial_hostname=partial_hostname,
        partial_note=partial_note,
    )

    if hostname is not None:
        return _dedupe_devices(matches)

    for hostname_alias in _hostnames_from_note(
        note,
        note_hosts,
        partial_note=partial_note,
    ):
        matches.extend(
            find_devices(
                known_devices,
                hostname=hostname_alias,
                partial_hostname=partial_hostname,
            )
        )

    return _dedupe_devices(matches)


def locate_devices(
    *,
    hostname: str | None = None,
    note: str | None = None,
    devices: Iterable[Device] | None = None,
    network: str | None = None,
    note_hosts: Mapping[str, str] | None = None,
    timeout: float = 1.0,
    partial_hostname: bool = False,
    partial_note: bool = False,
    resolve_hostname_names: bool = True,
    read_arp_cache: bool = True,
    prime_arp_cache: bool = True,
) -> list[Device]:
    """Locate all matching devices by hostname and/or note."""

    hostname = _clean_hostname(hostname)

    if _normalize_hostname(hostname) is None and _normalize_text(note) is None:
        msg = "hostname or note is required"
        raise ValueError(msg)

    known_devices = list(devices or [])
    matches: list[Device] = []
    matches.extend(
        _find_known_devices(
            known_devices,
            hostname=hostname,
            note=note,
            note_hosts=note_hosts,
            partial_hostname=partial_hostname,
            partial_note=partial_note,
        )
    )

    if network is not None:
        try:
            scanned_devices = arp_scan(network, timeout=timeout)
        except ARPScanError:
            scanned_devices = []

        if resolve_hostname_names:
            scanned_devices = enrich_hostnames(scanned_devices)

        known_devices.extend(scanned_devices)
        matches.extend(
            _find_known_devices(
                scanned_devices,
                hostname=hostname,
                note=note,
                note_hosts=note_hosts,
                partial_hostname=partial_hostname,
                partial_note=partial_note,
            )
        )

    hostnames_to_resolve: list[str] = []
    if hostname is not None:
        hostnames_to_resolve.append(hostname)
    else:
        hostnames_to_resolve.extend(
            _hostnames_from_note(
                note,
                note_hosts,
                partial_note=partial_note,
            )
        )

    for hostname_to_resolve in hostnames_to_resolve:
        for ip in resolve_ipv4_addresses(hostname_to_resolve):
            device = _device_from_resolved_ip(
                ip,
                hostname=hostname_to_resolve,
                note=note,
                known_devices=known_devices,
                read_arp_cache=read_arp_cache,
                prime_arp_cache=prime_arp_cache,
                timeout=timeout,
            )
            if device is not None:
                matches.append(device)

    if partial_hostname and hostname is not None:
        for candidate_hostname in _candidate_hostnames_from_mdns_text(
            hostname,
            timeout=timeout,
        ):
            for ip in resolve_ipv4_addresses(candidate_hostname):
                device = _device_from_resolved_ip(
                    ip,
                    hostname=candidate_hostname,
                    note=note,
                    known_devices=known_devices,
                    read_arp_cache=read_arp_cache,
                    prime_arp_cache=prime_arp_cache,
                    timeout=timeout,
                )
                if device is not None:
                    matches.append(device)
                    break

    return _dedupe_devices(matches)


def locate_device(
    *,
    hostname: str | None = None,
    note: str | None = None,
    devices: Iterable[Device] | None = None,
    network: str | None = None,
    note_hosts: Mapping[str, str] | None = None,
    timeout: float = 1.0,
    partial_hostname: bool = False,
    partial_note: bool = False,
    resolve_hostname_names: bool = True,
    read_arp_cache: bool = True,
    prime_arp_cache: bool = True,
) -> Device:
    """Locate one device's IPv4 and MAC address by hostname and/or note.

    Sources are tried in this order:

    1. The supplied ``devices`` collection, if any.
    2. An ARP scan of ``network``, if provided.
    3. System DNS/mDNS resolution for ``hostname`` (or ``note_hosts[note]``),
       followed by lookup in the known devices and the local ARP cache.

    ``note_hosts`` maps human notes/aliases to hostnames, for cases where the
    user remembers a note such as ``"living room printer"`` instead of the
    actual host name.
    """
    matches = locate_devices(
        hostname=hostname,
        note=note,
        devices=devices,
        network=network,
        note_hosts=note_hosts,
        timeout=timeout,
        partial_hostname=partial_hostname,
        partial_note=partial_note,
        resolve_hostname_names=resolve_hostname_names,
        read_arp_cache=read_arp_cache,
        prime_arp_cache=prime_arp_cache,
    )
    if len(matches) == 1:
        return matches[0]

    query = _format_query(hostname=_clean_hostname(hostname), note=note)
    if len(matches) > 1:
        msg = f"multiple devices match {query}: {matches!r}"
        raise AmbiguousDeviceError(msg)

    msg = f"could not locate device for {query}"
    raise DeviceNotFoundError(msg)
