import re
import socket
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import replace
from ipaddress import IPv4Address
from math import ceil

from hyping.discovery.arp import arp_scan
from hyping.models.device import Device

_MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}\b")


class DeviceNotFoundError(LookupError):
    """Raised when no device can be located for a hostname/note query."""


class AmbiguousDeviceError(LookupError):
    """Raised when a query matches more than one device."""


def _normalize_hostname(hostname: str | None) -> str | None:
    if hostname is None:
        return None

    normalized = hostname.strip().rstrip(".").casefold()
    if not normalized:
        return None

    return normalized


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

    normalized = hostname.strip().rstrip(".")
    if not normalized:
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

    parts = re.split("[:-]", mac.strip())
    if len(parts) != 6 or any(not part or len(part) > 2 for part in parts):
        msg = f"invalid MAC address: {mac!r}"
        raise ValueError(msg)

    try:
        return ":".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError as exc:
        msg = f"invalid MAC address: {mac!r}"
        raise ValueError(msg) from exc


def _device_matches_hostname(device: Device, hostname: str) -> bool:
    if device.hostname is None:
        return False

    device_hostnames = _hostname_candidates(device.hostname)
    query_hostnames = _hostname_candidates(hostname)

    return bool(device_hostnames & query_hostnames)


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
    partial_note: bool = False,
) -> list[Device]:
    """Find devices by hostname, note, or both.

    Matching is case-insensitive. Hostname matching also treats ``host`` and
    ``host.local`` as aliases so callers can use either DNS or mDNS-style names.
    When both ``hostname`` and ``note`` are provided, a device must match both.
    """

    if _normalize_hostname(hostname) is None and _normalize_text(note) is None:
        msg = "hostname or note is required"
        raise ValueError(msg)

    matches: list[Device] = []

    for device in devices:
        if hostname is not None and not _device_matches_hostname(device, hostname):
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
    partial_note: bool = False,
) -> Device | None:
    """Return a single matching device, or ``None`` if no device matches."""

    matches = find_devices(
        devices,
        hostname=hostname,
        note=note,
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
            return known_hostname

        if partial_note and normalized_note in normalized_known_note:
            partial_matches.append(known_hostname)

    if len(partial_matches) > 1:
        msg = f"multiple note aliases match note={note!r}: {partial_matches!r}"
        raise AmbiguousDeviceError(msg)

    if partial_matches:
        return partial_matches[0]

    return None


def _format_query(*, hostname: str | None, note: str | None) -> str:
    parts: list[str] = []

    if hostname is not None:
        parts.append(f"hostname={hostname!r}")

    if note is not None:
        parts.append(f"note={note!r}")

    return ", ".join(parts) if parts else "<empty query>"


def _find_known_device(
    devices: Iterable[Device],
    *,
    hostname: str | None,
    note: str | None,
    note_hosts: Mapping[str, str] | None,
    partial_note: bool,
) -> Device | None:
    known_devices = list(devices)

    match = find_one_device(
        known_devices,
        hostname=hostname,
        note=note,
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
    )


def locate_device(
    *,
    hostname: str | None = None,
    note: str | None = None,
    devices: Iterable[Device] | None = None,
    network: str | None = None,
    note_hosts: Mapping[str, str] | None = None,
    timeout: float = 1.0,
    partial_note: bool = False,
    resolve_hostname_names: bool = True,
    read_arp_cache: bool = True,
    prime_arp_cache: bool = True,
) -> Device:
    """Locate a device's IPv4 and MAC address by hostname and/or note.

    Sources are tried in this order:

    1. The supplied ``devices`` collection, if any.
    2. An ARP scan of ``network``, if provided.
    3. System DNS/mDNS resolution for ``hostname`` (or ``note_hosts[note]``),
       followed by lookup in the known devices and the local ARP cache.

    ``note_hosts`` maps human notes/aliases to hostnames, for cases where the
    user remembers a note such as ``"living room printer"`` instead of the
    actual host name.
    """

    if _normalize_hostname(hostname) is None and _normalize_text(note) is None:
        msg = "hostname or note is required"
        raise ValueError(msg)

    known_devices = list(devices or [])

    # Direct match against caller-provided inventory.
    if known_devices:
        match = _find_known_device(
            known_devices,
            hostname=hostname,
            note=note,
            note_hosts=note_hosts,
            partial_note=partial_note,
        )
        if match is not None:
            return match

    if network is not None:
        scanned_devices = arp_scan(network, timeout=timeout)
        if resolve_hostname_names:
            scanned_devices = enrich_hostnames(scanned_devices)

        known_devices.extend(scanned_devices)

        match = _find_known_device(
            known_devices,
            hostname=hostname,
            note=note,
            note_hosts=note_hosts,
            partial_note=partial_note,
        )
        if match is not None:
            return match

    hostname_to_resolve = hostname or _hostname_from_note(
        note,
        note_hosts,
        partial_note=partial_note,
    )
    if hostname_to_resolve is not None:
        for ip in resolve_ipv4_addresses(hostname_to_resolve):
            device = _find_by_ip(known_devices, ip)
            if device is not None:
                return replace(
                    device,
                    hostname=device.hostname or hostname_to_resolve,
                    note=device.note or note,
                )

            if read_arp_cache:
                mac = _read_arp_cache(ip)
                if mac is None and prime_arp_cache:
                    _prime_arp_cache(ip, timeout=timeout)
                    mac = _read_arp_cache(ip)

                if mac is not None:
                    return Device(
                        ip=ip,
                        mac=mac,
                        hostname=hostname_to_resolve,
                        note=note,
                    )

    query = _format_query(hostname=hostname, note=note)
    msg = f"could not locate device for {query}"
    raise DeviceNotFoundError(msg)
