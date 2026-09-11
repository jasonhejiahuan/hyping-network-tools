import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hyping.paths import (
    DEVICE_STORE_PATH,
    copy_legacy_file_if_present,
    legacy_hyping_path,
)

DEFAULT_STORE_PATH = DEVICE_STORE_PATH

DeviceRecord = dict[str, Any]


def normalize_mac_address(value: object) -> str | None:
    """Return one canonical MAC address, or ``None`` for invalid input."""

    if not isinstance(value, str):
        return None
    compact = "".join(character for character in value if character.isalnum())
    if len(compact) != 12:
        return None
    try:
        int(compact, 16)
    except ValueError:
        return None
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).lower()


def mac_addresses_from_record(record: DeviceRecord) -> tuple[str, ...]:
    """Read current and historical MAC addresses from a saved device record."""

    values: list[object] = [record.get("mac")]
    historical = record.get("mac_addresses")
    if isinstance(historical, list):
        values.extend(historical)
    locations = record.get("locations")
    if isinstance(locations, list):
        values.extend(
            location.get("mac")
            for location in locations
            if isinstance(location, dict)
        )

    addresses: list[str] = []
    for value in values:
        normalized = normalize_mac_address(value)
        if normalized is not None and normalized not in addresses:
            addresses.append(normalized)
    return tuple(addresses)


def _clean_identity_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().casefold().rstrip(".")
    return cleaned or None


def _record_names(record: DeviceRecord) -> set[str]:
    values: list[object] = [record.get("hostname"), record.get("alias")]
    historical = record.get("hostnames")
    if isinstance(historical, list):
        values.extend(historical)
    return {
        cleaned
        for value in values
        if (cleaned := _clean_identity_text(value)) is not None
    }


def _record_matches(existing: DeviceRecord, incoming: DeviceRecord) -> bool:
    existing_macs = set(mac_addresses_from_record(existing))
    incoming_macs = set(mac_addresses_from_record(incoming))
    if existing_macs & incoming_macs:
        return True

    existing_names = _record_names(existing)
    incoming_names = _record_names(incoming)
    if existing_names and incoming_names:
        if existing_names & incoming_names:
            return True
    elif not existing_macs or not incoming_macs:
        existing_ip = _clean_identity_text(existing.get("ip"))
        incoming_ip = _clean_identity_text(incoming.get("ip"))
        if existing_ip is not None and existing_ip == incoming_ip:
            return True

    return False


def _merge_locations(existing: object, incoming: object) -> list[dict[str, Any]]:
    locations: dict[str, dict[str, Any]] = {}
    for value in (existing, incoming):
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            ssid = _clean_identity_text(item.get("ssid"))
            if ssid is None:
                continue
            locations[ssid] = {**locations.get(ssid, {}), **item}
    return sorted(
        locations.values(),
        key=lambda item: str(item.get("ssid", "")).casefold(),
    )


def merge_device_records(
    existing: DeviceRecord,
    incoming: DeviceRecord,
) -> DeviceRecord:
    """Merge a fresh observation without losing historical device identities."""

    from hyping.fingerprint import merge_device_fingerprints

    merged = dict(existing)
    merged.update({key: value for key, value in incoming.items() if value is not None})
    names = sorted(_record_names(existing))
    for name in sorted(_record_names(incoming)):
        if name not in names:
            names.append(name)
    if names:
        merged["hostnames"] = names
    existing_hostname = existing.get("hostname")
    if (
        isinstance(existing_hostname, str)
        and _clean_identity_text(existing_hostname) in _record_names(incoming)
    ):
        merged["hostname"] = existing_hostname
    addresses = list(mac_addresses_from_record(existing))
    for address in mac_addresses_from_record(incoming):
        if address not in addresses:
            addresses.append(address)
    if addresses:
        merged["mac_addresses"] = addresses
        current = normalize_mac_address(incoming.get("mac"))
        merged["mac"] = current or addresses[-1]

    locations = _merge_locations(existing.get("locations"), incoming.get("locations"))
    if locations:
        merged["locations"] = locations
    fingerprint = merge_device_fingerprints(existing, incoming)
    if fingerprint:
        merged["fingerprint"] = fingerprint
    return merged


def observed_device_record(
    record: DeviceRecord,
    *,
    ssid: str | None,
    source: str,
    observed_at: str | None = None,
) -> DeviceRecord:
    """Attach network-location history to one discovery observation."""

    from hyping.fingerprint import attach_device_fingerprint

    result = attach_device_fingerprint(record)
    address = normalize_mac_address(result.get("mac"))
    if address is not None:
        result["mac"] = address
        result["mac_addresses"] = [address]
    if ssid:
        result["ssid"] = ssid
        location = {
            "ssid": ssid,
            "ip": result.get("ip"),
            "mac": address,
            "hostname": result.get("hostname"),
            "source": source,
            "last_seen": observed_at
            or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        result["locations"] = [
            {key: value for key, value in location.items() if value is not None}
        ]
    return result


def _migrate_default_store_if_needed(path: Path) -> None:
    if path != DEFAULT_STORE_PATH or path.exists():
        return

    for legacy_path in (
        legacy_hyping_path("devices.json"),
        Path("/var/root/.hyping/devices.json"),
    ):
        if copy_legacy_file_if_present(legacy_path, path):
            return


def load_device_records(path: Path = DEFAULT_STORE_PATH) -> list[DeviceRecord]:
    """Load saved device records from JSON."""

    _migrate_default_store_if_needed(path)
    if not path.exists():
        return []

    data = json.loads(path.read_text(encoding="utf-8"))
    records = data.get("devices", [])
    if not isinstance(records, list):
        msg = f"invalid device store format: {path}"
        raise ValueError(msg)

    return [record for record in records if isinstance(record, dict)]


def save_device_records(
    records: Iterable[DeviceRecord],
    path: Path = DEFAULT_STORE_PATH,
) -> None:
    """Save device records to JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {"devices": list(records)},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _record_key(record: DeviceRecord) -> tuple[str, str] | None:
    for key in ("hostname", "ip", "mac"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return key, value.strip().casefold().rstrip(".")

    addresses = mac_addresses_from_record(record)
    if addresses:
        return "mac", addresses[0]

    return None


def upsert_device_record(
    records: list[DeviceRecord],
    record: DeviceRecord,
) -> list[DeviceRecord]:
    """Insert or update a record, matching by hostname, then IP, then MAC."""

    key = _record_key(record)
    if key is None:
        return [*records, record]

    for index, existing in enumerate(records):
        if _record_matches(existing, record):
            records[index] = merge_device_records(existing, record)
            return records

    records.append(record)
    return records


def note_hosts_from_records(records: Iterable[DeviceRecord]) -> dict[str, str]:
    """Build a note -> hostname alias map from saved records."""

    aliases: dict[str, str] = {}
    for record in records:
        note = record.get("note")
        hostname = record.get("hostname")
        if isinstance(note, str) and note and isinstance(hostname, str) and hostname:
            aliases[note] = hostname

    return aliases
