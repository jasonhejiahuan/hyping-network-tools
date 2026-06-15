import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from hyping.paths import (
    DEVICE_STORE_PATH,
    copy_legacy_file_if_present,
    legacy_hyping_path,
)

DEFAULT_STORE_PATH = DEVICE_STORE_PATH

DeviceRecord = dict[str, Any]


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
        if _record_key(existing) == key:
            merged = {**existing, **record}
            records[index] = merged
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
