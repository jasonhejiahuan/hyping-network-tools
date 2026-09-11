from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from hyping.storage import DeviceRecord, mac_addresses_from_record


@dataclass(slots=True, frozen=True)
class FingerprintMatch:
    """A conservative, explainable device-fingerprint comparison."""

    score: int
    evidence: tuple[str, ...]


_MODEL_KEYS = ("model", "md", "ty", "product", "device_model")
_MANUFACTURER_KEYS = ("manufacturer", "vendor", "mf", "mfg")
_SERVICE_KEYS = ("type", "service_type", "services")
_STABLE_META_TERMS = (
    "model",
    "product",
    "device",
    "manufacturer",
    "vendor",
    "service",
    "type",
    "os",
    "platform",
)


def _clean(value: object) -> str | None:
    if not isinstance(value, (str, int, float, bool)):
        return None
    cleaned = " ".join(str(value).strip().casefold().split())
    return cleaned or None


def _mapping(record: DeviceRecord, key: str) -> dict[str, Any]:
    value = record.get(key)
    return value if isinstance(value, dict) else {}


def _values_for_keys(mapping: dict[str, Any], keys: tuple[str, ...]) -> set[str]:
    normalized_keys = {key.casefold() for key in keys}
    return {
        cleaned
        for key, value in mapping.items()
        if str(key).casefold() in normalized_keys
        if (cleaned := _clean(value)) is not None
    }


def _stable_meta(record: DeviceRecord) -> dict[str, str]:
    result: dict[str, str] = {}
    for source in (
        _mapping(record, "bettercap_meta"),
        _mapping(record, "fingerprint"),
    ):
        values = (
            source.get("values")
            if isinstance(source.get("values"), dict)
            else source
        )
        for key, value in values.items():
            normalized_key = str(key).casefold()
            if not any(term in normalized_key for term in _STABLE_META_TERMS):
                continue
            cleaned = _clean(value)
            if cleaned is not None:
                result[normalized_key] = cleaned
    return result


def device_fingerprint(record: DeviceRecord) -> dict[str, Any]:
    """Return stable identity hints, excluding IP and timestamps."""

    mdns = _mapping(record, "mdns")
    saved = _mapping(record, "fingerprint")
    meta = _stable_meta(record)
    result: dict[str, Any] = {}
    vendor = _clean(record.get("vendor"))
    if vendor is not None:
        result["vendor"] = vendor
    models = sorted(
        _values_for_keys(mdns, _MODEL_KEYS)
        | {_clean(value) for value in saved.get("models", []) if _clean(value)}
    )
    if models:
        result["models"] = models
    manufacturers = sorted(
        _values_for_keys(mdns, _MANUFACTURER_KEYS)
        | {
            _clean(value)
            for value in saved.get("manufacturers", [])
            if _clean(value)
        }
    )
    if manufacturers:
        result["manufacturers"] = manufacturers
    services = sorted(
        _values_for_keys(mdns, _SERVICE_KEYS)
        | {_clean(value) for value in saved.get("services", []) if _clean(value)}
    )
    if services:
        result["services"] = services
    if meta:
        result["values"] = meta
    return result


def attach_device_fingerprint(record: DeviceRecord) -> DeviceRecord:
    result = dict(record)
    fingerprint = device_fingerprint(result)
    if fingerprint:
        result["fingerprint"] = fingerprint
    return result


def merge_device_fingerprints(
    existing: DeviceRecord,
    incoming: DeviceRecord,
) -> dict[str, Any]:
    first = device_fingerprint(existing)
    second = device_fingerprint(incoming)
    merged: dict[str, Any] = {}
    for key in ("vendor",):
        value = second.get(key) or first.get(key)
        if value:
            merged[key] = value
    for key in ("models", "manufacturers", "services"):
        values = sorted(set(first.get(key, [])) | set(second.get(key, [])))
        if values:
            merged[key] = values
    values = {**first.get("values", {}), **second.get("values", {})}
    if values:
        merged["values"] = values
    return merged


def compare_device_fingerprints(
    target: DeviceRecord,
    candidate: DeviceRecord,
) -> FingerprintMatch:
    """Score non-address identity evidence without using IP as identity."""

    target_fp = device_fingerprint(target)
    candidate_fp = device_fingerprint(candidate)
    score = 0
    evidence: list[str] = []

    target_vendor = _clean(target_fp.get("vendor"))
    candidate_vendor = _clean(candidate_fp.get("vendor"))
    if target_vendor is not None and target_vendor == candidate_vendor:
        score += 15
        evidence.append(f"厂商一致：{target_vendor}")

    for key, weight, label in (
        ("models", 35, "型号"),
        ("manufacturers", 20, "制造商"),
        ("services", 30, "mDNS 服务组合"),
    ):
        shared = set(target_fp.get(key, [])) & set(candidate_fp.get(key, []))
        if shared:
            score += weight
            evidence.append(f"{label}一致：{', '.join(sorted(shared))}")

    target_meta = target_fp.get("values", {})
    candidate_meta = candidate_fp.get("values", {})
    if isinstance(target_meta, dict) and isinstance(candidate_meta, dict):
        shared_meta = sorted(
            key
            for key in set(target_meta) & set(candidate_meta)
            if target_meta[key] == candidate_meta[key]
        )
        if shared_meta:
            remaining = shared_meta
            for term, weight, label in (
                ("model", 35, "型号元数据"),
                ("product", 35, "产品元数据"),
                ("manufacturer", 20, "制造商元数据"),
                ("service", 30, "服务元数据"),
                ("type", 30, "类型元数据"),
            ):
                matching = [key for key in remaining if term in key]
                if matching:
                    score += weight
                    evidence.append(f"{label}一致：{', '.join(matching)}")
                    remaining = [key for key in remaining if key not in matching]
            if remaining:
                score += min(20, len(remaining) * 10)
                evidence.append("稳定元数据一致：" + ", ".join(remaining))

    target_macs = set(mac_addresses_from_record(target))
    candidate_macs = set(mac_addresses_from_record(candidate))
    if target_macs and candidate_macs and not target_macs & candidate_macs:
        evidence.append("MAC 不同，可能启用了随机地址")

    return FingerprintMatch(min(score, 100), tuple(evidence))


def unique_fingerprint_candidate(
    target: DeviceRecord,
    candidates: Iterable[DeviceRecord],
    *,
    threshold: int = 70,
    margin: int = 15,
) -> tuple[FingerprintMatch, DeviceRecord] | None:
    """Return one unambiguous high-confidence candidate, if one exists."""

    ranked = sorted(
        (
            (compare_device_fingerprints(target, candidate), candidate)
            for candidate in candidates
        ),
        key=lambda item: item[0].score,
        reverse=True,
    )
    if not ranked:
        return None
    best_match, best_record = ranked[0]
    runner_up = ranked[1][0].score if len(ranked) > 1 else 0
    matching_evidence = tuple(
        item for item in best_match.evidence if not item.startswith("MAC 不同")
    )
    if (
        best_match.score < threshold
        or len(matching_evidence) < 2
        or best_match.score - runner_up < margin
    ):
        return None
    return best_match, best_record


__all__ = [
    "FingerprintMatch",
    "attach_device_fingerprint",
    "compare_device_fingerprints",
    "device_fingerprint",
    "merge_device_fingerprints",
    "unique_fingerprint_candidate",
]
