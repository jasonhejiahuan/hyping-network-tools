from dataclasses import dataclass
from ipaddress import IPv4Address


@dataclass(slots=True, frozen=True)
class PingResult:
    address: IPv4Address
    alive: bool
    latency_ms: float | None
    ttl: int | None