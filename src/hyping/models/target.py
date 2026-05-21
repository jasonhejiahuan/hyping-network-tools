from dataclasses import dataclass
from ipaddress import IPv4Address
from time import monotonic


@dataclass(slots=True, frozen=True)
class PingTarget:
    address: IPv4Address
    created_at: float = monotonic()