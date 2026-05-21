from dataclasses import dataclass
from ipaddress import IPv4Address


@dataclass(slots=True, frozen=True)
class Device:
    ip: IPv4Address

    mac: str

    hostname: str | None = None

    note: str | None = None
