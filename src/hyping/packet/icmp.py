from dataclasses import dataclass

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0


@dataclass(slots=True, frozen=True)
class ICMPEchoRequest:
    identifier: int
    sequence: int

    payload_size: int

    timestamp: float