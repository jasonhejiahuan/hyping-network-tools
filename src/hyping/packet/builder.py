import os
import struct
import time

from hyping.packet.icmp import (
    ICMP_ECHO_REQUEST,
    ICMPEchoRequest,
)


def build_echo_request(
    sequence: int,
    payload_size: int,
) -> tuple[ICMPEchoRequest, bytes]:

    request = ICMPEchoRequest(
        identifier=os.getpid() & 0xFFFF,
        sequence=sequence,
        payload_size=payload_size,
        timestamp=time.monotonic(),
    )

    header = struct.pack(
        "!BBHHH",
        ICMP_ECHO_REQUEST,
        0,
        0,
        request.identifier,
        request.sequence,
    )

    payload = b"\x00" * payload_size

    packet = header + payload

    return request, packet