from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class AppConfig:
    ping_timeout: float = 1.0
    max_concurrent_pings: int = 1024

    packet_size: int = 64

    socket_recv_buffer_size: int = 4 * 1024 * 1024
    socket_send_buffer_size: int = 4 * 1024 * 1024

    enable_ipv6: bool = False