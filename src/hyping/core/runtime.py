import asyncio
from dataclasses import dataclass, field

from hyping.core.config import AppConfig


@dataclass(slots=True)
class RuntimeState:
    config: AppConfig

    shutdown_event: asyncio.Event = field(
        default_factory=asyncio.Event
    )

    packet_queue: asyncio.Queue = field(
        default_factory=asyncio.Queue
    )