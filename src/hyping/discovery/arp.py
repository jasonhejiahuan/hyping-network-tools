import os
import sys
from collections.abc import Callable, Iterator
from ipaddress import IPv4Address, ip_network

from scapy.all import ARP, Ether, srp

from hyping.models.device import Device


class ARPScanError(RuntimeError):
    """Raised when active ARP scanning cannot be performed."""


def can_run_active_arp_scan() -> bool:
    """Return whether active Scapy ARP scans are likely to work."""

    return not (sys.platform == "darwin" and hasattr(os, "geteuid") and os.geteuid())


def _ip_batches(network: str, batch_size: int) -> Iterator[list[str]]:
    addresses = [str(ip) for ip in ip_network(network, strict=False).hosts()]
    for index in range(0, len(addresses), batch_size):
        yield addresses[index : index + batch_size]


def iter_arp_scan(
    network: str,
    timeout: float = 0.5,
    *,
    passes: int = 3,
    batch_size: int = 64,
    interval: float = 0.002,
) -> Iterator[Device]:
    """Yield devices discovered by repeated, batched ARP scans.

    Sending one huge burst across a /22 or /21 can miss many Wi-Fi clients.
    Smaller batches repeated a few times are usually faster in practice and
    discover more devices because access points and clients are less likely to
    drop the burst.
    """

    if timeout <= 0:
        msg = "timeout must be greater than 0"
        raise ValueError(msg)
    if passes <= 0:
        msg = "passes must be greater than 0"
        raise ValueError(msg)
    if batch_size <= 0:
        msg = "batch_size must be greater than 0"
        raise ValueError(msg)
    if interval < 0:
        msg = "interval must not be negative"
        raise ValueError(msg)

    batches = list(_ip_batches(network, batch_size))
    seen: set[IPv4Address] = set()

    for _ in range(passes):
        for batch in batches:
            arp_request = ARP(pdst=batch)
            ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ethernet_frame / arp_request

            try:
                answered, _ = srp(
                    packet,
                    timeout=timeout,
                    inter=interval,
                    verbose=False,
                )
            except Exception as exc:
                msg = (
                    f"could not run ARP scan for {network!r}; active ARP scanning "
                    "usually requires root/admin privileges"
                )
                raise ARPScanError(msg) from exc

            for _, response in answered:
                ip = IPv4Address(response.psrc)
                if ip in seen:
                    continue

                seen.add(ip)
                yield Device(
                    ip=ip,
                    mac=str(response.hwsrc).lower(),
                )


def arp_scan(
    network: str,
    timeout: float = 1.0,
    *,
    passes: int = 1,
    batch_size: int = 256,
    interval: float = 0.0,
) -> list[Device]:
    return sorted(
        iter_arp_scan(
            network,
            timeout=timeout,
            passes=passes,
            batch_size=batch_size,
            interval=interval,
        ),
        key=lambda device: device.ip,
    )


def list_network_devices(
    network: str,
    timeout: float = 0.5,
    *,
    passes: int = 3,
    batch_size: int = 64,
    interval: float = 0.002,
    resolve_hostnames: bool = True,
    on_device: Callable[[Device], None] | None = None,
) -> list[Device]:
    """List devices visible on a local IPv4 network."""

    devices: list[Device] = []
    for device in iter_arp_scan(
        network,
        timeout=timeout,
        passes=passes,
        batch_size=batch_size,
        interval=interval,
    ):
        devices.append(device)
        if on_device is not None:
            on_device(device)

    if not resolve_hostnames:
        return sorted(devices, key=lambda device: device.ip)

    from hyping.discovery.resolver import enrich_hostnames

    return sorted(enrich_hostnames(devices), key=lambda device: device.ip)
