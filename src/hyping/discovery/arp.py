import os
import sys
from ipaddress import IPv4Address

from scapy.all import ARP, Ether, srp

from hyping.models.device import Device


class ARPScanError(RuntimeError):
    """Raised when active ARP scanning cannot be performed."""


def can_run_active_arp_scan() -> bool:
    """Return whether active Scapy ARP scans are likely to work."""

    return not (sys.platform == "darwin" and hasattr(os, "geteuid") and os.geteuid())


def arp_scan(
    network: str,
    timeout: float = 1.0,
) -> list[Device]:
    devices: list[Device] = []

    arp_request = ARP(pdst=network)

    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ethernet_frame / arp_request

    try:
        answered, _ = srp(
            packet,
            timeout=timeout,
            verbose=False,
        )
    except Exception as exc:
        msg = (
            f"could not run ARP scan for {network!r}; active ARP scanning "
            "usually requires root/admin privileges"
        )
        raise ARPScanError(msg) from exc

    for _, response in answered:
        device = Device(
            ip=IPv4Address(response.psrc),
            mac=response.hwsrc,
        )

        devices.append(device)

    return devices
