from ipaddress import IPv4Address

from scapy.all import ARP, Ether, srp

from hyping.models.device import Device


def arp_scan(
    network: str,
    timeout: float = 1.0,
) -> list[Device]:
    devices: list[Device] = []

    arp_request = ARP(pdst=network)

    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ethernet_frame / arp_request

    answered, _ = srp(
        packet,
        timeout=timeout,
        verbose=False,
    )

    for _, response in answered:
        device = Device(
            ip=IPv4Address(response.psrc),
            mac=response.hwsrc,
        )

        devices.append(device)

    return devices
