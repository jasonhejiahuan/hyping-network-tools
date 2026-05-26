import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class LocalNetworkInfo:
    """Best-effort details for the network used by the default route."""

    interface: str | None = None
    hardware_port: str | None = None
    ssid: str | None = None
    ipv4_network: str | None = None


def _run(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=1.0,
    )
    return f"{result.stdout}\n{result.stderr}"


def _default_interface() -> str | None:
    try:
        output = _run(["route", "-n", "get", "default"])
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        output = ""

    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface:"):
            interface = stripped.split(":", 1)[1].strip()
            return interface or None

    try:
        output = _run(["ip", "route", "show", "default"])
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None

    match = re.search(r"\bdev\s+(\S+)", output)
    return match.group(1) if match else None


def _macos_hardware_ports() -> dict[str, str]:
    """Return ``{device: hardware_port}`` from macOS networksetup output."""

    try:
        output = _run(["networksetup", "-listallhardwareports"])
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return {}

    ports: dict[str, str] = {}
    hardware_port: str | None = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Hardware Port:"):
            hardware_port = stripped.split(":", 1)[1].strip() or None
        elif stripped.startswith("Device:") and hardware_port:
            device = stripped.split(":", 1)[1].strip()
            if device:
                ports[device] = hardware_port
            hardware_port = None

    return ports


def _wifi_ssid(interface: str) -> str | None:
    """Return the connected Wi-Fi SSID on macOS when available."""

    commands = (
        ["networksetup", "-getairportnetwork", interface],
        ["ipconfig", "getsummary", interface],
        [
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
            "-I",
        ],
    )
    for command in commands:
        try:
            output = _run(command)
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            continue

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if "Current Wi-Fi Network:" in stripped:
                ssid = stripped.split("Current Wi-Fi Network:", 1)[1].strip()
                return ssid or None
            if stripped.startswith("SSID:"):
                ssid = stripped.split(":", 1)[1].strip()
                if ssid and ssid != "<redacted>":
                    return ssid
            if stripped.startswith("SSID :"):
                ssid = stripped.split(":", 1)[1].strip()
                if ssid and ssid != "<redacted>":
                    return ssid

    return None


def _netmask_from_text(value: str) -> str:
    if value.startswith("0x"):
        number = int(value, 16)
        return str(ipaddress.IPv4Address(number))

    return value


def _network_from_ifconfig(interface: str) -> str | None:
    try:
        output = _run(["ifconfig", interface])
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None

    for line in output.splitlines():
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)", line)
        if match is None:
            continue

        ip = match.group(1)
        if ip.startswith("127."):
            continue

        netmask = _netmask_from_text(match.group(2))
        return str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))

    return None


def _fallback_local_ip_network() -> str | None:
    """Best-effort fallback when the OS netmask cannot be discovered."""

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
        except OSError:
            return None

    if ip.startswith("127."):
        return None

    return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))


def detect_local_ipv4_network() -> str | None:
    """Detect the primary local IPv4 subnet, e.g. ``192.168.1.0/24``."""

    interface = _default_interface()
    if interface is not None:
        network = _network_from_ifconfig(interface)
        if network is not None:
            return network

    return _fallback_local_ip_network()


def detect_local_network_info() -> LocalNetworkInfo:
    """Detect the current interface, connection type, SSID and IPv4 subnet."""

    interface = _default_interface()
    hardware_port = None
    ssid = None
    network = None

    if interface is not None:
        hardware_port = _macos_hardware_ports().get(interface)
        if hardware_port and "wi-fi" in hardware_port.casefold():
            ssid = _wifi_ssid(interface)
        network = _network_from_ifconfig(interface)

    if network is None:
        network = _fallback_local_ip_network()

    return LocalNetworkInfo(
        interface=interface,
        hardware_port=hardware_port,
        ssid=ssid,
        ipv4_network=network,
    )
