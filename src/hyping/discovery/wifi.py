import subprocess
import time
from dataclasses import dataclass

from hyping.discovery.network import _macos_hardware_ports, _ssid_from_system_profiler


class WiFiError(RuntimeError):
    """Raised when a Wi-Fi command fails or returns unusable output."""


@dataclass(slots=True)
class WiFiNetwork:
    ssid: str
    current: bool = False
    phy_mode: str | None = None
    channel: str | None = None
    security: str | None = None
    signal_noise: str | None = None


_NETWORK_PROPERTY_KEYS = {
    "PHY Mode",
    "Channel",
    "Country Code",
    "Network Type",
    "Security",
    "Signal / Noise",
    "Transmit Rate",
    "MCS Index",
}


def _run(command: list[str], *, timeout: float = 10.0) -> str:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        msg = f"command not found: {command[0]}"
        raise WiFiError(msg) from exc
    except (subprocess.SubprocessError, OSError) as exc:
        msg = f"could not run {' '.join(command)}: {exc}"
        raise WiFiError(msg) from exc

    output = f"{result.stdout}\n{result.stderr}".strip()
    if result.returncode != 0:
        msg = output or f"{command[0]} exited with status {result.returncode}"
        raise WiFiError(msg)

    return output


def wifi_interface() -> str:
    for device, hardware_port in _macos_hardware_ports().items():
        if hardware_port.casefold() in {"wi-fi", "airport"}:
            return device

    msg = "未找到 Wi-Fi 设备"
    raise WiFiError(msg)


def _parse_preferred_wifi_output(output: str) -> list[str]:
    networks: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Preferred networks on"):
            continue
        networks.append(stripped)

    return networks


def list_saved_wifi_networks(interface: str | None = None) -> list[str]:
    interface = interface or wifi_interface()
    output = _run(["networksetup", "-listpreferredwirelessnetworks", interface])
    return _parse_preferred_wifi_output(output)


def _parse_system_profiler_wifi_networks(output: str) -> list[WiFiNetwork]:
    networks: list[WiFiNetwork] = []
    current_network: WiFiNetwork | None = None
    section: str | None = None

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped == "Current Network Information:":
            section = "current"
            current_network = None
            continue
        if stripped == "Other Local Wi-Fi Networks:":
            section = "nearby"
            current_network = None
            continue
        if section is None:
            continue

        key, separator, value = stripped.partition(":")
        if not separator:
            continue

        key = key.strip()
        value = value.strip()
        if value:
            if current_network is None:
                continue
            if key == "PHY Mode":
                current_network.phy_mode = value
            elif key == "Channel":
                current_network.channel = value
            elif key == "Security":
                current_network.security = value
            elif key == "Signal / Noise":
                current_network.signal_noise = value
            continue

        if key in _NETWORK_PROPERTY_KEYS:
            continue

        current_network = WiFiNetwork(ssid=key, current=section == "current")
        networks.append(current_network)

    return networks


def list_nearby_wifi_networks(*, include_current: bool = True) -> list[WiFiNetwork]:
    output = _run(["system_profiler", "SPAirPortDataType"], timeout=8.0)
    networks = _parse_system_profiler_wifi_networks(output)
    if include_current:
        return networks
    return [network for network in networks if not network.current]


def list_available_saved_wifi_networks(
    interface: str | None = None,
) -> list[str]:
    saved = list_saved_wifi_networks(interface)
    nearby = {network.ssid for network in list_nearby_wifi_networks()}
    return [ssid for ssid in saved if ssid in nearby]


def current_wifi_ssid(interface: str | None = None) -> str | None:
    interface = interface or wifi_interface()

    try:
        output = _run(["system_profiler", "SPAirPortDataType"], timeout=8.0)
    except WiFiError:
        output = ""
    ssid = _ssid_from_system_profiler(output)
    if ssid:
        return ssid

    try:
        output = _run(["networksetup", "-getairportnetwork", interface], timeout=2.0)
    except WiFiError:
        return None

    for line in output.splitlines():
        stripped = line.strip()
        if "Current Wi-Fi Network:" in stripped:
            ssid = stripped.split("Current Wi-Fi Network:", 1)[1].strip()
            return ssid or None

    return None


def switch_wifi_network(
    ssid: str,
    *,
    password: str | None = None,
    interface: str | None = None,
    verify: bool = True,
    verify_timeout: float = 12.0,
) -> str | None:
    ssid = ssid.strip()
    if not ssid:
        msg = "SSID 不能为空"
        raise WiFiError(msg)

    interface = interface or wifi_interface()
    command = ["networksetup", "-setairportnetwork", interface, ssid]
    if password:
        command.append(password)

    output = _run(command, timeout=45.0)
    if "Failed to join network" in output:
        raise WiFiError(output)

    if not verify:
        return None

    deadline = time.monotonic() + verify_timeout
    last_ssid: str | None = None
    while time.monotonic() <= deadline:
        last_ssid = current_wifi_ssid(interface)
        if last_ssid == ssid:
            return last_ssid
        time.sleep(0.5)

    status = f"当前 SSID: {last_ssid or '未获取'}"
    msg = f"已发送切换命令，但未确认连接到 {ssid}（{status}）"
    raise WiFiError(msg)
