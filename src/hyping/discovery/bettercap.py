import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from typing import Any


class BettercapAPIError(RuntimeError):
    """Raised when the Bettercap REST API cannot be reached or parsed."""


@dataclass(slots=True, frozen=True)
class BettercapLaunch:
    pid: int
    command: str


@dataclass(slots=True, frozen=True)
class BettercapHost:
    ip: IPv4Address
    mac: str
    hostname: str | None = None
    alias: str | None = None
    vendor: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def display_name(self) -> str | None:
        return self.alias or self.hostname


def _clean_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None

    cleaned = value.strip()
    return cleaned or None


def _clean_hostname(value: object) -> str | None:
    cleaned = _clean_text(value)
    if cleaned is None:
        return None

    return cleaned.rstrip(".") or None


def _meta_hostname(meta: dict[str, Any]) -> str | None:
    values = meta.get("values")
    if not isinstance(values, dict):
        return None

    for key in (
        "hostname",
        "name",
        "dhcp:hostname",
        "dhcp:host_name",
        "mdns:hostname",
        "mdns:Name",
        "mdns:CtlN",
        "nbns:name",
    ):
        hostname = _clean_hostname(values.get(key))
        if hostname is not None:
            return hostname

    for key, value in values.items():
        if not isinstance(key, str):
            continue
        normalized = key.casefold()
        if normalized.endswith(":hostname") or normalized.endswith(":host_name"):
            hostname = _clean_hostname(value)
            if hostname is not None:
                return hostname

    return None


def _meta_vendor(meta: dict[str, Any]) -> str | None:
    values = meta.get("values")
    if not isinstance(values, dict):
        return None

    for key in (
        "vendor",
        "manufacturer",
        "dhcp:vendor",
        "dhcp:vendor_class",
        "mdns:vendor",
        "mdns:manufacturer",
        "mdns:Manufacturer",
    ):
        vendor = _clean_text(values.get(key))
        if vendor is not None:
            return vendor

    for key, value in values.items():
        if not isinstance(key, str):
            continue
        normalized = key.casefold()
        if "vendor" in normalized or "manufacturer" in normalized:
            vendor = _clean_text(value)
            if vendor is not None:
                return vendor

    return None


def host_from_bettercap(value: dict[str, Any]) -> BettercapHost | None:
    ip_text = _clean_text(value.get("ipv4"))
    mac = _clean_text(value.get("mac"))
    if ip_text is None or mac is None:
        return None

    try:
        ip = IPv4Address(ip_text)
    except ValueError:
        return None

    meta = value.get("meta")
    meta = meta if isinstance(meta, dict) else {}
    hostname = (
        _clean_hostname(value.get("hostname"))
        or _clean_hostname(value.get("name"))
        or _meta_hostname(meta)
    )
    vendor = (
        _clean_text(value.get("vendor"))
        or _clean_text(value.get("manufacturer"))
        or _meta_vendor(meta)
    )

    return BettercapHost(
        ip=ip,
        mac=mac.lower(),
        hostname=hostname,
        alias=_clean_text(value.get("alias")),
        vendor=vendor,
        first_seen=_clean_text(value.get("first_seen")),
        last_seen=_clean_text(value.get("last_seen")),
        meta=meta,
    )


def hosts_from_session(session: dict[str, Any]) -> list[BettercapHost]:
    raw_hosts: list[dict[str, Any]] = []

    for key in ("interface", "gateway"):
        value = session.get(key)
        if isinstance(value, dict):
            raw_hosts.append(value)

    lan = session.get("lan")
    if isinstance(lan, dict) and isinstance(lan.get("hosts"), list):
        raw_hosts.extend(host for host in lan["hosts"] if isinstance(host, dict))

    hosts: dict[IPv4Address, BettercapHost] = {}
    for raw_host in raw_hosts:
        host = host_from_bettercap(raw_host)
        if host is None:
            continue

        existing = hosts.get(host.ip)
        if existing is None:
            hosts[host.ip] = host
            continue

        hosts[host.ip] = BettercapHost(
            ip=host.ip,
            mac=host.mac or existing.mac,
            hostname=host.hostname or existing.hostname,
            alias=host.alias or existing.alias,
            vendor=host.vendor or existing.vendor,
            first_seen=host.first_seen or existing.first_seen,
            last_seen=host.last_seen or existing.last_seen,
            meta=host.meta or existing.meta,
        )

    return sorted(hosts.values(), key=lambda host: host.ip)


def record_from_bettercap_host(host: BettercapHost) -> dict[str, Any]:
    return {
        "ip": str(host.ip),
        "mac": host.mac,
        "hostname": host.display_name,
        "note": None,
        "vendor": host.vendor,
        "first_seen": host.first_seen,
        "last_seen": host.last_seen,
    }


class BettercapClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8081",
        username: str = "user",
        password: str = "pass",
        *,
        timeout: float = 3.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        token = base64.b64encode(
            f"{self.username}:{self.password}".encode("utf-8")
        ).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
    ) -> Any:
        data = None
        headers = self._headers()
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace").strip()
            msg = detail or f"Bettercap API returned HTTP {exc.code}"
            raise BettercapAPIError(msg) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            msg = f"could not reach Bettercap API at {self.base_url}: {exc}"
            raise BettercapAPIError(msg) from exc

        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            msg = "Bettercap API returned invalid JSON"
            raise BettercapAPIError(msg) from exc

    def command(self, command: str) -> dict[str, Any]:
        response = self.request(
            "/api/session",
            method="POST",
            payload={"cmd": command},
        )
        if not isinstance(response, dict):
            msg = f"Bettercap command returned unexpected response: {response!r}"
            raise BettercapAPIError(msg)
        if response.get("success") is False:
            msg = str(response.get("msg") or f"Bettercap command failed: {command}")
            raise BettercapAPIError(msg)
        return response

    def is_online(self, *, timeout: float | None = None) -> bool:
        """Return whether the Bettercap REST API is reachable."""

        previous_timeout = self.timeout
        if timeout is not None:
            self.timeout = timeout
        try:
            self.session()
        except BettercapAPIError:
            return False
        finally:
            self.timeout = previous_timeout
        return True

    def start_discovery(
        self,
        *,
        warmup: float = 3.0,
        on_starting: Callable[[str], None] | None = None,
    ) -> None:
        started_modules: list[str] = []
        for command in ("net.recon on", "net.probe on"):
            try:
                self.command(command)
                started_modules.append(command.removesuffix(" on"))
            except BettercapAPIError as exc:
                if "already running" not in str(exc).casefold():
                    raise

        if started_modules and warmup > 0:
            for module in started_modules:
                if on_starting is not None:
                    on_starting(module)
            time.sleep(warmup)

    def shutdown(self) -> None:
        """Ask Bettercap to exit through its REST command API."""

        self.command("quit")

    def session(self) -> dict[str, Any]:
        response = self.request("/api/session")
        if not isinstance(response, dict):
            msg = f"Bettercap session returned unexpected response: {response!r}"
            raise BettercapAPIError(msg)
        return response

    def hosts(self) -> list[BettercapHost]:
        return hosts_from_session(self.session())


def _is_elevated() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        return os.getuid() == 0
    except AttributeError:
        return False


def _resolve_bettercap_command(command: str) -> str | None:
    if os.path.sep in command:
        return command if os.access(command, os.X_OK) else None

    resolved = shutil.which(command)
    if resolved is not None:
        return resolved

    for candidate in (
        "/opt/homebrew/bin/bettercap",
        "/usr/local/bin/bettercap",
        "/usr/bin/bettercap",
    ):
        if os.access(candidate, os.X_OK):
            return candidate

    return None


def _api_rest_listen_target(base_url: str) -> tuple[str, int]:
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or "127.0.0.1"
    if host.casefold() == "localhost":
        host = "127.0.0.1"

    if host not in {"127.0.0.1", "::1", "0.0.0.0"}:
        msg = "只能自动启动本机 Bettercap API"
        raise BettercapAPIError(msg)

    port = parsed.port or 8081
    return host, port


def _write_api_caplet(
    *,
    address: str,
    port: int,
    username: str,
    password: str,
) -> str:
    fd, path = tempfile.mkstemp(prefix="hyping-bettercap-", suffix=".cap")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"set api.rest.address {address}\n")
            handle.write(f"set api.rest.port {port}\n")
            handle.write(f"set api.rest.username {username}\n")
            handle.write(f"set api.rest.password {password}\n")
            handle.write("api.rest on\n")
        os.chmod(path, 0o600)
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise

    return path


def start_bettercap_api(
    client: BettercapClient,
    *,
    command: str = "bettercap",
    interface: str | None = None,
    startup_timeout: float = 8.0,
    poll_interval: float = 0.25,
    on_status: Callable[[str], None] | None = None,
) -> BettercapLaunch:
    if startup_timeout <= 0:
        msg = "startup_timeout must be greater than 0"
        raise ValueError(msg)
    if poll_interval <= 0:
        msg = "poll_interval must be greater than 0"
        raise ValueError(msg)
    if not _is_elevated():
        msg = "自动启动 Bettercap 需要 sudo/root 权限"
        raise BettercapAPIError(msg)

    executable = _resolve_bettercap_command(command)
    if executable is None:
        msg = f"找不到 bettercap 命令：{command}"
        raise BettercapAPIError(msg)

    address, port = _api_rest_listen_target(client.base_url)
    caplet_path = _write_api_caplet(
        address=address,
        port=port,
        username=client.username,
        password=client.password,
    )
    args = [
        executable,
        "-no-colors",
        "-no-history",
        "-silent",
    ]
    if interface:
        args.extend(["-iface", interface])
    args.extend(["-caplet", caplet_path])

    if on_status is not None:
        on_status(f"正在启动 Bettercap API：{client.base_url}")

    process: subprocess.Popen[bytes] | None = None
    ready = False
    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + startup_timeout
        while time.monotonic() <= deadline:
            if client.is_online(timeout=min(poll_interval, client.timeout)):
                ready = True
                if on_status is not None:
                    on_status(f"Bettercap API 已启动：pid {process.pid}")
                return BettercapLaunch(pid=process.pid, command=executable)
            if process.poll() is not None:
                msg = "bettercap 启动后过早退出"
                raise BettercapAPIError(msg)
            time.sleep(poll_interval)

        msg = f"Bettercap API 启动超时：{client.base_url}"
        raise BettercapAPIError(msg)
    except OSError as exc:
        msg = f"无法启动 bettercap：{exc}"
        raise BettercapAPIError(msg) from exc
    finally:
        try:
            os.unlink(caplet_path)
        except OSError:
            pass
        if process is not None and process.poll() is None and not ready:
            process.terminate()


def ensure_bettercap_api_online(
    client: BettercapClient,
    *,
    online_check_timeout: float = 0.25,
    auto_start: bool = True,
    command: str = "bettercap",
    interface: str | None = None,
    startup_timeout: float = 8.0,
    startup_poll_interval: float = 0.25,
    on_status: Callable[[str], None] | None = None,
) -> BettercapLaunch | None:
    if client.is_online(timeout=online_check_timeout):
        return None

    if not auto_start:
        msg = f"Bettercap API is not reachable at {client.base_url}"
        raise BettercapAPIError(msg)

    return start_bettercap_api(
        client,
        command=command,
        interface=interface,
        startup_timeout=startup_timeout,
        poll_interval=startup_poll_interval,
        on_status=on_status,
    )


def iter_bettercap_hosts(
    client: BettercapClient,
    *,
    wait: float = 5.0,
    poll_interval: float = 0.5,
    start_discovery: bool = True,
    discovery_warmup: float = 3.0,
    on_discovery_starting: Callable[[str], None] | None = None,
) -> Iterator[BettercapHost]:
    if wait < 0:
        msg = "wait must not be negative"
        raise ValueError(msg)
    if poll_interval <= 0:
        msg = "poll_interval must be greater than 0"
        raise ValueError(msg)

    latest_hosts = client.hosts()
    if start_discovery:
        try:
            client.start_discovery(
                warmup=discovery_warmup,
                on_starting=on_discovery_starting,
            )
        except TypeError:
            # Keep tests and user-provided lightweight client fakes compatible
            # with the older no-argument start_discovery() shape.
            client.start_discovery()

    deadline = time.monotonic() + wait
    seen: set[IPv4Address] = set()

    while True:
        for host in latest_hosts:
            if host.ip in seen:
                continue
            seen.add(host.ip)
            yield host

        if time.monotonic() >= deadline:
            break
        time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))
        latest_hosts = client.hosts()


def list_bettercap_hosts(
    client: BettercapClient,
    *,
    wait: float = 5.0,
    poll_interval: float = 0.5,
    start_discovery: bool = True,
    discovery_warmup: float = 3.0,
    on_discovery_starting: Callable[[str], None] | None = None,
    on_host: Callable[[BettercapHost], None] | None = None,
) -> list[BettercapHost]:
    hosts: list[BettercapHost] = []
    for host in iter_bettercap_hosts(
        client,
        wait=wait,
        poll_interval=poll_interval,
        start_discovery=start_discovery,
        discovery_warmup=discovery_warmup,
        on_discovery_starting=on_discovery_starting,
    ):
        hosts.append(host)
        if on_host is not None:
            on_host(host)

    return sorted(hosts, key=lambda host: host.ip)
