import base64
import hashlib
import hmac
import http.cookiejar
import json
import mimetypes
import os
import secrets
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from copy import deepcopy
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

from hyping.auto_wifi_scan import (
    AutoWiFiScanError,
    expand_wifi_rotation_path,
    find_hostname_with_bettercap_then_wifi_rotation,
    load_wifi_scan_targets,
    run_auto_wifi_scan,
    write_wifi_scan_template,
)
from hyping.config import ensure_config, save_config
from hyping.discovery.arp import can_run_active_arp_scan, list_network_devices
from hyping.discovery.bettercap import (
    BettercapClient,
    BettercapHost,
    ensure_bettercap_api_online,
    list_bettercap_hosts,
    record_from_bettercap_host,
)
from hyping.discovery.mdns import (
    DEFAULT_SERVICE_TYPES,
    MDNSService,
    find_mdns_services_by_hostname,
    format_mdns_key_values,
    format_mdns_service,
    merge_mdns_services,
    resolve_mdns_service,
)
from hyping.discovery.network import (
    detect_local_ipv4_network,
    detect_local_network_info,
)
from hyping.discovery.resolver import (
    locate_devices,
)
from hyping.discovery.wifi import (
    WiFiNetwork,
    current_wifi_ssid,
    list_available_saved_wifi_networks,
    list_nearby_wifi_networks,
    list_saved_wifi_networks,
    switch_wifi_network,
)
from hyping.loadtest import LoadTestConfig, run_load_test
from hyping.models.device import Device
from hyping.storage import (
    DEFAULT_STORE_PATH,
    DeviceRecord,
    load_device_records,
    note_hosts_from_records,
    save_device_records,
    upsert_device_record,
)

MASKED_SECRET = "••••••"
STATIC_DIR = Path(__file__).resolve().parent / "web_static"
AUTH_COOKIE_NAME = "hyping_web_session"
LOCALHOST_NAMES = {"127.0.0.1", "::1", "[::1]", "0.0.0.0", "localhost"}


class HypingWebServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        config: Mapping[str, Any],
        store_path: Path,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.config = dict(config)
        self.store_path = store_path
        self.auth_challenges: dict[str, dict[str, Any]] = {}
        self.auth_lock = threading.Lock()
        self.auth_session_secret = _web_auth_session_secret(self.config)


def run_web(
    *,
    host: str = "localhost",
    port: int = 8765,
    store_path: Path = DEFAULT_STORE_PATH,
    config: Mapping[str, Any] | None = None,
) -> int:
    """Start the local Hyping Web UI."""

    loaded_config = _apply_web_auth_env(config or ensure_config())
    server = HypingWebServer(
        (host, port),
        HypingWebHandler,
        config=loaded_config,
        store_path=store_path,
    )
    address, bound_port = server.server_address
    display_host = _display_web_host(host, str(address))
    print(f"Hyping Web UI: http://{display_host}:{bound_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在关闭 Hyping Web UI...")
    finally:
        server.server_close()
    return 0


def _is_elevated() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        return os.getuid() == 0
    except AttributeError:
        return False


def _display_web_host(configured_host: str, bound_host: str) -> str:
    host = configured_host.strip() or bound_host
    if _hostname_without_port(host).casefold() in LOCALHOST_NAMES:
        return "localhost"
    return bound_host if host in {"", "0.0.0.0", "::"} else host


def _hostname_without_port(host: str) -> str:
    value = host.strip()
    if value.startswith("["):
        end = value.find("]")
        return value[: end + 1] if end != -1 else value
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value


def _canonicalize_loopback_host(host: str) -> str:
    value = host.strip()
    if not value:
        return value

    if value.startswith("["):
        end = value.find("]")
        hostname = value[: end + 1] if end != -1 else value
        port = value[end + 1 :] if end != -1 else ""
    elif value.count(":") == 1:
        hostname, port_value = value.rsplit(":", 1)
        port = f":{port_value}"
    else:
        hostname = value
        port = ""

    if hostname.casefold() in LOCALHOST_NAMES:
        return f"localhost{port}"
    return value


def _env_bool(name: str, default: bool | None = None) -> bool | None:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "y", "on", "是"}:
        return True
    if normalized in {"0", "false", "no", "n", "off", "否"}:
        return False
    return default


def _env_float(name: str, default: float | None = None) -> float | None:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _apply_web_auth_env(config: Mapping[str, Any]) -> dict[str, Any]:
    merged = deepcopy(dict(config))
    web_auth = merged.get("web_auth")
    if not isinstance(web_auth, dict):
        web_auth = {}
        merged["web_auth"] = web_auth

    enabled = _env_bool("HYPING_WEB_AUTH_ENABLED")
    if enabled is not None:
        web_auth["enabled"] = enabled

    env_map = {
        "HYPING_PASSKEY_AUTH_FLOW": "login_flow",
        "HYPING_PASSKEY_AUTH_BASE_URL": "auth_base_url",
        "HYPING_PASSKEY_AUTH_CALLBACK_URL": "callback_url",
        "HYPING_PASSKEY_AUTH_CLIENT_ID": "client_id",
        "HYPING_PASSKEY_AUTH_CLIENT_SECRET": "client_secret",
        "HYPING_PASSKEY_AUTH_SERVER_API_TOKEN": "server_api_token",
        "HYPING_PASSKEY_AUTH_USERNAME": "username",
        "HYPING_WEB_AUTH_SESSION_SECRET": "session_secret",
    }
    for env_name, key in env_map.items():
        value = os.environ.get(env_name)
        if value is not None:
            web_auth[key] = value

    for env_name, key in {
        "HYPING_WEB_AUTH_SESSION_TTL_SECONDS": "session_ttl_seconds",
        "HYPING_WEB_AUTH_CHALLENGE_TTL_SECONDS": "challenge_ttl_seconds",
        "HYPING_PASSKEY_AUTH_REQUEST_TIMEOUT": "request_timeout",
    }.items():
        value = _env_float(env_name)
        if value is not None:
            web_auth[key] = value

    return merged


def _load_runtime_config(overrides: Mapping[str, Any] | None = None) -> dict[str, Any]:
    config = ensure_config()
    if overrides:
        config = _deep_merge(config, overrides)
    return _apply_web_auth_env(config)


def _deep_merge(base: Mapping[str, Any], update: Mapping[str, Any]) -> dict[str, Any]:
    merged = deepcopy(dict(base))
    for key, value in update.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _redact_config(config: Mapping[str, Any]) -> dict[str, Any]:
    redacted = deepcopy(dict(config))
    bettercap = redacted.get("bettercap")
    if isinstance(bettercap, dict):
        password = bettercap.get("password")
        bettercap["password"] = MASKED_SECRET if password else ""
        bettercap["password_saved"] = bool(password)
    web_auth = redacted.get("web_auth")
    if isinstance(web_auth, dict):
        client_secret = web_auth.get("client_secret")
        token = web_auth.get("server_api_token")
        session_secret = web_auth.get("session_secret")
        web_auth["client_secret"] = MASKED_SECRET if client_secret else ""
        web_auth["client_secret_saved"] = bool(client_secret)
        web_auth["server_api_token"] = MASKED_SECRET if token else ""
        web_auth["server_api_token_saved"] = bool(token)
        web_auth["session_secret"] = MASKED_SECRET if session_secret else ""
        web_auth["session_secret_saved"] = bool(session_secret)
    return redacted


def _client_from_config(config: Mapping[str, Any]) -> BettercapClient:
    bettercap = config.get("bettercap", {})
    bettercap = bettercap if isinstance(bettercap, Mapping) else {}
    return BettercapClient(
        str(bettercap.get("url", "http://127.0.0.1:8081")),
        str(bettercap.get("username", "user")),
        str(bettercap.get("password", "pass")),
        timeout=float(bettercap.get("api_timeout", 3.0)),
    )


def _clean_str(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _float_value(value: object, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int_value(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bool_value(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"1", "true", "yes", "y", "on", "是"}:
            return True
        if normalized in {"0", "false", "no", "n", "off", "否"}:
            return False
    return default


def _web_auth_config(config: Mapping[str, Any]) -> dict[str, Any]:
    web_auth = config.get("web_auth", {})
    return dict(web_auth) if isinstance(web_auth, Mapping) else {}


def _web_auth_enabled(config: Mapping[str, Any]) -> bool:
    return _bool_value(_web_auth_config(config).get("enabled"), False)


def _web_auth_login_flow(config: Mapping[str, Any]) -> str:
    flow = str(_web_auth_config(config).get("login_flow", "redirect")).casefold()
    return flow if flow in {"redirect", "proxy"} else "redirect"


def _web_auth_session_secret(config: Mapping[str, Any]) -> str:
    web_auth = _web_auth_config(config)
    configured = _clean_str(web_auth.get("session_secret"))
    return configured or secrets.token_urlsafe(32)


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - (len(value) % 4)) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _sign_auth_payload(payload: Mapping[str, Any], secret: str) -> str:
    data = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    encoded = _base64url_encode(data)
    digest = hmac.new(
        secret.encode("utf-8"),
        encoded.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{encoded}.{_base64url_encode(digest)}"


def _verify_auth_payload(token: str, secret: str) -> dict[str, Any] | None:
    if "." not in token:
        return None
    encoded, signature = token.rsplit(".", 1)
    expected = _base64url_encode(
        hmac.new(
            secret.encode("utf-8"),
            encoded.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = json.loads(_base64url_decode(encoded).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if _float_value(payload.get("exp"), 0) < time.time():
        return None
    return payload


def _cookie_value(cookie_header: str, name: str) -> str | None:
    for item in cookie_header.split(";"):
        if "=" not in item:
            continue
        key, value = item.strip().split("=", 1)
        if key == name:
            return value
    return None


def _auth_user_from_headers(
    headers: Mapping[str, str],
    *,
    secret: str,
) -> dict[str, Any] | None:
    token = _cookie_value(headers.get("Cookie", ""), AUTH_COOKIE_NAME)
    if not token:
        return None
    payload = _verify_auth_payload(token, secret)
    if payload is None:
        return None
    user = payload.get("user")
    return dict(user) if isinstance(user, Mapping) else None


def _auth_cookie(
    token: str,
    *,
    ttl_seconds: int,
    secure: bool,
) -> str:
    parts = [
        f"{AUTH_COOKIE_NAME}={token}",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        f"Max-Age={ttl_seconds}",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def _expired_auth_cookie() -> str:
    return (
        f"{AUTH_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; "
        "Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    )


def _cookie_header_from_jar(cookie_jar: http.cookiejar.CookieJar) -> str:
    values = []
    for cookie in cookie_jar:
        if cookie.is_expired():
            continue
        values.append(f"{cookie.name}={cookie.value}")
    return "; ".join(values)


def _passkey_auth_url(auth_config: Mapping[str, Any], path: str) -> str:
    base_url = _clean_str(auth_config.get("auth_base_url"))
    if base_url is None:
        msg = "Passkey-Auth 地址未配置"
        raise ValueError(msg)
    return f"{base_url.rstrip('/')}{path}"


def _read_json_response(response) -> dict[str, Any]:
    raw = response.read()
    if not raw:
        return {}
    data = json.loads(raw.decode("utf-8"))
    if isinstance(data, dict):
        return data
    msg = "Passkey-Auth 返回了非对象 JSON"
    raise ValueError(msg)


def _passkey_auth_error(exc: urllib.error.HTTPError) -> ValueError:
    try:
        payload = json.loads(exc.read().decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        payload = {}
    error = payload.get("error") if isinstance(payload, dict) else None
    description = (
        payload.get("error_description") if isinstance(payload, dict) else None
    )
    detail = description or error or exc.reason or exc.code
    return ValueError(f"Passkey-Auth 请求失败：{detail}")


def _passkey_auth_json_request(
    auth_config: Mapping[str, Any],
    path: str,
    body: Mapping[str, Any],
    *,
    cookie_jar: http.cookiejar.CookieJar | None = None,
    bearer_token: str | None = None,
) -> dict[str, Any]:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        _passkey_auth_url(auth_config, path),
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            **({"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}),
        },
        method="POST",
    )
    timeout = _float_value(auth_config.get("request_timeout"), 5.0)
    try:
        if cookie_jar is None:
            response_context = urllib.request.urlopen(request, timeout=timeout)
        else:
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cookie_jar)
            )
            response_context = opener.open(request, timeout=timeout)
        with response_context as response:
            return _read_json_response(response)
    except urllib.error.HTTPError as exc:
        raise _passkey_auth_error(exc) from exc
    except urllib.error.URLError as exc:
        msg = f"无法连接 Passkey-Auth：{exc.reason}"
        raise ValueError(msg) from exc


def _passkey_auth_get_json_request(
    auth_config: Mapping[str, Any],
    path: str,
    *,
    bearer_token: str | None = None,
) -> dict[str, Any]:
    request = urllib.request.Request(
        _passkey_auth_url(auth_config, path),
        headers={
            "Accept": "application/json",
            **({"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}),
        },
        method="GET",
    )
    timeout = _float_value(auth_config.get("request_timeout"), 5.0)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return _read_json_response(response)
    except urllib.error.HTTPError as exc:
        raise _passkey_auth_error(exc) from exc
    except urllib.error.URLError as exc:
        msg = f"无法连接 Passkey-Auth：{exc.reason}"
        raise ValueError(msg) from exc


def _device_to_record(device: Device) -> DeviceRecord:
    return {
        "ip": str(device.ip),
        "mac": device.mac,
        "hostname": device.hostname,
        "note": device.note,
    }


def _scan_item_to_record(item: Device | BettercapHost) -> DeviceRecord:
    if isinstance(item, BettercapHost):
        return record_from_bettercap_host(item)
    return _device_to_record(item)


def _records_to_devices(records: list[DeviceRecord]) -> list[Device]:
    devices: list[Device] = []
    for record in records:
        ip = _clean_str(record.get("ip"))
        mac = _clean_str(record.get("mac"))
        if ip is None or mac is None:
            continue
        try:
            address = IPv4Address(ip)
        except ValueError:
            continue
        devices.append(
            Device(
                ip=address,
                mac=mac,
                hostname=_clean_str(record.get("hostname")),
                note=_clean_str(record.get("note")),
            )
        )
    return devices


def _record_key(record: Mapping[str, Any]) -> tuple[str, str] | None:
    for key in ("hostname", "ip", "mac"):
        value = _clean_str(record.get(key))
        if value:
            return key, value.casefold().rstrip(".")
    return None


def _wifi_network_to_record(network: WiFiNetwork) -> dict[str, object]:
    return {
        "ssid": network.ssid,
        "current": network.current,
        "phy_mode": network.phy_mode,
        "channel": network.channel,
        "security": network.security,
        "signal_noise": network.signal_noise,
    }


def _service_to_record(service: MDNSService) -> dict[str, object]:
    return {
        "instance": service.instance,
        "service_type": service.service_type,
        "domain": service.domain,
        "hostname": service.hostname,
        "port": service.port,
        "txt": service.txt,
        "text": format_mdns_service(service),
    }


def _safe_status(config: Mapping[str, Any], store_path: Path) -> dict[str, Any]:
    logs: list[str] = []
    network_info = detect_local_network_info(
        on_reading_ssid=lambda: logs.append("正在读取 Wi-Fi SSID...")
    )
    bettercap = config.get("bettercap", {})
    bettercap = bettercap if isinstance(bettercap, Mapping) else {}
    client = _client_from_config(config)
    bettercap_online = False
    bettercap_error = None
    try:
        bettercap_online = client.is_online(
            timeout=float(bettercap.get("online_check_timeout", 0.25))
        )
    except Exception as exc:  # pragma: no cover - defensive status fallback
        bettercap_error = str(exc)

    records = load_device_records(store_path)
    return {
        "network": {
            "interface": network_info.interface,
            "hardware_port": network_info.hardware_port,
            "ssid": network_info.ssid,
            "ipv4_network": network_info.ipv4_network,
        },
        "bettercap": {
            "url": client.base_url,
            "online": bettercap_online,
            "error": bettercap_error,
        },
        "permissions": {
            "elevated": _is_elevated(),
            "can_active_arp": can_run_active_arp_scan(),
        },
        "paths": {
            "store": str(store_path),
        },
        "counts": {
            "saved_devices": len(records),
        },
        "logs": logs,
    }


class HypingWebHandler(BaseHTTPRequestHandler):
    server: HypingWebServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path.startswith("/api/"):
                if self._requires_auth(parsed.path):
                    self._send_auth_required()
                    return
                self._handle_api_get(parsed)
                return
            self._serve_static(parsed.path)
        except Exception as exc:
            self._send_error(exc)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path.startswith("/api/") and self._requires_auth(parsed.path):
                self._send_auth_required()
                return
            body = self._read_json_body()
            self._handle_api_post(parsed, body)
        except Exception as exc:
            self._send_error(exc)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}

        data = self.rfile.read(length)
        if not data:
            return {}

        value = json.loads(data.decode("utf-8"))
        if not isinstance(value, dict):
            msg = "JSON body must be an object"
            raise ValueError(msg)
        return value

    def _send_json(
        self,
        value: object,
        *,
        status: int = HTTPStatus.OK,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, header_value in (headers or {}).items():
            self.send_header(key, header_value)
        self.end_headers()
        self.wfile.write(body)

    def _send_redirect(
        self,
        location: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        for key, header_value in (headers or {}).items():
            self.send_header(key, header_value)
        self.end_headers()

    def _send_error(self, exc: Exception) -> None:
        status = HTTPStatus.BAD_REQUEST
        if isinstance(exc, FileNotFoundError):
            status = HTTPStatus.NOT_FOUND
        payload = {
            "ok": False,
            "error": str(exc) or exc.__class__.__name__,
            "type": exc.__class__.__name__,
        }
        if os.environ.get("HYPING_WEB_DEBUG"):
            payload["traceback"] = traceback.format_exc()
        self._send_json(payload, status=status)

    def _current_auth_user(self) -> dict[str, Any] | None:
        return _auth_user_from_headers(
            self.headers,
            secret=self.server.auth_session_secret,
        )

    def _requires_auth(self, path: str) -> bool:
        if not _web_auth_enabled(self.server.config):
            return False
        if path.startswith("/api/auth/"):
            return False
        return self._current_auth_user() is None

    def _send_auth_required(self) -> None:
        self._send_json(
            {
                "ok": False,
                "error": "请先使用 Passkey 登录",
                "type": "auth_required",
                "authRequired": True,
            },
            status=HTTPStatus.UNAUTHORIZED,
        )

    def _handle_api_get(self, parsed: urllib.parse.ParseResult) -> None:
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/api/auth/status":
            self._send_json(self._auth_status())
            return
        if path == "/api/auth/login":
            self._auth_login(query)
            return
        if path == "/api/auth/callback":
            self._auth_callback(query)
            return
        if path == "/api/status":
            self.server.config = _load_runtime_config(self.server.config)
            self._send_json(
                {
                    "ok": True,
                    "status": _safe_status(self.server.config, self.server.store_path),
                    "config": _redact_config(self.server.config),
                }
            )
            return
        if path == "/api/devices":
            self._send_json(
                {
                    "ok": True,
                    "devices": load_device_records(self.server.store_path),
                    "path": str(self.server.store_path),
                }
            )
            return
        if path == "/api/config":
            self.server.config = _load_runtime_config(self.server.config)
            self._send_json(
                {
                    "ok": True,
                    "config": _redact_config(self.server.config),
                }
            )
            return
        if path == "/api/wifi/current":
            interface = query.get("interface", [None])[0]
            self._send_json(
                {
                    "ok": True,
                    "ssid": current_wifi_ssid(interface),
                }
            )
            return
        if path == "/api/wifi/saved":
            interface = query.get("interface", [None])[0]
            self._send_json(
                {
                    "ok": True,
                    "networks": list_saved_wifi_networks(interface),
                }
            )
            return
        if path == "/api/wifi/nearby":
            include_current = query.get("include_current", ["true"])[0] != "false"
            networks = list_nearby_wifi_networks(include_current=include_current)
            self._send_json(
                {
                    "ok": True,
                    "networks": [
                        _wifi_network_to_record(network) for network in networks
                    ],
                }
            )
            return
        if path == "/api/wifi/available":
            interface = query.get("interface", [None])[0]
            self._send_json(
                {
                    "ok": True,
                    "networks": list_available_saved_wifi_networks(interface),
                }
            )
            return
        if path == "/api/wifi-rotation":
            self._send_json(self._load_wifi_rotation())
            return

        raise FileNotFoundError(path)

    def _handle_api_post(
        self,
        parsed: urllib.parse.ParseResult,
        body: dict[str, Any],
    ) -> None:
        routes = {
            "/api/auth/options": self._auth_options,
            "/api/auth/verify": self._auth_verify,
            "/api/auth/logout": self._auth_logout,
            "/api/scan": self._scan,
            "/api/locate": self._locate,
            "/api/devices/save": self._save_devices,
            "/api/devices/delete": self._delete_device,
            "/api/mdns": self._mdns,
            "/api/wifi/switch": self._switch_wifi,
            "/api/load-test": self._load_test,
            "/api/auto-wifi-scan": self._auto_wifi_scan,
            "/api/auto-locate": self._auto_locate,
            "/api/config": self._save_config,
            "/api/wifi-rotation": self._save_wifi_rotation,
        }
        handler = routes.get(parsed.path)
        if handler is None:
            raise FileNotFoundError(parsed.path)
        payload = dict(handler(body))
        headers = payload.pop("_headers", None)
        self._send_json(
            payload,
            headers=headers if isinstance(headers, Mapping) else None,
        )

    def _serve_static(self, path: str) -> None:
        if path in {"", "/"}:
            path = "/index.html"

        name = path.removeprefix("/")
        if "/" in name or name.startswith("."):
            raise FileNotFoundError(path)

        resource = STATIC_DIR / name
        if not resource.is_file():
            raise FileNotFoundError(path)

        data = resource.read_bytes()
        content_type, _ = mimetypes.guess_type(name)
        self.send_response(HTTPStatus.OK)
        self.send_header(
            "Content-Type",
            content_type or "application/octet-stream",
        )
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _auth_status(self) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        auth_config = _web_auth_config(self.server.config)
        enabled = _web_auth_enabled(self.server.config)
        user = self._current_auth_user()
        login_flow = _web_auth_login_flow(self.server.config)
        return {
            "ok": True,
            "enabled": enabled,
            "authenticated": not enabled or user is not None,
            "user": user,
            "auth": {
                "provider": "Passkey-Auth",
                "authBaseUrl": auth_config.get("auth_base_url", ""),
                "username": auth_config.get("username", ""),
                "loginFlow": login_flow,
                "loginUrl": "/api/auth/login" if login_flow == "redirect" else "",
                "callbackUrl": self._auth_callback_url(auth_config),
            },
        }

    def _auth_login(self, query: Mapping[str, list[str]]) -> None:
        self.server.config = _load_runtime_config(self.server.config)
        if not _web_auth_enabled(self.server.config):
            self._send_redirect(self._safe_next_path(query.get("next", [""])[0]))
            return
        if _web_auth_login_flow(self.server.config) != "redirect":
            msg = "当前 WebUI 认证不是 redirect flow"
            raise ValueError(msg)

        auth_config = _web_auth_config(self.server.config)
        client_id = _clean_str(auth_config.get("client_id"))
        if client_id is None:
            msg = "Passkey-Auth client_id 未配置"
            raise ValueError(msg)

        now = int(time.time())
        state = _sign_auth_payload(
            {
                "iat": now,
                "exp": now
                + int(_float_value(auth_config.get("challenge_ttl_seconds"), 300.0)),
                "nonce": secrets.token_urlsafe(16),
                "next": self._safe_next_path(query.get("next", [""])[0]),
            },
            self.server.auth_session_secret,
        )
        params = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": self._auth_callback_url(auth_config),
                "state": state,
            }
        )
        self._send_redirect(
            _passkey_auth_url(auth_config, f"/oauth/authorize?{params}")
        )

    def _auth_callback(self, query: Mapping[str, list[str]]) -> None:
        self.server.config = _load_runtime_config(self.server.config)
        if not _web_auth_enabled(self.server.config):
            self._send_redirect("/")
            return

        state = query.get("state", [""])[0]
        state_payload = _verify_auth_payload(state, self.server.auth_session_secret)
        if state_payload is None:
            self._send_redirect("/?auth_error=invalid_state")
            return

        next_path = self._safe_next_path(str(state_payload.get("next") or "/"))
        error = query.get("error", [""])[0]
        if error:
            self._send_redirect(
                self._url_with_params(next_path, {"auth_error": error})
            )
            return

        code = query.get("code", [""])[0]
        if not code:
            self._send_redirect(
                self._url_with_params(next_path, {"auth_error": "missing_code"})
            )
            return

        try:
            user = self._exchange_oauth_code_for_user(code)
        except ValueError as exc:
            self._send_redirect(
                self._url_with_params(
                    next_path,
                    {"auth_error": str(exc) or "oauth_failed"},
                )
            )
            return

        token, ttl_seconds = self._issue_auth_session(user)
        self._send_redirect(
            self._url_with_params(next_path, {"auth": "success"}),
            headers={
                "Set-Cookie": _auth_cookie(
                    token,
                    ttl_seconds=ttl_seconds,
                    secure=self._request_is_secure(),
                )
            },
        )

    def _auth_options(self, body: dict[str, Any]) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        auth_config = _web_auth_config(self.server.config)
        if not _web_auth_enabled(self.server.config):
            return {"ok": True, "enabled": False, "authenticated": True}

        cookie_jar = http.cookiejar.CookieJar()
        username = _clean_str(body.get("username"))
        if username is None:
            username = _clean_str(auth_config.get("username")) or ""
        data = _passkey_auth_json_request(
            auth_config,
            "/api/login/options",
            {"username": username},
            cookie_jar=cookie_jar,
        )
        public_key = data.get("publicKey")
        if not isinstance(public_key, Mapping):
            msg = "Passkey-Auth 没有返回 challenge"
            raise ValueError(msg)

        challenge_id = secrets.token_urlsafe(24)
        expires_at = time.time() + _float_value(
            auth_config.get("challenge_ttl_seconds"),
            300.0,
        )
        with self.server.auth_lock:
            self._prune_auth_challenges_locked()
            self.server.auth_challenges[challenge_id] = {
                "cookie_jar": cookie_jar,
                "expires_at": expires_at,
                "username": username,
            }

        return {
            "ok": True,
            "enabled": True,
            "challengeId": challenge_id,
            "publicKey": public_key,
        }

    def _auth_verify(self, body: dict[str, Any]) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        auth_config = _web_auth_config(self.server.config)
        if not _web_auth_enabled(self.server.config):
            return {"ok": True, "enabled": False, "authenticated": True}

        challenge_id = _clean_str(body.get("challengeId"))
        if challenge_id is None:
            msg = "challengeId 不能为空"
            raise ValueError(msg)

        with self.server.auth_lock:
            self._prune_auth_challenges_locked()
            challenge = self.server.auth_challenges.pop(challenge_id, None)
        if not challenge:
            msg = "登录 challenge 已过期，请重新开始"
            raise ValueError(msg)

        credential = body.get("credential")
        if not isinstance(credential, Mapping):
            msg = "credential 不能为空"
            raise ValueError(msg)

        cookie_jar = challenge["cookie_jar"]
        _passkey_auth_json_request(
            auth_config,
            "/api/login/verify",
            {"credential": credential},
            cookie_jar=cookie_jar,
        )
        user = self._verify_passkey_auth_session(auth_config, cookie_jar)
        token, ttl_seconds = self._issue_auth_session(user)
        response = {
            "ok": True,
            "enabled": True,
            "authenticated": True,
            "user": user,
        }
        response["_headers"] = {
            "Set-Cookie": _auth_cookie(
                token,
                ttl_seconds=ttl_seconds,
                secure=self._request_is_secure(),
            )
        }
        return response

    def _auth_logout(self, body: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": True,
            "authenticated": False,
            "_headers": {"Set-Cookie": _expired_auth_cookie()},
        }

    def _verify_passkey_auth_session(
        self,
        auth_config: Mapping[str, Any],
        cookie_jar: http.cookiejar.CookieJar,
    ) -> dict[str, Any]:
        token = _clean_str(auth_config.get("server_api_token"))
        if token is None:
            msg = "Passkey-Auth server_api_token 未配置"
            raise ValueError(msg)

        cookie_header = _cookie_header_from_jar(cookie_jar)
        data = _passkey_auth_json_request(
            auth_config,
            "/api/server/session/verify",
            {"sessionCookie": cookie_header},
            bearer_token=token,
        )
        if not data.get("authenticated"):
            msg = "Passkey-Auth 未确认登录状态"
            raise ValueError(msg)
        user = data.get("user")
        if not isinstance(user, Mapping):
            msg = "Passkey-Auth 没有返回用户信息"
            raise ValueError(msg)
        return {
            "sub": str(user.get("sub") or ""),
            "username": str(user.get("username") or ""),
            "id": user.get("id"),
            "createdAt": user.get("createdAt"),
        }

    def _exchange_oauth_code_for_user(self, code: str) -> dict[str, Any]:
        auth_config = _web_auth_config(self.server.config)
        client_id = _clean_str(auth_config.get("client_id"))
        client_secret = _clean_str(auth_config.get("client_secret"))
        if client_id is None or client_secret is None:
            msg = "Passkey-Auth OAuth client 未配置"
            raise ValueError(msg)

        token_data = _passkey_auth_json_request(
            auth_config,
            "/oauth/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": self._auth_callback_url(auth_config),
            },
        )
        user = token_data.get("user")
        if not isinstance(user, Mapping):
            access_token = _clean_str(token_data.get("access_token"))
            if access_token:
                user = _passkey_auth_get_json_request(
                    auth_config,
                    "/oauth/userinfo",
                    bearer_token=access_token,
                )
        if not isinstance(user, Mapping):
            msg = "Passkey-Auth 没有返回用户信息"
            raise ValueError(msg)
        return {
            "sub": str(user.get("sub") or ""),
            "username": str(user.get("username") or ""),
            "id": user.get("id"),
            "createdAt": user.get("createdAt"),
        }

    def _issue_auth_session(self, user: Mapping[str, Any]) -> tuple[str, int]:
        auth_config = _web_auth_config(self.server.config)
        ttl_seconds = max(
            60,
            int(_float_value(auth_config.get("session_ttl_seconds"), 3600.0)),
        )
        now = int(time.time())
        token = _sign_auth_payload(
            {
                "iat": now,
                "exp": now + ttl_seconds,
                "user": dict(user),
            },
            self.server.auth_session_secret,
        )
        return token, ttl_seconds

    def _auth_callback_url(self, auth_config: Mapping[str, Any]) -> str:
        return _clean_str(auth_config.get("callback_url")) or self._external_url(
            "/api/auth/callback"
        )

    def _external_url(self, path: str) -> str:
        return f"{self._request_origin()}{path}"

    def _request_origin(self) -> str:
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "")
        scheme = (
            forwarded_proto.split(",", 1)[0].strip()
            if forwarded_proto
            else "https"
            if self._request_is_secure()
            else "http"
        )
        forwarded_host = self.headers.get("X-Forwarded-Host", "")
        host = _canonicalize_loopback_host(
            forwarded_host.split(",", 1)[0].strip()
            or self.headers.get("Host", "")
            or f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        )
        return f"{scheme}://{host}"

    def _request_is_secure(self) -> bool:
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "")
        if forwarded_proto:
            return forwarded_proto.split(",", 1)[0].strip().casefold() == "https"
        return False

    def _safe_next_path(self, value: str | None) -> str:
        if not value:
            return "/"
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
            return "/"
        return urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))

    def _url_with_params(self, path: str, params: Mapping[str, str]) -> str:
        parsed = urllib.parse.urlsplit(path)
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        query.update({key: value for key, value in params.items() if value})
        return urllib.parse.urlunsplit(
            (
                "",
                "",
                parsed.path or "/",
                urllib.parse.urlencode(query),
                "",
            )
        )

    def _prune_auth_challenges_locked(self) -> None:
        now = time.time()
        expired = [
            challenge_id
            for challenge_id, challenge in self.server.auth_challenges.items()
            if _float_value(challenge.get("expires_at"), 0.0) < now
        ]
        for challenge_id in expired:
            self.server.auth_challenges.pop(challenge_id, None)

    def _scan(self, body: dict[str, Any]) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        config = self.server.config
        scan_config = config.get("scan", {})
        scan_config = scan_config if isinstance(scan_config, Mapping) else {}
        bettercap = config.get("bettercap", {})
        bettercap = bettercap if isinstance(bettercap, Mapping) else {}
        logs: list[str] = []

        scanner = str(body.get("scanner", scan_config.get("scanner", "bettercap")))
        scanner = scanner.casefold()
        if scanner not in {"bettercap", "builtin"}:
            msg = "scanner must be bettercap or builtin"
            raise ValueError(msg)

        records: list[DeviceRecord]
        if scanner == "bettercap":
            merged_config = _deep_merge(
                bettercap,
                body.get("bettercap")
                if isinstance(body.get("bettercap"), Mapping)
                else {},
            )
            client = BettercapClient(
                str(merged_config.get("url", "http://127.0.0.1:8081")),
                str(merged_config.get("username", "user")),
                str(merged_config.get("password", "pass")),
                timeout=_float_value(merged_config.get("api_timeout"), 3.0),
            )
            interface = str(merged_config.get("interface", "auto"))
            bettercap_interface = None if interface.casefold() == "auto" else interface
            ensure_bettercap_api_online(
                client,
                online_check_timeout=_float_value(
                    merged_config.get("online_check_timeout"),
                    0.25,
                ),
                auto_start=_bool_value(merged_config.get("auto_start_api"), True),
                command=str(merged_config.get("command", "bettercap")),
                interface=bettercap_interface,
                startup_timeout=_float_value(
                    merged_config.get("startup_timeout"),
                    8.0,
                ),
                startup_poll_interval=_float_value(
                    merged_config.get("startup_poll_interval"),
                    0.25,
                ),
                on_status=logs.append,
            )
            hosts = list_bettercap_hosts(
                client,
                wait=_float_value(
                    body.get("wait"), _float_value(bettercap.get("wait"), 5.0)
                ),
                poll_interval=_float_value(
                    body.get("poll_interval"),
                    _float_value(bettercap.get("poll_interval"), 0.5),
                ),
                start_discovery=_bool_value(
                    body.get("start_discovery"),
                    _bool_value(bettercap.get("start_discovery"), True),
                ),
                include_cached=False,
                discovery_warmup=_float_value(
                    body.get("discovery_warmup"),
                    _float_value(bettercap.get("discovery_warmup"), 3.0),
                ),
                on_discovery_starting=lambda module: logs.append(
                    f"{module} 正在启动，等待预热..."
                ),
            )
            logs.append("已排除扫描前的 Bettercap 会话缓存。")
            records = [_scan_item_to_record(host) for host in hosts]
        else:
            network = str(body.get("network", scan_config.get("network", "auto")))
            if network.casefold() == "auto":
                detected = detect_local_ipv4_network()
                if detected is None:
                    msg = "未能自动检测本机网段"
                    raise ValueError(msg)
                network = detected
                logs.append(f"已自动检测本机网段：{network}")
            if not can_run_active_arp_scan():
                msg = "内置 ARP 扫描需要 sudo/root 权限；请改用 Bettercap 或 sudo 启动"
                raise PermissionError(msg)
            devices = list_network_devices(
                network,
                timeout=_float_value(
                    body.get("timeout"), _float_value(scan_config.get("timeout"), 0.5)
                ),
                passes=_int_value(
                    body.get("passes"), _int_value(scan_config.get("passes"), 3)
                ),
                batch_size=_int_value(
                    body.get("batch_size"),
                    _int_value(scan_config.get("batch_size"), 64),
                ),
                interval=_float_value(
                    body.get("interval"),
                    _float_value(scan_config.get("interval"), 0.002),
                ),
                resolve_hostnames=_bool_value(
                    body.get("resolve_hostnames"),
                    _bool_value(scan_config.get("resolve_hostnames"), True),
                ),
            )
            records = [_scan_item_to_record(device) for device in devices]

        return {
            "ok": True,
            "scanner": scanner,
            "devices": records,
            "logs": logs,
            "count": len(records),
        }

    def _locate(self, body: dict[str, Any]) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        config = self.server.config
        locate_config = config.get("locate", {})
        locate_config = locate_config if isinstance(locate_config, Mapping) else {}
        records = load_device_records(self.server.store_path)

        network = _clean_str(body.get("network"))
        if _bool_value(body.get("scan_network"), False):
            network = network or "auto"
        if network and network.casefold() == "auto":
            network = detect_local_ipv4_network()
            if network is None:
                msg = "未能自动检测本机网段"
                raise ValueError(msg)
        if network and not can_run_active_arp_scan():
            network = None

        matches = locate_devices(
            hostname=_clean_str(body.get("hostname")),
            note=_clean_str(body.get("note")),
            devices=_records_to_devices(records),
            network=network,
            note_hosts=note_hosts_from_records(records),
            timeout=_float_value(
                body.get("timeout"), _float_value(locate_config.get("timeout"), 1.0)
            ),
            partial_hostname=_bool_value(
                body.get("partial_hostname"),
                _bool_value(locate_config.get("partial_hostname"), False),
            ),
            partial_note=_bool_value(
                body.get("partial_note"),
                _bool_value(locate_config.get("partial_note"), False),
            ),
            prime_arp_cache=_bool_value(
                body.get("prime_arp_cache"),
                _bool_value(locate_config.get("prime_arp_cache"), True),
            ),
        )
        return {
            "ok": True,
            "devices": [_device_to_record(device) for device in matches],
            "count": len(matches),
            "network_scanned": network,
        }

    def _save_devices(self, body: dict[str, Any]) -> dict[str, Any]:
        value = body.get("records", body.get("record"))
        if isinstance(value, Mapping):
            incoming = [dict(value)]
        elif isinstance(value, list):
            incoming = [dict(item) for item in value if isinstance(item, Mapping)]
        else:
            msg = "record or records is required"
            raise ValueError(msg)

        records = load_device_records(self.server.store_path)
        for record in incoming:
            records = upsert_device_record(records, record)
        save_device_records(records, self.server.store_path)
        return {
            "ok": True,
            "devices": records,
            "saved_count": len(incoming),
            "path": str(self.server.store_path),
        }

    def _delete_device(self, body: dict[str, Any]) -> dict[str, Any]:
        records = load_device_records(self.server.store_path)
        index = body.get("index")
        removed: DeviceRecord | None = None
        if isinstance(index, int):
            if index < 0 or index >= len(records):
                msg = "device index is out of range"
                raise IndexError(msg)
            removed = records.pop(index)
        elif isinstance(body.get("record"), Mapping):
            key = _record_key(body["record"])
            if key is None:
                msg = "record has no hostname, ip or mac key"
                raise ValueError(msg)
            for position, record in enumerate(records):
                if _record_key(record) == key:
                    removed = records.pop(position)
                    break
        else:
            msg = "index or record is required"
            raise ValueError(msg)

        if removed is None:
            msg = "device not found"
            raise ValueError(msg)
        save_device_records(records, self.server.store_path)
        return {"ok": True, "removed": removed, "devices": records}

    def _mdns(self, body: dict[str, Any]) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        mdns_config = self.server.config.get("mdns", {})
        mdns_config = mdns_config if isinstance(mdns_config, Mapping) else {}
        service_types = body.get("service_types")
        if isinstance(service_types, str):
            service_type_list = [
                item.strip() for item in service_types.split(",") if item.strip()
            ]
        elif isinstance(service_types, list):
            service_type_list = [
                str(item).strip() for item in service_types if str(item).strip()
            ]
        else:
            service_type_list = []

        domain = str(body.get("domain", mdns_config.get("domain", "local")))
        timeout = _float_value(
            body.get("timeout"), _float_value(mdns_config.get("timeout"), 1.0)
        )
        first = _bool_value(
            body.get("first"), _bool_value(mdns_config.get("first"), False)
        )
        merge = _bool_value(
            body.get("merge"), _bool_value(mdns_config.get("merge"), False)
        )
        instance = _clean_str(body.get("instance"))
        hostname = _clean_str(body.get("hostname"))

        if instance:
            if len(service_type_list) != 1:
                msg = "按 instance 查询时需要且只能提供一个 service type"
                raise ValueError(msg)
            services = [
                resolve_mdns_service(
                    instance,
                    service_type_list[0],
                    domain=domain,
                    timeout=timeout,
                )
            ]
        elif hostname:
            services = find_mdns_services_by_hostname(
                hostname,
                service_types=tuple(service_type_list) or DEFAULT_SERVICE_TYPES,
                domain=domain,
                timeout=timeout,
                first=first,
            )
        else:
            msg = "hostname or instance is required"
            raise ValueError(msg)

        merged = merge_mdns_services(services) if merge else None
        return {
            "ok": True,
            "services": [_service_to_record(service) for service in services],
            "merged": merged,
            "merged_text": format_mdns_key_values(merged) if merged else None,
            "count": len(services),
        }

    def _switch_wifi(self, body: dict[str, Any]) -> dict[str, Any]:
        ssid = _clean_str(body.get("ssid"))
        if ssid is None:
            msg = "SSID 不能为空"
            raise ValueError(msg)
        result = switch_wifi_network(
            ssid,
            password=_clean_str(body.get("password")),
            interface=_clean_str(body.get("interface")),
            verify=_bool_value(body.get("verify"), True),
            verify_timeout=_float_value(body.get("verify_timeout"), 12.0),
        )
        return {"ok": True, "ssid": result or ssid}

    def _load_test(self, body: dict[str, Any]) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        load_config = self.server.config.get("load", {})
        load_config = load_config if isinstance(load_config, Mapping) else {}
        duration_value = body.get("duration", load_config.get("duration", 10.0))
        duration = _float_value(duration_value, 10.0)
        config = LoadTestConfig(
            target=str(body.get("target", "")).strip(),
            protocol=str(body.get("protocol", load_config.get("protocol", "icmp"))),
            concurrency=_int_value(
                body.get("concurrency"),
                _int_value(load_config.get("concurrency"), 32),
            ),
            duration=None if duration == 0 else duration,
            count=None
            if body.get("count", load_config.get("count")) in {None, ""}
            else _int_value(body.get("count", load_config.get("count")), 0),
            timeout=_float_value(
                body.get("timeout"), _float_value(load_config.get("timeout"), 1.0)
            ),
            tcp_port=_int_value(
                body.get("tcp_port", body.get("port")),
                _int_value(load_config.get("tcp_port"), 5000),
            ),
            refresh_interval=_float_value(
                body.get("refresh_interval"),
                _float_value(load_config.get("refresh_interval"), 0.25),
            ),
            ramp_up=_float_value(
                body.get("ramp_up"), _float_value(load_config.get("ramp_up"), 0.75)
            ),
            per_worker_jitter=_float_value(
                body.get("per_worker_jitter", body.get("jitter")),
                _float_value(load_config.get("per_worker_jitter"), 0.002),
            ),
            payload_size=_int_value(
                body.get("payload_size"),
                _int_value(load_config.get("payload_size"), 0),
            ),
            tcp_keep_open=_bool_value(
                body.get("tcp_keep_open"),
                _bool_value(load_config.get("tcp_keep_open"), False),
            ),
        )
        summary = run_load_test(config, live=False, include_series=True)
        return {"ok": True, "summary": summary}

    def _auto_wifi_scan(self, body: dict[str, Any]) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        config = self.server.config
        bettercap = config.get("bettercap", {})
        bettercap = bettercap if isinstance(bettercap, Mapping) else {}
        wifi = config.get("wifi", {})
        wifi = wifi if isinstance(wifi, Mapping) else {}
        auto_config = config.get("auto_wifi_scan", {})
        auto_config = auto_config if isinstance(auto_config, Mapping) else {}
        wifi_list = expand_wifi_rotation_path(
            body.get(
                "wifi_list",
                auto_config.get("wifi_list", "HypingData/hyping-wifi-rotation.json"),
            )
        )
        if not wifi_list.exists():
            write_wifi_scan_template(wifi_list)
            return {
                "ok": False,
                "template_created": True,
                "path": str(wifi_list),
                "error": "已创建 Wi-Fi 轮换配置模板，请编辑后重新运行",
            }
        targets = load_wifi_scan_targets(wifi_list)
        logs: list[str] = []
        client = BettercapClient(
            str(
                body.get("bettercap_url", bettercap.get("url", "http://127.0.0.1:8081"))
            ),
            str(body.get("bettercap_user", bettercap.get("username", "user"))),
            str(body.get("bettercap_pass", bettercap.get("password", "pass"))),
            timeout=_float_value(
                body.get("bettercap_api_timeout"),
                _float_value(bettercap.get("api_timeout"), 3.0),
            ),
        )
        results = run_auto_wifi_scan(
            targets,
            client=client,
            interface=_clean_str(body.get("interface"))
            or _clean_str(wifi.get("interface")),
            bettercap_command=str(
                body.get("bettercap_command", bettercap.get("command", "bettercap"))
            ),
            startup_timeout=_float_value(
                body.get("startup_timeout"),
                _float_value(bettercap.get("startup_timeout"), 8.0),
            ),
            startup_poll_interval=_float_value(
                body.get("startup_poll_interval"),
                _float_value(bettercap.get("startup_poll_interval"), 0.25),
            ),
            bettercap_wait=_float_value(
                body.get("bettercap_wait"), _float_value(bettercap.get("wait"), 5.0)
            ),
            bettercap_poll=_float_value(
                body.get("bettercap_poll"),
                _float_value(bettercap.get("poll_interval"), 0.5),
            ),
            discovery_warmup=_float_value(
                body.get("discovery_warmup"),
                _float_value(bettercap.get("discovery_warmup"), 3.0),
            ),
            verify_timeout=_float_value(
                body.get("verify_timeout"),
                _float_value(wifi.get("verify_timeout"), 12.0),
            ),
            restore_original=_bool_value(
                body.get("restore_original"),
                _bool_value(auto_config.get("restore_original"), True),
            ),
            store_path=self.server.store_path,
            on_status=logs.append,
        )
        return {
            "ok": True,
            "logs": logs,
            "results": [
                {
                    "ssid": result.ssid,
                    "host_count": len(result.hosts),
                    "saved_count": result.saved_count,
                    "error": result.error,
                    "hosts": [_scan_item_to_record(host) for host in result.hosts],
                }
                for result in results
            ],
        }

    def _auto_locate(self, body: dict[str, Any]) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        config = self.server.config
        bettercap = config.get("bettercap", {})
        bettercap = bettercap if isinstance(bettercap, Mapping) else {}
        wifi = config.get("wifi", {})
        wifi = wifi if isinstance(wifi, Mapping) else {}
        auto_config = config.get("auto_wifi_scan", {})
        auto_config = auto_config if isinstance(auto_config, Mapping) else {}
        hostname = _clean_str(body.get("hostname"))
        if hostname is None:
            msg = "hostname 不能为空"
            raise ValueError(msg)
        wifi_list = expand_wifi_rotation_path(
            body.get(
                "wifi_list",
                auto_config.get("wifi_list", "HypingData/hyping-wifi-rotation.json"),
            )
        )
        if not wifi_list.exists():
            write_wifi_scan_template(wifi_list)
            return {
                "ok": False,
                "template_created": True,
                "path": str(wifi_list),
                "error": "已创建 Wi-Fi 轮换配置模板，请编辑后重新运行",
            }
        targets = load_wifi_scan_targets(wifi_list)
        logs: list[str] = []
        client = BettercapClient(
            str(
                body.get("bettercap_url", bettercap.get("url", "http://127.0.0.1:8081"))
            ),
            str(body.get("bettercap_user", bettercap.get("username", "user"))),
            str(body.get("bettercap_pass", bettercap.get("password", "pass"))),
            timeout=_float_value(
                body.get("bettercap_api_timeout"),
                _float_value(bettercap.get("api_timeout"), 3.0),
            ),
        )
        result = find_hostname_with_bettercap_then_wifi_rotation(
            hostname,
            targets,
            client=client,
            interface=_clean_str(body.get("interface"))
            or _clean_str(wifi.get("interface")),
            bettercap_command=str(
                body.get("bettercap_command", bettercap.get("command", "bettercap"))
            ),
            auto_start_bettercap_api=_bool_value(
                body.get("auto_start_bettercap_api"),
                _bool_value(bettercap.get("auto_start_api"), True),
            ),
            online_check_timeout=_float_value(
                body.get("online_check_timeout"),
                _float_value(bettercap.get("online_check_timeout"), 0.25),
            ),
            startup_timeout=_float_value(
                body.get("startup_timeout"),
                _float_value(bettercap.get("startup_timeout"), 8.0),
            ),
            startup_poll_interval=_float_value(
                body.get("startup_poll_interval"),
                _float_value(bettercap.get("startup_poll_interval"), 0.25),
            ),
            bettercap_wait=_float_value(
                body.get("bettercap_wait"), _float_value(bettercap.get("wait"), 5.0)
            ),
            bettercap_poll=_float_value(
                body.get("bettercap_poll"),
                _float_value(bettercap.get("poll_interval"), 0.5),
            ),
            discovery_warmup=_float_value(
                body.get("discovery_warmup"),
                _float_value(bettercap.get("discovery_warmup"), 3.0),
            ),
            verify_timeout=_float_value(
                body.get("verify_timeout"),
                _float_value(wifi.get("verify_timeout"), 12.0),
            ),
            restore_original=_bool_value(
                body.get("restore_original"),
                _bool_value(auto_config.get("restore_original"), True),
            ),
            partial_hostname=_bool_value(body.get("partial_hostname"), False),
            store_path=self.server.store_path,
            on_status=logs.append,
        )
        record = _scan_item_to_record(result.host) if result.host else None
        if record is not None and result.ssid:
            record["ssid"] = result.ssid
        return {
            "ok": True,
            "logs": logs,
            "query": result.query,
            "found": result.host is not None,
            "ssid": result.ssid,
            "scanned_ssids": list(result.scanned_ssids),
            "saved_count": result.saved_count,
            "host": record,
        }

    def _save_config(self, body: dict[str, Any]) -> dict[str, Any]:
        current = ensure_config()
        incoming = body.get("config", body)
        if not isinstance(incoming, Mapping):
            msg = "config object is required"
            raise ValueError(msg)
        merged = _deep_merge(current, incoming)
        bettercap = merged.get("bettercap")
        incoming_bettercap = (
            incoming.get("bettercap") if isinstance(incoming, Mapping) else None
        )
        if isinstance(bettercap, dict) and isinstance(incoming_bettercap, Mapping):
            password = incoming_bettercap.get("password")
            if password in {"", MASKED_SECRET, "******", "********"}:
                old_bettercap = current.get("bettercap", {})
                if isinstance(old_bettercap, Mapping):
                    bettercap["password"] = old_bettercap.get("password", "")
        web_auth = merged.get("web_auth")
        incoming_web_auth = (
            incoming.get("web_auth") if isinstance(incoming, Mapping) else None
        )
        if isinstance(web_auth, dict) and isinstance(incoming_web_auth, Mapping):
            for key in ("client_secret", "server_api_token", "session_secret"):
                value = incoming_web_auth.get(key)
                if value in {"", MASKED_SECRET, "******", "********"}:
                    old_web_auth = current.get("web_auth", {})
                    if isinstance(old_web_auth, Mapping):
                        web_auth[key] = old_web_auth.get(key, "")
        save_config(merged)
        self.server.config = _apply_web_auth_env(merged)
        return {"ok": True, "config": _redact_config(self.server.config)}

    def _load_wifi_rotation(self) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        auto_config = self.server.config.get("auto_wifi_scan", {})
        auto_config = auto_config if isinstance(auto_config, Mapping) else {}
        path = expand_wifi_rotation_path(
            auto_config.get("wifi_list", "HypingData/hyping-wifi-rotation.json")
        )
        if not path.exists():
            return {"ok": True, "path": str(path), "exists": False, "networks": []}
        targets = load_wifi_scan_targets(path)
        return {
            "ok": True,
            "path": str(path),
            "exists": True,
            "networks": [
                {
                    "ssid": target.ssid,
                    "password": MASKED_SECRET if target.password else "",
                    "password_saved": bool(target.password),
                }
                for target in targets
            ],
        }

    def _save_wifi_rotation(self, body: dict[str, Any]) -> dict[str, Any]:
        self.server.config = _load_runtime_config(self.server.config)
        auto_config = self.server.config.get("auto_wifi_scan", {})
        auto_config = auto_config if isinstance(auto_config, Mapping) else {}
        path = expand_wifi_rotation_path(
            body.get(
                "path",
                auto_config.get("wifi_list", "HypingData/hyping-wifi-rotation.json"),
            )
        )
        existing_passwords: dict[str, str | None] = {}
        if path.exists():
            try:
                for target in load_wifi_scan_targets(path):
                    existing_passwords[target.ssid] = target.password
            except AutoWiFiScanError:
                existing_passwords = {}
        networks = body.get("networks")
        if not isinstance(networks, list):
            msg = "networks list is required"
            raise ValueError(msg)
        saved_networks: list[dict[str, str | None]] = []
        for item in networks:
            if not isinstance(item, Mapping):
                continue
            ssid = _clean_str(item.get("ssid"))
            if ssid is None:
                continue
            password = item.get("password")
            if password in {MASKED_SECRET, "******", "********"}:
                password = existing_passwords.get(ssid)
            saved_networks.append(
                {
                    "ssid": ssid,
                    "password": _clean_str(password),
                }
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"networks": saved_networks}, ensure_ascii=False, indent=2)
            + "\n",
            encoding="utf-8",
        )
        return self._load_wifi_rotation()
