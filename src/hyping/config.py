import json
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from hyping.paths import (
    CONFIG_PATH,
    WIFI_ROTATION_PATH,
    copy_legacy_file_if_present,
    legacy_hyping_path,
)

DEFAULT_CONFIG_PATH = CONFIG_PATH

DEFAULT_CONFIG: dict[str, Any] = {
    "bettercap": {
        "url": "http://127.0.0.1:8081",
        "username": "user",
        "password": "pass",
        "api_timeout": 3.0,
        "online_check_timeout": 0.25,
        "wait": 5.0,
        "poll_interval": 0.5,
        "start_discovery": True,
        "discovery_warmup": 3.0,
        "auto_start_api": True,
        "command": "bettercap",
        "interface": "auto",
        "startup_timeout": 8.0,
        "startup_poll_interval": 0.25,
        "shutdown_on_ui_exit": True,
    },
    "scan": {
        "scanner": "bettercap",
        "network": "auto",
        "timeout": 0.5,
        "passes": 3,
        "batch_size": 64,
        "interval": 0.002,
        "resolve_hostnames": True,
        "json": False,
    },
    "load": {
        "protocol": "icmp",
        "tcp_port": 5000,
        "concurrency": 32,
        "duration": 10.0,
        "count": None,
        "timeout": 1.0,
        "refresh_interval": 0.25,
        "ramp_up": 0.75,
        "per_worker_jitter": 0.002,
        "payload_size": 0,
        "tcp_keep_open": False,
    },
    "locate": {
        "timeout": 1.0,
        "partial_hostname": False,
        "partial_note": False,
        "prime_arp_cache": True,
    },
    "mdns": {
        "timeout": 1.0,
        "domain": "local",
        "first": False,
        "merge": False,
    },
    "wifi": {
        "verify_timeout": 12.0,
    },
    "auto_wifi_scan": {
        "wifi_list": str(WIFI_ROTATION_PATH),
        "restore_original": True,
        "create_template": True,
    },
    "web_auth": {
        "enabled": True,
        "login_flow": "redirect",
        "auth_base_url": "http://localhost:5003",
        "callback_url": "",
        "client_id": "passkey-demo-client",
        "client_secret": "passkey-demo-secret",
        "server_api_token": "",
        "username": "",
        "session_ttl_seconds": 3600,
        "challenge_ttl_seconds": 300,
        "request_timeout": 5.0,
    },
}


def _deep_merge(
    defaults: dict[str, Any],
    override: Mapping[str, Any],
) -> dict[str, Any]:
    merged = deepcopy(defaults)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value

    return merged


def ensure_config(path: Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Create the config file with defaults if missing, then load it."""

    if not path.exists():
        if path == DEFAULT_CONFIG_PATH:
            if copy_legacy_file_if_present(legacy_hyping_path("config.json"), path):
                return ensure_config(path)

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        return deepcopy(DEFAULT_CONFIG)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"invalid config JSON: {path}"
        raise ValueError(msg) from exc

    if not isinstance(data, dict):
        msg = f"invalid config format: {path}"
        raise ValueError(msg)

    return _deep_merge(DEFAULT_CONFIG, data)


def save_config(config: Mapping[str, Any], path: Path = DEFAULT_CONFIG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
