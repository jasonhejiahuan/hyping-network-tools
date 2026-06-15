import os
import pwd
import shutil
from pathlib import Path


def default_user_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def project_root() -> Path:
    """Return the nearest visible project directory for runtime files."""

    candidates = [Path.cwd(), Path(__file__).resolve()]
    for start in candidates:
        current = start if start.is_dir() else start.parent
        for directory in (current, *current.parents):
            if (directory / "pyproject.toml").exists() and (
                directory / "src" / "hyping"
            ).exists():
                return directory

    return Path.cwd()


RUNTIME_DIR = project_root() / "HypingData"
CONFIG_PATH = RUNTIME_DIR / "hyping-config.json"
DEVICE_STORE_PATH = RUNTIME_DIR / "hyping-devices.json"
WIFI_ROTATION_PATH = RUNTIME_DIR / "hyping-wifi-rotation.json"


def expand_runtime_path(value: str | Path) -> Path:
    """Expand paths while keeping legacy ~/.hyping defaults in HypingData."""

    text = str(value)
    legacy_names = {
        "~/.hyping/config.json": CONFIG_PATH,
        "~/.hyping/devices.json": DEVICE_STORE_PATH,
        "~/.hyping/wifi-rotation.json": WIFI_ROTATION_PATH,
    }
    if text in legacy_names:
        return legacy_names[text]

    return Path(text).expanduser()


def legacy_hyping_path(filename: str) -> Path:
    return default_user_home() / ".hyping" / filename


def copy_legacy_file_if_present(source: Path, destination: Path) -> bool:
    if destination.exists() or not source.exists():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return True
