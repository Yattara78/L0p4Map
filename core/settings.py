"""User settings stored in ~/.l0p4map/config.json.

One JSON file shared by the GUI, the CLI and the scheduler. Sections are
independent dicts so a new feature can add one without a migration.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional

try:  # Unix only
    import pwd
except ImportError:  # pragma: no cover - Windows
    pwd = None  # type: ignore[assignment]


def user_home() -> Path:
    """Home of the invoking user, even when the GUI runs through sudo.

    The launcher starts the app with `sudo -E`, so HOME would be /var/root and
    the GUI would silently build a second inventory that the CLI never sees.
    """
    if os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and pwd is not None:
            try:
                return Path(pwd.getpwnam(sudo_user).pw_dir)
            except KeyError:
                pass
    return Path.home()


def _invoking_owner() -> Optional[tuple[int, int]]:
    if os.geteuid() != 0:
        return None
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or pwd is None:
        return None
    try:
        entry = pwd.getpwnam(sudo_user)
    except KeyError:
        return None
    return entry.pw_uid, entry.pw_gid


def fix_ownership(path: str | Path) -> None:
    """Give files created as root back to the invoking user (best effort)."""
    owner = _invoking_owner()
    if owner is None:
        return
    try:
        os.chown(Path(path), *owner)
    except OSError:
        pass


CONFIG_DIR = Path(
    os.environ.get("L0P4MAP_CONFIG_DIR") or (user_home() / ".l0p4map")
)
CONFIG_PATH = CONFIG_DIR / "config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "alerts": {
        "desktop": True,
        "telegram_token": "",
        "telegram_chat_id": "",
        "webhook_url": "",
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "smtp_starttls": True,
        "email_to": "",
    },
    "schedule": {
        "enabled": False,
        "mode": "interval",
        "interval_minutes": 60,
        "at_time": "08:00",
        "last_run": 0.0,
    },
}


def config_path(path: Optional[str | Path] = None) -> Path:
    return Path(path) if path else CONFIG_PATH


def load(path: Optional[str | Path] = None) -> dict:
    """Read the config, filling in defaults for missing keys."""
    target = config_path(path)
    data: dict[str, Any] = {}
    if target.exists():
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
    merged = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    for section, values in data.items():
        if isinstance(values, dict) and isinstance(merged.get(section), dict):
            merged[section].update(values)
        else:
            merged[section] = values
    return merged


def save(config: dict, path: Optional[str | Path] = None) -> Path:
    """Atomic write (temp file + rename) so a crash cannot truncate settings."""
    target = config_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".config-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    try:
        os.chmod(target, 0o600)  # may hold API tokens / SMTP password
    except OSError:
        pass
    fix_ownership(target)
    fix_ownership(target.parent)
    return target


def section(name: str, path: Optional[str | Path] = None) -> dict:
    return dict(load(path).get(name, {}))


def update_section(name: str, values: dict, path: Optional[str | Path] = None) -> dict:
    data = load(path)
    current = data.get(name)
    if not isinstance(current, dict):
        current = {}
    current.update(values)
    data[name] = current
    save(data, path)
    return current
