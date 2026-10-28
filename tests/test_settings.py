"""Config file behaviour: defaults, permissions, sudo-safe paths."""

import json
import os
from pathlib import Path

from core import settings


def test_load_missing_file_returns_defaults(tmp_path):
    data = settings.load(tmp_path / "nope.json")
    assert data["alerts"]["smtp_port"] == 587
    assert data["schedule"]["enabled"] is False


def test_corrupted_file_falls_back_to_defaults(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{not json", encoding="utf-8")
    assert settings.load(path)["alerts"]["desktop"] is True


def test_update_section_keeps_other_sections(tmp_path):
    path = tmp_path / "config.json"
    settings.update_section("alerts", {"desktop": False}, path)
    settings.update_section("schedule", {"interval_minutes": 15}, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["alerts"]["desktop"] is False
    assert data["schedule"]["interval_minutes"] == 15


def test_saved_file_is_private(tmp_path):
    path = tmp_path / "config.json"
    settings.save({"alerts": {"telegram_token": "x"}}, path)
    assert oct(path.stat().st_mode)[-3:] == "600"


def test_user_home_without_sudo(monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    assert settings.user_home() == Path.home()


def test_user_home_with_sudo_uses_invoking_user(monkeypatch):
    current = os.environ.get("USER") or Path.home().name
    monkeypatch.setenv("SUDO_USER", current)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert settings.user_home() == Path.home()


def test_fix_ownership_is_a_noop_when_not_root(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    settings.fix_ownership(tmp_path)  # must not raise
