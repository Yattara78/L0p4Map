"""Alert formatting and delivery (network calls are injected, never real)."""

import json

from core import alerts, settings
from core.inventory import ScanDiff


class FakeResponse:
    def __init__(self, payload=b"{}"):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.payload


class FakeOpener:
    def __init__(self):
        self.calls = []

    def __call__(self, request, timeout=None):
        self.calls.append(request)
        return FakeResponse()


def make_diff():
    return ScanDiff(
        scan_id=1,
        seen=[{"mac": "AA:BB:CC:00:00:01", "ip": "10.0.0.5", "name": "mac-mini"}],
        new=[{"mac": "AA:BB:CC:00:00:01", "ip": "10.0.0.5", "name": "mac-mini"}],
        missing=[{"mac": "AA:BB:CC:00:00:09", "ip": "10.0.0.9", "hostname": "printer"}],
        new_ports=[{"mac": "AA:BB:CC:00:00:01", "port": 23, "proto": "tcp"}],
    )


def test_format_scan_diff_lists_changes():
    title, body = alerts.format_scan_diff(make_diff(), subnet="10.0.0.0/24")
    assert "10.0.0.0/24" in title
    assert "Nouveaux appareils" in body
    assert "AA:BB:CC:00:00:01" in body
    assert "printer" in body
    assert "23/tcp" in body


def test_format_scan_diff_without_changes():
    title, body = alerts.format_scan_diff(ScanDiff(scan_id=2))
    assert "Aucun changement" in body


def test_telegram_payload_and_url():
    cfg = alerts.AlertConfig(telegram_token="TOKEN", telegram_chat_id="42")
    fake = FakeOpener()
    assert alerts.send_telegram(cfg, "hello", opener=fake) is None
    assert fake.calls[0].full_url == "https://api.telegram.org/botTOKEN/sendMessage"
    payload = json.loads(fake.calls[0].data.decode())
    assert payload["chat_id"] == "42" and payload["text"] == "hello"


def test_webhook_payload_has_text_and_content():
    cfg = alerts.AlertConfig(webhook_url="https://example.test/hook")
    fake = FakeOpener()
    assert alerts.send_webhook(cfg, "body", title="title", opener=fake) is None
    payload = json.loads(fake.calls[0].data.decode())
    assert payload["content"] == "body"
    assert "title" in payload["text"]


def test_unconfigured_channels_are_skipped():
    cfg = alerts.AlertConfig()
    assert alerts.send_telegram(cfg, "x") == "not configured"
    assert alerts.send_webhook(cfg, "x") == "not configured"
    assert alerts.send_email(cfg, "s", "x") == "not configured"
    assert cfg.is_configured() is False


def test_dispatch_calls_every_configured_channel():
    cfg = alerts.AlertConfig(
        desktop=True,
        telegram_token="T", telegram_chat_id="1",
        webhook_url="https://example.test/hook",
    )
    fake = FakeOpener()
    seen = []
    results = alerts.dispatch(
        cfg, "Titre", "Corps", notifier=lambda t, b: seen.append((t, b)), opener=fake
    )
    assert set(results) == {"desktop", "telegram", "webhook"}
    assert all(err == "" for err in results.values())
    assert seen and seen[0][0] == "Titre"
    assert len(fake.calls) == 2


def test_failed_delivery_returns_error_not_raises():
    def boom(request, timeout=None):
        raise OSError("network down")

    cfg = alerts.AlertConfig(telegram_token="T", telegram_chat_id="1")
    assert "network down" in alerts.send_telegram(cfg, "x", opener=boom)


def test_config_roundtrip_keeps_secrets_and_permissions(tmp_path):
    path = tmp_path / "config.json"
    cfg = alerts.AlertConfig(
        telegram_token="secret-token", telegram_chat_id="7", desktop=False
    )
    cfg.save(path)
    loaded = alerts.AlertConfig.load(path)
    assert loaded.telegram_token == "secret-token"
    assert loaded.telegram_chat_id == "7"
    assert loaded.desktop is False
    assert oct(path.stat().st_mode)[-3:] == "600"


def test_settings_merge_defaults(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"alerts": {"desktop": False}}), encoding="utf-8")
    data = settings.load(path)
    assert data["alerts"]["desktop"] is False
    assert data["alerts"]["smtp_port"] == 587  # default preserved
    assert data["schedule"]["mode"] == "interval"
